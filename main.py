import paramiko
import json
import logging
import smtplib
import os
import sys
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone

# ==========================================
# CONFIGURATION PARAMETERS
# ==========================================

# Configuration SSH (Authentification par clé RSA)
SSH_HOST = "" #IP Du serveur WAZUH
SSH_PORT = 22 # Port du SSH
SSH_USER = "" #Nom d'utilisateur ssh
SSH_KEY_PATH = "" #clé privé d'accès SSH

# Configuration Wazuh
WAZUH_LOG_PATH = "/var/ossec/logs/alerts/alerts.json" #chemin des alertes
ALERT_LEVEL_THRESHOLD = 5 # Level des alertes

# Configuration Ollama (Local)
OLLAMA_API_URL = "http://localhost:11434/api/generate" #Login de l'API OLLAMA
OLLAMA_MODEL = "llama3" #modele IA

# Configuration SMTP 
SMTP_HOST = "" #Serveur SMTP ex : smtp.office365.com
SMTP_PORT = #en int : Port du serveur SMTP 
SMTP_USER = "" # Email expediteur
SMTP_PASSWORD = "" # mot de passe du compte expediteur ou Utilisez un "App Password"
EMAIL_TO = "" # email destinataire

# Configuration du Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# ==========================================
# FONCTIONS
# ==========================================

def fetch_wazuh_logs_ssh() -> list:
    """Se connecte via SSH et extrait les logs des dernières 48h côté serveur."""
    logging.info(f"Connexion au serveur Wazuh {SSH_HOST}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    log_lines = []
    try:
        full_key_path = os.path.expanduser(SSH_KEY_PATH)
        client.connect(
            hostname=SSH_HOST, 
            port=SSH_PORT, 
            username=SSH_USER, 
            key_filename=full_key_path,
            look_for_keys=False,
            allow_agent=False,
            timeout=15
        )
        logging.info("✅ Connexion SSH établie avec succès.")
        
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%d')
        
        command = f"grep -E '({today}|{yesterday})' {WAZUH_LOG_PATH}"
        logging.info(f"Extraction des logs distants pour {yesterday} et {today}...")
        
        stdin, stdout, stderr = client.exec_command(command)
        
        for line in stdout:
            log_lines.append(line.strip())
            
        error_output = stderr.read().decode('utf-8')
        if error_output and not log_lines:
            logging.error(f"Erreur commande SSH : {error_output.strip()}")

    except Exception as e:
        logging.error(f"Erreur de connexion SSH : {e}")
    finally:
        client.close()
        
    logging.info(f"Récupération de {len(log_lines)} lignes de log brutes.")
    return log_lines


def parse_and_sort_for_ai(log_lines: list) -> list:
    """Analyse les logs, filtre sur 24h et compte les occurrences par machine."""
    logging.info(f"Analyse et tri des données (Niveau {ALERT_LEVEL_THRESHOLD}+, dernières 24h)...")
    alerts_summary = {}
    time_limit = datetime.now(timezone.utc) - timedelta(hours=24)
    
    parsed_count = 0
    
    for line in log_lines:
        if not line: continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError: continue
            
        timestamp_str = alert.get("timestamp")
        if not timestamp_str: continue
            
        try:
            clean_time_str = timestamp_str.split('+')[0][:26] + "+00:00"
            alert_time = datetime.fromisoformat(clean_time_str)
            if alert_time < time_limit: continue
        except ValueError: continue
            
        rule_level = alert.get("rule", {}).get("level", 0)
        if rule_level < ALERT_LEVEL_THRESHOLD: continue
            
        rule_id = alert.get("rule", {}).get("id", "Unknown")
        rule_desc = alert.get("rule", {}).get("description", "Aucune description")
        agent_name = alert.get("agent", {}).get("name", "Hôte Inconnu")
        
        if rule_id not in alerts_summary:
            alerts_summary[rule_id] = {
                "regle_id": rule_id,
                "description": rule_desc,
                "total_alertes": 0,
                "machines_en_alerte": {}
            }
            
        alerts_summary[rule_id]["total_alertes"] += 1
        
        if agent_name not in alerts_summary[rule_id]["machines_en_alerte"]:
            alerts_summary[rule_id]["machines_en_alerte"][agent_name] = 0
        alerts_summary[rule_id]["machines_en_alerte"][agent_name] += 1
        
        parsed_count += 1

    logging.info(f"✅ {parsed_count} alertes traitées et structurées par machine.")
    
    # Trier du plus grand nombre d'alertes au plus petit
    sorted_alerts = sorted(alerts_summary.values(), key=lambda x: x["total_alertes"], reverse=True)
    
    # Optionnel: Limiter au top 20 des règles pour ne pas surcharger la mémoire de l'IA
    return sorted_alerts[:20]


def analyze_with_ollama(alerts: list) -> str:
    """Envoie les alertes structurées à l'IA avec limitation CPU."""
    if not alerts:
        logging.info("Aucune alerte critique à analyser aujourd'hui.")
        return ""
        
    logging.info(f"Démarrage de l'analyse LLM via {OLLAMA_MODEL}...")
    
    prompt = (
        "Tu es un expert francophone en cybersécurité. Rédige un rapport d'analyse "
        "STRICTEMENT EN FRANÇAIS basé sur les logs Wazuh suivants des dernières 24 heures.\n\n"
        f"Données JSON des alertes (triées par criticité et fréquence) :\n{json.dumps(alerts, ensure_ascii=False)}\n\n"
        "Tu DOIS utiliser EXACTEMENT la structure suivante pour ta réponse :\n\n"
        "**1. Résumé des Menaces Critiques**\n"
        "Les alertes de sécurité Wazuh agrégées indiquent les menaces suivantes :\n"
        "* [Utilise 🔴 pour gravité critique, 🟠 pour élevée, 🟡 pour moyenne, 🟢 s'il y'a pas de gravité de sécurité] **[description] (Règle [regle_id]) :** *[total_alertes] occurrences.* \n"
        "  - 🖥️ **Hôtes les plus touchés :** [Liste ici de 1 à 8 machines ayant le plus grand nombre d'alertes parmi 'machines_en_alerte', avec leur nombre exact].\n"
        "  - ⚠️ **Analyse :** [1 phrase expliquant la menace, en précisant si l'attaque semble ciblée sur un hôte précis ou distribuée].\n"
        "(... Répète cette puce pour les autres règles listées dans le JSON ...)\n\n"
        "**2. Impact Potentiel Global**\n"
        "[Rédige un paragraphe expliquant les risques réels pour l'infrastructure]\n\n"
        "**3. Mesures Correctives Suggérées**\n"
        "[Propose des actions concrètes pour stopper ces menaces spécifiques]\n\n"
        "RAPPEL CRITIQUE : N'invente aucune donnée. Analyse intelligemment les chiffres dans 'machines_en_alerte'. Réponds UNIQUEMENT en français."
    )
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_thread": 2  # Limitation CPU !
        }
    }
    
    try:
        # Timeout de 90 minutes (5400 sec)
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=5400)
        response.raise_for_status()
        result = response.json()
        return result.get("response", "Erreur : Aucune réponse générée par l'IA.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Échec de la communication avec l'API Ollama : {e}")
        return f"Erreur lors de la génération de l'analyse : {e}"


def send_email_report(analysis_text: str):
    """Génère et envoie le rapport par e-mail via Outlook SMTP."""
    if not analysis_text:
        logging.warning("Aucun rapport généré. L'e-mail ne sera pas envoyé.")
        return

    logging.info("Préparation de l'envoi de l'e-mail via Outlook...")
    
    msg = MIMEMultipart("alternative")
    msg['Subject'] = f"IA Wazuh - Rapport Quotidien de Sécurité - {datetime.now().strftime('%d/%m/%Y')}"
    msg['From'] = SMTP_USER
    msg['To'] = EMAIL_TO

    text_body = f"Rapport d'Analyse de Sécurité IA Wazuh\n\n{analysis_text}"
    
    formatted_analysis = analysis_text.replace('\n', '<br>')
    formatted_analysis = formatted_analysis.replace('**', '<b>').replace('**', '</b>')
    
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; background-color: #f9f9f9; padding: 20px;">
        <div style="max-width: 850px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
            <h2 style="color: #0078D4; border-bottom: 2px solid #0078D4; padding-bottom: 10px;">🛡️ Synthèse de Sécurité IA Wazuh</h2>
            <p style="color: #666; font-size: 0.9em;">Généré le : {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
            <div style="margin-top: 20px; font-size: 14px;">
                <p>{formatted_analysis}</p>
            </div>
        </div>
      </body>
    </html>
    """

    msg.attach(MIMEText(text_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        logging.info("✅ E-mail envoyé avec succès !")
    except Exception as e:
        logging.error(f"❌ Échec de l'envoi de l'e-mail : {e}")


# ==========================================
# EXÉCUTION PRINCIPALE
# ==========================================
def main():
    logging.info("=== Démarrage de l'Agent IA Wazuh ===")
    
    # 1. Extraction des logs
    raw_logs = fetch_wazuh_logs_ssh()
    if not raw_logs:
        logging.warning("Aucun log récupéré. Fin du script.")
        return
        
    # 2. Tri Mathématique pour l'IA
    ai_ready_data = parse_and_sort_for_ai(raw_logs)
    if not ai_ready_data:
        logging.info(f"Aucune alerte pertinente à traiter aujourd'hui. Fin du script.")
        return
        
    # 3. Réflexion LLM (Llama 3)
    analysis_report = analyze_with_ollama(ai_ready_data)
    
    # 4. Envoi du rapport aux administrateurs
    send_email_report(analysis_report)
    
    logging.info("=== Exécution de l'Agent IA Wazuh terminée avec succès ===")

if __name__ == "__main__":
    main()
