AI LLM Agent Fore Wazuh
Wazuh AI Reporter est un agent intelligent conçu pour automatiser l'analyse des alertes de sécurité de votre serveur Wazuh. Au lieu de parcourir des milliers de lignes de logs JSON, cet outil extrait les alertes pertinentes, les fait analyser par une IA locale (Ollama) et vous envoie un rapport de synthèse structuré par e-mail.

🚀 Fonctionnement en 4 étapes
Extraction SSH : Le script se connecte à votre manager Wazuh pour récupérer les alertes.

Tri Intelligent : Il filtre les données (Niveau 5+ sur les dernières 24h), regroupe les alertes par regles filtré par régles, agents affectés par cet régles, et nombre d'occurences par agent.

Analyse IA (Llama 3) : L'IA interprète les menaces, identifie les machines cibles et propose des solutions.

Notification : Un rapport HTML élégant est envoyé par e-mail.

📊 Exemple de Rapport Généré
Voici à quoi ressemble le rapport que vous recevrez quotidiennement dans votre boîte mail :

🛡️ Synthèse de Sécurité IA Wazuh
Généré le : 06/04/2026 à 16:05:52

1. Résumé des Menaces Critiques
Les alertes de sécurité Wazuh agrégées indiquent les menaces suivantes :

🔴 Windows audit failure event (Règle 60104) : 50 027 occurrences.

🖥️ Hôtes les plus touchés : SRV-AD-01 (46 502), SRV-SQL-PROD (1 396), DC-MASTER (1 030), WS-RH-05 (123).

⚠️ Analyse : L'attaque semble ciblée sur les contrôleurs de domaine, avec une fréquence extrêmement élevée de tentatives d'accès non autorisées (Brute force suspecté).

🔴 Windows application error event (Règle 60602) : 1 269 occurrences.

🖥️ Hôtes les plus touchés : WS-DEV-12 (831), WS-DEV-14 (415).

⚠️ Analyse : Ces erreurs répétées sur le segment développement pourraient indiquer une tentative d'exploitation de vulnérabilité applicative.

🔴 Windows System error event (Règle 61102) : 114 occurrences.

🖥️ Hôtes les plus touchés : SRV-FILE-01 (63), SRV-BACKUP (65).

⚠️ Analyse : Les erreurs système sur les serveurs de stockage suggèrent une instabilité ou une modification non autorisée des services critiques.

2. Impact Potentiel Global
Le volume massif de tentatives d'accès non autorisées (Audit Failure) représente un risque critique pour la confidentialité des comptes à hauts privilèges. Les erreurs système concomitantes sur les serveurs de fichiers pourraient affecter la disponibilité des données et l'intégrité du système de fichiers.

3. Mesures Correctives Suggérées
Isolation Immédiate : Mettre en quarantaine les IP sources générant les échecs d'audit.

Hardening : Renforcer les politiques de verrouillage de compte Windows.

Patching : Appliquer les derniers correctifs de sécurité Windows sur les serveurs affectés.

Audit : Vérifier l'état des services SessionEnv sur SRV-FILE-01.

🛠️ Prérequis
Python 3.8+

Wazuh Manager avec accès SSH (Clé RSA).

Ollama installé localement avec le modèle llama3.

Accès SMTP (Outlook, Gmail ou Relais interne).

⚙️ Configuration
Ouvrez le script et modifiez la section CONFIGURATION PARAMETERS :

🔑 Accès Serveur & Wazuh
SSH_HOST : IP de votre serveur Wazuh.

SSH_KEY_PATH : Chemin vers votre clé privée (~/.ssh/id_rsa).

ALERT_LEVEL_THRESHOLD : Niveau minimum des alertes à traiter (défaut: 5).

🤖 Intelligence Artificielle
OLLAMA_API_URL : Par défaut http://localhost:11434/api/generate.

OLLAMA_MODEL : Modèle utilisé (ex: llama3 ou mistral).

📧 Envoi de rapports
SMTP_HOST / PORT : Vos paramètres serveur mail.

EMAIL_TO : L'adresse qui recevra les analyses.

🖥️ Utilisation
Pour lancer l'analyse manuellement :

Bash
python main.py
Astuce : Pour recevoir un rapport chaque matin, ajoutez une tâche Cron :

Bash
# Exemple : Lancer le script tous les jours à 08h00
00 08 * * * /usr/bin/python3 /chemin/vers/votre/script/main.py
📝 Structure du Rapport Généré
Le rapport reçu par mail contient trois sections clés :

Résumé des Menaces Critiques : Liste des alertes avec emojis de priorité (🔴, 🟠, 🟡 et 🟢).

Impact Potentiel Global : Analyse des risques pour votre infrastructure.

Mesures Correctives : Actions immédiates à entreprendre.

⚠️ Notes de Sécurité
Clés SSH : Utilisez une clé SSH sans mot de passe ou un agent SSH pour l'automatisation. Assurez-vous que l'utilisateur SSH a les droits de lecture sur /var/ossec/logs/alerts/alerts.json.

Ressources : L'analyse IA est limitée à 2 threads dans le code (num_thread: 2) pour éviter de saturer le processeur de votre machine de monitoring.
