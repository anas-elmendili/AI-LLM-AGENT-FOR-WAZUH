# 🛡️ Wazuh AI Reporter
### *L'intelligence artificielle au service de votre SOC*

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-orange)](https://wazuh.com/)
[![Ollama](https://img.shields.io/badge/Ollama-Llama3-white)](https://ollama.com/)

**Wazuh AI Reporter** est un agent intelligent conçu pour automatiser l'analyse des alertes de sécurité. Au lieu de parcourir manuellement des milliers de lignes de logs JSON, cet outil extrait les données critiques, les fait analyser par une IA locale (**Ollama**) et vous envoie une synthèse actionnable directement par e-mail.

---

## 🚀 Fonctionnement en 4 étapes

| Étape | Action | Description |
| :--- | :--- | :--- |
| **1** | **Extraction SSH** | Connexion sécurisée au manager Wazuh pour récupérer les logs bruts. |
| **2** | **Tri Intelligent** | Filtrage (Niveau 5+ / 24h) et agrégation par règle et par agent. |
| **3** | **Analyse IA** | Le modèle **Llama 3** interprète les menaces et identifie les patterns d'attaque. |
| **4** | **Notification** | Génération et envoi d'un rapport HTML élégant aux administrateurs. |

---

## 📊 Exemple de Rapport Généré

Le rapport reçu quotidiennement transforme des données complexes en informations claires :

> ### 🛡️ Synthèse de Sécurité IA Wazuh
> **Date :** 06/04/2026 à 16:05:52
>
> #### **1. Résumé des Menaces Critiques**
> * 🔴 **Windows audit failure (Règle 60104) :** *50 027 occurrences.*
>   - 🖥️ **Hôtes :** `SRV-AD-01` (46 502), `SRV-SQL-PROD` (1 396), `DC-MASTER` (1 030).
>   - ⚠️ **Analyse :** Attaque ciblée sur les contrôleurs de domaine (Brute force suspecté).
>
> * 🔴 **Windows application error (Règle 60602) :** *1 269 occurrences.*
>   - 🖥️ **Hôtes :** `WS-DEV-12` (831), `WS-DEV-14` (415).
>   - ⚠️ **Analyse :** Potentielle tentative d'exploitation de vulnérabilité applicative sur le segment dev.
>
> #### **2. Impact Potentiel Global**
> Le volume massif de tentatives d'accès non autorisées représente un risque critique pour la confidentialité des comptes à hauts privilèges.
>
> #### **3. Mesures Correctives Suggérées**
> * 🔒 **Isolation :** Quarantaine immédiate des IP sources.
> * 🛡️ **Hardening :** Renforcement des politiques de verrouillage de compte.
> * 🛠️ **Patching :** Mise à jour urgente des correctifs Windows.

---

## 🛠️ Prérequis

* **Environnement** : Python 3.8+
* **Wazuh** : Accès SSH au Manager (Authentification par clé RSA).
* **IA** : [Ollama](https://ollama.com/) installé localement avec le modèle `llama3`.
* **Mail** : Accès SMTP (Outlook, Gmail, ou relais interne).

---

## ⚙️ Configuration

Modifiez la section `CONFIGURATION PARAMETERS` directement dans le script `main.py` :

### 🔑 Accès Serveur & Wazuh
* `SSH_HOST` : Adresse IP de votre manager Wazuh.
* `SSH_KEY_PATH` : Chemin vers votre clé privée (ex: `~/.ssh/id_rsa`).
* `ALERT_LEVEL_THRESHOLD` : Niveau de gravité minimum (défaut: `5`).

### 🤖 Intelligence Artificielle
* `OLLAMA_API_URL` : URL de votre instance (défaut: `http://localhost:11434/api/generate`).
* `OLLAMA_MODEL` : Modèle utilisé (ex: `llama3`, `mistral`).

### 📧 Notification
* `SMTP_HOST` / `PORT` : Paramètres de votre serveur mail.
* `EMAIL_TO` : Destinataire du rapport.

---

## 🖥️ Utilisation

**Exécution manuelle :**
```bash
python main.py
```

**Automatisation (Cron) :**
Pour recevoir votre rapport tous les matins à 08h00, ajoutez cette ligne à votre crontab (`crontab -e`) :

```bash
00 08 * * * /usr/bin/python3 /chemin/vers/votre/script/main.py
```

⚠️ Notes de Sécurité & Performance
Sécurité SSH : Privilégiez une clé SSH dédiée sans passphrase ou utilisez un agent SSH. L'utilisateur doit avoir les droits de lecture sur /var/ossec/logs/alerts/alerts.json.

Performance IA : Par défaut, le script limite l'usage à 2 threads (num_thread: 2) pour ne pas impacter les performances de la machine de monitoring pendant l'inférence.

Confidentialité : L'analyse est 100% locale via Ollama. Aucune donnée de log n'est envoyée vers le cloud.
