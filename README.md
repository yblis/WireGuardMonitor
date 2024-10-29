# WireGuard Monitor

## Description
Un tableau de bord de surveillance WireGuard offrant une visualisation en temps réel des connexions, du trafic réseau et des alertes de sécurité. Cette application permet de suivre l'historique des connexions, surveiller la bande passante par utilisateur et configurer des alertes personnalisées pour une sécurité renforcée.

## Prérequis
- Python 3.8+
- Flask
- WireGuard installé et configuré
- SQLite3

## Installation
```bash
# Cloner le repository
git clone [URL_DU_REPO]
cd wireguard-monitor

# Installer les dépendances
pip install -r requirements.txt

# Copier le fichier de configuration
cp .env.template .env
```

## Configuration

1. Configuration de WireGuard
- Les logs WireGuard se trouvent généralement dans `/var/log/wireguard/` ou via `wg show all dump`
- Pour configurer le monitoring, assurez-vous que votre interface WireGuard est correctement configurée et que les logs sont accessibles

2. Configuration de l'application
- Modifiez le fichier `.env` avec vos paramètres SMTP :
  * SMTP_SERVER : Serveur SMTP pour les alertes email
  * SMTP_PORT : Port du serveur SMTP
  * SMTP_EMAIL : Adresse email d'envoi
  * SMTP_PASSWORD : Mot de passe SMTP (si nécessaire)
  * ALERT_EMAIL : Adresse email de réception des alertes

## Utilisation

Pour lancer l'application :
```bash
python app.py
```

L'interface est accessible sur `http://localhost:5000`

### Sections principales :

- **Dashboard** : Vue d'ensemble des connexions actives et statistiques en temps réel
- **Connexions** : Historique détaillé et timeline des connexions
- **Trafic** : Graphiques de trafic réseau et analyse de la bande passante
- **Logs** : Journal détaillé des événements avec filtrage
- **Alertes** : Configuration des règles d'alerte personnalisées

## Fonctionnalités

- **Monitoring en temps réel** : Suivi instantané des connexions et du trafic
- **Historique des connexions** : Timeline interactive des événements de connexion
- **Graphiques de trafic** : Visualisation détaillée du trafic réseau
- **Système d'alertes** : 
  * Alertes configurables par email ou logs
  * Détection des connexions suspectes
  * Alertes de pics de trafic
- **Monitoring de bande passante** : 
  * Suivi de l'utilisation par utilisateur
  * Statistiques par période
  * Détection des anomalies
