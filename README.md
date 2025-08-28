# lan_ids_v3 — Scanner LAN + IDS léger (sans nmap)

**lan_ids_v3.py** est un outil Python tout-en-un pour surveiller un réseau local :
- **Scan ARP** rapide (sans *nmap*), enrichi (MAC, vendor/OUI, reverse DNS).
- **Détection d’OS** best‑effort via **TTL** (ICMP puis TCP SYN).
- **Tableau console** clair (couleurs via *rich*, fallback ASCII).
- **Exports** : CSV / JSON (+ **XLSX** si *openpyxl*).
- **IDS passif** : heuristiques pour **ARP/DNS/DHCP** + détection de **scans** (SYN/ICMP).
- **Notifications** (facultatives) : **Telegram**, **Discord**, **WhatsApp Business Cloud API**.
- **Coloration persistante** :
  - **NEW** *(vert)* : nouvel hôte, pendant **3 heures**.
  - **DOWN** *(rouge)* : hôte connu non vu au scan courant.
  - **SCANNER** *(orange)* : activité de scan récente (SYN/ICMP), pendant **1 heure**.
  - **ALERT** *(rouge)* : alerte sécurité récente (ARP/DNS/DHCP), pendant **1 heure**.

> ⚠️ Nécessite des privilèges réseau (raw sockets). Voir la section **Permissions**.

---

## Sommaire
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Permissions](#permissions)
- [Démarrage rapide](#démarrage-rapide)
- [Arguments CLI](#arguments-cli)
- [Config YAML (optionnelle)](#config-yaml-optionnelle)
- [Sorties générées](#sorties-générées)
- [Notifications (Telegram/Discord/WhatsApp)](#notifications-telegramdiscordwhatsapp)
- [Service systemd (optionnel)](#service-systemd-optionnel)
- [Sécurité & bonnes pratiques](#sécurité--bonnes-pratiques)
- [Limites connues](#limites-connues)

---

## Prérequis
- **Python 3.9+** recommandé
- Bibliothèques Python :
  ```bash
  pip install scapy manuf rich openpyxl pyyaml requests
  ```
- **Linux** conseillé. **macOS** et **Windows** fonctionnent également :
  - Windows : installer **Npcap** (Scapy s’appuie dessus).
  - macOS : lancer le script avec `sudo`.

## Installation
Placez `lan_ids_v3.py` dans un dossier dédié, p.ex. `/opt/lan-scanner/`.

## Permissions
Le scan ARP/ICMP requiert des sockets RAW :
- **Linux** (recommandé) : soit exécuter en `sudo`, soit accorder des capabilities au binaire Python :
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
  ```
- **Windows/macOS** : exécuter en administrateur / via `sudo`.

---

## Démarrage rapide
```bash
# Scan continu sur 192.168.1.0/24 via eth0
sudo python3 lan_ids_v3.py --network 192.168.1.0/24 --iface eth0

# Un seul passage, sortie console + CSV/JSON
sudo python3 lan_ids_v3.py --once

# Avec fichier de configuration YAML
sudo python3 lan_ids_v3.py --config config.yaml
```

---

## Arguments CLI
> Tous les paramètres sont disponibles en CLI et/ou via YAML. Le YAML **n’écrase pas** une option explicitement fournie en CLI.

### Paramètres généraux
- `--config <fichier>` : fichier YAML optionnel.
- `--network 192.168.1.0/24` : réseau cible (CIDR).
- `--iface eth0` : interface réseau (défaut : interface Scapy).
- `--interval 60` : délai (s) entre scans en mode boucle.
- `--once` : effectue **un seul** scan puis quitte.
- `--no-rich` : désactive l’affichage coloré (*rich*).
- `--no-clear` : n’efface pas l’écran à chaque itération.

### Fichiers de sortie
- `--csv scan_report.csv` : export CSV.
- `--xlsx report.xlsx` : export XLSX (si *openpyxl*).
- `--json scan_hosts.json` : état complet des hôtes.
- `--log scan_results.log` : journal des **nouvelles IP** détectées.
- `--alerts alerts.jsonl` : journal **JSON Lines** des alertes IDS (avec rotation).

### Détection d’OS (timeouts/sondes)
- `--icmp-timeout 1.0` : timeout ICMP (s).
- `--tcp-timeout 1.0` : timeout TCP (s) pour SYN.
- `--tcp-probes 443 80` : ports sondés si ICMP bloqué.

### IDS (heuristiques)
- `--no-ids` : désactive l’IDS passif.
- `--dns-servers <ip ...>` : **liste blanche** de serveurs DNS autorisés.
- `--dhcp-servers <ip ...>` : **liste blanche** de serveurs DHCP autorisés.
- `--ids-window 30` : fenêtre (s) d’agrégation pour détection de scans.
- `--syn-threshold 30` : seuil de ports distincts (SYN) → scan.
- `--icmp-threshold 30` : seuil de destinations ICMP → sweep.
- `--arp-flood-threshold 100` : seuil de réponses ARP/10s par MAC → flood.
- `--dns-contradiction-sec 60` : fenêtre pour repérer des réponses DNS contradictoires.
- `--no-arp-change-alert` : ne pas alerter sur changement IP↔MAC.
- `--no-arp-validation` : ne pas **revalider activement** un changement ARP via ARP probe.

### Notifications (facultatives)
- `--notify-min-level INFO|WARN|ALERT` : seuil minimal d’envoi (défaut : `WARN`).
- **Telegram** : `--tg-token <tok>` et `--tg-chat <id>`.
- **Discord** : `--discord-webhook <url>`.
- **WhatsApp Business Cloud** : `--wa-token <tok> --wa-phone-id <id> --wa-to <E164>`
  - Optionnel : `--wa-template <nom>` (fallback hors 24h) et `--wa-template-lang fr`.

---

## Config YAML (optionnelle)
```yaml
network: "192.168.1.0/24"
iface: "eth0"
interval: 30
csv: "/var/log/lan-scan/report.csv"
xlsx: "/var/log/lan-scan/report.xlsx"
json: "/var/log/lan-scan/hosts.json"
log: "/var/log/lan-scan/new_ips.log"
alerts: "/var/log/lan-scan/alerts.jsonl"

ids:
  dns_servers: ["192.168.1.1", "10.0.0.53"]
  dhcp_servers: ["192.168.1.1"]
  window: 30
  syn_threshold: 20
  icmp_threshold: 20
  arp_flood_threshold: 60
  dns_contradiction_sec: 60
  arp_change_alert: true
  arp_validation: true

notify:
  min_level: "WARN"
  telegram:
    token: "1234567:ABCDEF..."
    chat: "-1001234567890"
  discord:
    webhook: "https://discord.com/api/webhooks/..."
  whatsapp:
    access_token: "EAAG..."
    phone_number_id: "123456789012345"
    to: "33612345678"
    template: "net_alert"   # optionnel
    template_lang: "fr"     # optionnel
```
> Règle : les valeurs du YAML **n’écrasent pas** celles fournies en CLI.

---

## Sorties générées
- **Console** : tableau trié (IP), avec colonne **Status** : `NEW` (vert) · `DOWN` (rouge) · `SCANNER` (orange) · `ALERT` (rouge).
- **CSV / XLSX** : colonnes : IP, Hostname, MAC, Type MAC, Vendor, OS, TTL, Src TTL, **Status**.
- **JSON (`scan_hosts.json`)** : liste d’hôtes connus avec `first_seen` / `last_seen` et métadonnées.
- **Logs** :
  - `scan_results.log` : nouvelles IP détectées.
  - `alerts.jsonl` : événements IDS (rotation automatique, format JSONL). 

### Comment sont déterminés les statuts
- **NEW** : `now - first_seen < 3h`.
- **DOWN** : hôte présent dans `scan_hosts.json` mais **absent** du scan courant.
- **SCANNER** : IP marquée *warn* par l’IDS (SYN scan/ICMP sweep récents).
- **ALERT** : IP marquée *alert* par l’IDS (ARP spoof validé, DNS non autorisé, DHCP rogue…).

> La détection d’OS via TTL est **indicative** (pare‑feux/routeurs peuvent biaiser les TTL).

---

## Notifications (Telegram/Discord/WhatsApp)
- Le seuil `--notify-min-level` contrôle ce qui part : `WARN` ou `ALERT` par défaut.
- **Telegram** : créez un bot via `@BotFather`, récupérez `token` + `chat_id` et passez-les en CLI/YAML.
- **Discord** : créez un **webhook** dans le salon cible et collez l’URL.
- **WhatsApp Business Cloud** : utilisez un **access token** & **phone_number_id**. 
  - Pour envoyer un texte **hors fenêtre de 24h**, définissez un **template** approuvé (ex. `net_alert`) et fournissez `--wa-template`.

---

## Service systemd (optionnel)
`/etc/systemd/system/lan-ids.service`
```ini
[Unit]
Description=LAN IDS scanner (sans nmap)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lan-scanner
ExecStart=/usr/bin/python3 /opt/lan-scanner/lan_ids_v3.py --config /opt/lan-scanner/config.yaml
Restart=on-failure
# Sécurité (Linux):
# AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
# NoNewPrivileges=true
# ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /opt/lan-scanner /var/log/lan-scan
sudo cp lan_ids_v3.py /opt/lan-scanner/
sudo cp config.yaml /opt/lan-scanner/
sudo systemctl daemon-reload
sudo systemctl enable --now lan-ids.service
sudo systemctl status lan-ids.service
```

---

## Sécurité & bonnes pratiques
- Limitez les privilèges : privilégiez les **capabilities** Linux à `sudo` global.
- Ajustez les **seuils IDS** à votre trafic (heures de pointe vs heures creuses).
- Renseignez `--dns-servers` et `--dhcp-servers` (whitelists) pour réduire les faux positifs.
- Protégez les **secrets** (tokens) via variables d’environnement ou fichiers de config aux droits restreints.

## Limites connues
- ARP/ICMP ne traversent pas les routeurs : l’outil est **LAN‑local**.
- La **détection d’OS** est heuristique.
- Certains bruits légitimes (VMs, DHCP, proxies DNS, split‑horizon) peuvent déclencher des alertes ; adaptez les seuils et whitelists.

---

**Licence** :  MIT
