#!/usr/bin/env python3
"""
Script avancé de surveillance réseau pour détecter :
- Scans de ports
- Connexions vers des IP suspectes
- Tentatives de brute force SSH
- Attaques DDoS (volume de trafic anormal)
- Paquets malformés
"""

import logging
import time
import json
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict, deque
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

# Configuration des logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("trafic_suspect.log"),
        logging.StreamHandler()
    ]
)

# Liste des IP suspectes (à adapter)
SUSPECT_IPS = {
    "192.168.1.100",
    "10.0.0.5",
    "2001:db8::1",  # Exemple IPv6
}

# Liste des IP de confiance (à exclure des alertes)
TRUSTED_IPS = {
    "192.168.1.1",
    "10.0.0.1",
}

# Seuil pour détecter un scan de port
PORT_SCAN_THRESHOLD = 15

# Seuil pour détecter une attaque DDoS (paquets/seconde)
DDOS_THRESHOLD = 1000

# Seuil pour détecter un brute force SSH (tentatives en 10 secondes)
SSH_BRUTE_FORCE_THRESHOLD = 5

# Configuration pour les notifications par e-mail
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "ton_email@example.com"
SMTP_PASSWORD = "ton_mot_de_passe"
EMAIL_TO = "admin@example.com"

# Structures de données pour le suivi
ip_port_counts = defaultdict(set)  # Scan de ports
ssh_attempts = defaultdict(deque)  # Brute force SSH
ip_packet_counts = defaultdict(int)  # Volume de trafic (DDoS)
malformed_packets = defaultdict(int)  # Paquets malformés

# Fichier pour sauvegarder les alertes en JSON
ALERT_JSON_FILE = "alertes.json"

def send_email_alert(subject, message):
    """Envoie une alerte par e-mail."""
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        logging.info(f"Notification envoyée : {subject}")
    except Exception as e:
        logging.error(f"Échec de l'envoi de l'e-mail : {e}")

def log_alert_to_json(alert_type, source_ip, details):
    """Enregistre l'alerte dans un fichier JSON."""
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "source_ip": source_ip,
        "details": details
    }

    try:
        with open(ALERT_JSON_FILE, "a") as f:
            json.dump(alert, f)
            f.write("\n")
    except Exception as e:
        logging.error(f"Échec de l'écriture dans {ALERT_JSON_FILE} : {e}")

def is_trusted_ip(ip):
    """Vérifie si une IP est dans la liste de confiance."""
    return ip in TRUSTED_IPS

def detect_port_scan(packet):
    """Détecte les scans de ports."""
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
        if is_trusted_ip(src_ip):
            return

        dst_port = packet[TCP].dport
        ip_port_counts[src_ip].add(dst_port)

        if len(ip_port_counts[src_ip]) > PORT_SCAN_THRESHOLD:
            alert_msg = (
                f"Scan de port détecté depuis {src_ip} ! "
                f"Ports contactés : {sorted(ip_port_counts[src_ip])}"
            )
            logging.warning(alert_msg)
            log_alert_to_json("port_scan", src_ip, {"ports": sorted(ip_port_counts[src_ip])})
            send_email_alert(f"Scan de port détecté depuis {src_ip}", alert_msg)
            ip_port_counts[src_ip].clear()

def detect_suspect_ip(packet):
    """Détecte les connexions vers des IP suspectes."""
    if packet.haslayer(IP):
        dst_ip = packet[IP].dst
        src_ip = packet[IP].src
    elif packet.haslayer(IPv6):
        dst_ip = packet[IPv6].dst
        src_ip = packet[IPv6].src
    else:
        return

    if dst_ip in SUSPECT_IPS and not is_trusted_ip(src_ip):
        alert_msg = f"Connexion suspecte de {src_ip} vers {dst_ip} !"
        logging.warning(alert_msg)
        log_alert_to_json("suspect_ip", src_ip, {"destination_ip": dst_ip})
        send_email_alert(f"Connexion suspecte depuis {src_ip}", alert_msg)

def detect_brute_force(packet):
    """Détecte les tentatives de brute force SSH."""
    if packet.haslayer(TCP) and packet[TCP].dport == 22:
        src_ip = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
        if is_trusted_ip(src_ip):
            return

        current_time = time.time()
        ssh_attempts[src_ip].append(current_time)

        # Nettoyer les anciennes tentatives (plus de 10 secondes)
        ssh_attempts[src_ip] = deque(
            [t for t in ssh_attempts[src_ip] if current_time - t <= 10]
        )

        if len(ssh_attempts[src_ip]) > SSH_BRUTE_FORCE_THRESHOLD:
            alert_msg = f"Tentative de brute force SSH depuis {src_ip} !"
            logging.warning(alert_msg)
            log_alert_to_json("brute_force_ssh", src_ip, {"attempts": len(ssh_attempts[src_ip])})
            send_email_alert(f"Brute force SSH depuis {src_ip}", alert_msg)

def detect_ddos(packet):
    """Détecte les attaques DDoS basées sur le volume de trafic."""
    src_ip = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
    if is_trusted_ip(src_ip):
        return

    ip_packet_counts[src_ip] += 1
    if ip_packet_counts[src_ip] > DDOS_THRESHOLD:
        alert_msg = f"Attaque DDoS suspectée depuis {src_ip} !"
        logging.warning(alert_msg)
        log_alert_to_json("ddos", src_ip, {"packets_count": ip_packet_counts[src_ip]})
        send_email_alert(f"Attaque DDoS depuis {src_ip}", alert_msg)
        ip_packet_counts[src_ip] = 0  # Réinitialiser après alerte

def detect_malformed_packet(packet):
    """Détecte les paquets malformés."""
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
        else:
            return

        # Exemple de détection : paquet TCP sans couche IP (anormal)
        if packet.haslayer(TCP) and not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            malformed_packets[src_ip] += 1
            alert_msg = f"Paquet malformé détecté depuis {src_ip} !"
            logging.warning(alert_msg)
            log_alert_to_json("malformed_packet", src_ip, {"count": malformed_packets[src_ip]})
    except Exception:
        pass  # Ignorer les erreurs de parsing

def packet_handler(packet):
    """Gère chaque paquet capturé."""
    detect_port_scan(packet)
    detect_suspect_ip(packet)
    detect_brute_force(packet)
    detect_ddos(packet)
    detect_malformed_packet(packet)

def print_stats():
    """Affiche les statistiques en temps réel."""
    while True:
        time.sleep(10)
        logging.info(
            f"Statistiques - Scans: {len(ip_port_counts)}, "
            f"Brute force SSH: {len(ssh_attempts)}, "
            f"DDoS: {sum(ip_packet_counts.values())}, "
            f"Paquets malformés: {sum(malformed_packets.values())}"
        )

def main():
    """Point d'entrée du script."""
    logging.info("Début de la surveillance du trafic réseau...")
    try:
        # Lancer un thread pour afficher les stats
        import threading
        stats_thread = threading.Thread(target=print_stats, daemon=True)
        stats_thread.start()

        # Capture des paquets en temps réel
        sniff(prn=packet_handler, store=0)
    except KeyboardInterrupt:
        logging.info("Arrêt de la surveillance (Ctrl+C).")
    except Exception as e:
        logging.error(f"Erreur inattendue : {e}")

if __name__ == "__main__":
    main()
