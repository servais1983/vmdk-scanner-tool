#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fonctions supplémentaires pour le scanner VMDK
"""

import os
import re
import logging

logger = logging.getLogger('VMDKScanner')

def detect_encryption(self):
    """Détecter les signes de BitLocker et d'autres chiffrements"""
    logger.info("Recherche de signes de chiffrement...")
    os_type = self.results['general_info']['os_type']
    
    if "Windows" in os_type:
        self._detect_windows_encryption()
    elif "Linux" in os_type:
        self._detect_linux_encryption()
    elif "macOS" in os_type:
        self._detect_macos_encryption()

def detect_windows_encryption(self):
    """Détecter les signes de chiffrement sous Windows (BitLocker, etc.)"""
    # Vérifier les fichiers BitLocker
    bitlocker_paths = [
        os.path.join(self.mount_point, "$BitLocker"),
        os.path.join(self.mount_point, "$BitLocker.bek"),
        os.path.join(self.mount_point, "$BitLocker.fve")
    ]
    
    for path in bitlocker_paths:
        if os.path.exists(path):
            self.results['encryption_findings'].append({
                'type': 'bitlocker',
                'severity': 'info',
                'description': 'Fichier BitLocker détecté',
                'location': path,
                'details': 'La présence de fichiers BitLocker indique que le disque est ou a été chiffré'
            })
    
    # Vérifier les clefs de registre BitLocker
    # Dans un environnement réel, nous examinerions les fichiers de registre pour les clefs BitLocker
    # mais cela nécessiterait des outils spécialisés pour lire le registre Windows hors ligne

def detect_linux_encryption(self):
    """Détecter les signes de chiffrement sous Linux (LUKS, eCryptfs, etc.)"""
    # Vérifier LUKS
    crypttab_file = os.path.join(self.mount_point, "etc", "crypttab")
    if os.path.exists(crypttab_file):
        self.results['encryption_findings'].append({
            'type': 'luks',
            'severity': 'info',
            'description': 'Configuration LUKS détectée',
            'location': crypttab_file,
            'details': 'Le fichier crypttab indique l\'utilisation de LUKS (Linux Unified Key Setup)'
        })
    
    # Vérifier eCryptfs
    for root, dirs, files in os.walk(os.path.join(self.mount_point, "home")):
        for dir_name in dirs:
            if dir_name == ".ecryptfs":
                self.results['encryption_findings'].append({
                    'type': 'ecryptfs',
                    'severity': 'info',
                    'description': 'Répertoire eCryptfs détecté',
                    'location': os.path.join(root, dir_name),
                    'details': 'La présence de répertoires .ecryptfs indique l\'utilisation de chiffrement de répertoire personnel'
                })
                break
    
    # Vérifier dm-crypt/LUKS via /proc/crypto (non disponible dans un montage hors ligne)

def detect_macos_encryption(self):
    """Détecter les signes de chiffrement sous macOS (FileVault, etc.)"""
    # Vérifier FileVault
    filevault_plist = os.path.join(self.mount_point, "Library", "Preferences", "com.apple.security.filevault.plist")
    if os.path.exists(filevault_plist):
        self.results['encryption_findings'].append({
            'type': 'filevault',
            'severity': 'info',
            'description': 'Configuration FileVault détectée',
            'location': filevault_plist,
            'details': 'La présence du fichier de préférences FileVault indique que le disque est ou a été chiffré'
        })

def analyze_network_artifacts(self):
    """Analyser les artefacts réseau"""
    logger.info("Analyse des artefacts réseau...")
    os_type = self.results['general_info']['os_type']
    
    if "Windows" in os_type:
        self._analyze_windows_network()
    elif "Linux" in os_type or os_type == "Inconnu":
        self._analyze_linux_network()
    elif "macOS" in os_type:
        self._analyze_macos_network()

def analyze_windows_network(self):
    """Analyser les artefacts réseau sous Windows"""
    # Vérifier les fichiers hosts
    hosts_file = os.path.join(self.mount_point, "Windows", "System32", "drivers", "etc", "hosts")
    if os.path.exists(hosts_file):
        try:
            with open(hosts_file, 'r', errors='ignore') as f:
                hosts_content = f.read()
                # Vérifier les entrées suspectes dans le fichier hosts
                suspicious_domains = [
                    "malware", "trojan", "virus", "botnet", "backdoor",
                    "hack", "crack", "keygen", "warez", "pirat", "torrent",
                    "steal", "ransom", "crypt", "coin", "miner"
                ]
                
                for line in hosts_content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if any(domain in line.lower() for domain in suspicious_domains):
                            self.results['network_artifacts'].append({
                                'type': 'suspicious_hosts_entry',
                                'severity': 'medium',
                                'description': 'Entrée suspecte dans le fichier hosts',
                                'location': hosts_file,
                                'details': f'Entrée suspecte: {line}'
                            })
        except Exception as e:
            logger.debug(f"Erreur lors de l'analyse du fichier hosts: {e}")
    
    # Analyser les fichiers de configuration réseau
    # Dans un environnement réel, nous examinerions le registre Windows pour les configurations réseau

def analyze_linux_network(self):
    """Analyser les artefacts réseau sous Linux"""
    # Vérifier le fichier hosts
    hosts_file = os.path.join(self.mount_point, "etc", "hosts")
    if os.path.exists(hosts_file):
        try:
            with open(hosts_file, 'r', errors='ignore') as f:
                hosts_content = f.read()
                # Vérifier les entrées suspectes dans le fichier hosts
                suspicious_domains = [
                    "malware", "trojan", "virus", "botnet", "backdoor",
                    "hack", "crack", "keygen", "warez", "pirat", "torrent",
                    "steal", "ransom", "crypt", "coin", "miner"
                ]
                
                for line in hosts_content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if any(domain in line.lower() for domain in suspicious_domains):
                            self.results['network_artifacts'].append({
                                'type': 'suspicious_hosts_entry',
                                'severity': 'medium',
                                'description': 'Entrée suspecte dans le fichier hosts',
                                'location': hosts_file,
                                'details': f'Entrée suspecte: {line}'
                            })
        except Exception as e:
            logger.debug(f"Erreur lors de l'analyse du fichier hosts: {e}")
    
    # Vérifier les fichiers de configuration SSH connus
    ssh_config_dir = os.path.join(self.mount_point, "etc", "ssh")
    known_hosts_files = [
        os.path.join(self.mount_point, "root", ".ssh", "known_hosts")
    ]
    
    # Ajouter les fichiers known_hosts des utilisateurs
    home_dir = os.path.join(self.mount_point, "home")
    if os.path.exists(home_dir):
        for user_dir in os.listdir(home_dir):
            user_known_hosts = os.path.join(home_dir, user_dir, ".ssh", "known_hosts")
            if os.path.exists(user_known_hosts):
                known_hosts_files.append(user_known_hosts)
    
    # Analyser les fichiers known_hosts
    for known_hosts_file in known_hosts_files:
        if os.path.exists(known_hosts_file):
            try:
                with open(known_hosts_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Enregistrer les connexions SSH connues pour analyse
                            parts = line.split()
                            if len(parts) > 0:
                                host = parts[0]
                                self.results['network_artifacts'].append({
                                    'type': 'ssh_known_host',
                                    'severity': 'info',
                                    'description': 'Hôte SSH connu',
                                    'location': known_hosts_file,
                                    'details': f'Hôte: {host}'
                                })
            except Exception as e:
                logger.debug(f"Erreur lors de l'analyse du fichier known_hosts: {e}")

def analyze_macos_network(self):
    """Analyser les artefacts réseau sous macOS"""
    # Similaire à l'analyse Linux
    self._analyze_linux_network()
    
    # Analyser les préférences réseau spécifiques à macOS
    network_prefs = os.path.join(self.mount_point, "Library", "Preferences", "SystemConfiguration", "preferences.plist")
    if os.path.exists(network_prefs):
        self.results['network_artifacts'].append({
            'type': 'network_prefs',
            'severity': 'info',
            'description': 'Préférences réseau macOS',
            'location': network_prefs,
            'details': 'Fichier de préférences réseau détecté'
        })

def calculate_risk_score(self):
    """Calculer le score global de risque"""
    logger.info("Calcul du score de risque...")
    
    # Pondération des différentes catégories de menaces
    weights = {
        'threats': 5.0,
        'suspicious_activities': 3.0,
        'privilege_escalation': 4.0,
        'suspicious_files': 2.5,
        'malware_detections': 5.0,
        'encryption_findings': 1.0,  # L'encryption n'est pas nécessairement malveillante
        'network_artifacts': 2.0
    }
    
    # Pondération des niveaux de sévérité
    severity_weights = {
        'critical': 10.0,
        'high': 7.0,
        'medium': 4.0,
        'low': 1.0,
        'info': 0.5
    }
    
    total_score = 0
    total_findings = 0
    
    # Calculer le score pondéré pour chaque catégorie
    for category, weight in weights.items():
        if category in self.results and isinstance(self.results[category], list):
            category_findings = self.results[category]
            for finding in category_findings:
                severity = finding.get('severity', 'medium')
                severity_weight = severity_weights.get(severity, 1.0)
                total_score += weight * severity_weight
                total_findings += 1
    
    # Normaliser le score (0-100)
    normalized_score = 0
    if total_findings > 0:
        # Le score maximum possible serait total_findings * max_weight * max_severity
        max_possible_score = total_findings * 5.0 * 10.0
        normalized_score = min(100, (total_score / max_possible_score) * 100)
    
    self.results['overall_score'] = round(normalized_score, 2)
    
    # Catégoriser le niveau de risque
    risk_level = "Aucun risque détecté"
    if normalized_score >= 80:
        risk_level = "Critique"
    elif normalized_score >= 60:
        risk_level = "Élevé"
    elif normalized_score >= 40:
        risk_level = "Moyen"
    elif normalized_score >= 20:
        risk_level = "Faible"
    elif normalized_score > 0:
        risk_level = "Très faible"
        
    self.results['risk_level'] = risk_level

def generate_report(self):
    """Générer un rapport HTML détaillé"""
    logger.info("Génération du rapport HTML...")
    
    # Préparer les données pour le rapport
    report_data = {
        'general_info': self.results['general_info'],
        'overall_score': self.results['overall_score'],
        'risk_level': self.results['risk_level'],
        'threats': len(self.results['threats']),
        'suspicious_activities': len(self.results['suspicious_activities']),
        'privilege_escalation': len(self.results['privilege_escalation']),
        'suspicious_files': len(self.results['suspicious_files']),
        'malware_detections': len(self.results['malware_detections']),
        'encryption_findings': len(self.results['encryption_findings']),
        'network_artifacts': len(self.results['network_artifacts']),
        'detailed_findings': {}
    }
    
    # Ajouter les détails pour chaque catégorie
    for category in ['threats', 'suspicious_activities', 'privilege_escalation', 'suspicious_files', 
                    'malware_detections', 'encryption_findings', 'network_artifacts']:
        report_data['detailed_findings'][category] = self.results[category]
    
    # Générer le rapport HTML
    report_template = self._get_report_template()
    report_html = self._render_template(report_template, report_data)
    
    # Écrire le rapport dans un fichier
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"vmdk_scan_report_{timestamp}.html"
    report_path = os.path.join(self.output_dir, report_filename)
    
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        logger.info(f"Rapport enregistré dans: {report_path}")
        
        # Générer également un rapport JSON pour une utilisation programmatique
        json_path = os.path.join(self.output_dir, f"vmdk_scan_report_{timestamp}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        logger.info(f"Rapport JSON enregistré dans: {json_path}")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture du rapport: {e}")
        
    return report_path
