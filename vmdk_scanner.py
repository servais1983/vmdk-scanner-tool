#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VMDK Scanner Tool - Outil forensique pour l'analyse de fichiers VMDK

Ce script permet de scanner des fichiers VMDK à la recherche d'activités malveillantes
et de générer un rapport de sécurité détaillé.
"""

import argparse
import logging
import os
import sys
import yara
import magic
import hashlib
from typing import List, Dict, Any

# Configuration de la journalisation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VMDKScanner:
    def __init__(self, config_path: str = None):
        """
        Initialise le scanner VMDK avec une configuration optionnelle.
        
        :param config_path: Chemin vers le fichier de configuration
        """
        self.config = self.load_config(config_path)
        self.yara_rules = self.load_yara_rules()
    
    def load_config(self, config_path: str = None) -> Dict[str, Any]:
        """
        Charge la configuration du scanner.
        
        :param config_path: Chemin vers le fichier de configuration
        :return: Dictionnaire de configuration
        """
        default_config = {
            'yara_rules_path': './yara_rules/',
            'network_analysis': True,
            'log_directory': './logs',
            'report_format': 'html'
        }
        return default_config
    
    def load_yara_rules(self) -> Dict[str, yara.Rules]:
        """
        Charge les règles YARA depuis le répertoire spécifié.
        
        :return: Dictionnaire de règles YARA compilées
        """
        rules_dict = {}
        rules_path = self.config.get('yara_rules_path', './yara_rules/')
        
        try:
            for filename in os.listdir(rules_path):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    full_path = os.path.join(rules_path, filename)
                    try:
                        rules = yara.compile(full_path)
                        rules_dict[filename] = rules
                    except Exception as e:
                        logger.error(f"Erreur lors du chargement des règles YARA {filename}: {e}")
        except FileNotFoundError:
            logger.warning(f"Répertoire de règles YARA non trouvé: {rules_path}")
        
        return rules_dict
    
    def scan_vmdk_file(self, vmdk_path: str) -> Dict[str, Any]:
        """
        Analyse un fichier VMDK pour détecter des activités malveillantes.
        
        :param vmdk_path: Chemin vers le fichier VMDK à analyser
        :return: Dictionnaire contenant les résultats de l'analyse
        """
        results = {
            'file_path': vmdk_path,
            'file_hash': self.calculate_file_hash(vmdk_path),
            'file_type': self.detect_file_type(vmdk_path),
            'yara_matches': {},
            'network_analysis': None
        }
        
        # Analyse YARA
        for rule_name, rules in self.yara_rules.items():
            try:
                matches = rules.match(vmdk_path)
                if matches:
                    results['yara_matches'][rule_name] = [match.rule for match in matches]
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse YARA pour {rule_name}: {e}")
        
        # Analyse réseau (si activé)
        if self.config.get('network_analysis', False):
            results['network_analysis'] = self.perform_network_analysis(vmdk_path)
        
        return results
    
    def calculate_file_hash(self, file_path: str) -> str:
        """
        Calcule le hash SHA-256 d'un fichier.
        
        :param file_path: Chemin vers le fichier
        :return: Hash SHA-256 du fichier
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def detect_file_type(self, file_path: str) -> str:
        """
        Détecte le type MIME du fichier.
        
        :param file_path: Chemin vers le fichier
        :return: Type MIME du fichier
        """
        try:
            return magic.from_file(file_path, mime=True)
        except Exception as e:
            logger.error(f"Erreur lors de la détection du type de fichier: {e}")
            return "unknown"
    
    def perform_network_analysis(self, vmdk_path: str) -> Dict[str, Any]:
        """
        Effectue une analyse réseau sur le fichier VMDK.
        
        :param vmdk_path: Chemin vers le fichier VMDK
        :return: Résultats de l'analyse réseau
        """
        # TODO: Implémenter l'analyse réseau
        # Cette méthode pourrait extraire des configurations réseau, 
        # des adresses IP, des connexions, etc.
        return {
            'status': 'non implémenté',
            'note': 'Fonctionnalité à développer'
        }
    
    def generate_report(self, scan_results: Dict[str, Any], output_format: str = None) -> str:
        """
        Génère un rapport à partir des résultats de scan.
        
        :param scan_results: Résultats de l'analyse
        :param output_format: Format de sortie du rapport (html, json, txt)
        :return: Chemin vers le fichier de rapport généré
        """
        output_format = output_format or self.config.get('report_format', 'html')
        
        # TODO: Implémenter la génération de rapport dans différents formats
        # Actuellement, génère un rapport basique en texte
        report_content = self.generate_text_report(scan_results)
        
        # Créer le répertoire de logs si nécessaire
        log_dir = self.config.get('log_directory', './logs')
        os.makedirs(log_dir, exist_ok=True)
        
        report_path = os.path.join(log_dir, f"vmdk_scan_report_{os.path.basename(scan_results['file_path'])}.txt")
        
        with open(report_path, 'w') as report_file:
            report_file.write(report_content)
        
        return report_path
    
    def generate_text_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Génère un rapport au format texte.
        
        :param scan_results: Résultats de l'analyse
        :return: Contenu du rapport en texte
        """
        report = f"Rapport d'analyse VMDK\n"
        report += f"==================\n\n"
        report += f"Fichier analysé: {scan_results['file_path']}\n"
        report += f"Hash SHA-256: {scan_results['file_hash']}\n"
        report += f"Type de fichier: {scan_results['file_type']}\n\n"
        
        if scan_results['yara_matches']:
            report += "Correspondances YARA:\n"
            for rule_file, matches in scan_results['yara_matches'].items():
                report += f"  - Règles de {rule_file}: {', '.join(matches)}\n"
        else:
            report += "Aucune correspondance YARA trouvée.\n"
        
        if scan_results['network_analysis']:
            report += "\nAnalyse réseau:\n"
            report += str(scan_results['network_analysis'])
        
        return report

def main():
    """
    Point d'entrée principal du script.
    """
    parser = argparse.ArgumentParser(description="VMDK Scanner Tool - Analyse forensique de fichiers VMDK")
    parser.add_argument('vmdk_file', help="Chemin vers le fichier VMDK à analyser")
    parser.add_argument('-c', '--config', help="Chemin vers le fichier de configuration", default=None)
    parser.add_argument('-o', '--output', help="Format de sortie du rapport", choices=['html', 'json', 'txt'], default=None)
    
    args = parser.parse_args()
    
    try:
        scanner = VMDKScanner(args.config)
        scan_results = scanner.scan_vmdk_file(args.vmdk_file)
        report_path = scanner.generate_report(scan_results, args.output)
        
        logger.info(f"Analyse terminée. Rapport généré : {report_path}")
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
