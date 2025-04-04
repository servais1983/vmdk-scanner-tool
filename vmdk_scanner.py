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
import json
import re
from typing import List, Dict, Any, Optional

# Configuration de la journalisation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='vmdk_scan.log',
    filemode='w'
)
logger = logging.getLogger(__name__)

class VMDKScanner:
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialise le scanner VMDK avec une configuration optionnelle.
        
        :param config_path: Chemin vers le fichier de configuration
        """
        self.config = self.load_config(config_path)
        self.yara_rules = self.load_yara_rules()
    
    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Charge la configuration du scanner.
        
        :param config_path: Chemin vers le fichier de configuration
        :return: Dictionnaire de configuration
        """
        default_config = {
            'yara_rules_path': './rules/',
            'network_analysis': True,
            'log_directory': './logs',
            'report_format': 'html',
            'false_positive_reduction': True
        }
        return default_config
    
    def load_yara_rules(self) -> Dict[str, yara.Rules]:
        """
        Charge les règles YARA depuis le répertoire spécifié.
        
        :return: Dictionnaire de règles YARA compilées
        """
        rules_dict = {}
        rules_path = self.config.get('yara_rules_path', './rules/')
        
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
        return {
            'status': 'non implémenté',
            'note': 'Fonctionnalité à développer'
        }
    
    def reduce_false_positives(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Réduit les faux positifs dans les résultats de scan.
        
        :param scan_results: Résultats de l'analyse
        :return: Résultats de scan filtrés
        """
        if not self.config.get('false_positive_reduction', True):
            return scan_results
        
        # Liste blanche de règles et de motifs connus
        whitelist_patterns = [
            r'(windows|system32).*',
            r'.*\.(dll|sys)$',
            r'.*microsoft.*',
            r'.*antivirus.*',
            r'.*backup.*'
        ]
        
        # Filtrer les règles YARA
        filtered_yara_matches = {}
        for rule_name, matches in scan_results['yara_matches'].items():
            is_whitelisted = any(
                re.search(pattern, scan_results['file_path'], re.IGNORECASE) 
                for pattern in whitelist_patterns
            )
            
            if not is_whitelisted:
                filtered_yara_matches[rule_name] = matches
        
        scan_results['yara_matches'] = filtered_yara_matches
        return scan_results
    
    def generate_report(self, scan_results: Dict[str, Any], output_dir: str, output_format: str = 'html') -> str:
        """
        Génère un rapport à partir des résultats de scan.
        
        :param scan_results: Résultats de l'analyse
        :param output_dir: Répertoire de sortie pour le rapport
        :param output_format: Format de sortie du rapport
        :return: Chemin vers le fichier de rapport généré
        """
        # Créer le répertoire de sortie si nécessaire
        os.makedirs(output_dir, exist_ok=True)
        
        # Nom de base du fichier de rapport
        base_filename = f"vmdk_scan_report_{os.path.basename(scan_results['file_path'])}"
        
        # Réduire les faux positifs
        scan_results = self.reduce_false_positives(scan_results)
        
        if output_format == 'html':
            report_path = os.path.join(output_dir, f"{base_filename}.html")
            self.generate_html_report(scan_results, report_path)
        elif output_format == 'json':
            report_path = os.path.join(output_dir, f"{base_filename}.json")
            self.generate_json_report(scan_results, report_path)
        elif output_format == 'txt':
            report_path = os.path.join(output_dir, f"{base_filename}.txt")
            self.generate_text_report(scan_results, report_path)
        else:
            raise ValueError(f"Format de rapport non supporté : {output_format}")
        
        return report_path
    
    def generate_html_report(self, scan_results: Dict[str, Any], report_path: str):
        """
        Génère un rapport HTML détaillé.
        
        :param scan_results: Résultats de l'analyse
        :param report_path: Chemin de sortie du fichier HTML
        """
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport d'analyse VMDK</title>
        </head>
        <body>
            <h1>Rapport d'analyse VMDK</h1>
            <h2>Détails du fichier</h2>
            <p>Chemin : {scan_results['file_path']}</p>
            <p>Type : {scan_results['file_type']}</p>
            <p>Hash SHA-256 : {scan_results['file_hash']}</p>
            
            <h2>Résultats YARA</h2>
            {'<p>Aucune correspondance YARA trouvée.</p>' if not scan_results['yara_matches'] else ''}
            <ul>
                {''.join([f'<li>{rule}: {matches}</li>' for rule, matches in scan_results['yara_matches'].items()])}
            </ul>
        </body>
        </html>
        """
        
        with open(report_path, 'w') as f:
            f.write(html_content)
    
    def generate_json_report(self, scan_results: Dict[str, Any], report_path: str):
        """
        Génère un rapport JSON.
        
        :param scan_results: Résultats de l'analyse
        :param report_path: Chemin de sortie du fichier JSON
        """
        with open(report_path, 'w') as f:
            json.dump(scan_results, f, indent=4)
    
    def generate_text_report(self, scan_results: Dict[str, Any], report_path: str):
        """
        Génère un rapport texte.
        
        :param scan_results: Résultats de l'analyse
        :param report_path: Chemin de sortie du fichier texte
        """
        report_content = f"""
Rapport d'analyse VMDK
=====================

Détails du fichier
-----------------
Chemin : {scan_results['file_path']}
Type : {scan_results['file_type']}
Hash SHA-256 : {scan_results['file_hash']}

Résultats YARA
--------------
{'Aucune correspondance YARA trouvée.' if not scan_results['yara_matches'] else ''}
{chr(10).join([f"{rule}: {matches}" for rule, matches in scan_results['yara_matches'].items()])}
"""
        
        with open(report_path, 'w') as f:
            f.write(report_content)

def main():
    """
    Point d'entrée principal du script.
    """
    parser = argparse.ArgumentParser(description="VMDK Scanner Tool - Analyse forensique de fichiers VMDK")
    parser.add_argument('vmdk_file', nargs='?', help="Chemin vers le fichier VMDK à analyser")
    parser.add_argument('-f', '--file', help="Chemin vers le fichier VMDK à analyser")
    parser.add_argument('-c', '--config', help="Chemin vers le fichier de configuration", default=None)
    parser.add_argument('-o', '--output', 
                        help="Répertoire de sortie pour le rapport", 
                        default='output',
                        type=str)
    parser.add_argument('--format', 
                        help="Format du rapport de sortie", 
                        choices=['html', 'json', 'txt'], 
                        default='html')
    
    args = parser.parse_args()
    
    # Gestion de l'argument de fichier VMDK
    vmdk_file = args.file or args.vmdk_file
    
    if not vmdk_file:
        parser.error("Vous devez spécifier un fichier VMDK à analyser.")
    
    try:
        scanner = VMDKScanner(args.config)
        scan_results = scanner.scan_vmdk_file(vmdk_file)
        report_path = scanner.generate_report(scan_results, args.output, args.format)
        
        logger.info(f"Analyse terminée. Rapport généré : {report_path}")
        print(f"Analyse terminée. Rapport généré : {report_path}")
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse : {e}")
        print(f"Erreur lors de l'analyse : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
