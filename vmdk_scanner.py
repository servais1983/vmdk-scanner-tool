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
    
    def analyze_suspicious_behaviors(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse les comportements suspects dans les résultats de scan.
        
        :param scan_results: Résultats de l'analyse
        :return: Dictionnaire des comportements suspects
        """
        suspicious_behaviors = {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': []
        }
        
        # Règles de détection de comportements suspects
        def detect_suspicious_file_patterns(file_path: str) -> List[str]:
            suspicious_patterns = [
                r'(antivirus|security).*disable',
                r'(backdoor|shell)\.exe',
                r'(nc|netcat)\.exe',
                r'(mimikatz|procdump)\.exe',
                r'(powersploit|empire).*\.ps1',
                r'(malware|virus|trojan).*\.(exe|dll|bat)',
                r'.*keylog.*',
                r'.*rat.*\.(exe|dll)'
            ]
            
            matches = []
            for pattern in suspicious_patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    matches.append(pattern)
            
            return matches
        
        # Vérification des motifs de fichiers suspects
        suspicious_file_matches = detect_suspicious_file_patterns(scan_results['file_path'])
        if suspicious_file_matches:
            suspicious_behaviors['high_risk'].extend(suspicious_file_matches)
        
        # Vérification des règles YARA
        if scan_results['yara_matches']:
            for rule_name, matches in scan_results['yara_matches'].items():
                if 'malware' in rule_name.lower() or 'suspicious' in rule_name.lower():
                    suspicious_behaviors['high_risk'].append(f"Règle YARA suspecte : {rule_name}")
        
        return suspicious_behaviors
    
    def calculate_risk_score(self, scan_results: Dict[str, Any], suspicious_behaviors: Dict[str, Any]) -> int:
        """
        Calcule un score de risque basé sur les résultats de scan et les comportements suspects.
        
        :param scan_results: Résultats de l'analyse
        :param suspicious_behaviors: Comportements suspects détectés
        :return: Score de risque (0-100)
        """
        base_score = 0
        
        # Points pour les correspondances YARA
        base_score += len(scan_results['yara_matches']) * 10
        
        # Points pour les comportements suspects
        base_score += len(suspicious_behaviors['high_risk']) * 20
        base_score += len(suspicious_behaviors['medium_risk']) * 10
        base_score += len(suspicious_behaviors['low_risk']) * 5
        
        # Limiter le score entre 0 et 100
        return min(max(base_score, 0), 100)
    
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
    
    def generate_html_report(self, scan_results: Dict[str, Any], report_path: str):
        """
        Génère un rapport HTML détaillé avec scoring et comportements suspects.
        
        :param scan_results: Résultats de l'analyse
        :param report_path: Chemin de sortie du fichier HTML
        """
        # Réduire les faux positifs
        scan_results = self.reduce_false_positives(scan_results)
        
        # Analyser les comportements suspects
        suspicious_behaviors = self.analyze_suspicious_behaviors(scan_results)
        
        # Calculer le score de risque
        risk_score = self.calculate_risk_score(scan_results, suspicious_behaviors)
        
        # Déterminer la couleur et le niveau de risque
        def get_risk_color(score):
            if score < 30:
                return 'green', 'Faible'
            elif score < 60:
                return 'orange', 'Moyen'
            else:
                return 'red', 'Élevé'
        
        risk_color, risk_level = get_risk_color(risk_score)
        
        # Générer le HTML
        html_content = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <title>Rapport Forensique VMDK</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }}
                .risk-score {{ 
                    text-align: center; 
                    font-size: 24px; 
                    font-weight: bold; 
                    color: white; 
                    background-color: {risk_color}; 
                    padding: 10px; 
                    border-radius: 10px; 
                }}
                .section {{ 
                    border: 1px solid #ddd; 
                    margin-bottom: 20px; 
                    padding: 15px; 
                    border-radius: 5px; 
                }}
                .high-risk {{ color: red; }}
                .medium-risk {{ color: orange; }}
                .low-risk {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>Rapport Forensique VMDK</h1>
            
            <div class="risk-score">
                Score de Risque : {risk_score}% - Niveau de Risque : {risk_level}
            </div>
            
            <div class="section">
                <h2>Détails du Fichier</h2>
                <p><strong>Chemin :</strong> {scan_results['file_path']}</p>
                <p><strong>Type :</strong> {scan_results['file_type']}</p>
                <p><strong>Hash SHA-256 :</strong> {scan_results['file_hash']}</p>
            </div>
            
            <div class="section">
                <h2>Résultats YARA</h2>
                {(''.join([f'<p>{rule}: {matches}</p>' for rule, matches in scan_results["yara_matches"].items()])) 
                 if scan_results["yara_matches"] else '<p>Aucune correspondance YARA trouvée.</p>'}
            </div>
            
            <div class="section">
                <h2>Comportements Suspects</h2>
                <h3 class="high-risk">Risque Élevé</h3>
                {(''.join([f'<p>{match}</p>' for match in suspicious_behaviors['high_risk']])) 
                 if suspicious_behaviors['high_risk'] else '<p>Aucun comportement à risque élevé détecté.</p>'}
                
                <h3 class="medium-risk">Risque Moyen</h3>
                {(''.join([f'<p>{match}</p>' for match in suspicious_behaviors['medium_risk']])) 
                 if suspicious_behaviors['medium_risk'] else '<p>Aucun comportement à risque moyen détecté.</p>'}
                
                <h3 class="low-risk">Risque Faible</h3>
                {(''.join([f'<p>{match}</p>' for match in suspicious_behaviors['low_risk']])) 
                 if suspicious_behaviors['low_risk'] else '<p>Aucun comportement à faible risque détecté.</p>'}
            </div>
            
            <div class="section">
                <h2>Recommandations</h2>
                {''.join([
                    '<p>🚨 Analyse approfondie recommandée en raison des comportements suspects détectés.</p>' 
                    if suspicious_behaviors['high_risk'] else '',
                    '<p>✅ Aucun comportement suspect critique détecté.</p>' 
                    if not suspicious_behaviors['high_risk'] else ''
                ])}
            </div>
        </body>
        </html>
        """
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

# Le reste du code reste inchangé
