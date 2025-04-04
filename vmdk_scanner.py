#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VMDK Scanner Tool - Outil forensique pour l'analyse de fichiers VMDK

Ce script permet de scanner des fichiers VMDK à la recherche d'activités malveillantes
et de générer un rapport de sécurité détaillé.
"""

# [Tout le code précédent reste identique jusqu'à la méthode generate_html_report]

    def generate_html_report(self, scan_results: Dict[str, Any], report_path: str):
        """
        Génère un rapport HTML détaillé avec scoring et comportements suspects.
        
        :param scan_results: Résultats de l'analyse
        :param report_path: Chemin de sortie du fichier HTML
        """
        logger.info(f"Génération du rapport HTML : {report_path}")
        
        # Vérifier si le répertoire de sortie existe
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
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
                body {{ 
                    font-family: Arial, sans-serif; 
                    line-height: 1.6; 
                    max-width: 800px; 
                    margin: 0 auto; 
                    padding: 20px; 
                }}
                .risk-score {{ 
                    text-align: center; 
                    font-size: 24px; 
                    font-weight: bold; 
                    color: white; 
                    background-color: {risk_color}; 
                    padding: 10px; 
                    border-radius: 10px; 
                    margin-bottom: 20px;
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
                .badge {{
                    display: inline-block;
                    padding: 5px 10px;
                    border-radius: 5px;
                    margin-right: 10px;
                    font-weight: bold;
                }}
                .yara-badge {{ background-color: #007bff; color: white; }}
                .suspicious-badge {{ background-color: #dc3545; color: white; }}
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
                {(''.join([f'<p><span class="badge yara-badge">Règle</span>{rule}: {matches}</p>' 
                            for rule, matches in scan_results["yara_matches"].items()])) 
                 if scan_results["yara_matches"] else '<p>Aucune correspondance YARA trouvée.</p>'}
            </div>
            
            <div class="section">
                <h2>Comportements Suspects</h2>
                <h3 class="high-risk">Risque Élevé</h3>
                {(''.join([f'<p><span class="badge suspicious-badge">Critique</span>{match}</p>' 
                            for match in suspicious_behaviors['high_risk']])) 
                 if suspicious_behaviors['high_risk'] else '<p>Aucun comportement à risque élevé détecté.</p>'}
                
                <h3 class="medium-risk">Risque Moyen</h3>
                {(''.join([f'<p><span class="badge" style="background-color: orange; color: white;">Modéré</span>{match}</p>' 
                            for match in suspicious_behaviors['medium_risk']])) 
                 if suspicious_behaviors['medium_risk'] else '<p>Aucun comportement à risque moyen détecté.</p>'}
                
                <h3 class="low-risk">Risque Faible</h3>
                {(''.join([f'<p><span class="badge" style="background-color: green; color: white;">Mineur</span>{match}</p>' 
                            for match in suspicious_behaviors['low_risk']])) 
                 if suspicious_behaviors['low_risk'] else '<p>Aucun comportement à faible risque détecté.</p>'}
            </div>
            
            <div class="section">
                <h2>Recommandations</h2>
                {''.join([
                    f'<p style="color: red;">🚨 Analyse approfondie recommandée. Score de risque élevé : {risk_score}%</p>' 
                    if suspicious_behaviors['high_risk'] else '',
                    '<p style="color: green;">✅ Aucun comportement suspect critique détecté.</p>' 
                    if not suspicious_behaviors['high_risk'] else ''
                ])}
            </div>
            
            <div class="section" style="font-size: 0.8em; color: #666;">
                <h3>Informations sur l'analyse</h3>
                <p>Généré par VMDK Scanner Tool</p>
                <p>Date et heure : {os.popen('date').read().strip()}</p>
            </div>
        </body>
        </html>
        """
        
        # Écriture du fichier HTML
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"Rapport HTML généré avec succès : {report_path}")
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport HTML : {e}")
            raise

    def generate_json_report(self, scan_results: Dict[str, Any], report_path: str):
        """
        Génère un rapport JSON.
        
        :param scan_results: Résultats de l'analyse
        :param report_path: Chemin de sortie du fichier JSON
        """
        # Créer le répertoire de sortie si nécessaire
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        # Réduire les faux positifs
        scan_results = self.reduce_false_positives(scan_results)
        
        # Analyser les comportements suspects
        suspicious_behaviors = self.analyze_suspicious_behaviors(scan_results)
        
        # Calculer le score de risque
        risk_score = self.calculate_risk_score(scan_results, suspicious_behaviors)
        
        # Ajouter les informations de risque au rapport
        full_report = {
            **scan_results,
            'risk_score': risk_score,
            'suspicious_behaviors': suspicious_behaviors
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(full_report, f, indent=4)
        
        logger.info(f"Rapport JSON généré : {report_path}")

    def generate_text_report(self, scan_results: Dict[str, Any], report_path: str):
        """
        Génère un rapport texte.
        
        :param scan_results: Résultats de l'analyse
        :param report_path: Chemin de sortie du fichier texte
        """
        # Créer le répertoire de sortie si nécessaire
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        # Réduire les faux positifs
        scan_results = self.reduce_false_positives(scan_results)
        
        # Analyser les comportements suspects
        suspicious_behaviors = self.analyze_suspicious_behaviors(scan_results)
        
        # Calculer le score de risque
        risk_score = self.calculate_risk_score(scan_results, suspicious_behaviors)
        
        report_content = f"""
RAPPORT D'ANALYSE VMDK
=====================

DÉTAILS DU FICHIER
-----------------
Chemin : {scan_results['file_path']}
Type : {scan_results['file_type']}
Hash SHA-256 : {scan_results['file_hash']}

SCORE DE RISQUE
---------------
Score : {risk_score}%
Niveau de Risque : {'Faible' if risk_score < 30 else 'Moyen' if risk_score < 60 else 'Élevé'}

RÉSULTATS YARA
--------------
{chr(10).join([f"{rule}: {matches}" for rule, matches in scan_results['yara_matches'].items()]) 
 if scan_results['yara_matches'] else 'Aucune correspondance YARA trouvée.'}

COMPORTEMENTS SUSPECTS
---------------------
Risque Élevé :
{chr(10).join(suspicious_behaviors['high_risk']) 
 if suspicious_behaviors['high_risk'] else 'Aucun comportement à risque élevé détecté.'}

Risque Moyen :
{chr(10).join(suspicious_behaviors['medium_risk']) 
 if suspicious_behaviors['medium_risk'] else 'Aucun comportement à risque moyen détecté.'}

Risque Faible :
{chr(10).join(suspicious_behaviors['low_risk']) 
 if suspicious_behaviors['low_risk'] else 'Aucun comportement à faible risque détecté.'}

RECOMMANDATIONS
---------------
{f"CRITIQUE : Analyse approfondie recommandée. Score de risque élevé : {risk_score}%" 
 if suspicious_behaviors['high_risk'] else "Aucun comportement suspect critique détecté."}
"""
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"Rapport texte généré : {report_path}")

# Le reste du code main() reste inchangé
