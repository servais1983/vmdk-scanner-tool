# VMDK Scanner Tool

[Contenu précédent du README...]

## Guide de démarrage rapide avancé

### Configuration personnalisée

Vous pouvez personnaliser le comportement de l'outil en utilisant le fichier `config.json` :

```json
{
    "network_analysis": true,
    "false_positive_reduction": true,
    "logging_level": "INFO",
    "report_format": ["html", "json"],
    "max_threads": 4
}
```

### Intégration avec d'autres outils

#### Extraction de données forensiques

Le script peut être intégré dans des pipelines forensiques plus larges. Exemple de script wrapper :

```bash
#!/bin/bash
# Script de pipeline forensique

# Analyse VMDK
./vmdk_scanner_wrapper.sh -f image_disque.vmdk -o resultats_vmdk

# Analyse supplémentaire avec d'autres outils
volatility -f resultats_vmdk/memory_dump.raw imageinfo
```

### Personnalisation des règles YARA

Pour ajouter des règles personnalisées :
1. Placez vos fichiers `.yar` dans le dossier `rules/`
2. Utilisez la syntaxe YARA standard
3. Redémarrez l'analyse

#### Exemple de règle personnalisée

```yara
rule Suspicious_PowerShell_Activity {
    meta:
        description = "Détecte des activités PowerShell potentiellement suspectes"
        author = "Votre Nom"
    
    strings:
        $ps_base64 = "FromBase64String" nocase
        $ps_download = "DownloadString" nocase
        $ps_webclient = "WebClient" nocase
    
    condition:
        2 of them
}
```

### Conseils de performance

- Pour de grands disques VMDK, augmentez le nombre de threads
- Utilisez l'option `--reduce-false-positives` pour des analyses plus précises
- Surveillez l'utilisation des ressources système pendant l'analyse

### Journalisation et débogage

Consultez les journaux dans `./logs/` pour des détails d'analyse :
- `vmdk_scan.log`: Journal principal
- `network_analysis.log`: Logs d'analyse réseau
- `yara_detection.log`: Résultats des règles YARA

### Mises à jour et maintenance

```bash
# Mettre à jour l'outil
git pull origin main

# Mettre à jour les dépendances
./venv/bin/pip install --upgrade yara-python tqdm plotly
```

## Notes supplémentaires

- Les analyses peuvent prendre du temps selon la taille du disque
- Certaines fonctionnalités avancées nécessitent des privilèges root
- Toujours travailler sur des copies de disques, jamais sur les originaux
