# VMDK Scanner Tool

Un outil forensique puissant pour scanner les fichiers VMDK (VMware Virtual Disk) à la recherche de menaces, d'activités malveillantes et de configurations suspectes. Développé spécifiquement pour Kali Linux.

![VMDK Scanner Banner](https://img.shields.io/badge/VMDK%20Scanner-v1.0-blue)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2023.1-black)
![License](https://img.shields.io/badge/License-GPL%20v3-green)

## Fonctionnalités

- **Analyse complète des fichiers VMDK** - Montage et analyse de disques virtuels VMware
- **Détection de multiples systèmes d'exploitation** - Windows, Linux et macOS
- **Détection de malware** - Utilise des signatures YARA et des patterns pour identifier les logiciels malveillants
- **Détection de ransomware** - Identifie les signes de chiffrement et les notes de rançon
- **Analyse des escalades de privilèges** - Détecte les configurations système suspectes permettant l'élévation de privilèges
- **Analyse réseau** - Identifie les artefacts réseau suspects et les configurations anormales
- **Détection de BitLocker et autres chiffrements** - Identifie les systèmes chiffrés
- **Rapport détaillé** - Génère des rapports HTML interactifs avec graphiques et tableaux
- **Calcul du score de risque** - Fournit une évaluation globale du niveau de risque du système
- **Réduction des faux positifs** - Système de liste blanche pour éliminer les faux positifs
- **Performance optimisée** - Multithreading pour une analyse rapide des systèmes volumineux

## Installation

### Prérequis

- Kali Linux (ou autre distribution Linux basée sur Debian)
- Python 3.7 ou supérieur
- Privilèges root (pour monter les disques VMDK)

### Installation complète

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/vmdk-scanner-tool.git
cd vmdk-scanner-tool

# Installer les dépendances
sudo chmod +x install_dependencies.sh
sudo ./install_dependencies.sh

# Activer l'environnement virtuel
source venv/bin/activate

# Vérifier l'installation
./venv/bin/python3 vmdk_scanner.py --help
```

### Installation automatique

```bash
git clone https://github.com/servais1983/vmdk-scanner-tool.git
cd vmdk-scanner-tool
sudo chmod +x install_dependencies.sh
sudo ./install_dependencies.sh
```

L'installation crée un environnement virtuel Python et installe toutes les dépendances nécessaires dans cet environnement.

### Installation manuelle

Si vous préférez installer manuellement les dépendances :

```bash
# Installer les dépendances système
sudo apt-get update
sudo apt-get install -y qemu-utils python3 python3-pip python3-dev python3-venv

# Créer un environnement virtuel
python3 -m venv venv

# Activer l'environnement virtuel
source venv/bin/activate

# Installer les dépendances Python
pip install yara-python tqdm plotly pandas kaitaistruct matplotlib

# Charger le module NBD si nécessaire
sudo modprobe nbd
```

## Utilisation

### Commande de base

```bash
# Utiliser le script wrapper qui active automatiquement l'environnement virtuel
sudo ./vmdk_scanner_wrapper.sh -f chemin/vers/fichier.vmdk -o dossier/sortie

# Ou directement avec l'environnement virtuel
sudo ./venv/bin/python3 vmdk_scanner.py -f chemin/vers/fichier.vmdk -o dossier/sortie
```

### Options

```
Options:
  -h, --help            Afficher l'aide et quitter
  -f VMDK, --file VMDK  Chemin vers le fichier VMDK à analyser
  -o OUTPUT, --output OUTPUT
                        Dossier de sortie pour les rapports (défaut: ./output)
  -t THREADS, --threads THREADS
                        Nombre de threads pour l'analyse (défaut: 4)
  --no-mount            Ne pas monter le VMDK (utiliser une image déjà montée)
  --mount-path MOUNT_PATH
                        Chemin de montage si --no-mount est utilisé
  --reduce-false-positives
                        Appliquer des règles pour réduire les faux positifs
  -v, --verbose         Mode verbeux
```

### Exemples

#### Analyse standard
```bash
sudo ./vmdk_scanner_wrapper.sh -f /chemin/vers/disque.vmdk
```

#### Analyse avec réduction des faux positifs
```bash
sudo ./vmdk_scanner_wrapper.sh -f /chemin/vers/disque.vmdk --reduce-false-positives
```

#### Analyse multithreadée
```bash
sudo ./vmdk_scanner_wrapper.sh -f /chemin/vers/disque.vmdk -t 8
```

#### Analyse d'un VMDK déjà monté
```bash
sudo ./vmdk_scanner_wrapper.sh --no-mount --mount-path /mnt/vmdk
```

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

## Structure du rapport

[Reste du contenu précédent du README...]
