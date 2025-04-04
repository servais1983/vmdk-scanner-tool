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

# Installer les dépendances Python dans l'environnement virtuel
./venv/bin/pip install yara-python tqdm plotly pandas kaitaistruct matplotlib

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

## Structure du rapport

Le rapport HTML généré comprend les sections suivantes :

1. **Score de risque global** - Représentation visuelle du niveau de risque avec un indicateur coloré
2. **Résumé des découvertes** - Aperçu rapide des résultats par catégorie
3. **Graphiques de distribution** - Visualisation des résultats par catégorie et par sévérité
4. **Informations système** - Détails sur le système analysé (OS, utilisateurs, hachages, etc.)
5. **Catégories de résultats** - Tableaux détaillés des résultats par catégorie
   - Détections de malware
   - Escalades de privilèges
   - Activités suspectes
   - Fichiers suspects
   - Chiffrement
   - Artefacts réseau
6. **Recommandations de sécurité** - Suggestions basées sur les résultats de l'analyse

## Extension des règles YARA

Vous pouvez ajouter vos propres règles YARA dans le dossier `rules/` pour améliorer la détection :

```yara
rule Custom_Malware_Detection {
    meta:
        description = "Détection personnalisée"
        author = "Votre nom"
        severity = "high"
    
    strings:
        $s1 = "chaîne suspecte 1"
        $s2 = "chaîne suspecte 2"
    
    condition:
        any of them
}
```

## Dépannage

Si vous rencontrez des problèmes lors de l'installation ou de l'exécution :

1. **Erreur de module NBD** : Assurez-vous que le module kernel NBD est chargé
   ```bash
   sudo modprobe nbd
   ```

2. **Erreurs de permission** : L'outil nécessite des privilèges root pour monter les disques VMDK
   ```bash
   sudo ./vmdk_scanner_wrapper.sh ...
   ```

3. **Problèmes avec Python** : Vérifiez que l'environnement virtuel est correctement créé
   ```bash
   # Recréer l'environnement virtuel si nécessaire
   python3 -m venv --clear venv
   ./venv/bin/pip install yara-python tqdm plotly pandas kaitaistruct matplotlib
   ```

## Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

1. Forkez le projet
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/ma-nouvelle-fonction`)
3. Commitez vos changements (`git commit -am 'Ajout d'une nouvelle fonction'`)
4. Pushez vers la branche (`git push origin feature/ma-nouvelle-fonction`)
5. Créez une nouvelle Pull Request

## Licence

Ce projet est sous licence GPL v3. Voir le fichier `LICENSE` pour plus de détails.

## Avertissement

Cet outil est destiné à être utilisé par des professionnels de la sécurité informatique dans le cadre d'analyses légitimes. Ne l'utilisez pas sur des systèmes pour lesquels vous n'avez pas d'autorisation explicite.

## Auteur

Développé par Servais1983