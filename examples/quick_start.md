# Guide de démarrage rapide pour VMDK Scanner

Ce guide vous aidera à démarrer rapidement avec VMDK Scanner pour analyser vos disques virtuels VMware à la recherche de menaces de sécurité.

## Installation rapide

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/vmdk-scanner-tool.git
cd vmdk-scanner-tool

# Installer les dépendances
sudo ./install_dependencies.sh
```

## Exemple d'utilisation basique

Voici un exemple simple pour analyser un fichier VMDK :

```bash
# Analyser un disque VMDK
sudo python3 vmdk_scanner.py -f /chemin/vers/disque.vmdk -o ./resultats
```

Une fois l'analyse terminée, vous trouverez un rapport HTML détaillé dans le dossier `./resultats`.

## Exemples de cas d'utilisation courants

### 1. Analyse forensique après un incident de sécurité

Si vous enquêtez sur un système potentiellement compromis :

```bash
sudo python3 vmdk_scanner.py -f /chemin/vers/disque.vmdk --reduce-false-positives -v
```

L'option `--reduce-false-positives` aide à minimiser les faux positifs dans les résultats.

### 2. Analyse d'un système non-monté

Si le VMDK est déjà monté (ou si vous voulez pointer vers un système de fichiers) :

```bash
sudo python3 vmdk_scanner.py --no-mount --mount-path /mnt/point_de_montage
```

### 3. Analyse rapide d'un répertoire spécifique

Pour une analyse ciblée de certaines parties du système :

```bash
sudo python3 vmdk_scanner.py -f /chemin/vers/disque.vmdk --priority-only
```

L'option `--priority-only` se concentre uniquement sur les répertoires prioritaires définis dans `config.json`.

### 4. Analyse avancée avec options personnalisées

Pour une analyse complète avec des paramètres personnalisés :

```bash
sudo python3 vmdk_scanner.py -f /chemin/vers/disque.vmdk -t 8 --custom-rules ./mes_regles_yara -o ./resultats_detailles
```

## Interprétation des résultats

Le rapport HTML généré contient plusieurs sections importantes :

1. **Score de risque global** - Un indicateur visuel du niveau de risque général
2. **Résumé des découvertes** - Aperçu rapide des problèmes par catégorie
3. **Visualisations** - Graphiques montrant la répartition des résultats
4. **Tableaux détaillés** - Les problèmes spécifiques identifiés par catégorie
5. **Recommandations** - Actions suggérées en fonction des résultats

### Comprendre le niveau de risque

- **Critique (80-100)** : Compromission active probable, action immédiate requise
- **Élevé (60-79)** : Signes significatifs de compromission, investigation approfondie nécessaire
- **Moyen (40-59)** : Activités suspectes détectées, examen recommandé
- **Faible (20-39)** : Quelques configurations ou fichiers suspects, mais risque limité
- **Très faible (1-19)** : Peu de problèmes identifiés, probablement de faux positifs
- **Aucun risque (0)** : Aucun problème détecté

## Exemple de flux de travail d'analyse

1. Exécuter une analyse initiale :
   ```bash
   sudo python3 vmdk_scanner.py -f /chemin/vers/disque.vmdk -o ./resultats_initiaux
   ```

2. Examiner les résultats et identifier les zones d'intérêt

3. Effectuer une analyse approfondie ciblant ces zones :
   ```bash
   sudo python3 vmdk_scanner.py -f /chemin/vers/disque.vmdk -o ./resultats_approfondis --focus-areas "Windows/System32,Users/Administrator" -t 8
   ```

4. Utiliser les rapports pour guider une investigation plus approfondie avec d'autres outils forensiques si nécessaire

## Dépannage rapide

Si vous rencontrez des problèmes :

- **Erreur de montage** : Vérifiez que qemu-nbd est installé et que le module nbd est chargé
  ```bash
  sudo modprobe nbd
  ```

- **Erreurs de permission** : Assurez-vous d'exécuter l'outil avec sudo
  ```bash
  sudo python3 vmdk_scanner.py ...
  ```

- **Performances lentes** : Augmentez le nombre de threads
  ```bash
  sudo python3 vmdk_scanner.py -f /chemin/vers/disque.vmdk -t 12
  ```

## Ressources supplémentaires

- Consultez le [README.md](../README.md) pour la documentation complète
- Explorez le dossier `rules/` pour comprendre les règles de détection
- Examinez `config.json` pour personnaliser les options de numérisation