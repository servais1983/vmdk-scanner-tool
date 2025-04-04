#!/bin/bash

# Script d'installation des dépendances pour VMDKScanner
# À exécuter avec les privilèges root

echo "Installation des dépendances pour VMDKScanner..."

# Vérifier si l'utilisateur est root
if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root. Utilisez sudo."
    exit 1
fi

# Mettre à jour les listes de paquets
echo "Mise à jour des listes de paquets..."
apt-get update

# Installer les paquets système nécessaires
echo "Installation des paquets système..."
apt-get install -y qemu-utils python3 python3-pip python3-dev

# Installer les dépendances Python
echo "Installation des dépendances Python..."
pip3 install yara-python tqdm plotly pandas kaitaistruct

# Créer les répertoires nécessaires
echo "Création des répertoires..."
mkdir -p rules signatures output

# Vérifier si le module NBD est chargé
if ! lsmod | grep -q "^nbd "; then
    echo "Chargement du module NBD..."
    modprobe nbd
fi

# Rendre le script d'analyse exécutable
chmod +x vmdk_scanner.py

echo "Installation terminée avec succès."
echo "Utilisation: sudo python3 vmdk_scanner.py -f chemin/vers/fichier.vmdk"
