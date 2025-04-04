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
apt-get install -y qemu-utils python3 python3-pip python3-dev python3-venv

# Créer un environnement virtuel Python
echo "Création d'un environnement virtuel Python..."
VENV_DIR="./venv"
python3 -m venv $VENV_DIR

# Installer les dépendances Python dans l'environnement virtuel
echo "Installation des dépendances Python dans l'environnement virtuel..."
$VENV_DIR/bin/pip install yara-python tqdm plotly pandas kaitaistruct matplotlib

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

# Créer un script wrapper pour faciliter l'exécution avec l'environnement virtuel
cat > vmdk_scanner_wrapper.sh << 'EOF'
#!/bin/bash
# Wrapper pour exécuter vmdk_scanner.py avec l'environnement virtuel
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
$DIR/venv/bin/python3 $DIR/vmdk_scanner.py "$@"
EOF

chmod +x vmdk_scanner_wrapper.sh

echo "Installation terminée avec succès."
echo "Utilisation: sudo ./vmdk_scanner_wrapper.sh -f chemin/vers/fichier.vmdk"
