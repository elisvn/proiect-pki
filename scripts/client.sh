#!/bin/bash

set -e

function config() {
    read -p "Introdu IP-ul RootCA (serverul NFS): " NFS_SERVER_IP
    read -p "Introdu numele clientului (subfolderul din NFS): " CLIENT_NAME
    read -p "Path export NFS [default: /srv/pki_shared]: " NFS_EXPORT_PATH
    NFS_EXPORT_PATH=${NFS_EXPORT_PATH:-/srv/pki_shared}
    read -p "Punct de montare local [default: /mnt/pki_shared]: " NFS_MOUNT
    NFS_MOUNT=${NFS_MOUNT:-/mnt/pki_shared}

    sudo apt update
    sudo apt install -y nfs-common

    sudo mkdir -p "$NFS_MOUNT"
    if ! grep -qs "$NFS_MOUNT" /proc/mounts; then
        sudo mount "${NFS_SERVER_IP}:${NFS_EXPORT_PATH}" "$NFS_MOUNT"
    fi

    SRC_DIR="${NFS_MOUNT}/${CLIENT_NAME}"
    # Caută .key
    KEY_SRC="${SRC_DIR}/${CLIENT_NAME}.key"
    if [[ ! -f "$KEY_SRC" && -f "${SRC_DIR}/${CLIENT_NAME}/${CLIENT_NAME}.key" ]]; then
        KEY_SRC="${SRC_DIR}/${CLIENT_NAME}/${CLIENT_NAME}.key"
    fi
    # Caută .crt
    CRT_SRC="${SRC_DIR}/${CLIENT_NAME}.crt"
    if [[ ! -f "$CRT_SRC" && -f "${SRC_DIR}/${CLIENT_NAME}/${CLIENT_NAME}.crt" ]]; then
        CRT_SRC="${SRC_DIR}/${CLIENT_NAME}/${CLIENT_NAME}.crt"
    fi
    # Caută .p12
    P12_SRC="${SRC_DIR}/${CLIENT_NAME}.p12"
    if [[ ! -f "$P12_SRC" && -f "${SRC_DIR}/${CLIENT_NAME}/${CLIENT_NAME}.p12" ]]; then
        P12_SRC="${SRC_DIR}/${CLIENT_NAME}/${CLIENT_NAME}.p12"
    fi
    ROOTCA_SRC="${NFS_MOUNT}/root/rootCA.pem"

    DEST_DIR="$HOME/cert_client"
    DESKTOP_DIR="$HOME/Desktop"
    DOWNLOADS_DIR="$HOME/Downloads"
    
    # Încearcă să găsească Desktop-ul real
    echo " Caut folderul potrivit pentru Firefox..."
    if [[ -d "$HOME/Desktop" ]]; then
        FIREFOX_DIR="$HOME/Desktop"
        echo "   Găsit Desktop: $FIREFOX_DIR"
    elif [[ -d "$HOME/Descărcări" ]]; then
        FIREFOX_DIR="$HOME/Descărcări"
        echo "   Găsit Descărcări: $FIREFOX_DIR"
    elif [[ -d "$DOWNLOADS_DIR" ]]; then
        FIREFOX_DIR="$DOWNLOADS_DIR"
        echo "   Găsit Downloads: $FIREFOX_DIR"
    else
        FIREFOX_DIR="$HOME"
        echo "   Folosesc home directory: $FIREFOX_DIR"
    fi
    
    # Dacă suntem root, copiază și în /tmp pentru acces ușor din browser
    if [[ "$EUID" -eq 0 ]]; then
        FIREFOX_DIR="/tmp/certs"
        echo "   Root detectat - copiez în $FIREFOX_DIR pentru acces ușor din browser"
    else
        # Pentru user normal, asigură-te că folderul este accesibil
        FIREFOX_DIR="$HOME/Downloads"
        echo "   User normal - copiez în $FIREFOX_DIR"
    fi
    
    mkdir -p "$DEST_DIR"
    mkdir -p "$FIREFOX_DIR"

    # Copiază fișierele dacă există
    if [[ -f "$KEY_SRC" ]]; then
        sudo cp "$KEY_SRC" "$DEST_DIR/"
        sudo chown $USER:$USER "$DEST_DIR/${CLIENT_NAME}.key"
        chmod 600 "$DEST_DIR/${CLIENT_NAME}.key"
        # Copiază și în folderul pentru Firefox
        sudo cp "$KEY_SRC" "$FIREFOX_DIR/"
        sudo chown $USER:$USER "$FIREFOX_DIR/${CLIENT_NAME}.key"
        chmod 600 "$FIREFOX_DIR/${CLIENT_NAME}.key"
    else
        echo "Atenție: cheia privată nu a fost găsită!"
    fi
    if [[ -f "$CRT_SRC" ]]; then
        sudo cp "$CRT_SRC" "$DEST_DIR/"
        sudo chown $USER:$USER "$DEST_DIR/${CLIENT_NAME}.crt"
        chmod 644 "$DEST_DIR/${CLIENT_NAME}.crt"
        # Copiază și în folderul pentru Firefox
        sudo cp "$CRT_SRC" "$FIREFOX_DIR/"
        sudo chown $USER:$USER "$FIREFOX_DIR/${CLIENT_NAME}.crt"
        chmod 644 "$FIREFOX_DIR/${CLIENT_NAME}.crt"
    else
        echo "Atenție: certificatul client nu a fost găsit!"
    fi
    if [[ -f "$P12_SRC" ]]; then
        echo " Copiez ${CLIENT_NAME}.p12..."
        sudo cp "$P12_SRC" "$DEST_DIR/"
        sudo chown $USER:$USER "$DEST_DIR/${CLIENT_NAME}.p12"
        chmod 600 "$DEST_DIR/${CLIENT_NAME}.p12"
        # Copiază și în folderul accesibil pentru import ușor în Firefox
        echo "   Copiez în $FIREFOX_DIR..."
        sudo cp "$P12_SRC" "$FIREFOX_DIR/"
        sudo chown $USER:$USER "$FIREFOX_DIR/${CLIENT_NAME}.p12"
        chmod 600 "$FIREFOX_DIR/${CLIENT_NAME}.p12"
        echo " ${CLIENT_NAME}.p12 copiat cu succes"
    else
        echo " Atenție: fișierul .p12 nu a fost găsit la $P12_SRC!"
    fi
    if [[ -f "$ROOTCA_SRC" ]]; then
        echo " Copiez rootCA.pem..."
        sudo cp "$ROOTCA_SRC" "$DEST_DIR/"
        sudo chown $USER:$USER "$DEST_DIR/rootCA.pem"
        chmod 644 "$DEST_DIR/rootCA.pem"
        # Copiază și în folderul accesibil pentru import ușor în Firefox
        echo "   Copiez în $FIREFOX_DIR..."
        sudo cp "$ROOTCA_SRC" "$FIREFOX_DIR/"
        sudo chown $USER:$USER "$FIREFOX_DIR/rootCA.pem"
        chmod 644 "$FIREFOX_DIR/rootCA.pem"
        echo "  rootCA.pem copiat cu succes"
    else
        echo " Atenție: rootCA.pem nu a fost găsit la $ROOTCA_SRC!"
    fi

    echo " Certificatul, cheia și rootCA.pem au fost copiate în $DEST_DIR"
    echo " Fișierele .p12 și rootCA.pem au fost copiate și în $FIREFOX_DIR pentru import ușor în Firefox"
    echo ""
    echo " Verificare finală:"
    if [[ -f "$FIREFOX_DIR/rootCA.pem" ]]; then
        echo "    rootCA.pem găsit în $FIREFOX_DIR"
    else
        echo "    rootCA.pem NU a fost găsit în $FIREFOX_DIR"
    fi
    if [[ -f "$FIREFOX_DIR/${CLIENT_NAME}.p12" ]]; then
        echo "  ${CLIENT_NAME}.p12 găsit în $FIREFOX_DIR"
    else
        echo " ${CLIENT_NAME}.p12 NU a fost găsit în $FIREFOX_DIR"
    fi
    echo ""
    echo "Fișiere disponibile în $FIREFOX_DIR:"
    echo "   - rootCA.pem (import ca autoritate)"
    echo "   - ${CLIENT_NAME}.p12 (import ca certificat personal)"
    echo ""
    echo "Instrucțiuni pentru Firefox:"
    echo "1. Deschide Firefox → Settings → Privacy & Security → Certificates → View Certificates"
    echo "2. Tab 'Authorities': Importă rootCA.pem din $FIREFOX_DIR"
    echo "3. Tab 'Your Certificates': Importă ${CLIENT_NAME}.p12 din $FIREFOX_DIR"
    echo "4. Accesează site-ul webserverului și selectează certificatul la cerere"
    echo ""
    if [[ "$EUID" -eq 0 ]]; then
        echo " Pentru a accesa /tmp/certs din browser:"
        echo "   - Navighează la /tmp/certs în dialogul de import"
        echo "   - Sau folosește comanda: ls -la /tmp/certs"
    fi
}

function firefox() {
    ROOTCA_CRT="/mnt/pki_shared/root/rootCA.pem"
    if [ -f "$ROOTCA_CRT" ]; then
        echo "[Firefox] Instalez libnss3-tools și import RootCA în toate profilele Firefox..."
        sudo apt install -y libnss3-tools
        FIREFOX_PROFILES=$(find ~/.mozilla/firefox -maxdepth 1 -type d -name "*.default*" 2>/dev/null)
        for PROFILE in $FIREFOX_PROFILES; do
            echo "Import în profilul Firefox: $PROFILE"
            certutil -A -n "Local RootCA PKI" -t "TC,C,C" -i "$ROOTCA_CRT" -d sql:"$PROFILE"
        done
        echo "Certificatul RootCA a fost importat în Firefox. Repornește browserul pentru ca modificarea să aibă efect."
    else
        echo "[Firefox] Certificatul $ROOTCA_CRT nu a fost găsit. Montează NFS și asigură-te că rootCA.pem există în /mnt/pki_shared/root pentru import automat în Firefox."
    fi
}

case "$1" in
    config)
        config
        ;;
    firefox)
        firefox
        ;;
    *)
        echo "Usage: $0 {config|firefox}"
        echo "  config   - Montează NFS și copiază fișierele de certificat/cheie în $HOME/cert_client"
        echo "  firefox  - Importează RootCA în Firefox (dacă rootCA.pem e în /mnt/pki_shared/root)"
        ;;
esac 
