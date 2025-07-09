#!/bin/bash

# RootCA Script 
# Script pentru automatizarea unei CA rădăcină offline

ROOT_DIR="/root/rootCA"
OPENSSL_CNF="$ROOT_DIR/openssl.cnf"
KEY="$ROOT_DIR/private/rootCA.key"
CERT="$ROOT_DIR/rootCA.pem"
DAYS=3650
SHARED_DIR="/srv/pki_shared"
SUBCA_DIR="$SHARED_DIR/subca"
ROOT_EXPORT_DIR="$SHARED_DIR/root"

# Verifică dacă rulezi ca root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Avertisment: Nu rulezi ca root!"
        echo "Pentru RootCA offline, recomand să rulezi ca root."
        echo "Sau modifică ROOT_DIR în script pentru un folder accesibil."
        read -p "Continui oricum? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

setup_nfs_shared() {
    echo "[NFS] Configurare folder shared la $SHARED_DIR..."
    sudo mkdir -p "$SHARED_DIR"
    sudo mkdir -p "$SUBCA_DIR"
    sudo mkdir -p "$ROOT_EXPORT_DIR"
    sudo chown nobody:nogroup "$SHARED_DIR"
    sudo chown nobody:nogroup "$SUBCA_DIR"
    sudo chown nobody:nogroup "$ROOT_EXPORT_DIR"
    sudo chmod 755 "$SHARED_DIR"
    sudo chmod 755 "$SUBCA_DIR"
    sudo chmod 755 "$ROOT_EXPORT_DIR"
    
    # Adaugă export NFS dacă nu există deja
    if ! grep -q "$SHARED_DIR" /etc/exports; then
        echo "$SHARED_DIR  *(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
        echo "[NFS] Export NFS general adăugat."
    else
        echo "[NFS] Export NFS general deja prezent."
    fi
    
    # Interactiv: cere IP-urile pentru acces NFS
    echo "\nIntroduceți IP-urile care vor avea acces la NFS (ex: SubCA, WebServer, Client, etc)."
    echo "Introduceți fiecare IP pe rând, ENTER după fiecare. Lăsați gol și apăsați ENTER când ați terminat."
    while true; do
        read -p "IP: " ip
        if [ -z "$ip" ]; then
            break
        fi
        if ! grep -q "$ip" /etc/exports; then
            echo "$SHARED_DIR  $ip(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
            echo "  - Acces NFS pentru $ip adăugat."
        else
            echo "  - $ip deja are acces NFS."
        fi
    done
    sudo exportfs -a
    sudo systemctl restart nfs-kernel-server
    echo "[NFS] Export NFS configurat și server repornit."
}

reconfig_nfs() {
    echo "[NFS] Reconfigurare IP-uri acces NFS pentru $SHARED_DIR..."
    echo "Introduceți IP-urile suplimentare care vor avea acces la NFS."
    echo "Introduceți fiecare IP pe rând, ENTER după fiecare. Lăsați gol și apăsați ENTER când ați terminat."
    while true; do
        read -p "IP: " ip
        if [ -z "$ip" ]; then
            break
        fi
        if ! grep -q "$ip" /etc/exports; then
            echo "$SHARED_DIR  $ip(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
            echo "  - Acces NFS pentru $ip adăugat."
        else
            echo "  - $ip deja are acces NFS."
        fi
    done
    sudo exportfs -a
    sudo systemctl restart nfs-kernel-server
    echo "[NFS] Export NFS reconfigurat și server repornit."
}

sync_files() {
    echo "[NFS] Sincronizare fișiere RootCA în zona shared..."
    
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "RootCA nu este inițializat! Rulează mai întâi: ./rootca.sh init"
        exit 1
    fi
    
    # Copiază certificatul RootCA
    if [ -f "$CERT" ]; then
        cp "$CERT" "$ROOT_EXPORT_DIR/rootCA.pem"
        echo "  - rootCA.pem sincronizat în $ROOT_EXPORT_DIR/"
    fi
    
    # Copiază CRL-ul RootCA
    if [ -f "$ROOT_DIR/crl.pem" ]; then
        cp "$ROOT_DIR/crl.pem" "$ROOT_EXPORT_DIR/rootCA.crl.pem"
        echo "  - rootCA.crl.pem sincronizat în $ROOT_EXPORT_DIR/"
    fi
    
    # Copiază și alte fișiere importante dacă există
    if [ -f "$OPENSSL_CNF" ]; then
        cp "$OPENSSL_CNF" "$ROOT_EXPORT_DIR/openssl.cnf"
        echo "  - openssl.cnf sincronizat în $ROOT_EXPORT_DIR/"
    fi
    
    echo "✅ Toate fișierele RootCA au fost sincronizate în zona shared!"
    echo "SubCA poate accesa fișierele actualizate prin NFS."
}

copy_to_shared() {
    echo "[NFS] Copiere fișiere necesare în zona shared..."
    
    # Copiază certificatul RootCA
    if [ -f "$CERT" ]; then
        cp "$CERT" "$ROOT_EXPORT_DIR/rootCA.pem"
        echo "  - rootCA.pem copiat în $ROOT_EXPORT_DIR/"
    fi
    
    # Copiază CRL-ul RootCA
    if [ -f "$ROOT_DIR/crl.pem" ]; then
        cp "$ROOT_DIR/crl.pem" "$ROOT_EXPORT_DIR/rootCA.crl.pem"
        echo "  - rootCA.crl.pem copiat în $ROOT_EXPORT_DIR/"
    fi
    
    # Dacă există un fișier specific de copiat
    if [ -n "$1" ] && [ -f "$1" ]; then
        cp "$1" "$SUBCA_DIR/"
        echo "  - $1 copiat în subca/"
    fi
}

init_rootca() {
    check_root
    
    echo "Inițializare RootCA în $ROOT_DIR"
    echo "=================================="
    
    # Creează structura de foldere conform standardului OpenSSL
    mkdir -p "$ROOT_DIR"/{private,certs,crl,newcerts,csr}
    touch "$ROOT_DIR/index.txt"
    echo 1000 > "$ROOT_DIR/serial"
    echo 1000 > "$ROOT_DIR/crlnumber"
    chmod 700 "$ROOT_DIR/private"

    echo "Introduceți datele pentru RootCA:"
    echo "-----------------------------------"
    read -p "Country (C) [ex: RO]: " C
    read -p "State (ST) [ex: Sibiu]: " ST
    read -p "Locality (L) [ex: Sibiu]: " L
    read -p "Organization (O) [ex: Academie]: " O
    read -p "Organizational Unit (OU) [ex: IT]: " OU
    read -p "Common Name (CN) [ex: rootca.local]: " CN
    read -p "Email Address (email): " EMAIL

    echo ""
    echo "Alegeți o parolă pentru cheia privată RootCA:"
    echo "Lăsați gol pentru fără parolă (NU recomandat pentru RootCA!)"
    read -s PASS1
    if [ -n "$PASS1" ]; then
        echo "Confirmați parola pentru cheia privată RootCA:"
        read -s PASS2
        if [ "$PASS1" != "$PASS2" ]; then
            echo "Parolele nu coincid! Inițializarea RootCA a fost anulată."
            exit 1
        fi
        PASS="$PASS1"
    else
        PASS=""
    fi
    echo ""

    # Generează cheia privată
    echo "Generare cheie privată RootCA..."
    if [ -z "$PASS" ]; then
        openssl genrsa -out "$KEY" 4096
        echo "ATENȚIE: Cheia RootCA NU este protejată cu parolă!"
    else
        openssl genrsa -aes256 -passout pass:"$PASS" -out "$KEY" 4096
        echo "Cheia RootCA protejată cu parolă."
    fi
    chmod 600 "$KEY"

    # Generează openssl.cnf complet cu toate extensiile necesare
    echo "Generare fișier openssl.cnf complet..."
    cat > "$OPENSSL_CNF" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ROOT_DIR
certs             = $ROOT_DIR/certs
crl_dir           = $ROOT_DIR/crl
database          = $ROOT_DIR/index.txt
new_certs_dir     = $ROOT_DIR/newcerts
certificate       = $ROOT_DIR/rootCA.pem
serial            = $ROOT_DIR/serial
crlnumber         = $ROOT_DIR/crlnumber
crl               = $ROOT_DIR/crl.pem
private_key       = $ROOT_DIR/private/rootCA.key
RANDFILE          = $ROOT_DIR/private/.rand

default_days      = 3650
default_crl_days  = 30
default_md        = sha256
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits       = 4096
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_ca

[ dn ]
C  = $C
ST = $ST
L  = $L
O  = $O
OU = $OU
CN = $CN
emailAddress = $EMAIL

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_server_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ v3_client_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[ v3_email_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection

[ v3_codesign_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning

[ v3_router_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
EOF

    # Generează certificatul self-signed RootCA
    echo "Generare certificat RootCA self-signed..."
    if [ -z "$PASS" ]; then
        openssl req -x509 -new -nodes -key "$KEY" -sha256 -days $DAYS -out "$CERT" -config "$OPENSSL_CNF" -extensions v3_ca
    else
        openssl req -x509 -new -key "$KEY" -sha256 -days $DAYS -out "$CERT" -config "$OPENSSL_CNF" -extensions v3_ca -passin pass:"$PASS"
    fi

    # Generează prima listă de revocare goală
    echo "Generare listă de revocare inițială..."
    if [ -z "$PASS" ]; then
        openssl ca -gencrl -out "$ROOT_DIR/crl.pem" -config "$OPENSSL_CNF"
    else
        openssl ca -gencrl -out "$ROOT_DIR/crl.pem" -config "$OPENSSL_CNF" -passin pass:"$PASS"
    fi

    echo ""
    echo "RootCA inițializat cu succes în $ROOT_DIR"
    echo "Structura creată:"
    echo "   - $ROOT_DIR/private/rootCA.key (cheia privată)"
    echo "   - $ROOT_DIR/rootCA.pem (certificatul RootCA)"
    echo "   - $ROOT_DIR/openssl.cnf (configurația)"
    echo "   - $ROOT_DIR/index.txt (baza de date certificate)"
    echo "   - $ROOT_DIR/crl.pem (lista de revocare)"
    echo ""
    echo "Pentru a semna un CSR SubCA, folosește: ./rootca.sh sign-csr"

    setup_nfs_shared
    copy_to_shared
}

sign_csr() {
    check_root
    
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "RootCA nu este inițializat! Rulează mai întâi: ./rootca.sh init"
        exit 1
    fi

    echo "Semnare CSR SubCA"
    echo "===================="
    
    echo "Introduceți calea către CSR-ul SubCA:"
    read -e -p "CSR path: " CSR
    
    if [ ! -f "$CSR" ]; then
        echo "Fișierul CSR nu există: $CSR"
        exit 1
    fi
    
    echo "Introduceți calea pentru certificatul SubCA semnat (ex: subCA.pem):"
    read -e -p "Output path: " OUT
    
    echo "Introduceți parola pentru cheia RootCA (dacă există, altfel ENTER):"
    read -s PASS
    echo ""

    echo "Verificare CSR..."
    openssl req -in "$CSR" -noout -text | head -20
    
    echo ""
    echo "Semnare certificat SubCA cu extensiile pentru CA intermediar..."
    
    if [ -z "$PASS" ]; then
        openssl x509 -req -in "$CSR" -CA "$CERT" -CAkey "$KEY" -CAcreateserial -out "$OUT" -days 1825 -sha256 -extfile "$OPENSSL_CNF" -extensions v3_intermediate_ca
    else
        openssl x509 -req -in "$CSR" -CA "$CERT" -CAkey "$KEY" -CAcreateserial -out "$OUT" -days 1825 -sha256 -extfile "$OPENSSL_CNF" -extensions v3_intermediate_ca -passin pass:"$PASS"
    fi

    if [ $? -eq 0 ]; then
        echo ""
        echo "Certificatul SubCA a fost semnat cu succes!"
        echo "Certificat salvat la: $OUT"
        echo ""
        echo "Detalii certificat semnat:"
        openssl x509 -in "$OUT" -noout -subject -issuer -dates
        echo ""
        echo "[NFS] Copiere certificat SubCA semnat în zona shared/subca..."
        setup_nfs_shared
        copy_to_shared "$OUT"
        echo "Pentru a importa în SubCA, accesează fișierul din $SUBCA_DIR sau montează-l pe SubCA."
    else
        echo "Eroare la semnarea certificatului!"
        exit 1
    fi
}

update_crl() {
    check_root
    
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "RootCA nu este inițializat! Rulează mai întâi: ./rootca.sh init"
        exit 1
    fi

    echo "Actualizare listă de revocare RootCA"
    echo "===================================="
    
    echo "Introduceți parola pentru cheia RootCA (dacă există, altfel ENTER):"
    read -s PASS
    echo ""

    echo "Actualizare CRL..."
    if [ -z "$PASS" ]; then
        openssl ca -gencrl -out "$ROOT_DIR/crl.pem" -config "$OPENSSL_CNF"
    else
        openssl ca -gencrl -out "$ROOT_DIR/crl.pem" -config "$OPENSSL_CNF" -passin pass:"$PASS"
    fi

    if [ $? -eq 0 ]; then
        echo "Lista de revocare actualizată cu succes!"
        echo "CRL salvat la: $ROOT_DIR/crl.pem"
        setup_nfs_shared
        copy_to_shared
    else
        echo "Eroare la actualizarea CRL!"
        exit 1
    fi
}

revoke_cert() {
    check_root
    
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "RootCA nu este inițializat! Rulează mai întâi: ./rootca.sh init"
        exit 1
    fi

    echo "Revocare certificat"
    echo "==================="
    
    echo "Introduceți calea către certificatul de revocat:"
    read -e -p "Cert path: " CERT_PATH
    
    if [ ! -f "$CERT_PATH" ]; then
        echo "Fișierul certificat nu există: $CERT_PATH"
        exit 1
    fi
    
    echo "Introduceți motivul revocării (1-9, default 1):"
    echo "  1 - unspecified"
    echo "  2 - keyCompromise"
    echo "  3 - CACompromise"
    echo "  4 - affiliationChanged"
    echo "  5 - superseded"
    echo "  6 - cessationOfOperation"
    echo "  7 - certificateHold"
    echo "  8 - removeFromCRL"
    echo "  9 - privilegeWithdrawn"
    read -p "Motiv (1-9): " REASON
    REASON=${REASON:-1}
    
    echo "Introduceți parola pentru cheia RootCA (dacă există, altfel ENTER):"
    read -s PASS
    echo ""

    echo "Revocare certificat..."
    if [ -z "$PASS" ]; then
        openssl ca -revoke "$CERT_PATH" -config "$OPENSSL_CNF" -crl_reason $REASON
    else
        openssl ca -revoke "$CERT_PATH" -config "$OPENSSL_CNF" -crl_reason $REASON -passin pass:"$PASS"
    fi

    if [ $? -eq 0 ]; then
        echo "Certificat revocat cu succes!"
        echo "Actualizare CRL..."
        update_crl
    else
        echo "Eroare la revocarea certificatului!"
        exit 1
    fi
}

show_status() {
    echo "Status RootCA"
    echo "==============="
    echo "Folder RootCA: $ROOT_DIR"
    
    if [ -f "$CERT" ]; then
        echo "Certificat RootCA: EXISTĂ"
        echo "Valabilitate:"
        openssl x509 -in "$CERT" -noout -dates
        echo "Subiect:"
        openssl x509 -in "$CERT" -noout -subject
        echo "Emitor:"
        openssl x509 -in "$CERT" -noout -issuer
    else
        echo "Certificat RootCA: NU EXISTĂ"
    fi
    
    if [ -f "$KEY" ]; then
        echo "Cheie privată: EXISTĂ"
    else
        echo "Cheie privată: NU EXISTĂ"
    fi
    
    if [ -f "$OPENSSL_CNF" ]; then
        echo "Config OpenSSL: EXISTĂ"
    else
        echo "Config OpenSSL: NU EXISTĂ"
    fi
    
    if [ -f "$ROOT_DIR/crl.pem" ]; then
        echo "CRL: EXISTĂ"
        echo "Ultima actualizare CRL:"
        openssl crl -in "$ROOT_DIR/crl.pem" -noout -lastupdate -nextupdate
    else
        echo "CRL: NU EXISTĂ"
    fi
    
    echo ""
    echo "Status NFS:"
    if [ -d "$SHARED_DIR" ]; then
        echo "  Shared directory: EXISTĂ ($SHARED_DIR)"
        if [ -f "$ROOT_EXPORT_DIR/rootCA.pem" ]; then
            echo "  RootCA.pem exportat: DA"
        else
            echo "  RootCA.pem exportat: NU"
        fi
        if [ -f "$ROOT_EXPORT_DIR/rootCA.crl.pem" ]; then
            echo "  RootCA.crl.pem exportat: DA"
        else
            echo "  RootCA.crl.pem exportat: NU"
        fi
    else
        echo "  Shared directory: NU EXISTĂ"
    fi
}



show_help() {
    echo "RootCA Management Script - Compatibil cu aplicația SubCA"
    echo "========================================================"
    echo "Usage: $0 {init|sign-csr|revoke|update-crl|status|reconfig_nfs|sync-files|help}"
    echo ""
    echo "Comenzi:"
    echo "  init      - Inițializează RootCA (cheie + certificat self-signed + CRL)"
    echo "  sign-csr  - Semnează un CSR SubCA cu extensiile pentru CA intermediar"
    echo "  revoke    - Revocă un certificat și actualizează CRL"
    echo "  update-crl- Actualizează lista de revocare"
    echo "  status    - Afișează statusul RootCA și NFS"
    echo "  reconfig_nfs - Adăugă IP-uri suplimentare pentru acces NFS"
    echo "  sync-files- Sincronizează fișierele RootCA în zona shared"
    echo "  help      - Afișează acest mesaj de ajutor"
    echo ""
    echo "Flux recomandat pentru scenariul real:"
    echo "  1. Pe RootCA: ./rootca.sh init"
    echo "  2. Pe SubCA: folosește aplicația pentru a genera CSR-ul"
    echo "  3. Pe RootCA: ./rootca.sh sign-csr"
    echo "  4. Pe SubCA: importă certificatul și lanțul de încredere"
    echo "  5. Pe SubCA: generează certificate pentru clienți"
    echo "  6. Pe WebServer/Client: montează NFS și accesează certificatele"
    echo ""
    echo "Compatibilitate cu aplicația SubCA:"
    echo "  - Exportă fișierele prin NFS în /srv/pki_shared/"
    echo "  - SubCA poate monta și accesa fișierele automat"
    echo "  - Structura compatibilă cu ~/PKIAppData/"
    echo "  - IP-uri pre-configurate pentru scenariul real"
}

case "$1" in
    init)
        init_rootca
        ;;
    sign-csr)
        sign_csr
        ;;
    revoke)
        revoke_cert
        ;;
    update-crl)
        update_crl
        ;;
    sync-files)
        sync_files
        ;;
    reconfig_nfs)
        reconfig_nfs
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        ;;
esac 
