#!/bin/bash

client_import() {
    read -p "Enter the IP of the RootCA (NFS server): " nfs_ip
    read -p "Enter the client name (folder in NFS, e.g., client1): " client_name
    nfs_mount="/mnt/pki_shared"
    sudo mkdir -p "$nfs_mount"
    if ! mountpoint -q "$nfs_mount"; then
        echo "Mounting NFS export from $nfs_ip..."
        sudo mount -t nfs ${nfs_ip}:/srv/pki_shared "$nfs_mount"
    fi
    client_nfs_dir="$nfs_mount/$client_name"
    if [ ! -d "$client_nfs_dir" ]; then
        echo "ERROR: Client folder $client_nfs_dir does not exist in NFS. Aborting."
        exit 1
    fi
    local_dir="$HOME/${client_name}_certs"
    mkdir -p "$local_dir"
    cp "$client_nfs_dir/$client_name.crt" "$local_dir/" 2>/dev/null
    cp "$client_nfs_dir/$client_name.key" "$local_dir/" 2>/dev/null
    cp "$client_nfs_dir/$client_name.p12" "$local_dir/" 2>/dev/null
    echo "\nCertificatul, cheia și (dacă există) fișierul .p12 au fost copiate în: $local_dir"
    if [ -f "$local_dir/$client_name.p12" ]; then
        echo "\n=== Instrucțiuni import certificat client în browser ==="
        echo "1. Deschide browserul (Chrome/Firefox/Edge)."
        echo "2. Mergi la Settings > Privacy & Security > Certificates > Import."
        echo "3. Selectează fișierul $local_dir/$client_name.p12."
        echo "4. Introdu parola dacă este necesar."
        echo "5. După import, accesează site-ul web securizat și selectează certificatul la cerere."
    else
        echo "\nNu există fișier .p12 pentru acest client. Poți importa manual .crt și .key dacă browserul permite."
    fi
}

webserver_setup() {
    echo "=== Setup webserver cu mutual TLS și pagină modernă ==="
    read -p "Introdu IP-ul RootCA (NFS server): " nfs_ip
    nfs_mount="/mnt/pki_shared"
    sudo mkdir -p "$nfs_mount"
    if ! mountpoint -q "$nfs_mount"; then
        echo "[INFO] Montez NFS export de la $nfs_ip..."
        sudo mount -t nfs ${nfs_ip}:/srv/pki_shared "$nfs_mount"
    fi
    ws_nfs_dir="$nfs_mount/webserver"
    subca_nfs_dir="$nfs_mount/subca"
    rootca_nfs_dir="$nfs_mount/root"
    certs_dir="/etc/nginx/certs"
    sudo mkdir -p "$certs_dir"
    # Copiere fișiere webserver
    sudo cp "$ws_nfs_dir/webserver.crt" "$certs_dir/" || { echo "Eroare: nu găsesc webserver.crt"; exit 1; }
    sudo cp "$ws_nfs_dir/webserver.key" "$certs_dir/" || { echo "Eroare: nu găsesc webserver.key"; exit 1; }
    # Copiere SubCA, RootCA, CRL
    sudo cp "$subca_nfs_dir/subCA.pem" "$certs_dir/" || { echo "Eroare: nu găsesc subCA.pem"; exit 1; }
    sudo cp "$rootca_nfs_dir/rootCA.pem" "$certs_dir/" || { echo "Eroare: nu găsesc rootCA.pem"; exit 1; }
    # Copiere CRL cu verificare nume
    if [ -f "$subca_nfs_dir/subCA.crl" ]; then
        sudo cp "$subca_nfs_dir/subCA.crl" "$certs_dir/SubCA.crl"
    elif [ -f "$subca_nfs_dir/SubCA.crl" ]; then
        sudo cp "$subca_nfs_dir/SubCA.crl" "$certs_dir/SubCA.crl"
    else
        echo "Eroare: nu găsesc subCA.crl/SubCA.crl în $subca_nfs_dir"
    fi
    # Creează ca_chain.pem
    sudo bash -c "cat $certs_dir/subCA.pem $certs_dir/rootCA.pem > $certs_dir/ca_chain.pem"
    sudo chmod 600 $certs_dir/*
    sudo chmod 644 $certs_dir/*.pem $certs_dir/*.crt $certs_dir/*.crl 2>/dev/null
    # Generează pagina web modernă
    sudo mkdir -p /var/www/html
    sudo bash -c 'cat > /var/www/html/index.html' <<EOF
<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>web_server - Secure Webserver</title>
  <link href="https://fonts.googleapis.com/css?family=Roboto:700&display=swap" rel="stylesheet">
  <style>
    body { background: #232a34; color: #fff; font-family: Roboto, Arial, sans-serif; margin: 0; }
    .center-box { max-width: 420px; margin: 8% auto; background: #2d3642; border-radius: 18px; box-shadow: 0 8px 32px #0008; padding: 2.5em 2em; text-align: center; }
    h1 { color: #2196f3; font-size: 2.1em; margin-bottom: 0.2em; }
    .highlight { background: #2196f3; color: #fff; border-radius: 8px; padding: 0.1em 0.5em; }
    .desc { color: #b0b8c1; margin-bottom: 1.2em; }
    .status { font-weight: bold; font-size: 1.1em; }
    .status.active { color: #4caf50; }
    .status.inactive { color: #f44336; }
    @media (max-width: 600px) { .center-box { margin: 2em 1em; padding: 1.5em 0.5em; } }
  </style>
</head>
<body>
  <div class="center-box">
    <h1>Bine ai venit pe <span class="highlight">web_server</span> !</h1>
    <div class="desc">Acest webserver folosește certificat SSL generat și distribuit automat prin PKI și NFS.</div>
    <div class="status active">Status SSL: Activ</div>
    <div style="margin-top:1.2em; color:#b0b8c1; font-size:0.98em;">Pagina generată automat la configurare.</div>
  </div>
</body>
</html>
EOF
    # Configurare NGINX
    sudo tee /etc/nginx/sites-available/web_server.conf > /dev/null <<NGINXCONF
server {
    listen 443 ssl;
    server_name _;
    root /var/www/html;
    index index.html;
    ssl_certificate     $certs_dir/webserver.crt;
    ssl_certificate_key $certs_dir/webserver.key;
    ssl_client_certificate $certs_dir/ca_chain.pem;
    ssl_verify_client on;
    ssl_crl $certs_dir/SubCA.crl;
    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINXCONF
    sudo ln -sf /etc/nginx/sites-available/web_server.conf /etc/nginx/sites-enabled/web_server.conf
    sudo rm -f /etc/nginx/sites-enabled/default
    echo "[INFO] Restart nginx..."
    sudo systemctl restart nginx
    sleep 1
    sudo systemctl status nginx --no-pager | grep -q running && echo "[OK] NGINX rulează cu succes!" || { echo "[EROARE] NGINX nu rulează!"; exit 1; }
    echo "\n✔️ Setup complet! Accesează site-ul cu: https://<ip_webserver> (cu mutual TLS activ)"
}
 
if [[ "$1" == "client-import" ]]; then
    client_import
    exit 0
fi
if [[ "$1" == "webserver-setup" ]]; then
    webserver_setup
    exit 0
fi

