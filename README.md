# Proiect PKI – Infrastructura cu Chei Publice în Mediu Virtual


## Descriere generală

Acest proiect implementează o infrastructură completă PKI într-un mediu virtualizat, compus din 4 mașini virtuale:

- **Root CA** (offline, fără GUI): generează și semnează SubCA.
- **SubCA** (cu aplicație PyQt5): administrează certificatele pentru clienți și servere.
- **Web Server** (NGINX): configurat cu certificat TLS, acceptă autentificare mutuală.
- **Client**: deține certificat digital și accesează web serverul cu mTLS.

Aplicația SubCA oferă o interfață intuitivă pentru inițializarea autorității, generarea, semnarea, revocarea și exportul certificatelor digitale, cu suport complet pentru OpenSSL.


## Funcționalități cheie

- Interfață grafică (PyQt5) pentru gestionarea SubCA-ului
- Generare și semnare CSR-uri pentru entități finale
- Revocare și verificare a certificatelor cu CRL
- Export certificate în formate `.crt`, `.key`, `.p12`
- Log activități și verificare integritate infrastructură
- Suport pentru semnarea CSR-uri externe
- Scripturi automatizate pentru RootCA, Web Server și Client



## Structura proiectului

```bash
proiect-pki/
├── app.py                 # Interfața grafică SubCA
├── main.py                # Funcții backend pentru SubCA
├── client_cert.py         # Generare și semnare certificate client/server
├── revoke.py              # Funcții de revocare certificat
├── export.py              # Export în formate PEM, DER, PKCS#12
├── config.py              # Configurări directoare și fișiere
├── scripts/
│   ├── rootca.sh          # Inițializare Root CA și semnare CSR SubCA
│   ├── web_script.sh      # Configurare Web Server cu HTTPS și mTLS
│   └── client.sh          # Import certificat client în browser
├── LICENSE                # Licență MIT
├── README.md              # Acest fișier
