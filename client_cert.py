# client_cert.py
import os
import shutil
from main import run, create_chain_file
from config import CLIENT_DIR, SUBCA_DIR

def gen_client_cert(client_name, subject, password, client_type):
    client_path = os.path.join(CLIENT_DIR, client_name)
    os.makedirs(client_path, exist_ok=True)

    key_path = os.path.join(client_path, f"{client_name}.key")
    csr_path = os.path.join(client_path, f"{client_name}.csr")
    cert_path = os.path.join(client_path, f"{client_name}.crt")
    ext_section = f"v3_{client_type}"

    conf_path = os.path.join(SUBCA_DIR, "openssl.cnf")
    if not os.path.exists(conf_path):
        return "❌ Fișierul openssl.cnf nu există în subca/"

    with open(conf_path, "r") as f:
        content = f.read()
    if f"[ {ext_section} ]" not in content:
        extra = f"\n\n[{ext_section}]\n"
        extra += "basicConstraints = CA:FALSE\n"
        extra += "keyUsage = digitalSignature, keyEncipherment\n"
        if client_type in ["router", "server"]:
            extra += "extendedKeyUsage = serverAuth\n"
        else:
            extra += "extendedKeyUsage = clientAuth\n"
        with open(conf_path, "a") as f:
            f.write(extra)

    # Generează cheia și CSR-ul
    out = run(f"openssl genrsa -out {key_path} 2048")
    out += run(f"openssl req -new -key {key_path} -out {csr_path} -subj '{subject}'")

    # Semnează certificatul
    cmd = (f"openssl x509 -req -in {csr_path} -CA {SUBCA_DIR}/subCA.pem -CAkey {SUBCA_DIR}/subCA.key "
           f"-CAcreateserial -out {cert_path} -days 365 -sha256 "
           f"-extfile {conf_path} -extensions {ext_section}")
    if password:
        cmd += f" -passin pass:{password}"
    out += run(cmd)

    # Verifică dacă certificatul este valid
    verify_cert = os.system(f"openssl x509 -in {cert_path} -noout > /dev/null 2>&1")
    if not os.path.exists(cert_path) or verify_cert != 0:
        return out + f"\n❌ Eroare: Certificatul nu a fost generat corect pentru {client_name}!\nVerifică output-ul de mai sus și configurația subCA."

    # Creează fișierul de lanț chain.pem și verifică certificatul
    chain_path, msg = create_chain_file()
    out += msg + "\n"
    if chain_path:
        verify = run(f"openssl verify -CAfile {chain_path} {cert_path}")
        out += "🧪 Verificare certificat:\n" + verify + "\n"

    return out

def sign_external_csr(csr_path, client_name, ext_name, password):
    cert_dir = os.path.join(CLIENT_DIR, client_name)
    os.makedirs(cert_dir, exist_ok=True)

    cert_path = os.path.join(cert_dir, f"{client_name}.crt")
    conf_path = os.path.join(SUBCA_DIR, "openssl.cnf")

    if not os.path.exists(csr_path):
        return f"❌ CSR-ul nu există: {csr_path}"

    cmd = (f"openssl x509 -req -in {csr_path} -CA {SUBCA_DIR}/subCA.pem -CAkey {SUBCA_DIR}/subCA.key "
           f"-CAcreateserial -out {cert_path} -days 365 -sha256 "
           f"-extfile {conf_path} -extensions {ext_name} -passin stdin")

    result = run(cmd, input_text=password)
    result += f"\n✔ Certificat extern semnat salvat la: {cert_path}"
    return result

def verify_cert_simple(client_name):
    import subprocess
    client_cert_path = os.path.join(CLIENT_DIR, client_name, f"{client_name}.crt")
    chain_path = os.path.join(SUBCA_DIR, "chain.pem")

    try:
        output = subprocess.check_output([
            "openssl", "verify", "-CAfile", chain_path, client_cert_path
        ], stderr=subprocess.STDOUT, text=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip()