# === main.py REFACTORIZAT ===
# Centralizează importurile și constantele comune pentru aplicația PKI
import os
import subprocess
import shutil
import logging
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from config import CLIENT_DIR, SUBCA_DIR

logging.basicConfig(
    filename='pki_app.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

BASE_DIR = os.path.abspath(".")
ROOT_DIR = os.path.join(BASE_DIR, "root")


def run(cmd, input_text=None):
    import re
    safe_cmd = re.sub(r'(-pass(in|out) (pass:)?)[^ ]+', r'\1***', cmd)
    safe_cmd = re.sub(r'(-passin stdin)', r'\1 [input ascuns]', safe_cmd)
    try:
        result = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT,
            input=input_text.encode() if input_text else None
        ).decode()
        logging.info(f"Executed: {safe_cmd}\n{result}")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing: {safe_cmd}\n{e.output.decode()}")
        return e.output.decode()


def generate_openssl_cnf(country, state, locality, organization, org_unit, common_name, email=""):
    import os
    subca_dir = os.path.abspath(SUBCA_DIR)
    os.makedirs(subca_dir, exist_ok=True)
    config_path = os.path.join(subca_dir, "openssl.cnf")
    config_content = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {subca_dir}
certs             = {subca_dir}/certs
crl_dir           = {subca_dir}/crl
database          = {subca_dir}/index.txt
new_certs_dir     = {subca_dir}/newcerts
certificate       = {subca_dir}/subCA.pem
serial            = {subca_dir}/serial
crlnumber         = {subca_dir}/crlnumber
crl               = {subca_dir}/crl.pem
private_key       = {subca_dir}/subCA.key
RANDFILE          = {subca_dir}/private/.rand

default_days      = 365
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
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_req_default

[ dn ]
C            = {country}
ST           = {state}
L            = {locality}
O            = {organization}
OU           = {org_unit}
CN           = {common_name}
emailAddress = {email}

# Extensions for each cert type
[ v3_req_client ]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[ v3_req_server ]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ v3_req_router ]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth

[ v3_req_email ]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection

[ v3_req_codesign ]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature
extendedKeyUsage = codeSigning

[ v3_req_default ]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:true
keyUsage               = critical,digitalSignature,cRLSign,keyCertSign
"""
    with open(config_path, "w") as f:
        f.write(config_content.strip())





def init_sub_ca():
    os.makedirs(SUBCA_DIR, exist_ok=True)
    for f in ["index.txt", "serial", "crlnumber"]:
        path = os.path.join(SUBCA_DIR, f)
        if not os.path.exists(path):
            with open(path, "w") as out:
                if f in ["serial", "crlnumber"]:
                    out.write("1000\n")

    for subdir in ["newcerts", "crl", "certs"]:
        os.makedirs(os.path.join(SUBCA_DIR, subdir), exist_ok=True)


    key_path = os.path.join(SUBCA_DIR, "subCA.key")
    csr_path = os.path.join(SUBCA_DIR, "subCA.csr")
    conf_path = os.path.join(SUBCA_DIR, "openssl.cnf")

    run(f"openssl genrsa -out {key_path} 4096")
    run(
        f"openssl req -new -key {key_path} -out {csr_path} "
        f"-config {conf_path}"
    )

    return f"✔ SubCA inițializată în {SUBCA_DIR}"


def gen_subca_key(password):

    for fname, default in [("index.txt", ""), ("serial", "1000\n"), ("crlnumber", "1000\n")]:
        fpath = os.path.join(SUBCA_DIR, fname)
        if not os.path.exists(fpath):
            with open(fpath, "w") as f:
                f.write(default)
    return run(f"openssl genrsa -aes256 -passout stdin -out {SUBCA_DIR}/subCA.key 4096", input_text=password)


def gen_subca_csr(password):
    return run(f"openssl req -new -key {SUBCA_DIR}/subCA.key -out {SUBCA_DIR}/subCA.csr -passin stdin -subj '/C=RO/ST=Sibiu/O=Academie/CN=SubCA'", input_text=password)


def create_chain_file():
    chain_path = os.path.join(SUBCA_DIR, "chain.pem")
    subca_cert = os.path.join(SUBCA_DIR, "subCA.pem")
    root_cert = os.path.join(ROOT_DIR, "rootCA.pem")

    if os.path.exists(chain_path):
        return chain_path, "✔ chain.pem deja există."

    if not os.path.exists(subca_cert) or not os.path.exists(root_cert):
        return None, "❌ Lipsesc subCA.pem sau rootCA.pem pentru lanțul de încredere."


    with open(chain_path, "w") as out:
        with open(subca_cert, "r") as f1:
            out.write(f1.read())
        with open(root_cert, "r") as f2:
            out.write(f2.read())
    return chain_path, "✔ chain.pem creat cu succes."


def view_conf(conf_path):
    if os.path.exists(conf_path):
        with open(conf_path) as f:
            return f.read()
    return "❌ Fișierul nu există."

def update_conf(conf_path, new_text):
    with open(conf_path, "w") as f:
        f.write(new_text)
    return "✔ Fișierul a fost actualizat."



def generate_crl_if_missing(password=None):
    import subprocess
    for f in ["index.txt", "serial", "crlnumber"]:
        path = os.path.join(SUBCA_DIR, f)
        if not os.path.exists(path):
            with open(path, "w") as out:
                if f in ["serial", "crlnumber"]:
                    out.write("1000\n")
    for subdir in ["newcerts", "crl", "certs"]:
        os.makedirs(os.path.join(SUBCA_DIR, subdir), exist_ok=True)

    crl_dir = os.path.join(SUBCA_DIR, "crl")
    crl_path = os.path.join(crl_dir, "subca.crl.pem")
    openssl_cnf = os.path.join(SUBCA_DIR, "openssl.cnf")
    os.makedirs(crl_dir, exist_ok=True)
    if not os.path.exists(crl_path):
        try:
            cmd = [
                "openssl", "ca", "-gencrl",
                "-config", openssl_cnf,
                "-out", crl_path
            ]
            if password:
                cmd += ["-passin", f"pass:{password}"]
            subprocess.run(cmd, check=True)
            return crl_path, "✔ CRL generat automat."
        except Exception as e:
            return None, f"❌ Eroare la generarea CRL: {e}"
    else:
        return crl_path, "✔ CRL deja există."


def delete_client_folder(client_name):
    client_path = os.path.join(SUBCA_DIR, "certs", "clients", client_name)
    cert_path = os.path.join(client_path, f"{client_name}.crt")
    crl_path = os.path.join(SUBCA_DIR, "crl", "subca.crl.pem")
    index_path = os.path.join(SUBCA_DIR, "index.txt")

    if not os.path.exists(client_path):
        return f"[!] Folderul clientului {client_name} nu există."


    can_delete = False
    reason = ""

    try:

        if not os.path.exists(cert_path):
            can_delete = True
            reason = "nu are certificat valid (nu a fost semnat)"


        else:
            client_serial = None
            revoked_serials = []
            try:
                with open(cert_path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    client_serial = cert.serial_number
            except Exception as e:
                can_delete = True
                reason = f"certificat invalid/corupt: {str(e)}"
                client_serial = None

            if client_serial is not None:
                if os.path.exists(crl_path):
                    try:
                        with open(crl_path, "rb") as f:
                            crl = x509.load_pem_x509_crl(f.read(), default_backend())
                            revoked_serials = [rev.serial_number for rev in crl]

                        if client_serial in revoked_serials:
                            can_delete = True
                            reason = "certificat revocat în CRL"
                        else:
                            if os.path.exists(index_path):
                                with open(index_path, "r") as f:
                                    for line in f:
                                        if line.strip().endswith(f"/CN={client_name}"):
                                            parts = line.strip().split("\t")
                                            if len(parts) > 3 and parts[0] == "R":  # R = revoked
                                                can_delete = True
                                                reason = "certificat revocat în index.txt"
                                                break
                    except Exception as e:
                        if os.path.exists(index_path):
                            with open(index_path, "r") as f:
                                for line in f:
                                    if line.strip().endswith(f"/CN={client_name}") and line.startswith("R"):
                                        can_delete = True
                                        reason = "certificat revocat în index.txt (CRL corupt)"
                                        break
                else:
                    if os.path.exists(index_path):
                        with open(index_path, "r") as f:
                            for line in f:
                                if line.strip().endswith(f"/CN={client_name}") and line.startswith("R"):
                                    can_delete = True
                                    reason = "certificat revocat în index.txt (fără CRL)"
                                    break

    except Exception as e:
        return f"[!] Eroare la verificarea clientului {client_name}: {str(e)}"

    if not can_delete:
        return f"[!] Clientul {client_name} nu poate fi șters: certificat valid și nerevocat."

    try:
        shutil.rmtree(client_path)
        return f"[✓] Clientul {client_name} șters cu succes ({reason})."
    except Exception as e:
        return f"[!] Eroare la ștergerea folderului {client_name}: {str(e)}"

def preview_csr(csr_path):
    cmd = f"openssl req -in {csr_path} -noout -text"
    return run(cmd)
