# revoke.py
import os
from main import SUBCA_DIR, CLIENT_DIR, run

def revoke_client_cert(client_name, password):
    cmd = (
        f"openssl ca -config {os.path.join(SUBCA_DIR,'openssl.cnf')} "
        f"-revoke {os.path.join(CLIENT_DIR, client_name, client_name + '.crt')} "
        f"-passin stdin"
    )
    run(cmd, input_text=password)

    crl_dir = os.path.join(SUBCA_DIR, "crl")
    os.makedirs(crl_dir, exist_ok=True)
    crl_out = os.path.join(crl_dir, "subca.crl.pem")

    run(
        f"openssl ca -gencrl -config {os.path.join(SUBCA_DIR,'openssl.cnf')} "
        f"-out {crl_out} -passin stdin",
        input_text=password
    )

    return f"✔ {client_name} revoked; CRL updated."



def verify_cert_with_crl(client_name):
    cert_path = os.path.join(CLIENT_DIR, client_name, f"{client_name}.crt")
    chain_path = os.path.join(SUBCA_DIR, "chain.pem")
    crl_path = os.path.join(SUBCA_DIR, "crl", "subca.crl.pem")



    if not os.path.exists(cert_path):
        return f"❌ Certificatul {cert_path} nu există."
    if not os.path.exists(chain_path):
        return f"❌ chain.pem lipsește."
    if not os.path.exists(crl_path):
        return f"❌ Fișierul crl.pem lipsește. Nu s-a generat nicio revocare."

    cmd = f"openssl verify -crl_check -CAfile {chain_path} -CRLfile {crl_path} {cert_path}"
    result = run(cmd)
    if ": OK" in result:
        return f"✔ Certificatul {client_name} NU este în CRL. (valid)"
    if "certificate revoked" in result.lower():
        return f"❌ Certificatul {client_name} este revocat conform CRL."
    return f"❌ Certificatul {client_name} NU este valid (verificare eșuată).\n{result}"