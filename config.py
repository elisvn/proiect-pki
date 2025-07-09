# config.py
import os

BASE_DIR = os.path.expanduser("~/PKIAppData")

CA_DIR = os.path.join(BASE_DIR, "ca")
SUBCA_DIR = os.path.join(BASE_DIR, "subca")
ROOT_DIR = os.path.join(BASE_DIR, "root")
CLIENT_DIR = os.path.join(SUBCA_DIR, "certs", "clients")
os.makedirs(CLIENT_DIR, exist_ok=True)