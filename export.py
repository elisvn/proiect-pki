# export.py
import os
import shutil
from tkinter import Toplevel, Checkbutton, BooleanVar, Label, Button, Entry, StringVar, messagebox
from main import SUBCA_DIR, CLIENT_DIR, run

def export_client_files(client_name, key_path, crt_path):
    # Verifică clienți existenți
    all_clients = [d for d in os.listdir(CLIENT_DIR) if os.path.isdir(os.path.join(CLIENT_DIR, d))]
    if not all_clients:
        messagebox.showinfo("Export", "Nu există clienți pentru export.")
        return

    win = Toplevel()
    win.title("Export certificat – selecție multiplă")
    win.geometry("400x400")

    Label(win, text="Selectează clienții pentru export:").pack(pady=5)

    client_vars = {}
    for client in all_clients:
        var = BooleanVar()
        Checkbutton(win, text=client, variable=var).pack(anchor="w", padx=20)
        client_vars[client] = var

    Label(win, text="Formate de export:").pack(pady=5)
    formats = {"p12": BooleanVar(), "der": BooleanVar(), "crt": BooleanVar()}
    for fmt in formats:
        Checkbutton(win, text=fmt.upper(), variable=formats[fmt]).pack(anchor="w", padx=20)

    Label(win, text="Parolă globală pentru .p12 (opțional):").pack()
    p12_pass_var = StringVar()
    Entry(win, textvariable=p12_pass_var, show="*").pack(pady=5)

    def do_export_all():
        result = ""
        for client, selected in client_vars.items():
            if not selected.get():
                continue
            client_path = os.path.join(CLIENT_DIR, client)
            key_path = os.path.join(client_path, f"{client}.key")
            cert_path = os.path.join(client_path, f"{client}.crt")
            export_path = os.path.join(client_path, "exports")
            os.makedirs(export_path, exist_ok=True)

            if formats["p12"].get():
                chain_path = os.path.join(SUBCA_DIR, "chain.pem")
                p12_path = os.path.join(export_path, f"{client}.p12")
                cmd = (f"openssl pkcs12 -export -inkey {key_path} -in {cert_path} "
                       f"-certfile {chain_path} -out {p12_path} -passout pass:{p12_pass_var.get() or ''}")
                result += run(cmd) + f"✔ Exportat .p12: {p12_path}\n"

            if formats["der"].get():
                der_path = os.path.join(export_path, f"{client}.der")
                result += run(f"openssl x509 -in {cert_path} -outform DER -out {der_path}")
                result += f"✔ Exportat .der: {der_path}\n"

            if formats["crt"].get():
                crt_copy = os.path.join(export_path, f"{client}_copy.crt")
                shutil.copy(cert_path, crt_copy)
                result += f"✔ Copiat: {crt_copy}\n"

        messagebox.showinfo("Rezultat export", result or "Nimic nu a fost exportat.")
        win.destroy()

    Button(win, text="Exportă selecția", command=do_export_all).pack(pady=15)