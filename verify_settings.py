# verify_settings.py
import os
def run():
    for d in ["users", "chains", "imports", "temp_qr"]:
        os.makedirs(d, exist_ok=True)