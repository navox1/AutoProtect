"""Mini antivirus : scan par empreintes SHA-256, mise à jour manuelle.

Usage :
  python antivirus.py scan <dossier_ou_fichier>
  python antivirus.py update [--url URL]
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request

if getattr(sys, "frozen", False):
    DIR = os.path.dirname(sys.executable)
else:
    DIR = os.path.dirname(os.path.abspath(__file__))
SIG = os.path.join(DIR, "signatures.txt")
CFG = os.path.join(DIR, "config.json")
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def load_sigs():
    sigs = {}
    if not os.path.exists(SIG):
        return sigs
    with open(SIG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            h, _, name = line.partition(" ")
            if HASH_RE.match(h):
                sigs[h.lower()] = name.strip() or "Malware"
    return sigs


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


DECOY = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg",
         "jpeg", "png", "gif", "mp3", "mp4", "zip", "rar"}
EXEC = {"exe", "scr", "bat", "cmd", "com", "pif", "js", "vbs", "lnk", "msi"}


def double_ext(path):
    """Vrai pour 'facture.pdf.exe'. Les .dll et autres fichiers Windows
    légitimes (ex: x.dll, x.dll.config) ne sont jamais signalés."""
    parts = os.path.basename(path).lower().split(".")
    return len(parts) >= 3 and parts[-1] in EXEC and parts[-2] in DECOY


def scan(target):
    sigs = load_sigs()
    if not sigs:
        print("Aucune signature. Lance d'abord : python antivirus.py update")
        return 2
    if os.path.isfile(target):
        files = [target]
    else:
        files = (os.path.join(r, n) for r, _, ns in os.walk(target) for n in ns)
    total, found = 0, 0
    for p in files:
        if double_ext(p):
            print(f"[SUSPECT] double extension : {p}")
        try:
            digest = sha256(p)
        except OSError:
            continue
        total += 1
        if digest in sigs:
            found += 1
            print(f"[MENACE] {p} -> {sigs[digest]}")
    print(f"{total} fichier(s) analysé(s), {found} menace(s), {len(sigs)} signatures.")
    return 1 if found else 0


def update(url):
    if not url and os.path.exists(CFG):
        with open(CFG, encoding="utf-8") as f:
            url = json.load(f).get("url")
    if not url:
        print("Aucune URL. Utilise : python antivirus.py update --url <URL>")
        return 2
    with urllib.request.urlopen(url, timeout=30) as r:
        text = r.read().decode("utf-8")
    valid = [
        l.strip() for l in text.splitlines()
        if l.strip() and not l.startswith("#") and HASH_RE.match(l.split()[0])
    ]
    if not valid:
        print("Fichier invalide : mise à jour annulée.")
        return 2
    tmp = SIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, SIG)
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump({"url": url}, f)
    print(f"Mise à jour OK : {len(valid)} signatures.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("target")
    u = sub.add_parser("update")
    u.add_argument("--url")
    a = ap.parse_args()
    sys.exit(scan(a.target) if a.cmd == "scan" else update(a.url))


if __name__ == "__main__":
    main()
