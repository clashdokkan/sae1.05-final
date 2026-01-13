#python -m markdown rapport_final.md > rapport_final.html
import csv
import re
import os
import tkinter as tk
from tkinter import filedialog
import matplotlib.pyplot as plt
from collections import defaultdict

# ======================
# Sélection du fichier
# ======================
def choisir_fichier():
    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename(
        title="Sélectionnez le fichier de capture",
        filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )

input_file = choisir_fichier()
if not input_file:
    print("❌ Aucun fichier sélectionné")
    exit()

csv_file = "capture.csv"
rapport_md = "rapport_final.md"

# ======================
# Conversion TXT → CSV
# ======================
pattern = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+"
    r"(?P<src>[^ ]+)\s+>\s+"
    r"(?P<dst>[^:]+):"
)
flags_re = re.compile(r"Flags\s+\[([^\]]+)\]")
length_re = re.compile(r"length\s+(\d+)")

with open(input_file, "r", encoding="utf-8", errors="ignore") as f, \
     open(csv_file, "w", newline="", encoding="utf-8") as out:

    writer = csv.writer(out, delimiter=";")
    writer.writerow(["Heure","Source","IP_Destination","Port_Destination","Flags","Taille"])

    for line in f:
        if line.lstrip().startswith("0x"):
            continue
        match = pattern.search(line)
        if not match:
            continue
        heure = match.group("time")
        src = match.group("src")
        dst_full = match.group("dst")
        if "." in dst_full and dst_full.split(".")[-1].isdigit():
            parts = dst_full.split(".")
            dst_ip = ".".join(parts[:-1])
            dst_port = parts[-1]
        else:
            dst_ip = dst_full
            dst_port = ""
        flags = flags_re.search(line)
        flags = flags.group(1) if flags else ""
        taille = length_re.search(line)
        taille = taille.group(1) if taille else ""
        writer.writerow([heure, src, dst_ip, dst_port, flags, taille])

print("✅ CSV généré avec IP et Port séparés.")

# ======================
# ANALYSE SSH
# ======================
ssh_counter = defaultdict(int)
traffic = defaultdict(int)
scan_ports = defaultdict(lambda: defaultdict(int))

with open(csv_file, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f, delimiter=";")
    for row in reader:
        src = row["Source"]
        port = row["Port_Destination"]
        traffic[src] += 1
        if port == "22" or "ssh" in src.lower():
            ssh_counter[src] += 1
        if port:
            scan_ports[src][port] += 1

ssh_alerts = {src: c for src, c in ssh_counter.items() if c > 20}

# ======================
# SCAN DE PORTS
# ======================
scan_alerts = {src: ports for src, ports in scan_ports.items() if len(ports) > 10}

# ======================
# TRAFIC ANORMAL
# ======================
traffic_alerts = {src: c for src, c in traffic.items() if c > 100}

# ======================
# AFFICHAGE CONSOLE
# ======================
print("\n=== Activité SSH === (Beaucoup de tentatives SSH)")
for src, count in sorted(ssh_counter.items(), key=lambda x: x[1], reverse=True):
    print(f"{src} → {count} paquets")

for src, count in ssh_alerts.items():
    print(f" Activité SSH suspecte depuis {src} ({count} tentatives)")

print("\n=== Scan de ports === (Test de nombreux ports)")
for src, ports in scan_alerts.items():
    print(f"⚠️ Scan probable depuis {src} ({len(ports)} ports)")

print("\n=== Trafic anormal === (Saturation du réseau)")
for src, count in sorted(traffic_alerts.items(), key=lambda x: x[1], reverse=True):
    print(f"⚠️ Trafic anormal depuis {src} ({count} paquets)")

# ======================
# GRAPHIQUES
# ======================
# SSH
ssh_image = None
if ssh_alerts:
    sources = list(ssh_alerts.keys())
    counts = list(ssh_alerts.values())
    plt.figure(figsize=(8,4))
    plt.bar(sources, counts, color="red")
    plt.title("Activité SSH suspecte")
    plt.xlabel("Source")
    plt.ylabel("Nombre de tentatives")
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.savefig("ssh_alertes.png")
    plt.close()
    ssh_image = "ssh_alertes.png"

# Scan de ports
scan_images = {}
for src, ports in scan_alerts.items():
    safe_src = re.sub(r"[^a-zA-Z0-9_.-]", "_", src)
    img = f"scan_ports_{safe_src}.png"
    ports_sorted = sorted(ports.items(), key=lambda x: x[1], reverse=True)
    plt.figure(figsize=(10,5))
    plt.bar([p[0] for p in ports_sorted], [p[1] for p in ports_sorted], color="orange")
    plt.title(f"Scan de ports depuis {src}")
    plt.xlabel("Port")
    plt.ylabel("Nombre de tentatives")
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(img)
    plt.close()
    scan_images[src] = img

# Top trafic
top = sorted(traffic.items(), key=lambda x: x[1], reverse=True)[:5]
plt.figure(figsize=(9,5))
plt.bar([x[0] for x in top], [x[1] for x in top], color="steelblue")
plt.title("Top 5 des hôtes générant le plus de trafic")
plt.xlabel("Source")
plt.ylabel("Nombre de paquets")
plt.xticks(rotation=30)
plt.tight_layout()
plt.savefig("top_trafic.png")
plt.close()

# ======================
# RAPPORT MARKDOWN
# ======================
with open(rapport_md, "w", encoding="utf-8") as f:
    f.write("# Rapport d'analyse du trafic réseau\n\n")
    f.write("## Objectif\nAnalyser une capture réseau pour détecter les activités suspectes.\n\n")

    # SSH
    f.write("## Activité SSH suspecte\n")
    if ssh_alerts:
        for src, c in ssh_alerts.items():
            f.write(f"- {src} : {c} tentatives SSH ⚠️\n")
        if ssh_image:
            f.write(f"\n![Activité SSH]({ssh_image})\n\n")
    else:
        f.write("Aucune activité SSH suspecte détectée ✅\n\n")

    # Scan de ports
    f.write("## Scan de ports suspect\n")
    if scan_alerts:
        for src, ports in scan_alerts.items():
            f.write(f"- {src} : {len(ports)} ports testés ⚠️\n")
            f.write(f"![Scan de ports]({scan_images[src]})\n\n")
    else:
        f.write("Aucun scan de ports détecté ✅\n\n")

    # Trafic anormal
    f.write("## Trafic anormal\n")
    if traffic_alerts:
        for src, count in traffic_alerts.items():
            f.write(f"- {src} : {count} paquets envoyés ⚠️\n")
    else:
        f.write("Aucun trafic anormal détecté ✅\n\n")

    # Graphique top trafic
    f.write("### Top 5 des hôtes générant le plus de trafic\n")
    f.write("![Top trafic](top_trafic.png)\n\n")

    f.write("## Conclusion\n")
    f.write("Cette analyse met en évidence plusieurs comportements potentiellement malveillants. "
            "Le rapport inclut les alertes SSH, scan de ports et trafic anormal avec graphiques.\n")

print(f"✅ Rapport Markdown généré : {rapport_md}")
