#!/usr/bin/env python3
import sys
import os
import random
import argparse

# Asegurar que root/sudo está presente
if os.geteuid() != 0:
    print("❌ Error: Esta aplicación requiere privilegios de root (sudo) para enviar/recibir paquetes RAW.")
    print("Uso: sudo python3 run.py --interface eth0")
    sys.exit(1)

# Añadir src al path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.tui import DHCPApp

def get_random_mac():
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DHCP EDU CLI - Simulador Educativo")
    parser.add_argument("--interface", required=True, help="Interfaz de red (ej: eth0, wlan0)")
    args = parser.parse_args()

    # Generamos una MAC aleatoria para esta sesión
    current_mac = get_random_mac()
    
    app = DHCPApp(interface=args.interface, mac_addr=current_mac)
    app.run()
