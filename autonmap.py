```
#!/usr/bin/env python3
import subprocess
import sys
import os
import re
import getpass

# Colores
G, Y, R, B, C, NC = '\033[0;32m', '\033[1;33m', '\033[0;31m', '\033[0;34m', '\033[0;36m', '\033[0m'


def pedir_sudo():
    """Pide la contraseña y valida/cachea las credenciales sudo."""
    print(f"{Y}[*] Se necesitan privilegios sudo para el escaneo SYN.{NC}")
    for intento in range(3):
        try:
            password = getpass.getpass("[sudo] password: ")
        except KeyboardInterrupt:
            print(f"\n{R}[!] Cancelado.{NC}")
            sys.exit(1)

        # -S lee la pass de stdin, -v refresca el timestamp
        p = subprocess.run(
            ["sudo", "-S", "-v"],
            input=password + "\n",
            text=True,
            capture_output=True
        )
        if p.returncode == 0:
            print(f"{G}[+] Credenciales sudo OK.{NC}")
            return
        print(f"{R}[!] Contraseña incorrecta. Intento {intento + 1}/3{NC}")
    print(f"{R}[!] Demasiados intentos fallidos.{NC}")
    sys.exit(1)


def run(cmd):
    """Ejecuta un comando mostrando la línea."""
    print(f"{C}$ {' '.join(cmd)}{NC}")
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    if len(sys.argv) < 2:
        print(f"{R}[!] Uso: {sys.argv[0]} <IP_OBJETIVO>{NC}")
        sys.exit(1)

    ip = sys.argv[1]
    outdir = f"scan_{ip}"
    os.makedirs(outdir, exist_ok=True)

    # Pedir sudo ANTES de empezar
    pedir_sudo()

    print(f"\n{B}{'=' * 45}{NC}")
    print(f"{B}   AutoScan sobre {ip}{NC}")
    print(f"{B}{'=' * 45}{NC}")

    # Fase 1: escaneo completo de puertos
    print(f"\n{Y}[*] Fase 1: Escaneo de todos los puertos...{NC}")
    gnmap = os.path.join(outdir, "scan.gnmap")
    run(["sudo", "nmap", "-sS", "-p-", "--open", "-Pn", "-n",
         "--min-rate", "5000", ip, "-oG", gnmap])

    if not os.path.exists(gnmap):
        print(f"{R}[!] No se generó el archivo grepeable.{NC}")
        sys.exit(1)

    # Fase 2: extraer puertos
    print(f"\n{Y}[*] Fase 2: Extrayendo puertos abiertos...{NC}")
    ports = set()
    with open(gnmap) as f:
        for line in f:
            m = re.search(r'Ports: ([^ ]+)', line)
            if m:
                for entry in m.group(1).split(','):
                    parts = entry.split('/')
                    if len(parts) >= 2 and parts[1] == 'open':
                        ports.add(parts[0])

    if not ports:
        print(f"{R}[!] No se encontraron puertos abiertos.{NC}")
        sys.exit(1)

    ports_str = ",".join(sorted(ports, key=int))
    print(f"{G}[+] Puertos abiertos: {ports_str}{NC}")

    # Fase 3: escaneo de servicios
    print(f"\n{Y}[*] Fase 3: Escaneo de servicios y versiones...{NC}")
    services = os.path.join(outdir, "services.txt")
    run(["sudo", "nmap", "-sVC", "-p", ports_str, ip, "-oN", services])

    # Fase 4: mostrar output final
    print(f"\n{B}{'=' * 45}{NC}")
    print(f"{B}   RESULTADOS DE SERVICIOS{NC}")
    print(f"{B}{'=' * 45}{NC}\n")

    with open(services) as f:
        print(f.read())

    print(f"\n{G}[✓] Escaneo completado. Archivos en: {outdir}/{NC}")


if __name__ == "__main__":
    main()
```

guardalo en tu path .bin

