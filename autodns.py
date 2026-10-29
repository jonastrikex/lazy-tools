```
#!/usr/bin/env python3
import subprocess
import sys
import os
import shutil
import re

# Colores
G, Y, R, B, C, M, NC = (
    '\033[0;32m', '\033[1;33m', '\033[0;31m',
    '\033[0;34m', '\033[0;36m', '\033[0;35m', '\033[0m'
)

# ----------------------------------------------------------
# Helpers
# ----------------------------------------------------------
def check_tool(name):
    """Comprueba si una herramienta está instalada."""
    return shutil.which(name) is not None


def run(cmd, outfile=None, timeout=300):
    """Ejecuta un comando, muestra la línea y guarda el output si se pide."""
    print(f"{C}$ {' '.join(cmd)}{NC}")
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="ignore"
        )
        output = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        output = f"[!] Timeout tras {timeout}s\n"
        print(f"{R}[!] Timeout: {' '.join(cmd)}{NC}")
    except FileNotFoundError:
        output = f"[!] Herramienta no encontrada: {cmd[0]}\n"
        print(f"{R}[!] No existe: {cmd[0]}{NC}")

    if output.strip():
        print(output)
    if outfile:
        with open(outfile, "a", errors="ignore") as f:
            f.write(f"\n{'='*60}\n$ {' '.join(cmd)}\n{'='*60}\n{output}\n")
    return output


def prompt(texto, default=None):
    val = input(f"{Y}[?] {texto}{NC} ").strip()
    if not val and default is not None:
        return default
    return val


# ----------------------------------------------------------
# Fases
# ----------------------------------------------------------
def fase_axfr(ip, dominio, outdir):
    print(f"\n{M}{'='*60}{NC}")
    print(f"{M}   FASE 1: Transferencia de Zona (AXFR){NC}")
    print(f"{M}{'='*60}{NC}")
    log = os.path.join(outdir, "01_axfr.txt")

    # AXFR sin dominio (lista zonas si el server lo permite)
    if check_tool("dig"):
        run(["dig", "axfr", f"@{ip}"], outfile=log, timeout=60)

    # AXFR con dominio
    if dominio:
        if check_tool("dig"):
            run(["dig", "axfr", f"@{ip}", dominio], outfile=log, timeout=60)
        if check_tool("dnsrecon"):
            run(["dnsrecon", "-d", dominio, "-t", "axfr", "-n", ip],
                outfile=log, timeout=120)


def fase_basico(ip, dominio, outdir):
    print(f"\n{M}{'='*60}{NC}")
    print(f"{M}   FASE 2: Consultas básicas (dig){NC}")
    print(f"{M}{'='*60}{NC}")
    log = os.path.join(outdir, "02_dig.txt")

    if not check_tool("dig"):
        print(f"{R}[!] dig no instalado (apt install dnsutils){NC}")
        return

    # Versión del servidor
    run(["dig", "version.bind", "CHAOS", "TXT", f"@{ip}"], outfile=log)
    run(["dig", "hostname.bind", "CHAOS", "TXT", f"@{ip}"], outfile=log)

    if not dominio:
        return

    # Registros comunes
    for tipo in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "ANY"]:
        run(["dig", tipo, dominio, f"@{ip}"], outfile=log)


def fase_dnsrecon(ip, dominio, outdir):
    print(f"\n{M}{'='*60}{NC}")
    print(f"{M}   FASE 3: dnsrecon{NC}")
    print(f"{M}{'='*60}{NC}")
    log = os.path.join(outdir, "03_dnsrecon.txt")

    if not check_tool("dnsrecon"):
        print(f"{R}[!] dnsrecon no instalado (apt install dnsrecon){NC}")
        return

    # Escaneo estándar
    run(["dnsrecon", "-d", dominio, "-n", ip], outfile=log, timeout=180)

    # Fuerza bruta con diccionario
    wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/wordlists/dnsmap.txt"
    if os.path.exists(wordlist):
        run(["dnsrecon", "-d", dominio, "-D", wordlist, "-t", "brt", "-n", ip],
            outfile=log, timeout=600)
    else:
        print(f"{Y}[!] No encontré wordlist para fuerza bruta de subdominios{NC}")


def fase_dnsenum(ip, dominio, outdir):
    print(f"\n{M}{'='*60}{NC}")
    print(f"{M}   FASE 4: dnsenum{NC}")
    print(f"{M}{'='*60}{NC}")
    log = os.path.join(outdir, "04_dnsenum.txt")

    if not check_tool("dnsenum"):
        print(f"{R}[!] dnsenum no instalado (apt install dnsenum){NC}")
        return

    run(["dnsenum", "--dnsserver", ip, "--enum", dominio],
        outfile=log, timeout=600)


def fase_fierce(ip, dominio, outdir):
    print(f"\n{M}{'='*60}{NC}")
    print(f"{M}   FASE 5: fierce{NC}")
    print(f"{M}{'='*60}{NC}")
    log = os.path.join(outdir, "05_fierce.txt")

    if not check_tool("fierce"):
        print(f"{R}[!] fierce no instalado (apt install fierce){NC}")
        return

    run(["fierce", "--domain", dominio, "--dns-servers", ip],
        outfile=log, timeout=300)


def fase_nse(ip, dominio, outdir):
    print(f"\n{M}{'='*60}{NC}")
    print(f"{M}   FASE 6: Scripts NSE de Nmap{NC}")
    print(f"{M}{'='*60}{NC}")
    log = os.path.join(outdir, "06_nse.txt")

    # dns-brute
    run(["nmap", "-p", "53", "--script", "dns-brute",
         "--script-args", f"dns-brute.domain={dominio}",
         ip], outfile=log, timeout=600)

    # Scripts DNS varios
    run(["nmap", "-n", "-p", "53", "--script",
         "dns-zone-transfer,dns-nsid,dns-recursion,dns-service-discovery",
         ip], outfile=log, timeout=300)


def fase_reversa(ip, dominio, outdir):
    print(f"\n{M}{'='*60}{NC}")
    print(f"{M}   FASE 7: Búsqueda inversa de red{NC}")
    print(f"{M}{'='*60}{NC}")
    log = os.path.join(outdir, "07_reversa.txt")

    # Rango /24 basado en la IP
    partes = ip.split(".")
    if len(partes) == 4:
        rango = f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
        if check_tool("dnsrecon"):
            run(["dnsrecon", "-r", rango, "-n", ip],
                outfile=log, timeout=300)
        else:
            print(f"{R}[!] dnsrecon no instalado{NC}")


# ----------------------------------------------------------
# Main
# ----------------------------------------------------------
def main():
    print(f"{B}{'='*60}{NC}")
    print(f"{B}   DNS Enumeration Auto-Tool{NC}")
    print(f"{B}{'='*60}{NC}\n")

    # Pedir IP del DNS
    ip = prompt("IP del servidor DNS (ej. 10.129.229.5):")
    if not ip:
        print(f"{R}[!] IP obligatoria.{NC}")
        sys.exit(1)

    # Dominio opcional
    dominio = prompt("Dominio (ej. snoopy.htb, deja vacío si no lo sabes):")
    dominio = dominio if dominio else None

    # Crear directorio de salida
    outdir = f"dnsenum_{ip}"
    os.makedirs(outdir, exist_ok=True)

    print(f"\n{G}[+] Target DNS: {ip}{NC}")
    print(f"{G}[+] Dominio:    {dominio or '(no especificado)'}{NC}")
    print(f"{G}[+] Output dir: {outdir}/{NC}")

    # -------- Ejecutar fases --------
    fase_axfr(ip, dominio, outdir)

    fase_basico(ip, dominio, outdir)

    if dominio:
        fase_dnsrecon(ip, dominio, outdir)
        fase_dnsenum(ip, dominio, outdir)
        fase_fierce(ip, dominio, outdir)
        fase_nse(ip, dominio, outdir)

    fase_reversa(ip, dominio, outdir)

    # -------- Resumen final --------
    print(f"\n{B}{'='*60}{NC}")
    print(f"{B}   RESUMEN FINAL{NC}")
    print(f"{B}{'='*60}{NC}")

    # Extraer TODOS los subdominios/hosts encontrados de todos los logs
    hallazgos = set()
    patron_dominio = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})')

    for archivo in os.listdir(outdir):
        path = os.path.join(outdir, archivo)
        if not os.path.isfile(path):
            continue
        with open(path, errors="ignore") as f:
            for linea in f:
                # Buscar hosts que contengan el dominio si lo tenemos
                if dominio and dominio in linea:
                    for m in patron_dominio.findall(linea):
                        if m.endswith(dominio) and len(m) > len(dominio):
                            hallazgos.add(m)

    if hallazgos:
        print(f"{G}[+] Posibles subdominios encontrados:{NC}")
        for h in sorted(hallazgos):
            print(f"    - {h}")
    else:
        print(f"{Y}[*] No se detectaron subdominios automáticamente.{NC}")
        print(f"{Y}    Revisa los logs manualmente en {outdir}/{NC}")

    print(f"\n{G}[✓] Todo listo. Archivos en: {outdir}/{NC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Cancelado por el usuario.{NC}")
        sys.exit(130)
```
