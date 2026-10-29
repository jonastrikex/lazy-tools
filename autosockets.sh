
```
#!/bin/bash
# enum_sockets_v2.sh - Enumerar sockets y analizar cada uno
# Uso: ./enum_sockets_v2.sh [archivo_salida]

OUTFILE="${1:-/tmp/sockets_enum_$(date +%s).txt}"
INTERESTING_FILTER="php|fpm|docker|mysql|redis|postgres|gromox|supervisor|mongo|memcache|tomcat|nodejs|sockd|fastcgi|zcore"

# --- 1. Detectar herramienta ---
if command -v ss >/dev/null 2>&1; then
    ss -xlp > "$OUTFILE" 2>/dev/null
    TOOL="ss -xlp"
elif command -v netstat >/dev/null 2>&1; then
    netstat -xlnp > "$OUTFILE" 2>/dev/null
    TOOL="netstat -xlnp"
else
    cp /proc/net/unix "$OUTFILE" 2>/dev/null
    TOOL="/proc/net/unix"
fi

echo "[*] Herramienta: $TOOL"
echo "[*] Resultados crudos en: $OUTFILE"
echo ""

# --- 2. Extraer rutas ---
PATHS=$(grep -oE '/[^ ]+' "$OUTFILE" | sort -u)

echo "=========================================="
echo " ANÁLISIS DE CADA SOCKET"
echo "=========================================="
echo ""

while IFS= read -r sock; do
    [ -z "$sock" ] && continue
    [ ! -S "$sock" ] && continue
    
    # ls -la (como pediste)
    echo "=== $sock ==="
    ls -la "$sock" 2>/dev/null
    
    # Permisos y dueño
    perms=$(stat -c "%a" "$sock" 2>/dev/null)
    owner=$(stat -c "%U:%G" "$sock" 2>/dev/null)
    
    # Determinar si es writable por "otros"
    if [ $((perms % 10 & 2)) -ne 0 ]; then
        echo "  → [PELIGROSO] World-writable (otros pueden escribir)"
    else
        echo "  → [OK] No world-writable"
    fi
    
    # Proceso dueño
    proc=$(ss -xlp 2>/dev/null | grep -F "$sock" | grep -oE 'users:\(\("[^"]+' | head -1 | sed 's/users:(("//')
    echo "  → Proceso: ${proc:-N/A}"
    echo "  → Owner: $owner  Perms: $perms"
    
    # Intentar cat (para ver qué devuelve el kernel)
    echo "  → cat (primeros bytes):"
    timeout 1 cat "$sock" 2>&1 | head -c 80 | sed 's/^/     /'
    echo ""
    echo ""
done <<< "$PATHS"

# --- 3. Resumen final: solo los world-writable ---
echo "=========================================="
echo " RESUMEN: SOLO WORLD-WRITABLE"
echo "=========================================="

WW_COUNT=0
while IFS= read -r sock; do
    [ -z "$sock" ] && continue
    [ ! -S "$sock" ] && continue
    perms=$(stat -c "%a" "$sock" 2>/dev/null)
    if [ $((perms % 10 & 2)) -ne 0 ]; then
        owner=$(stat -c "%U:%G" "$sock" 2>/dev/null)
        printf "  %-50s [%s] owner=%s\n" "$sock" "$perms" "$owner"
        WW_COUNT=$((WW_COUNT + 1))
    fi
done <<< "$PATHS"

echo ""
echo "[*] Total sockets world-writable: $WW_COUNT"
echo ""

# --- 4. Filtro por nombre (interesantes) ---
echo "=========================================="
echo " INTERESANTES (filtro por nombre)"
echo "=========================================="
echo ""
while IFS= read -r sock; do
    [ -z "$sock" ] && continue
    [ ! -S "$sock" ] && continue
    if echo "$sock" | grep -qiE "$INTERESTING_FILTER"; then
        ls -la "$sock" 2>/dev/null
        echo ""
    fi
done <<< "$PATHS"

echo "[*] Fin."

```
