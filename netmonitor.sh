#!/bin/bash
# ============================================================
#   NET MONITOR — Monitor de Red en Bash
#   Autor: Kaleth Corcho | WolvesTI | 2026
#   Compatible: a-Shell (iOS/iPadOS)
#   Uso: bash netmonitor.sh
# ============================================================

# ── CONFIGURACION ─────────────────────────────────────────
INTERVALO=5
LOG_FILE="netmonitor_log.txt"

# ── FUNCIONES BASE ─────────────────────────────────────────

timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

hora() {
    date "+%H:%M:%S"
}

separador() {
    echo "=============================================="
}

linea() {
    echo "----------------------------------------------"
}

limpiar() {
    clear
}

# ── IP LOCAL ───────────────────────────────────────────────

get_ip_local() {
    # a-Shell usa ifconfig
    IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
    if [ -z "$IP" ]; then
        IP="No detectada"
    fi
    echo "$IP"
}

get_hostname() {
    HNAME=$(hostname 2>/dev/null)
    if [ -z "$HNAME" ]; then
        HNAME="iPhone/iPad"
    fi
    echo "$HNAME"
}

# ── HEADER ────────────────────────────────────────────────

mostrar_header() {
    separador
    echo "  NET MONITOR | WolvesTI 2026"
    separador
    echo "  Hora     : $(timestamp)"
    echo "  Host     : $(get_hostname)"
    echo "  IP Local : $(get_ip_local)"
    separador
}

# ── MODULO 1: INTERFACES DE RED ───────────────────────────

mostrar_interfaces() {
    limpiar
    separador
    echo "  INTERFACES DE RED ACTIVAS"
    separador
    echo ""

    ifconfig 2>/dev/null | while IFS= read -r linea_if; do
        echo "  $linea_if"
    done

    echo ""
    linea
    echo "  IPs detectadas:"
    ifconfig 2>/dev/null | grep "inet " | while read -r l; do
        IP_IF=$(echo "$l" | awk '{print $2}')
        MASK=$(echo "$l" | awk '{print $4}')
        echo "    IP   : $IP_IF"
        echo "    Mask : $MASK"
        linea
    done

    echo ""
    read -p "  [Enter] para volver..." dummy
}

# ── MODULO 2: CONEXIONES ACTIVAS ──────────────────────────

clasificar_puerto() {
    PUERTO=$1
    case $PUERTO in
        20|21)   echo "FTP" ;;
        22)      echo "SSH" ;;
        23)      echo "TELNET-RIESGO" ;;
        25)      echo "SMTP" ;;
        53)      echo "DNS" ;;
        80)      echo "HTTP" ;;
        443)     echo "HTTPS" ;;
        445)     echo "SMB-RIESGO" ;;
        3306)    echo "MySQL" ;;
        3389)    echo "RDP-RIESGO" ;;
        4444)    echo "METASPLOIT-CRITICO" ;;
        5555)    echo "ADB-RIESGO" ;;
        6666)    echo "BACKDOOR-CRITICO" ;;
        8080)    echo "HTTP-PROXY" ;;
        8443)    echo "HTTPS-ALT" ;;
        9090)    echo "WEBSHELL-CRITICO" ;;
        *)       echo "PUERTO-$PUERTO" ;;
    esac
}

mostrar_conexiones() {
    limpiar
    separador
    echo "  CONEXIONES DE RED ACTIVAS"
    separador
    echo ""

    RESULT=$(netstat -an 2>/dev/null)

    if [ -z "$RESULT" ]; then
        echo "  [WARN] netstat no disponible en este entorno."
        echo "  Usando alternativa con ifconfig..."
        echo ""
        ifconfig 2>/dev/null | grep -E "inet |status"
    else
        echo "  Proto  Local               Remoto              Estado"
        linea
        echo "$RESULT" | grep -E "^tcp|^udp|^TCP|^UDP" | while read -r linea_c; do
            PROTO=$(echo "$linea_c" | awk '{print $1}')
            LOCAL=$(echo "$linea_c" | awk '{print $4}')
            REMOTO=$(echo "$linea_c" | awk '{print $5}')
            ESTADO=$(echo "$linea_c" | awk '{print $6}')

            # Extraer puerto remoto
            PUERTO_R=$(echo "$REMOTO" | rev | cut -d'.' -f1 | rev 2>/dev/null)
            SERVICIO=$(clasificar_puerto "$PUERTO_R")

            # Marcar criticos
            if echo "$SERVICIO" | grep -q "CRITICO"; then
                PREFIJO="!! "
            elif echo "$SERVICIO" | grep -q "RIESGO"; then
                PREFIJO="!  "
            else
                PREFIJO="   "
            fi

            printf "${PREFIJO}%-6s %-20s %-20s %-12s %s\n" \
                "$PROTO" "$LOCAL" "$REMOTO" "$ESTADO" "$SERVICIO"
        done
    fi

    echo ""
    read -p "  [Enter] para volver..." dummy
}

# ── MODULO 3: ESCANEO DE PUERTOS LOCALES ─────────────────

escanear_puertos_locales() {
    limpiar
    separador
    echo "  ESCANEO DE PUERTOS LOCALES (127.0.0.1)"
    separador
    echo ""
    echo "  Escaneando puertos comunes..."
    echo ""

    PUERTOS="21 22 23 25 53 80 443 445 3306 3389 4444 5555 6666 8080 8443 9090"
    ABIERTOS=0

    for PUERTO in $PUERTOS; do
        # a-Shell tiene nc (netcat) disponible
        RESULTADO=$(nc -z -w1 127.0.0.1 "$PUERTO" 2>/dev/null && echo "ABIERTO" || echo "cerrado")

        if [ "$RESULTADO" = "ABIERTO" ]; then
            SERVICIO=$(clasificar_puerto "$PUERTO")
            ABIERTOS=$((ABIERTOS + 1))

            if echo "$SERVICIO" | grep -q "CRITICO"; then
                echo "  !! CRITICO  Puerto $PUERTO -> $SERVICIO"
            elif echo "$SERVICIO" | grep -q "RIESGO"; then
                echo "  !  RIESGO   Puerto $PUERTO -> $SERVICIO"
            else
                echo "     ABIERTO  Puerto $PUERTO -> $SERVICIO"
            fi
        fi
    done

    echo ""
    linea
    echo "  Total puertos abiertos detectados: $ABIERTOS"
    echo ""
    read -p "  [Enter] para volver..." dummy
}

# ── MODULO 4: PING Y CONECTIVIDAD ────────────────────────

test_conectividad() {
    limpiar
    separador
    echo "  TEST DE CONECTIVIDAD"
    separador
    echo ""

    HOSTS="8.8.8.8 1.1.1.1 google.com cloudflare.com"

    for HOST in $HOSTS; do
        echo -n "  Ping $HOST ... "
        RESULTADO=$(ping -c 1 -W 2 "$HOST" 2>/dev/null)
        if [ $? -eq 0 ]; then
            TIEMPO=$(echo "$RESULTADO" | grep "time=" | awk -F"time=" '{print $2}' | cut -d' ' -f1)
            echo "OK ($TIEMPO ms)"
        else
            echo "FALLO"
        fi
    done

    echo ""
    linea
    echo "  DNS Resolution:"
    for DOMINIO in google.com cloudflare.com; do
        echo -n "  $DOMINIO -> "
        IP_RES=$(nslookup "$DOMINIO" 2>/dev/null | grep "Address" | tail -1 | awk '{print $2}')
        if [ -z "$IP_RES" ]; then
            # Fallback con host
            IP_RES=$(host "$DOMINIO" 2>/dev/null | grep "has address" | head -1 | awk '{print $4}')
        fi
        if [ -z "$IP_RES" ]; then
            echo "No resuelto"
        else
            echo "$IP_RES"
        fi
    done

    echo ""
    read -p "  [Enter] para volver..." dummy
}

# ── MODULO 5: MONITOR CONTINUO ────────────────────────────

monitor_continuo() {
    limpiar
    echo ""
    echo "  Monitor continuo activo. Ctrl+C para detener."
    echo "  Intervalo: ${INTERVALO}s"
    echo ""
    sleep 1

    while true; do
        limpiar
        mostrar_header

        echo ""
        echo "  CONEXIONES ACTIVAS:"
        linea

        CONNS=$(netstat -an 2>/dev/null | grep -E "^tcp|^udp" | wc -l | tr -d ' ')
        echo "  Total detectadas: $CONNS"

        # Mostrar solo establecidas
        ESTAB=$(netstat -an 2>/dev/null | grep "ESTABLISHED" | wc -l | tr -d ' ')
        echo "  Establecidas    : $ESTAB"

        # Buscar puertos críticos activos
        echo ""
        echo "  Revisando puertos criticos..."
        for PCRIT in 4444 6666 9090 23 445 3389 5555; do
            SERVICIO=$(clasificar_puerto "$PCRIT")
            if netstat -an 2>/dev/null | grep -q ":$PCRIT "; then
                echo "  !! ALERTA: Puerto $PCRIT ($SERVICIO) ACTIVO"
                echo "  [$(hora)] ALERTA Puerto $PCRIT $SERVICIO" >> "$LOG_FILE"
            fi
        done

        echo ""
        echo "  IP Local: $(get_ip_local)"
        echo "  Siguiente scan en ${INTERVALO}s... (Ctrl+C para salir)"

        sleep "$INTERVALO"
    done
}

# ── MODULO 6: GUARDAR LOG ─────────────────────────────────

guardar_reporte() {
    limpiar
    separador
    echo "  GENERANDO REPORTE"
    separador
    echo ""

    {
        echo "================================================"
        echo "  NET MONITOR REPORT | WolvesTI 2026"
        echo "  Fecha: $(timestamp)"
        echo "================================================"
        echo ""
        echo "HOSTNAME: $(get_hostname)"
        echo "IP LOCAL: $(get_ip_local)"
        echo ""
        echo "--- INTERFACES ---"
        ifconfig 2>/dev/null
        echo ""
        echo "--- CONEXIONES ---"
        netstat -an 2>/dev/null || echo "netstat no disponible"
        echo ""
        echo "================================================"
    } >> "$LOG_FILE"

    echo "  Reporte guardado en: $LOG_FILE"
    echo ""
    read -p "  [Enter] para volver..." dummy
}

# ── MENU PRINCIPAL ────────────────────────────────────────

menu_principal() {
    while true; do
        limpiar
        separador
        echo "  NET MONITOR | WolvesTI | a-Shell"
        separador
        echo "  IP: $(get_ip_local)"
        echo ""
        echo "  [1] Ver interfaces de red"
        echo "  [2] Ver conexiones activas"
        echo "  [3] Escanear puertos locales"
        echo "  [4] Test de conectividad (ping/DNS)"
        echo "  [5] Monitor continuo"
        echo "  [6] Guardar reporte"
        echo "  [0] Salir"
        separador
        echo ""
        read -p "  Opcion: " OPCION

        case $OPCION in
            1) mostrar_interfaces ;;
            2) mostrar_conexiones ;;
            3) escanear_puertos_locales ;;
            4) test_conectividad ;;
            5) monitor_continuo ;;
            6) guardar_reporte ;;
            0)
                echo ""
                echo "  Saliendo... Bye."
                echo ""
                exit 0
                ;;
            *)
                echo "  Opcion invalida."
                sleep 1
                ;;
        esac
    done
}

# ── ENTRY POINT ───────────────────────────────────────────
menu_principal









Listo para bash de script. Para ejecutarlo en a-Shell:
bash# Dar permisos y correr
chmod +x netmonitor.sh
bash netmonitor.sh
6 módulos disponibles:

Interfaces de red — ifconfigcompleto con IPs y máscaras
Conexiones activas — netstat -ancon clasificación de puertos y alertas !!para críticos
Escaneo de puertos locales — usa nc(netcat, disponible en a-Shell) para verificar 16 puertos comunes
Prueba de conectividad : ping a 4 hosts + resolución DNS
Monitor continuo — refresco cada 5s, detecta puertos críticos activos y guarda alertas en log automáticamente
Guardar informe — exportar todo anetmonitor_log.txt

Solo usa comandos nativos de a-Shell: ifconfig, netstat, nc, ping, hostname— sin dependencias externas.