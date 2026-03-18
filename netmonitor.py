#!/usr/bin/env python3
# ============================================================
#   NET MONITOR — Monitor de Conexiones Activas
#   Autor: Kaleth Corcho | WolvesTI | 2026
#   Compatible: a-Shell (iOS/iPadOS) + Python 3
#   Uso: python3 netmonitor.py
# ============================================================

import socket
import subprocess
import time
import os
from datetime import datetime

# ── CONFIGURACIÓN ────────────────────────────────────────────
INTERVALO_SCAN   = 5       # Segundos entre cada escaneo
MAX_HISTORIAL    = 50      # Máximo de conexiones en historial
PUERTOS_RIESGO   = {
    20:   "FTP Data",
    21:   "FTP Control",
    22:   "SSH",
    23:   "Telnet (INSEGURO)",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    443:  "HTTPS",
    445:  "SMB (RIESGO)",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP (RIESGO)",
    4444: "Metasploit (CRITICO)",
    5555: "ADB Android (RIESGO)",
    6666: "IRC/Backdoor (CRITICO)",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    9090: "Webshell (RIESGO)",
}

PUERTOS_CRITICOS = {4444, 6666, 9090, 23, 445, 3389, 5555}

historial_conexiones = []
conexiones_previas   = set()


# ── UTILIDADES ───────────────────────────────────────────────
def limpiar_pantalla():
    os.system('clear')


def timestamp():
    return datetime.now().strftime("%H:%M:%S")


def fecha_completa():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def evaluar_riesgo(puerto):
    """Evalúa el nivel de riesgo de un puerto."""
    if puerto in PUERTOS_CRITICOS:
        return "CRITICO"
    if puerto in PUERTOS_RIESGO:
        nombre = PUERTOS_RIESGO[puerto]
        if "RIESGO" in nombre or "INSEGURO" in nombre:
            return "ALTO"
        return "MEDIO"
    if puerto < 1024:
        return "BAJO"
    return "INFO"


def nombre_puerto(puerto):
    """Retorna nombre descriptivo del puerto."""
    return PUERTOS_RIESGO.get(puerto, f"Puerto {puerto}")


# ── OBTENER IP LOCAL ─────────────────────────────────────────
def obtener_ip_local():
    """Obtiene la IP local del dispositivo."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "No disponible"


# ── OBTENER HOSTNAME ─────────────────────────────────────────
def obtener_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "Desconocido"


# ── ESCANEAR CONEXIONES VÍA netstat ──────────────────────────
def obtener_conexiones_netstat():
    """
    Obtiene conexiones activas usando netstat.
    Compatible con a-Shell en iOS.
    """
    conexiones = []
    try:
        resultado = subprocess.run(
            ["netstat", "-an"],
            capture_output=True,
            text=True,
            timeout=10
        )
        lineas = resultado.stdout.splitlines()

        for linea in lineas:
            linea = linea.strip()
            if not linea:
                continue
            if linea.startswith(("tcp", "udp", "TCP", "UDP")):
                partes = linea.split()
                if len(partes) >= 5:
                    protocolo    = partes[0].upper()
                    local_addr   = partes[3] if len(partes) > 3 else "?"
                    foreign_addr = partes[4] if len(partes) > 4 else "?"
                    estado       = partes[5] if len(partes) > 5 else "?"

                    # Extraer puerto local
                    try:
                        puerto_local = int(local_addr.split(".")[-1])
                    except (ValueError, IndexError):
                        try:
                            puerto_local = int(local_addr.split(":")[-1])
                        except (ValueError, IndexError):
                            puerto_local = 0

                    # Extraer puerto remoto
                    try:
                        puerto_remoto = int(foreign_addr.split(".")[-1])
                    except (ValueError, IndexError):
                        try:
                            puerto_remoto = int(foreign_addr.split(":")[-1])
                        except (ValueError, IndexError):
                            puerto_remoto = 0

                    conexiones.append({
                        "protocolo":    protocolo,
                        "local":        local_addr,
                        "remoto":       foreign_addr,
                        "estado":       estado,
                        "puerto_local": puerto_local,
                        "puerto_remoto": puerto_remoto,
                        "riesgo":       evaluar_riesgo(puerto_remoto) if puerto_remoto else evaluar_riesgo(puerto_local),
                        "timestamp":    timestamp(),
                    })

    except FileNotFoundError:
        conexiones = obtener_conexiones_socket_fallback()
    except Exception as e:
        print(f"[ERROR] No se pudo ejecutar netstat: {e}")

    return conexiones


# ── FALLBACK: ESCANEO DE PUERTOS LOCALES ─────────────────────
def obtener_conexiones_socket_fallback():
    """
    Fallback si netstat no está disponible.
    Escanea puertos comunes en localhost.
    """
    conexiones = []
    puertos_a_escanear = list(PUERTOS_RIESGO.keys()) + [
        8000, 8888, 9000, 5000, 3000, 27017
    ]

    for puerto in puertos_a_escanear:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            resultado = s.connect_ex(("127.0.0.1", puerto))
            s.close()
            if resultado == 0:
                conexiones.append({
                    "protocolo":     "TCP",
                    "local":         f"127.0.0.1:{puerto}",
                    "remoto":        "localhost",
                    "estado":        "LISTEN",
                    "puerto_local":  puerto,
                    "puerto_remoto": 0,
                    "riesgo":        evaluar_riesgo(puerto),
                    "timestamp":     timestamp(),
                })
        except Exception:
            pass

    return conexiones


# ── RESOLVER IP ───────────────────────────────────────────────
def resolver_hostname(ip):
    """Intenta resolver el hostname de una IP."""
    try:
        ip_limpia = ip.split(":")[0].split(".")[:-1]
        ip_limpia = ".".join(ip_limpia) if len(ip_limpia) >= 3 else ip
        resultado = socket.gethostbyaddr(ip_limpia)
        return resultado[0]
    except Exception:
        return None


# ── DETECTAR NUEVAS CONEXIONES ────────────────────────────────
def detectar_nuevas(conexiones_actuales, previas):
    """Detecta conexiones nuevas comparando con el estado anterior."""
    ids_actuales = {
        f"{c['protocolo']}:{c['local']}:{c['remoto']}"
        for c in conexiones_actuales
    }
    nuevas = ids_actuales - previas
    return nuevas, ids_actuales


# ── MOSTRAR HEADER ────────────────────────────────────────────
def mostrar_header(ip_local, hostname, total_conn, criticas):
    print("=" * 60)
    print("  NET MONITOR — Monitor de Conexiones | WolvesTI 2026")
    print("=" * 60)
    print(f"  Hora          : {fecha_completa()}")
    print(f"  Hostname      : {hostname}")
    print(f"  IP Local      : {ip_local}")
    print(f"  Conexiones    : {total_conn}")
    print(f"  Criticas      : {criticas}")
    print("=" * 60)


# ── MOSTRAR CONEXIONES ────────────────────────────────────────
def mostrar_conexiones(conexiones, solo_riesgo=False):
    """Muestra las conexiones en formato tabla de texto."""
    if not conexiones:
        print("\n  [OK] Sin conexiones activas detectadas.\n")
        return

    # Ordenar: críticas primero
    orden_riesgo = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3, "INFO": 4}
    conexiones_ordenadas = sorted(
        conexiones,
        key=lambda x: orden_riesgo.get(x["riesgo"], 5)
    )

    print(f"\n  {'PROTO':<6} {'LOCAL':<22} {'REMOTO':<22} {'ESTADO':<12} {'RIESGO':<8} {'SERVICIO'}")
    print("  " + "-" * 85)

    for c in conexiones_ordenadas:
        if solo_riesgo and c["riesgo"] in ("INFO", "BAJO"):
            continue

        riesgo  = c["riesgo"]
        prefijo = "  "
        if riesgo == "CRITICO":
            prefijo = "!!"
        elif riesgo == "ALTO":
            prefijo = "! "

        servicio = nombre_puerto(c["puerto_remoto"]) if c["puerto_remoto"] else nombre_puerto(c["puerto_local"])

        local_str  = c["local"][:21]
        remoto_str = c["remoto"][:21]
        estado_str = c["estado"][:11]

        print(f"{prefijo}  {c['protocolo']:<6} {local_str:<22} {remoto_str:<22} {estado_str:<12} {riesgo:<8} {servicio}")

    print()


# ── MOSTRAR ALERTAS ───────────────────────────────────────────
def mostrar_alertas(conexiones):
    """Muestra solo conexiones críticas como alertas."""
    criticas = [c for c in conexiones if c["riesgo"] in ("CRITICO", "ALTO")]
    if not criticas:
        return

    print("  *** ALERTAS DE SEGURIDAD ***")
    print("  " + "-" * 40)
    for c in criticas:
        servicio = nombre_puerto(c["puerto_remoto"]) if c["puerto_remoto"] else nombre_puerto(c["puerto_local"])
        print(f"  [{c['riesgo']}] {c['protocolo']} | {c['remoto']} | {servicio} | {c['timestamp']}")
    print()


# ── GUARDAR LOG ───────────────────────────────────────────────
def guardar_log(conexiones, archivo="netmonitor_log.txt"):
    """Guarda las conexiones detectadas en un archivo de log."""
    try:
        with open(archivo, "a") as f:
            f.write(f"\n[{fecha_completa()}] SCAN\n")
            for c in conexiones:
                if c["riesgo"] in ("CRITICO", "ALTO"):
                    f.write(
                        f"  [{c['riesgo']}] {c['protocolo']} "
                        f"{c['local']} -> {c['remoto']} "
                        f"({c['estado']}) {c['timestamp']}\n"
                    )
        print(f"  [LOG] Guardado en {archivo}")
    except Exception as e:
        print(f"  [ERROR] No se pudo guardar log: {e}")


# ── MENU PRINCIPAL ────────────────────────────────────────────
def mostrar_menu():
    print("\n  OPCIONES:")
    print("  [1] Escaneo unico")
    print("  [2] Monitor continuo (cada 5s)")
    print("  [3] Solo conexiones de riesgo")
    print("  [4] Guardar log de sesion")
    print("  [5] Info del dispositivo")
    print("  [0] Salir")
    print()
    return input("  Selecciona: ").strip()


def info_dispositivo():
    """Muestra información del dispositivo."""
    print("\n" + "=" * 40)
    print("  INFO DEL DISPOSITIVO")
    print("=" * 40)
    print(f"  Hostname  : {obtener_hostname()}")
    print(f"  IP Local  : {obtener_ip_local()}")
    try:
        resultado = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        lineas = [l for l in resultado.stdout.splitlines() if "inet " in l]
        for l in lineas[:5]:
            print(f"  Interface : {l.strip()}")
    except Exception:
        pass
    print("=" * 40 + "\n")


# ── ENTRY POINT ───────────────────────────────────────────────
def main():
    ip_local = obtener_ip_local()
    hostname  = obtener_hostname()
    log_sesion = []

    limpiar_pantalla()
    print("\n  Iniciando Net Monitor...")
    print(f"  IP detectada: {ip_local}")
    time.sleep(1)

    while True:
        limpiar_pantalla()
        opcion = mostrar_menu()

        # ── ESCANEO ÚNICO ─────────────────────────────
        if opcion == "1":
            limpiar_pantalla()
            print("\n  Escaneando conexiones...\n")
            conexiones = obtener_conexiones_netstat()
            criticas = len([c for c in conexiones if c["riesgo"] in ("CRITICO", "ALTO")])
            mostrar_header(ip_local, hostname, len(conexiones), criticas)
            mostrar_alertas(conexiones)
            mostrar_conexiones(conexiones)
            log_sesion.extend(conexiones)
            input("  [Enter] para volver al menu...")

        # ── MONITOR CONTINUO ──────────────────────────
        elif opcion == "2":
            print(f"\n  Monitor activo. Intervalo: {INTERVALO_SCAN}s")
            print("  Presiona Ctrl+C para detener.\n")
            time.sleep(1)
            previas = set()
            try:
                while True:
                    conexiones = obtener_conexiones_netstat()
                    nuevas, previas = detectar_nuevas(conexiones, previas)
                    criticas = len([c for c in conexiones if c["riesgo"] in ("CRITICO", "ALTO")])

                    limpiar_pantalla()
                    mostrar_header(ip_local, hostname, len(conexiones), criticas)

                    if nuevas:
                        print(f"  [NUEVO] {len(nuevas)} conexion(es) nueva(s) detectada(s)")

                    mostrar_alertas(conexiones)
                    mostrar_conexiones(conexiones)
                    log_sesion.extend(conexiones)
                    time.sleep(INTERVALO_SCAN)

            except KeyboardInterrupt:
                print("\n  Monitor detenido.\n")
                time.sleep(1)

        # ── SOLO RIESGO ───────────────────────────────
        elif opcion == "3":
            limpiar_pantalla()
            print("\n  Filtrando conexiones de riesgo...\n")
            conexiones = obtener_conexiones_netstat()
            criticas = len([c for c in conexiones if c["riesgo"] in ("CRITICO", "ALTO")])
            mostrar_header(ip_local, hostname, len(conexiones), criticas)
            mostrar_conexiones(conexiones, solo_riesgo=True)
            if criticas == 0:
                print("  [OK] No se detectaron conexiones de riesgo.\n")
            input("  [Enter] para volver al menu...")

        # ── GUARDAR LOG ───────────────────────────────
        elif opcion == "4":
            if log_sesion:
                guardar_log(log_sesion)
            else:
                print("  [INFO] Ejecuta un escaneo primero.")
            time.sleep(1.5)

        # ── INFO DISPOSITIVO ──────────────────────────
        elif opcion == "5":
            info_dispositivo()
            input("  [Enter] para volver al menu...")

        # ── SALIR ─────────────────────────────────────
        elif opcion == "0":
            print("\n  Saliendo... Bye.\n")
            break

        else:
            print("  Opcion invalida.")
            time.sleep(1)


if __name__ == "__main__":
    main()