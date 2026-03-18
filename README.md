<div align="center">
 
```
███╗   ██╗███████╗████████╗    ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝    ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║       ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
██║╚██╗██║██╔══╝     ██║       ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
██║ ╚████║███████╗   ██║       ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```
 
# 📡 Net Monitor
### Monitor de Conexiones de Red para a-Shell (iOS/iPadOS)
 
**Herramienta de análisis de tráfico de red en tiempo real.**  
Detecta conexiones sospechosas, clasifica puertos por nivel de riesgo  
y exporta alertas — todo desde tu iPhone o iPad.
 
---
 
[![Python](https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-a--Shell_iOS-black?style=for-the-badge&logo=apple&logoColor=white)](https://holzschu.github.io/a-Shell_iOS/)
[![Security](https://img.shields.io/badge/Categoría-Blue_Team-0077ff?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/)
[![Deps](https://img.shields.io/badge/Dependencias-Ninguna-00c853?style=for-the-badge)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge)](LICENSE)
 
</div>
 
---
 
## 📱 ¿Qué es Net Monitor?
 
**Net Monitor** es un script Python para **a-Shell** que convierte tu iPhone o iPad en una herramienta de análisis de red. Monitorea conexiones activas, detecta puertos peligrosos y te alerta en tiempo real — sin necesidad de instalar ninguna librería externa.
 
```
iPhone/iPad con a-Shell
         │
         ▼
   netmonitor.py
         │
    ┌────┴────┐
    │ netstat │ ← fuente principal
    └────┬────┘
         │ (si falla)
    ┌────┴────┐
    │ socket  │ ← fallback automático
    └────┬────┘
         │
    ┌────▼──────────────────────────┐
    │  Clasificación de riesgo      │
    │  INFO / BAJO / MEDIO /        │
    │  ALTO / CRITICO               │
    └────┬──────────────────────────┘
         │
    ┌────▼──────────────────────────┐
    │  Terminal + Log exportable    │
    └───────────────────────────────┘
```
 
---
 
## 🚀 Instalación y uso
 
```bash
# No requiere instalación de librerías
# Solo descarga el archivo y ejecuta:
 
python3 netmonitor.py
```
 
> ✅ **Sin dependencias externas** — usa únicamente la librería estándar de Python.  
> Compatible con **a-Shell** y **a-Shell mini** en iOS/iPadOS.
 
---
 
## 🎛️ Modos disponibles
 
```
==================================================
  NET MONITOR | WolvesTI | a-Shell
==================================================
  IP: 192.168.1.10
 
  [1] Escaneo único
  [2] Monitor continuo (cada 5s)
  [3] Solo conexiones de riesgo
  [4] Guardar log de sesión
  [5] Info del dispositivo
  [0] Salir
==================================================
```
 
| Modo | Función | Output |
|------|---------|--------|
| `1` **Escaneo único** | Snapshot de todas las conexiones activas | Terminal |
| `2` **Monitor continuo** | Refresco automático cada 5 segundos | Terminal en vivo |
| `3` **Filtro de riesgo** | Muestra solo ALTO y CRÍTICO | Terminal filtrado |
| `4` **Guardar log** | Exporta alertas a `netmonitor_log.txt` | Archivo de texto |
| `5` **Info del dispositivo** | IP local, hostname e interfaces | Terminal |
 
---
 
## 🚨 Clasificación de riesgo
 
El script evalúa automáticamente cada conexión y le asigna un nivel de riesgo:
 
| Nivel | Prefijo | Descripción |
|-------|---------|-------------|
| ✅ **INFO** | `   ` | Puertos estándar sin riesgo conocido |
| 🔵 **BAJO** | `   ` | Puertos del sistema sin amenaza activa |
| 🟡 **MEDIO** | `   ` | Servicios comunes que merecen atención |
| 🟠 **ALTO** | `!  ` | Servicios potencialmente explotables |
| 🔴 **CRÍTICO** | `!! ` | Puertos asociados a ataques activos |
 
### Puertos monitoreados
 
```
CRÍTICO  !! ───────────────────────────────────────────
  4444   Metasploit reverse shell
  6666   Backdoor / IRC malicioso
  9090   Webshell
  23     Telnet — protocolo inseguro sin cifrado
  445    SMB — EternalBlue / ransomware
  3389   RDP — ataques de fuerza bruta
  5555   ADB Android — acceso remoto
 
ALTO     !  ────────────────────────────────────────────
  1433   MSSQL
  3306   MySQL expuesto
  8080   HTTP Proxy
  8443   HTTPS alternativo
 
MEDIO       ────────────────────────────────────────────
  21     FTP
  22     SSH
  25     SMTP
  53     DNS
  80     HTTP
  443    HTTPS
```
 
---
 
## 🖥️ Demo de salida
 
```bash
# Escaneo único
============================================================
  NET MONITOR | WolvesTI 2026
============================================================
  Hora     : 2026-03-18 19:23:44
  Host     : iPhone-Kaleth
  IP Local : 192.168.1.10
  Conexiones: 8
  Críticas  : 1
============================================================
 
  Proto  Local               Remoto              Estado       Riesgo   Servicio
  ─────────────────────────────────────────────────────────────────────────────
!!  TCP    192.168.1.10:52341  203.0.113.99:4444   ESTABLISHED  CRITICO  Metasploit
!   TCP    192.168.1.10:63210  52.88.0.14:3389     ESTABLISHED  ALTO     RDP-RIESGO
    TCP    192.168.1.10:49823  172.217.0.1:443     ESTABLISHED  MEDIO    HTTPS
    TCP    192.168.1.10:51902  8.8.8.8:53          TIME_WAIT    MEDIO    DNS
    TCP    0.0.0.0:22          0.0.0.0:*           LISTEN       MEDIO    SSH
```
 
```bash
# Monitor continuo — detección de nueva conexión
  ⚡ Monitor activo. Intervalo: 5s
  Ctrl+C para detener.
 
  [NUEVO] 1 conexión(es) nueva(s) detectada(s)
 
  !! ALERTA: 203.0.113.99:4444 — Metasploit reverse shell
  !! ALERTA: Puerto CRÍTICO activo — Revisar inmediatamente
```
 
```bash
# Log exportado
  [LOG] Guardado en netmonitor_log.txt
 
# Contenido del log:
[2026-03-18 19:23:44] SCAN
  [CRITICO] TCP 192.168.1.10:52341 -> 203.0.113.99:4444 (ESTABLISHED) 19:23:44
  [ALTO]    TCP 192.168.1.10:63210 -> 52.88.0.14:3389   (ESTABLISHED) 19:23:44
```
 
---
 
## 🔧 Arquitectura técnica
 
```
netmonitor.py
│
├── obtener_ip_local()         → socket UDP a 8.8.8.8
├── obtener_hostname()         → socket.gethostname()
│
├── obtener_conexiones_netstat()
│   └── subprocess("netstat -an")
│       └── [falla] → obtener_conexiones_socket_fallback()
│                      └── nc/socket en puertos conocidos
│
├── clasificar_riesgo(puerto)
│   └── CRITICO / ALTO / MEDIO / BAJO / INFO
│
├── detectar_nuevas(actuales, previas)
│   └── diff de conjuntos por ID de conexión
│
└── modos/
    ├── escaneo_unico()
    ├── monitor_continuo()     → threading.Thread
    ├── filtro_riesgo()
    ├── guardar_log()          → append a .txt
    └── info_dispositivo()
```
 
---
 
## 📂 Estructura del proyecto
 
```
net-monitor/
│
├── 📄 netmonitor.py        # Script principal
├── 📄 README.md            # Documentación
└── 📄 netmonitor_log.txt   # Log generado automáticamente (sesión)
```
 
---
 
## 🔬 Conceptos de seguridad aplicados
 
| Concepto | Implementación |
|----------|----------------|
| **Port scanning** | Análisis de puertos abiertos y estados |
| **Risk classification** | Categorización por nivel de amenaza |
| **Anomaly detection** | Detección de conexiones nuevas por diff |
| **Logging** | Exportación de alertas para análisis forense |
| **Fallback resilience** | Degradación elegante si netstat no está disponible |
 
---
 
## ⚠️ Consideraciones
 
```
✅  Usar únicamente en tu propia red o con autorización
✅  Ideal para aprendizaje de Blue Team y monitoreo personal
✅  Compatible con a-Shell y a-Shell mini (iOS/iPadOS)
❌  No reemplaza un IDS/IPS profesional en producción
❌  No ejecutar contra redes de terceros sin permiso
```
 
---
 
## 👤 Autor
 
**Kaleth Corcho**  
Ingeniería de Sistemas · WolvesTI · Bogotá, Colombia
 
[![LinkedIn](https://img.shields.io/badge/LinkedIn-kaleth--corcho-0077B5?style=flat&logo=linkedin)](https://linkedin.com)
[![GitHub](https://img.shields.io/badge/GitHub-kaleth4-181717?style=flat&logo=github)](https://github.com/kaleth4)
 
---
 
<div align="center">
 
**⭐ Si este proyecto te fue útil, dale una estrella**
 
*Herramienta de red para a-Shell · Blue Team · 2026 · WolvesTI*
 
</div>
