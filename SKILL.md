---
name: tenable-sc
description: >
  Usa la librería ruvic_tenable_sc_connector para gestionar
  vulnerabilidades en Tenable Security Center (on-premise) - listar
  vulnerabilidades por plugin (list_vulnerabilities), consultar activos con
  su exposición (list_assets), consultar hallazgos por host o plugin
  (get_findings), listar escaneos (list_scans) y lanzar un escaneo ya
  definido (launch_scan). Úsala cuando el usuario pregunte por
  vulnerabilidades, activos expuestos o escaneos en Tenable.sc / Security
  Center. Para Tenable Vulnerability Management (cloud) usa el conector
  tenable_nessus (CON-051).
triggers:
- tenable
- security center
- tenable.sc
- vulnerabilidades
- escaneo de vulnerabilidades
- nessus
- activos expuestos
---

# Conector Tenable Security Center (ruvic_tenable_sc_connector)

Librería Python para la API REST de Tenable Security Center. Está **preinstalada en el runtime** cuando el
conector está configurado (si no, instálala con
`pip install git+https://github.com/RuvicDev/CON-090-Tenable-Security-Center.git#subdirectory=lib`).

## Regla crítica de credenciales

El código generado **NUNCA hardcodea credenciales**. Siempre se leen de
variables de entorno, disponibles cuando el conector `tenable_sc` está
configurado:

| Variable | Contenido |
|----------|-----------|
| `RUVIC_TENABLE_SC_BASE_URL` | URL de Tenable Security Center |
| `RUVIC_TENABLE_SC_ACCESS_KEY` | Access Key |
| `RUVIC_TENABLE_SC_SECRET_KEY` | Secret Key |
| `RUVIC_TENABLE_SC_VERIFY_SSL` | (opcional) Verificar certificado SSL, default true |
| `RUVIC_TENABLE_SC_CONNECT_TIMEOUT` | (opcional) Timeout de conexión (segundos), default 30 |

Si estas variables NO existen, el conector no está configurado: no
generes código que lo use; indica al usuario que lo configure en
**Settings → Conectores**. El código generado **NUNCA** usa nombres con
segmento de alias (`_DEFAULT_INSTANCIA_`, `_PRODUCCION_`, etc.) salvo que
aparezcan en una sección autogenerada `## Variables en tu entorno` al final
de este skill.

## Lanzar un escaneo es una acción real

Las consultas son de solo lectura. `launch_scan` **SÍ ejecuta** un escaneo
real contra la red definida en ese escaneo: genera tráfico y carga en los
equipos. Lánzalo solo si el usuario lo pide y confirma antes cuál
(nombre e ID de `list_scans`). El conector no crea ni modifica escaneos.

## Conexión (siempre igual)

```python
from ruvic_tenable_sc_connector import TenableScClient

client = TenableScClient()  # lee RUVIC_TENABLE_SC_* del entorno automáticamente
```

## Capacidad 1 — Listar vulnerabilidades

```python
vulns = client.list_vulnerabilities(severity=["critical", "high"], exploit_available=True, limit=20)
for v in vulns:
    print(v["severity"], v["plugin_id"], v["name"], f"{v['hosts']} activos")
```

Severidades: `critical`, `high`, `medium`, `low`, `info` (una o una lista).

## Capacidad 2 — Consultar activos

```python
activos = client.list_assets(ip_range="10.0.0.0/24", limit=20)
for a in activos:
    print(a["ip"], a["dns"], "críticas:", a["critical"], "altas:", a["high"])
```

## Capacidad 3 — Consultar hallazgos

```python
hallazgos = client.get_findings(ip="10.0.0.5", severity="critical")
for h in hallazgos:
    print(h["port"], h["plugin_id"], h["name"], h["last_seen"])
```

## Capacidad 4 — Listar y lanzar escaneos

```python
for s in client.list_scans():
    print(s["id"], s["name"], s["repository"])
resultado = client.launch_scan(12)
print(resultado["scan_result_id"], resultado["status"])
```

## Manejo de errores

```python
from ruvic_tenable_sc_connector import (
    TenableScAuthError, TenableScDataError, TenableScNetworkError,
)

try:
    client.list_vulnerabilities(severity="critical")
except TenableScAuthError as e:
    print(f"Credenciales o permisos: {e}")
except TenableScNetworkError as e:
    print(f"No se pudo alcanzar el servicio: {e}")
except TenableScDataError as e:
    print(f"Error de datos: {e}")
```

Muestra el mensaje de la excepción tal cual al usuario: indica qué corregir.

## Buenas prácticas al generar código

1. Lee credenciales SOLO de las variables `RUVIC_TENABLE_SC_*` (el constructor de `TenableScClient` ya lo hace).
2. Nunca imprimas `RUVIC_TENABLE_SC_ACCESS_KEY` ni `RUVIC_TENABLE_SC_SECRET_KEY`.
3. Filtra por severidad o rango de IP: los resultados completos pueden tener miles de filas.
4. Antes de `launch_scan`, muestra el nombre del escaneo y pide confirmación.
5. Para Tenable en la nube (cloud.tenable.com) no uses este conector: usa tenable_nessus (CON-051).
