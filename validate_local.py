"""Validación local del conector tenable_sc (solo lectura por defecto).

Uso:
    python validate_local.py

Requiere RUVIC_TENABLE_SC_BASE_URL, RUVIC_TENABLE_SC_ACCESS_KEY y
RUVIC_TENABLE_SC_SECRET_KEY exportadas.
"""

from ruvic_tenable_sc_connector import TenableScClient, setup_logging

setup_logging("INFO")
client = TenableScClient()

print("== 0. Ping ==")
client.ping()

print("== 1. Vulnerabilidades críticas/altas ==")
for v in client.list_vulnerabilities(severity=["critical", "high"], limit=5):
    print(f"  {v['severity']} {v['plugin_id']} {v['name']} ({v['hosts']} activos)")

print("== 2. Activos más expuestos ==")
activos = client.list_assets(limit=5)
for a in activos:
    print(f"  {a['ip']} {a['dns']} críticas={a['critical']}")

print("== 3. Hallazgos del primer activo ==")
if activos:
    for h in client.get_findings(ip=activos[0]["ip"], limit=5):
        print(f"  {h['port']} {h['name']}")

print("== 4. Escaneos ==")
for s in client.list_scans()[:5]:
    print(f"  {s['id']} {s['name']}")

# == 5. Lanzar un escaneo (ESCRIBE): descomenta con un escaneo de prueba ==
# print(client.launch_scan(<id>))

print("\nTodo OK.")
