# Conector Tenable Security Center (CON-090)

Conector Ruvic para Tenable Security Center (on-premise): vulnerabilidades, activos, hallazgos y escaneos. Complementa al CON-051, que apunta a Tenable Vulnerability Management en la nube.

## Instalación

```bash
pip install git+https://github.com/RuvicDev/CON-090-Tenable-Security-Center.git#subdirectory=lib
```

Python 3.10+. Dependencias: `requests>=2.31,<3.0`.

## Permisos requeridos

Autenticación con **API Keys** (Security Center 5.13+), header
`x-apikey: accesskey=...; secretkey=...;`.

1. Un administrador habilita las API Keys en **System → Configuration → Security → Allow API Keys**.
2. Crea un usuario con rol **Security Analyst** (o uno personalizado) con acceso a los repositorios a consultar y permiso para lanzar escaneos.
3. Con ese usuario, **Username → My Profile → API Keys → Generate API Key**. La Secret Key solo se muestra una vez.

## Variables de entorno (`RUVIC_TENABLE_SC_*`)

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `RUVIC_TENABLE_SC_BASE_URL` | Sí | URL de Tenable Security Center |
| `RUVIC_TENABLE_SC_ACCESS_KEY` | Sí | Access Key |
| `RUVIC_TENABLE_SC_SECRET_KEY` | Sí | Secret Key |
| `RUVIC_TENABLE_SC_VERIFY_SSL` | No (default `true`) | Verificar certificado SSL |
| `RUVIC_TENABLE_SC_CONNECT_TIMEOUT` | No (default `30`) | Timeout de conexión (segundos) |

Los campos opcionales vacíos usan su valor por defecto (la plataforma envía
`""` cuando un campo queda en blanco).

## Pruebas locales

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ./lib

export RUVIC_TENABLE_SC_BASE_URL=...
export RUVIC_TENABLE_SC_ACCESS_KEY=...
export RUVIC_TENABLE_SC_SECRET_KEY=...

python test_connection.py
python validate_local.py
```

`validate_local.py` consulta vulnerabilidades, activos, hallazgos y escaneos. El lanzamiento de un escaneo está comentado.

## Notas de integración

- Las consultas usan `POST /rest/analysis` con `sourceType: cumulative` y las herramientas `sumid`, `sumip` y `listvuln`.
- Los resultados se ordenan por severidad o puntaje y se paginan con `startOffset`/`endOffset` hasta `limit`.
- `launch_scan` usa `POST /rest/scan/{id}/launch` y devuelve el ID del resultado creado.
- Si la consola usa un certificado autofirmado, desactiva `verify_ssl` solo en redes de confianza.
- Rutas y payloads verificados contra pyTenable, el SDK oficial de Tenable.

## Limitaciones conocidas

- No crea, edita ni borra escaneos, políticas o activos.
- No exporta reportes PDF/CSV.
- `limit` máximo 1000 filas por consulta.
