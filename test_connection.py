"""Prueba de conexión estándar del conector tenable_sc.

Firma estándar Ruvic: def test_connection() -> tuple[bool, str]
- Lee la configuración EXCLUSIVAMENTE de las env vars RUVIC_TENABLE_SC_*.
- Nunca lanza excepciones; retorna (ok, mensaje).

Ejecutable también como script para pruebas locales:
    python test_connection.py
"""

from __future__ import annotations


def test_connection() -> tuple[bool, str]:
    """Consulta el usuario actual de Tenable Security Center con las env vars RUVIC_TENABLE_SC_*."""
    try:
        from ruvic_tenable_sc_connector import (
            TenableScAuthError,
            TenableScClient,
            TenableScDataError,
            TenableScNetworkError,
        )
    except ImportError:
        return (
            False,
            (
                "La librería ruvic-tenable-sc-connector no está instalada. "
                "Instala con: pip install git+https://github.com/RuvicDev/"
                "CON-090-Tenable-Security-Center.git#subdirectory=lib"
            ),
        )

    try:
        client = TenableScClient()  # valida que existan las env vars
    except ValueError as exc:
        return False, str(exc)

    try:
        client.ping()
    except TenableScAuthError as exc:
        return False, f"Autenticación fallida: {exc}"
    except TenableScNetworkError as exc:
        return False, f"Error de red: {exc}"
    except TenableScDataError as exc:
        return False, f"Error de datos: {exc}"
    except Exception as exc:  # noqa: BLE001 - red de seguridad: jamás propagar
        return False, f"Error inesperado: {exc}"

    return True, f"Conexión exitosa a Tenable Security Center ({client.config.base_url})"


if __name__ == "__main__":
    ok, message = test_connection()
    print(f"{'OK' if ok else 'FALLO'}: {message}")
    raise SystemExit(0 if ok else 1)
