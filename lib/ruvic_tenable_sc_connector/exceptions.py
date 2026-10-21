"""Excepciones propias del conector Tenable Security Center.

Separan los tres tipos de fallo que el usuario debe distinguir:
autenticación, red/servidor y datos. Nunca exponemos excepciones
crípticas del cliente HTTP subyacente.
"""


class TenableScConnectorError(Exception):
    """Error base del conector."""


class TenableScAuthError(TenableScConnectorError):
    """Credenciales inválidas o permisos insuficientes."""


class TenableScNetworkError(TenableScConnectorError):
    """No se pudo alcanzar el servicio (red, timeout o error del servidor)."""


class TenableScDataError(TenableScConnectorError):
    """La operación es válida pero los datos o parámetros no lo son."""
