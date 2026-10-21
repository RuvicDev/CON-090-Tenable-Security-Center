"""Cliente de gestión de vulnerabilidades para Tenable Security Center (API REST).

Capacidades:
- list_vulnerabilities(): vulnerabilidades agrupadas por plugin (herramienta sumid).
- list_assets():          activos (IPs) con su conteo de vulnerabilidades (sumip).
- get_findings():         hallazgos individuales con filtros (listvuln).
- list_scans():           escaneos definidos.
- launch_scan():          lanzar un escaneo ya definido.

Autenticación: header x-apikey "accesskey=...; secretkey=...;" (Security
Center 5.13+). Base de la API: <base_url>/rest.

Las credenciales SIEMPRE provienen de variables de entorno RUVIC_TENABLE_SC_*
(ver config.TenableScConfig.from_env). Prohibido hardcodearlas.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import requests
import urllib3

from .config import TenableScConfig
from .exceptions import TenableScAuthError, TenableScDataError, TenableScNetworkError
from .logging_utils import get_logger

_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_NAME = {str(v): k for k, v in _SEVERITY.items()}


def _limit(value: Any, maximum: int = 1000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise TenableScDataError(f"limit debe ser un entero entre 1 y {maximum}.")
    return value


def _severity_filter(severity: str | list[str] | None) -> dict[str, str] | None:
    if severity is None:
        return None
    values = [severity] if isinstance(severity, str) else list(severity)
    ids = []
    for s in values:
        key = str(s).strip().lower()
        if key not in _SEVERITY:
            raise TenableScDataError(f"severity {s!r} inválida. Valores permitidos: {list(_SEVERITY)}")
        ids.append(str(_SEVERITY[key]))
    return {"filterName": "severity", "operator": "=", "value": ",".join(sorted(set(ids)))}


def _sev_name(value: Any) -> str | None:
    if isinstance(value, dict):
        return (value.get("name") or "").lower() or _SEVERITY_NAME.get(str(value.get("id")))
    return _SEVERITY_NAME.get(str(value), value)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class TenableScClient:
    """Cliente de Tenable Security Center.

    Args:
        config: configuración. Si se omite, se lee de RUVIC_TENABLE_SC_*.

    Ejemplo:
        >>> client = TenableScClient()
        >>> client.list_vulnerabilities(severity=["critical", "high"], limit=10)
        [{'plugin_id': '19506', 'name': '...', 'severity': 'critical', 'hosts': 12}, ...]
    """

    def __init__(self, config: TenableScConfig | None = None) -> None:
        self.config = config or TenableScConfig.from_env()
        base = self.config.base_url.removesuffix("/rest")
        self.api_url = f"{base}/rest"
        self._logger = get_logger()
        self._session = requests.Session()
        self._session.verify = self.config.verify_ssl
        self._session.headers.update({
            "x-apikey": f"accesskey={self.config.access_key}; secretkey={self.config.secret_key};",
            "Accept": "application/json",
        })
        if not self.config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------ #
    # Conexión
    # ------------------------------------------------------------------ #

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            resp = self._session.request(method, f"{self.api_url}/{path}",
                                         timeout=self.config.connect_timeout, **kwargs)
        except requests.exceptions.SSLError as exc:
            raise TenableScNetworkError(
                "Error de certificado SSL. Si la consola usa un certificado autofirmado, desactiva "
                "'Verificar certificado SSL' en la configuración del conector."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise TenableScNetworkError(f"No se pudo alcanzar Tenable Security Center: {exc}") from exc
        try:
            body = resp.json()
        except ValueError:
            body = {}
        message = str(body.get("error_msg") or "").strip()
        if resp.status_code in (401, 403):
            raise TenableScAuthError(
                "API Keys inválidas o sin permiso. Verifica las llaves y que las API Keys estén "
                f"habilitadas (System → Configuration → Security). {message}".strip()
            )
        if resp.status_code == 404:
            raise TenableScDataError(f"El recurso solicitado no existe. {message}".strip())
        if resp.status_code >= 500:
            raise TenableScNetworkError(f"Tenable respondió {resp.status_code}; reintenta en unos segundos. {message}".strip())
        if resp.status_code >= 400 or body.get("error_code"):
            raise TenableScDataError(f"Tenable rechazó la petición: {message or resp.text[:300]}")
        return body.get("response")

    def ping(self) -> bool:
        """Verifica las API Keys consultando el usuario actual.

        Raises:
            TenableScAuthError / TenableScNetworkError / TenableScDataError.
        """
        user = self._request("GET", "currentUser", params={"fields": "id,username"}) or {}
        self._logger.info("Ping exitoso a Tenable SC como %s", user.get("username"))
        return True

    def _analysis(self, tool: str, filters: list[dict[str, str]], limit: int,
                  sort_field: str | None = None) -> tuple[list[dict[str, Any]], int]:
        query: dict[str, Any] = {
            "type": "vuln", "tool": tool, "filters": filters,
            "startOffset": 0, "endOffset": limit,
        }
        payload: dict[str, Any] = {"type": "vuln", "sourceType": "cumulative", "query": query}
        if sort_field:
            payload["sortField"] = sort_field
            payload["sortDir"] = "DESC"
        resp = self._request("POST", "analysis", json=payload) or {}
        return resp.get("results", []), _to_int(resp.get("totalRecords")) or 0

    # ------------------------------------------------------------------ #
    # Capacidad 1: vulnerabilidades
    # ------------------------------------------------------------------ #

    def list_vulnerabilities(self, severity: str | list[str] | None = None,
                             exploit_available: bool | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Lista vulnerabilidades agrupadas por plugin, con cuántos activos las tienen.

        Args:
            severity: "critical", "high", "medium", "low", "info" o una lista.
            exploit_available: True para solo las que tienen exploit público.
            limit: máximo de resultados (1-1000).

        Returns:
            Lista de dicts: plugin_id, name, family, severity, hosts.

        Ejemplo:
            >>> client.list_vulnerabilities(severity="critical", exploit_available=True)
            [{'plugin_id': '19506', 'name': '...', 'severity': 'critical', 'hosts': 12}]
        """
        filters = [f for f in [_severity_filter(severity)] if f]
        if exploit_available is not None:
            filters.append({"filterName": "exploitAvailable", "operator": "=",
                            "value": "true" if exploit_available else "false"})
        rows, total = self._analysis("sumid", filters, _limit(limit), sort_field="severity")
        self._logger.info("Vulnerabilidades: %d de %d", len(rows), total)
        return [{
            "plugin_id": r.get("pluginID"),
            "name": r.get("name") or r.get("pluginName"),
            "family": (r.get("family") or {}).get("name") if isinstance(r.get("family"), dict) else r.get("family"),
            "severity": _sev_name(r.get("severity")),
            "hosts": _to_int(r.get("hostTotal") or r.get("total")),
        } for r in rows]

    # ------------------------------------------------------------------ #
    # Capacidad 2: activos
    # ------------------------------------------------------------------ #

    def list_assets(self, ip_range: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Lista activos (IPs) con su puntaje y conteo de vulnerabilidades por severidad.

        Args:
            ip_range: IP, rango o CIDR para filtrar (ej. "10.0.0.0/24").
            limit: máximo de activos (1-1000).

        Returns:
            Lista de dicts: ip, dns, netbios, os, score, critical, high,
            medium, low, total, last_seen.

        Ejemplo:
            >>> client.list_assets(ip_range="10.0.0.0/24", limit=20)
            [{'ip': '10.0.0.5', 'dns': 'srv-app01', 'critical': 3, 'high': 7, ...}]
        """
        filters = []
        if ip_range:
            filters.append({"filterName": "ip", "operator": "=", "value": self._ip_value(ip_range)})
        rows, total = self._analysis("sumip", filters, _limit(limit), sort_field="score")
        self._logger.info("Activos: %d de %d", len(rows), total)
        return [{
            "ip": r.get("ip"),
            "dns": r.get("dnsName"),
            "netbios": r.get("netbiosName"),
            "os": r.get("osCPE") or r.get("os"),
            "score": _to_int(r.get("score")),
            "critical": _to_int(r.get("severityCritical")),
            "high": _to_int(r.get("severityHigh")),
            "medium": _to_int(r.get("severityMedium")),
            "low": _to_int(r.get("severityLow")),
            "total": _to_int(r.get("total")),
            "last_seen": r.get("lastAuthRun") or r.get("lastUnauthRun"),
        } for r in rows]

    @staticmethod
    def _ip_value(value: str) -> str:
        text = str(value).strip()
        try:
            if "-" in text:
                a, b = text.split("-", 1)
                ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
            elif "/" in text:
                ipaddress.ip_network(text, strict=False)
            else:
                ipaddress.ip_address(text)
        except ValueError:
            raise TenableScDataError(f"ip_range inválido: {value!r}. Usa una IP, un rango a-b o un CIDR.") from None
        return text

    # ------------------------------------------------------------------ #
    # Capacidad 3: hallazgos
    # ------------------------------------------------------------------ #

    def get_findings(self, ip: str | None = None, plugin_id: int | str | None = None,
                     severity: str | list[str] | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Consulta hallazgos individuales (vulnerabilidad en un host/puerto).

        Args:
            ip: IP, rango o CIDR (opcional).
            plugin_id: ID de plugin de Nessus (opcional).
            severity: severidad o lista de severidades (opcional).
            limit: máximo de hallazgos (1-1000).

        Returns:
            Lista de dicts: ip, dns, port, protocol, plugin_id, name,
            severity, first_seen, last_seen.

        Ejemplo:
            >>> client.get_findings(ip="10.0.0.5", severity="critical")
            [{'ip': '10.0.0.5', 'port': '443', 'plugin_id': '19506', ...}]
        """
        filters = [f for f in [_severity_filter(severity)] if f]
        if ip:
            filters.append({"filterName": "ip", "operator": "=", "value": self._ip_value(ip)})
        if plugin_id is not None:
            pid = _to_int(plugin_id)
            if not pid or pid <= 0:
                raise TenableScDataError(f"plugin_id inválido: {plugin_id!r}")
            filters.append({"filterName": "pluginID", "operator": "=", "value": str(pid)})
        rows, total = self._analysis("listvuln", filters, _limit(limit), sort_field="severity")
        self._logger.info("Hallazgos: %d de %d", len(rows), total)
        return [{
            "ip": r.get("ip"),
            "dns": r.get("dnsName"),
            "port": r.get("port"),
            "protocol": r.get("protocol"),
            "plugin_id": r.get("pluginID"),
            "name": r.get("pluginName") or r.get("name"),
            "severity": _sev_name(r.get("severity")),
            "first_seen": r.get("firstSeen"),
            "last_seen": r.get("lastSeen"),
        } for r in rows]

    # ------------------------------------------------------------------ #
    # Capacidad 4: escaneos
    # ------------------------------------------------------------------ #

    def list_scans(self) -> list[dict[str, Any]]:
        """Lista los escaneos definidos que el usuario puede usar.

        Returns:
            Lista de dicts: id, name, description, policy, repository, schedule.

        Ejemplo:
            >>> client.list_scans()
            [{'id': '12', 'name': 'Escaneo semanal DMZ', 'schedule': 'ical', ...}]
        """
        resp = self._request("GET", "scan", params={
            "fields": "id,name,description,policy,repository,schedule"}) or {}
        scans = resp.get("usable", []) if isinstance(resp, dict) else resp
        return [{
            "id": s.get("id"),
            "name": s.get("name"),
            "description": s.get("description"),
            "policy": (s.get("policy") or {}).get("name"),
            "repository": (s.get("repository") or {}).get("name"),
            "schedule": (s.get("schedule") or {}).get("type"),
        } for s in scans]

    def launch_scan(self, scan_id: int | str) -> dict[str, Any]:
        """Lanza un escaneo ya definido (no crea ni modifica escaneos).

        Args:
            scan_id: ID del escaneo (de list_scans).

        Returns:
            Dict con scan_id, scan_result_id (instancia creada) y status.

        Ejemplo:
            >>> client.launch_scan(12)
            {'scan_id': 12, 'scan_result_id': '458', 'status': 'Queued'}
        """
        sid = _to_int(scan_id)
        if not sid or sid <= 0:
            raise TenableScDataError(f"scan_id inválido: {scan_id!r}")
        resp = self._request("POST", f"scan/{sid}/launch", json={}) or {}
        result = resp.get("scanResult") or {}
        self._logger.info("Escaneo %s lanzado (resultado %s)", sid, result.get("id"))
        return {"scan_id": sid, "scan_result_id": result.get("id"), "status": result.get("status")}
