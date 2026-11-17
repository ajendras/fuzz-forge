"""OpenAPI specification parser using prance.

Converts YAML/JSON OpenAPI documents into a structured APISpec with
extracted endpoints, component schemas, security schemes and server URLs.
Now extracts per-operation security requirements for first-class OAuth2
and API-key support.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import prance

from .core import APISpec


class OpenAPIParser:
    """Parser for OpenAPI v2/v3 specifications."""

    def parse(self, path: str) -> APISpec:
        """Parse an OpenAPI file and return a semantic APISpec model.

        Uses prance.ResolvingParser to dereference $refs and validate.

        Args:
            path: Filesystem path to the OpenAPI document.

        Returns:
            APISpec instance populated with endpoints, schemas etc.

        Raises:
            FileNotFoundError: If the spec file does not exist.
            ValueError: If the document cannot be parsed as OpenAPI.
        """
        spec_path = Path(path)
        if not spec_path.is_file():
            raise FileNotFoundError(f"OpenAPI spec not found: {path}")

        try:
            parser = prance.ResolvingParser(
                str(spec_path),
                backend="openapi-spec-validator",
                strict=False,
            )
            spec_dict: Dict[str, Any] = parser.specification

            # Extract basic info
            info = spec_dict.get("info", {})
            title = info.get("title", "Untitled API")
            version = info.get("version", "1.0.0")

            # Servers
            servers: List[str] = []
            for server in spec_dict.get("servers", []):
                if isinstance(server, dict) and "url" in server:
                    url = server["url"]
                    if isinstance(url, str):
                        servers.append(url)
            if not servers and "host" in spec_dict:  # Swagger 2.0 fallback
                host = spec_dict["host"]
                schemes = spec_dict.get("schemes", ["http"])
                servers.append(f"{schemes[0]}://{host}")
            if not servers:
                servers = ["http://localhost:8000"]

            # Endpoints
            endpoints: List[Dict[str, Any]] = []
            paths: Dict[str, Any] = spec_dict.get("paths", {})
            for path_template, operations in paths.items():
                for method, operation in operations.items():
                    if not isinstance(operation, dict):
                        continue
                    method_upper = method.upper()
                    if method_upper not in {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}:
                        continue

                    summary = operation.get("summary") or operation.get("description", "")[:80]

                    # Extract example payload if available
                    example: Dict[str, Any] = {}
                    request_body = operation.get("requestBody", {})
                    if isinstance(request_body, dict):
                        content = request_body.get("content", {})
                        for media in content.values():
                            if isinstance(media, dict):
                                if "example" in media:
                                    example = media["example"]
                                    break
                                schema = media.get("schema", {})
                                if isinstance(schema, dict) and "example" in schema:
                                    example = schema["example"]
                                    break

                    endpoints.append({
                        "method": method_upper,
                        "path": path_template,
                        "summary": summary,
                        "example": example,
                        "operationId": operation.get("operationId"),
                        "tags": operation.get("tags", []),
                        "security": operation.get("security", []),  # first-class auth support
                    })

            # Schemas
            components = spec_dict.get("components", {})
            schemas = components.get("schemas", {})
            if not schemas and "definitions" in spec_dict:  # Swagger 2.0
                schemas = spec_dict["definitions"]

            security_schemes = components.get("securitySchemes", {})

            return APISpec(
                title=title,
                version=version,
                endpoints=endpoints,
                schemas=schemas,
                security_schemes=security_schemes,
                servers=servers,
                raw_spec={
                    "title": title,
                    "version": version,
                    "num_endpoints": len(endpoints),
                },
            )

        except Exception as exc:
            raise ValueError(f"Failed to parse OpenAPI spec {path}: {exc}") from exc
