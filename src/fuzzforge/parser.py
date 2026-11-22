"""OpenAPI specification parser using prance.

Converts YAML/JSON OpenAPI documents into a structured APISpec with
extracted endpoints, component schemas, security schemes and server URLs.
Now also supports GraphQL SDL schemas with mutation extraction.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

import prance
from graphql import GraphQLSchema, build_schema

from .core import APISpec


class OpenAPIParser:
    """Parser for OpenAPI v2/v3 specifications and GraphQL SDL."""

    def parse(self, path: str) -> APISpec:
        """Parse an OpenAPI or GraphQL file and return a semantic APISpec model.

        Uses prance.ResolvingParser for OpenAPI and graphql.build_schema for
        GraphQL SDL. Auto-detects by file extension.

        Args:
            path: Filesystem path to the specification document.

        Returns:
            APISpec instance populated with endpoints, schemas etc.

        Raises:
            FileNotFoundError: If the spec file does not exist.
            ValueError: If the document cannot be parsed.
            ImportError: If graphql-core is not available for GraphQL files.
        """
        spec_path = Path(path)
        if not spec_path.is_file():
            raise FileNotFoundError(f"Spec not found: {path}")

        if spec_path.suffix.lower() in (".graphql", ".gql"):
            return self._parse_graphql(spec_path)

        return self._parse_openapi(spec_path)

    def _parse_openapi(self, spec_path: Path) -> APISpec:
        """Parse OpenAPI YAML/JSON."""
        try:
            # Fix common YAML parsing issue where version: 1.0 becomes float 1.0
            # but OpenAPI validators require a string. We quote it via regex so
            # the downstream validator succeeds.
            spec_text = spec_path.read_text(encoding="utf-8")
            spec_text = re.sub(
                r"(?m)^(\s*version\s*:\s*)([0-9][0-9.]*)(\s*(?:#.*)?$)",
                r'\1"\2"\3',
                spec_text,
            )

            parser = prance.ResolvingParser(
                spec_string=spec_text,
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
                spec_type="openapi",
            )

        except Exception as exc:
            raise ValueError(f"Failed to parse OpenAPI spec {spec_path}: {exc}") from exc

    def _parse_graphql(self, spec_path: Path) -> APISpec:
        """Parse GraphQL SDL and extract mutations (and queries) as test endpoints."""
        sdl = spec_path.read_text(encoding="utf-8")
        try:
            schema: GraphQLSchema = build_schema(sdl)
        except Exception as exc:
            raise ValueError(f"Invalid GraphQL schema {spec_path}: {exc}") from exc

        title = "GraphQL API"
        endpoints: List[Dict[str, Any]] = []

        # Mutations first (per task emphasis on mutation generation)
        if schema.mutation_type:
            for field_name, field in schema.mutation_type.fields.items():
                args_dict: Dict[str, str] = {}
                for arg_name, arg in field.args.items():
                    args_dict[arg_name] = str(arg.type)
                args_str = ", ".join(f"{k}: \\\"value\\\"" for k in args_dict) if args_dict else ""
                example_query = f"mutation {{ {field_name}({args_str}) {{ id }} }}"
                endpoints.append({
                    "method": "POST",
                    "path": "/graphql",
                    "summary": f"Mutation {field_name}",
                    "example": {"query": example_query},
                    "operation": "mutation",
                    "name": field_name,
                    "args": args_dict,
                    "tags": ["graphql", "mutation"],
                })

        # Queries for completeness
        if schema.query_type:
            for field_name, field in schema.query_type.fields.items():
                example_query = f"{{ {field_name} }}"
                endpoints.append({
                    "method": "POST",
                    "path": "/graphql",
                    "summary": f"Query {field_name}",
                    "example": {"query": example_query},
                    "operation": "query",
                    "name": field_name,
                    "tags": ["graphql", "query"],
                })

        # Schemas / types
        schemas: Dict[str, str] = {}
        for type_name, gql_type in schema.type_map.items():
            if not type_name.startswith("__"):
                schemas[type_name] = str(gql_type)

        return APISpec(
            title=title,
            version="1.0",
            endpoints=endpoints,
            schemas=schemas,
            security_schemes={},
            servers=["http://localhost:4000/graphql"],
            raw_spec={"type": "graphql", "num_operations": len(endpoints)},
            spec_type="graphql",
        )
