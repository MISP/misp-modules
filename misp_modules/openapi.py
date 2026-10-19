"""
Utilities to assemble a baseline OpenAPI document for the misp-modules service.
"""

# Contributor: Adam McHugh (adam@mchughcyber.com.au)

from __future__ import annotations

import datetime
from typing import Any, Dict, Mapping

from . import ModuleType

OPENAPI_VERSION = "3.1.0"


def _module_descriptors(handlers: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Collect module descriptors using the global handlers cache."""
    descriptors: list[dict[str, Any]] = []
    for module_name, module in handlers.items():
        if module_name.startswith("type:"):
            continue
        module_type = handlers.get(f"type:{module_name}", "unknown")
        try:
            mispattributes = module.introspection()
        except AttributeError:
            mispattributes = {}
        try:
            moduleinfo = module.version()
        except AttributeError:
            moduleinfo = {}
        descriptors.append(
            {
                "name": module_name,
                "type": module_type,
                "mispattributes": mispattributes,
                "meta": moduleinfo,
            }
        )
    descriptors.sort(key=lambda descriptor: descriptor["name"])
    return descriptors


def build_document(
    handlers: Mapping[str, Any], listen: str, port: int, generated_at: datetime.datetime | None = None
) -> Dict[str, Any]:
    """
    Build a coarse OpenAPI document for the misp-modules REST API.

    The contract focuses on the core endpoints and intentionally keeps the schema
    for `/query` permissive so all modules remain consumable.
    """
    descriptors = _module_descriptors(handlers)
    generated_at = generated_at or datetime.datetime.utcnow()
    servers = [{"url": f"http://{listen}:{port}"}]

    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "MISP Modules API",
            "version": "1.0.0",
            "summary": "Baseline OpenAPI contract for the misp-modules service.",
            "description": (
                "This document is generated at runtime using the available module metadata. "
                "Module-specific request and response payloads remain flexible and may vary."
            ),
            "contact": {"name": "MISP Project", "url": "https://github.com/MISP/misp-modules"},
            "x-generated-at": generated_at.replace(microsecond=0).isoformat() + "Z",
        },
        "servers": servers,
        "paths": {
            "/modules": {
                "get": {
                    "operationId": "listModules",
                    "summary": "List loaded modules",
                    "description": "Returns the modules currently available on the misp-modules service.",
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/ModuleDescriptor"},
                                    },
                                    "examples": {
                                        "modules": {"summary": "Detected modules", "value": descriptors},
                                    },
                                }
                            },
                        }
                    },
                }
            },
            "/query": {
                "post": {
                    "operationId": "queryModule",
                    "summary": "Execute a module",
                    "description": "Dispatch a request to a specific module. The payload shape depends on the module.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ModuleQuery"},
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Module response",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"},
                                    "examples": {
                                        "generic": {
                                            "summary": "Generic result container",
                                            "value": {
                                                "results": [{"values": ["example"], "types": ["ip-src", "ip-dst"]}]
                                            },
                                        },
                                        "tagging": {
                                            "summary": "Result tagging and untagging an attribute",
                                            "value": {
                                                "results": [
                                                    {
                                                        "values": ["198.51.100.10"],
                                                        "types": ["ip-dst"],
                                                        "tags": ['misp-module:verdict="benign"'],
                                                        "remove_tags": ["false-positive"],
                                                    }
                                                ]
                                            },
                                        },
                                    },
                                }
                            },
                        },
                        "400": {
                            "description": "Invalid request",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        },
                        "504": {
                            "description": "Module execution timed out",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        },
                    },
                }
            },
            "/healthcheck": {
                "get": {
                    "operationId": "healthcheck",
                    "summary": "Health check",
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {
                                "application/json": {"schema": {"$ref": "#/components/schemas/HealthResponse"}}
                            },
                        }
                    },
                }
            },
            "/statistics": {
                "get": {
                    "operationId": "getStatistics",
                    "summary": "Retrieve module query statistics",
                    "description": (
                        "Process-local counters since startup, including unused modules. Only queries dispatched to"
                        " loaded modules are counted. Errors include module errors, exceptions and timeouts. Response"
                        " times include executor queueing and serialization, ending at response preparation or timeout;"
                        " timed-out workers may continue running. No request or response contents are retained."
                    ),
                    "responses": {
                        "200": {
                            "description": "Current statistics snapshot",
                            "content": {
                                "application/json": {"schema": {"$ref": "#/components/schemas/StatisticsResponse"}}
                            },
                        }
                    },
                }
            },
            "/version": {
                "get": {
                    "operationId": "getVersion",
                    "summary": "Retrieve package version",
                    "responses": {
                        "200": {
                            "description": "Service version",
                            "content": {
                                "application/json": {"schema": {"$ref": "#/components/schemas/VersionResponse"}}
                            },
                        },
                        "500": {
                            "description": "Version lookup failed",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        },
                    },
                }
            },
        },
        "components": {
            "schemas": {
                "StatisticsResponse": {
                    "type": "object",
                    "required": ["started_at", "uptime_seconds", "totals", "modules"],
                    "properties": {
                        "started_at": {"type": "string", "format": "date-time"},
                        "uptime_seconds": {"type": "number", "minimum": 0},
                        "totals": {"$ref": "#/components/schemas/QueryStatistics"},
                        "modules": {
                            "type": "object",
                            "description": "Statistics keyed by loaded module name, including custom modules.",
                            "additionalProperties": {"$ref": "#/components/schemas/QueryStatistics"},
                        },
                    },
                },
                "QueryStatistics": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "description": "Module type; omitted from totals."},
                        **{
                            name: {"type": "integer", "minimum": 0, "description": description}
                            for name, description in {
                                "queries": "Queries dispatched to the module.",
                                "completed": "Queries with a response or timeout.",
                                "in_flight": "Queries still awaiting a response; excludes timed-out workers.",
                                "successes": "Responses without a nonempty top-level error or errors field.",
                                "errors": "Sum of module_errors, exceptions and timeouts.",
                                "module_errors": "Responses with a nonempty top-level error or errors field.",
                                "exceptions": "Unhandled execution or serialization failures.",
                                "timeouts": "Queries exceeding the requested timeout.",
                                "request_bytes": "Total dispatched request body bytes.",
                                "response_bytes": "Total response body bytes, including generated errors.",
                            }.items()
                        },
                        **{
                            name: {"type": ["number", "null"], "minimum": 0, "maximum": 1}
                            for name in ("success_rate", "error_rate")
                        },
                        **{
                            name: {"type": ["string", "null"], "format": "date-time"}
                            for name in ("last_query_at", "last_completed_at")
                        },
                        "response_time_seconds": {"$ref": "#/components/schemas/ResponseTimeStatistics"},
                    },
                },
                "ResponseTimeStatistics": {
                    "type": "object",
                    "properties": {
                        "count": {"type": "integer", "minimum": 0},
                        "total": {"type": "number", "minimum": 0},
                        **{
                            name: {"type": ["number", "null"], "minimum": 0}
                            for name in ("min", "max", "average", "last")
                        },
                        "buckets": {
                            "type": "object",
                            "description": (
                                "Cumulative latency counts keyed by inclusive upper bound in seconds: "
                                "0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300 and +Inf. "
                                "+Inf equals count. Rates and unobserved timings are null before completion."
                            ),
                            "additionalProperties": {"type": "integer", "minimum": 0},
                        },
                    },
                },
                "ModuleDescriptor": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "type": {
                            "type": "string",
                            "enum": [module_type.name for module_type in ModuleType],
                        },
                        "mispattributes": {"type": "object"},
                        "meta": {"type": "object"},
                    },
                    "required": ["name", "type"],
                    "additionalProperties": False,
                },
                "ModuleQuery": {
                    "type": "object",
                    "properties": {
                        "module": {"type": "string", "description": "Module name to execute."},
                        "timeout": {
                            "type": "integer",
                            "description": "Optional timeout override in seconds.",
                            "minimum": 1,
                        },
                        "attribute": {
                            "type": "object",
                            "description": "MISP attribute payload for modules expecting standard input.",
                        },
                        "config": {
                            "type": "object",
                            "description": "Module configuration or credentials.",
                        },
                    },
                    "required": ["module"],
                    "additionalProperties": True,
                },
                "HealthResponse": {
                    "type": "object",
                    "properties": {"status": {"type": "boolean"}},
                    "required": ["status"],
                    "additionalProperties": False,
                },
                "VersionResponse": {
                    "type": "object",
                    "properties": {"version": {"type": "string"}},
                    "required": ["version"],
                    "additionalProperties": False,
                },
            }
        },
    }
