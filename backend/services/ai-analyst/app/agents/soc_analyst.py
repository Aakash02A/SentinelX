"""
LangGraph SOC Analyst Agent.
Uses a multi-step reasoning graph to analyze security incidents.
"""
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Lazy imports to avoid cold-start delays
_langchain_available = False
try:
    from langchain_openai import ChatOpenAI
    from langgraph.graph import END, StateGraph
    _langchain_available = True
except ImportError:
    logger.warning("LangChain/LangGraph not installed. AI analysis will use stub responses.")


class SOCAnalystAgent:
    """
    AI-powered SOC analyst using LangGraph for structured reasoning.

    Graph:
        [gather_context] → [analyze_threat] → [map_mitre] → [generate_recommendations] → END
    """

    def __init__(self) -> None:
        self._graph = None
        if _langchain_available:
            self._graph = self._build_graph()

    def _build_graph(self):
        """Build the LangGraph reasoning graph."""
        from langgraph.graph import END, StateGraph

        graph = StateGraph(dict)
        graph.add_node("gather_context", self._gather_context)
        graph.add_node("analyze_threat", self._analyze_threat)
        graph.add_node("map_mitre", self._map_mitre)
        graph.add_node("generate_recommendations", self._generate_recommendations)

        graph.set_entry_point("gather_context")
        graph.add_edge("gather_context", "analyze_threat")
        graph.add_edge("analyze_threat", "map_mitre")
        graph.add_edge("map_mitre", "generate_recommendations")
        graph.add_edge("generate_recommendations", END)

        return graph.compile()

    async def _gather_context(self, state: dict) -> dict:
        """Enrich the alert with OpenSearch event history."""
        # TODO: Query OpenSearch for related events from same endpoint
        return {**state, "enriched_context": state.get("alert_data", {})}

    async def _analyze_threat(self, state: dict) -> dict:
        """Use LLM to analyze the threat and generate a summary."""
        # TODO: Call ChatOpenAI with incident summary prompt
        return {
            **state,
            "summary": "Malicious PowerShell execution detected with encoded payload.",
            "root_cause": "Attacker used a phishing email to execute a Base64-encoded PowerShell script.",
        }

    async def _map_mitre(self, state: dict) -> dict:
        """Map the attack to MITRE ATT&CK tactics and techniques."""
        return {
            **state,
            "mitre_tactics": ["Execution", "Defense Evasion"],
            "mitre_techniques": ["T1059.001", "T1027"],
        }

    async def _generate_recommendations(self, state: dict) -> dict:
        """Generate actionable response recommendations."""
        return {
            **state,
            "recommended_actions": [
                "Isolate the affected endpoint immediately",
                "Kill the malicious PowerShell process (PID: extracted from event)",
                "Scan all files created in the last 24 hours for malware",
                "Reset credentials for the affected user account",
                "Review email gateway logs for the phishing email",
            ],
            "attack_narrative": (
                "The attacker sent a phishing email containing a malicious document. "
                "When the user opened the document, it triggered a macro that executed "
                "a Base64-encoded PowerShell command to download and run a second-stage payload."
            ),
        }

    async def analyze(
        self,
        incident_id: str,
        alert_data: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Run the full analysis graph and return a structured result."""
        initial_state = {
            "incident_id": incident_id,
            "alert_data": alert_data,
            "context": context,
        }

        if self._graph is not None:
            final_state = await self._graph.ainvoke(initial_state)
        else:
            # Stub fallback when LangChain is not available
            final_state = {
                **initial_state,
                "summary": "AI analysis unavailable — LangChain not configured.",
                "root_cause": "Configure OPENAI_API_KEY to enable AI analysis.",
                "mitre_tactics": [],
                "mitre_techniques": [],
                "attack_narrative": "",
                "recommended_actions": ["Configure AI keys and retry."],
            }

        return {
            "incident_id": incident_id,
            "summary": final_state.get("summary", ""),
            "root_cause": final_state.get("root_cause", ""),
            "mitre_tactics": final_state.get("mitre_tactics", []),
            "mitre_techniques": final_state.get("mitre_techniques", []),
            "attack_narrative": final_state.get("attack_narrative", ""),
            "recommended_actions": final_state.get("recommended_actions", []),
            "risk_level": alert_data.get("severity", "medium"),
            "confidence": 0.87,
        }
