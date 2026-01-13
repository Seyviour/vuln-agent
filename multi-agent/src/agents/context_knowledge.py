"""
Repository Expert Agent - deep codebase understanding and security knowledge.

This agent functions as the repository specialist, building comprehensive understanding
of the codebase structure, patterns, and constraints at initialization. It serves as
the go-to expert for contextual information about how the vulnerability fits into the
broader system and provides security remediation guidance.
"""

from typing import Any, Dict, List, Optional
import json
import logging

from .base import BaseAgent, AgentOutput
from ..config import LLMConfig
from ..tools import ToolRegistry


logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are a Repository Expert and Security Knowledge Analyst.

**IMPORTANT**: When invoked via AskAgent, focus on your task and provide a clear, actionable response.

## Role

You are the **go-to expert** for understanding this codebase in the context of the vulnerability. Your role is to:

1. **Build Deep Repository Understanding**: At initialization, thoroughly investigate the repository structure, architecture, and patterns around the vulnerable code. You should become intimately familiar with:
   - How the vulnerable code fits into the broader system
   - Dependencies, imports, and relationships with other components
   - Coding patterns, conventions, and architectural decisions used in this repository
   - Test infrastructure and validation approaches
   - Build system and deployment considerations

2. **Provide Contextual Constraints**: Create a detailed Constraint Sheet that captures:
   - What can and cannot be modified
   - Dependencies that must be preserved
   - API contracts and interfaces that must be maintained
   - Side effects to be aware of
   - Edge cases specific to this repository
   - Remediation strategies appropriate for this codebase architecture
   - Potential pitfalls based on repository patterns

4. **Synthesize Failure Insights**: If prior patch attempts failed, analyze the feedback and provide concrete guidance to avoid repeating mistakes.

**Think of yourself as the repository specialist** who has spent time understanding the codebase deeply. Other agents will rely on your expertise to make informed decisions about how to safely patch the vulnerability without breaking the system.

## Tools
- ReadFile: Read file contents
- FindClass: Find definitions and usages of symbols
- SymbolVerify: Verify symbol definitions and imports

## Output Format
Return a single JSON object:

```json
{
  "constraint_sheet": { ... },
  "knowledge_packet": { ... },
  "failure_insights": {
    "issues": ["summary of observed problems or risks"],
    "suspected_cause": "likely root cause of previous failure (if any)",
    "suggestions": ["concrete guidance to fix or avoid failures"]
  }
}
```

If no prior feedback is provided, set "failure_insights" to an empty object.
"""


class ContextKnowledgeAgent(BaseAgent):
    """
    Repository Expert and Security Knowledge Analyst.

    This agent serves as the repository specialist, building deep understanding of the
    codebase structure, patterns, and constraints in the context of the vulnerability.
    It provides contextual constraints and security remediation guidance to other agents.
    """

    name = "ContextKnowledgeAgent"
    description = "Repository expert that builds deep codebase understanding and provides contextual constraints with CWE/CVE remediation guidance"

    def __init__(
        self,
        llm_config: LLMConfig,
        tool_registry: Optional[ToolRegistry] = None
    ):
        super().__init__(
            llm_config=llm_config,
            tool_registry=tool_registry,
            allowed_tools=["ReadFile", "FindClass", "SymbolVerify"],
        )

    def get_system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def run(self, context: Dict[str, Any]) -> AgentOutput:
        try:
            user_prompt = self._build_user_prompt(context)

            response, tool_calls, token_usage = self._run_with_tools(user_prompt, max_iterations=-1)
            combined = self._parse_combined_output(response)

            return AgentOutput(
                agent_name=self.name,
                success=True,
                content=combined,
                raw_response=response,
                tool_calls=tool_calls,
                token_usage=token_usage,
                tool_calls_count=len(tool_calls),
            )
        except Exception as e:
            logger.exception(f"ContextKnowledgeAgent failed: {e}")
            return AgentOutput(
                agent_name=self.name,
                success=False,
                content={},
                error=str(e),
                token_usage=getattr(self, "_last_token_usage", {}),
                tool_calls_count=0,
            )

    def _build_user_prompt(self, context: Dict[str, Any]) -> str:
        """Build the combined prompt from context."""
        problem_statement = context.get("problem_statement", "")
        vulnerable_code = context.get("vulnerable_code", "")
        cwe_info_text = json.dumps(context.get("cwe_info", {}), indent=2)

        # CWE information is already in context, agent will use its own knowledge
        pass

        if problem_statement:
            vuln_info = f"""## Vulnerability Information

**CVE ID:** {context.get('cve_id', 'Unknown')}

{problem_statement}
"""
        else:
            vuln_info = f"""## Vulnerability Information

**CVE ID:** {context.get('cve_id', 'Unknown')}

**Description:** {context.get('patch_description', context.get('cve_description', 'No description provided'))}

**CWE Information:**
{cwe_info_text}
"""

        if vulnerable_code and vulnerable_code.strip():
            vuln_func_section = f"""
## Vulnerable Function

**File:** {context.get('file_path', 'Unknown')}
**Lines:** {context.get('start_line', '?')} - {context.get('end_line', '?')}

```python
{vulnerable_code}
```
"""
        else:
            file_path = context.get("file_path", "")
            vuln_locations = context.get("vulnerability_locations", [])
            if vuln_locations:
                locations_str = "\n".join([
                    f"  - {loc.get('file_path', 'unknown')}: lines {loc.get('start_line', '?')}-{loc.get('end_line', '?')}"
                    for loc in vuln_locations
                ])
                vuln_func_section = f"""
## Vulnerable Code Locations

The vulnerable code is at:
{locations_str}

**You must use ReadFile to read the code at these locations.**
"""
            elif file_path:
                vuln_func_section = f"""
## Vulnerable File

**File:** {file_path}

**You must use ReadFile to read the vulnerable code from this file.**
"""
            else:
                vuln_func_section = ""

        feedback = (
            context.get("prev_feedback")
            or context.get("verification_result", {}).get("feedback_for_planner")
            or {}
        )
        feedback_section = ""
        if feedback:
            feedback_section = f"""
## Patch Failure Feedback

The previous patch attempt had issues:
```json
{json.dumps(feedback, indent=2)}
```

Analyze this feedback and produce failure_insights to help the next patch attempt.
"""

        return f"""{vuln_info}{vuln_func_section}
## Your Tasks

1. Read the vulnerable file and analyze context.
2. Produce a Constraint Sheet capturing semantics, API contracts, security flows, and repo conventions.
3. If feedback is present, provide failure insights for the next patch attempt.

{feedback_section}
Return a single JSON object with keys: constraint_sheet, failure_insights.
"""

    def _parse_combined_output(self, response: str) -> Dict[str, Any]:
        parsed = self._parse_json_from_response(response)
        if "parse_error" in parsed and "raw_response" in parsed:
            return {
                "constraint_sheet": {},
                "knowledge_packet": {},
                "failure_insights": {},
                "raw_response": parsed.get("raw_response"),
                "parse_error": parsed.get("parse_error"),
            }
        return {
            "constraint_sheet": parsed.get("constraint_sheet", {}),
            "knowledge_packet": parsed.get("knowledge_packet", {}),
            "failure_insights": parsed.get("failure_insights", {}),
        }
