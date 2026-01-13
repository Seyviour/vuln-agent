"""
Coordinator Agent - unified orchestration and planning for vulnerability patching.

This agent combines the roles of orchestrator and planner into a single agent
that naturally collaborates with specialist agents (Context, Patch, Verification).
"""

from typing import Any, Dict, List, Optional
import os
import json
import logging

from .base import BaseAgent, AgentOutput
from ..config import LLMConfig
from ..utils.constants import DEFAULT_ARTIFACTS_DIR
from ..tools import ToolRegistry

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are a Security Patch Coordinator. You lead a team of specialists to fix security vulnerabilities.

## Role

You are both the **strategist** and **orchestrator**. You:
1. Analyze vulnerabilities and formulate fix strategies
2. Delegate research and implementation to specialists
3. Learn from failures and iterate until successful

## Specialists

Use the **AskAgent** tool to consult specialists:

### ContextKnowledgeAgent (Research)
Ask them to:
- Read and analyze code files
- Explain code patterns and security flows
- Provide CWE/CVE remediation guidance
- Investigate test files and expected behaviors

Example: "Read h11/_readers.py and explain how ChunkedReader handles line terminators"

### PatchAgent (Implementation)
Ask them to:
- Apply specific code changes you've designed
- They have EditCode tool access

Example: "In _readers.py, modify the __call__ method to reject bare \\n line terminators"

### VerificationAgent (Testing)
Ask them to:
- Run PoC (proof of concept) tests to verify the vulnerability is fixed
- Run regression tests to ensure nothing broke

Example: "Run the PoC and regression tests to verify the patch"

## Tools

You also have direct access to:
- **ReadFile**: Quick file reads (for simple checks)
- **EditCode**: Apply changes directly (if you're confident)
- **RunTest**: Run tests directly

## Strategy

When planning a fix, consider:

1. **Minimal change** - Smallest diff that fixes the vulnerability
2. **Preserve behavior** - Don't break existing functionality
3. **Match conventions** - Follow the repo's existing patterns
4. **Security completeness** - Block all attack vectors, not just the PoC

## Workflow

### Phase 1: Understand
- Ask ContextKnowledgeAgent to analyze the vulnerable code
- Understand what the code does and why it's vulnerable
- Look at related tests to understand expected behavior

### Phase 2: Strategize (YOU DO THIS - no Planner needed)
- Formulate 1-2 fix approaches
- Consider trade-offs
- Choose the best approach
- Be specific about what needs to change

### Phase 3: Implement
- Ask PatchAgent to apply your chosen fix
- Be specific: which file, which function, what change

### Phase 4: Verify
- Ask VerificationAgent to run tests
- If tests fail, analyze why and iterate

### Phase 5: Iterate (if needed)
- If the fix didn't work, DON'T just retry the same thing
- Ask ContextKnowledgeAgent for more context
- Revise your strategy based on what you learned
- Try a different approach

## Communication

Have **natural conversations** with your specialists:

GOOD: "I see the vulnerability is in extract(). Can you show me how 'name' flows through the function?"
BAD: "Analyze constraint_sheet and produce knowledge_packet"

GOOD: "The last patch failed because we didn't handle absolute paths. Let's add that check."
BAD: "Generate strategy for iteration 2"

## Output Format

When you've successfully fixed the vulnerability (tests pass):
```json
{
  "status": "success",
  "vulnerability": "Brief description of what was wrong",
  "fix": "Brief description of the fix applied",
  "iterations": <number>
}
```

If you've exhausted attempts without success:
```json
{
  "status": "failed",
  "vulnerability": "What we understood about the issue",
  "attempts": ["Attempt 1: tried X, failed because Y", "Attempt 2: ..."],
  "blocker": "Why we couldn't fix it"
}
```

## Rules

1. **YOU are the strategist** - Feel free to consult with specialists but you must make the final decisions
2. **Specialists execute** - ContextAgent researches, PatchAgent implements, VerificationAgent tests
3. **Learn from failures** - Each iteration should try something DIFFERENT
4. **Be specific** - Vague instructions lead to vague results
5. **Stay focused** - Only modify the vulnerable file(s), not the whole codebase
6. **Workflow** - Follow the Understand -> Strategize -> Implement -> Verify -> Iterate process for the first patch at least
"""


class CoordinatorAgent(BaseAgent):
    """
    Unified Coordinator that handles both orchestration and planning.

    This replaces the separate Planner + Graph-based orchestration with
    a single agent that naturally collaborates with specialists.
    """

    name = "CoordinatorAgent"
    description = "Orchestrates and plans vulnerability fixes with specialist agents"

    def __init__(
        self,
        llm_config: LLMConfig,
        tool_registry: Optional[ToolRegistry] = None,
        max_iterations: int = 30,
    ):
        super().__init__(
            llm_config=llm_config,
            tool_registry=tool_registry,
            allowed_tools=["AskAgent", "ReadFile", "EditCode", "RunTest"],
        )
        self.max_iterations = max_iterations

    def get_system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def run(self, context: Dict[str, Any]) -> AgentOutput:
        """
        Run the coordinator to fix a vulnerability.

        The coordinator will naturally iterate with specialists
        until the patch succeeds or max_iterations is reached.
        """
        try:
            if self._session_id is None:
                sample_id = context.get("sample_id") or context.get("cve_id") or "unknown"
                session_id = f"{sample_id}:{self.name}"
                artifacts_dir = os.getenv("ARTIFACTS_DIR", DEFAULT_ARTIFACTS_DIR)
                db_path = os.path.join(artifacts_dir, "agent_sessions.sqlite")
                os.makedirs(artifacts_dir, exist_ok=True)
                self.set_session(session_id, db_path)

            user_prompt = self._build_initial_prompt(context)

            # Run with tools - coordinator will naturally iterate
            response, tool_calls, token_usage = self._run_with_tools(
                user_prompt,
                max_iterations=self.max_iterations
            )

            # Parse the final result
            result = self._parse_result(response)

            return AgentOutput(
                agent_name=self.name,
                success=result.get("status") == "success",
                content=result,
                raw_response=response,
                tool_calls=tool_calls,
                token_usage=token_usage,
                tool_calls_count=len(tool_calls),
                llm_calls=self._last_llm_calls,
            )

        except Exception as e:
            logger.exception(f"CoordinatorAgent failed: {e}")
            return AgentOutput(
                agent_name=self.name,
                success=False,
                content={"status": "error", "reason": str(e)},
                error=str(e),
                token_usage=getattr(self, "_last_token_usage", {}),
                tool_calls_count=0,
                llm_calls=getattr(self, "_last_llm_calls", 0),
            )

    def _build_initial_prompt(self, context: Dict[str, Any]) -> str:
        """Build the initial prompt with vulnerability information."""
        cve_id = context.get("cve_id", "Unknown")
        cwe_id = context.get("cwe_id", "")
        file_path = context.get("file_path", "Unknown")
        vulnerable_code = context.get("vulnerable_code", "")
        problem_statement = context.get("problem_statement", "")
        vulnerability_locations = context.get("vulnerability_locations", [])

        # Build a clear, actionable prompt
        prompt = f"""## Your Mission

Fix the security vulnerability in this codebase.

## Vulnerability Details

**CVE:** {cve_id}
**CWE:** {cwe_id}
**Affected File:** {file_path}
**Vulnerable Locations:**
{self._format_vulnerability_locations(vulnerability_locations)}

### Description
{problem_statement or "No description provided. You'll need to investigate."}

### Vulnerable Code Snippet (may be stale vs line numbers)
```python
{vulnerable_code if vulnerable_code else "No snippet provided. Use ReadFile or ask ContextKnowledgeAgent to investigate."}
```

## Get Started

1. First, ask ContextKnowledgeAgent to analyze the vulnerable files/locations and explain the security issue
2. Based on their analysis, formulate YOUR fix strategy
3. Ask PatchAgent to implement your fix
4. Ask VerificationAgent to run tests
5. Iterate if needed

You must account for **all** listed vulnerable locations (multiple hunks/files may be affected).

Remember: YOU are the strategist. You decide what to do. Specialists help you research and execute.

Begin!
"""
        return prompt

    def _format_vulnerability_locations(self, locations: Any) -> str:
        """Format vulnerability locations as line ranges."""
        if not locations:
            return "Not provided."
        if not isinstance(locations, list):
            return "Not provided."
        formatted = []
        for entry in locations:
            if not isinstance(entry, dict):
                continue
            file_path = entry.get("file_path", "unknown")
            start_line = entry.get("start_line")
            end_line = entry.get("end_line")
            if isinstance(start_line, int) and isinstance(end_line, int):
                formatted.append(f"- {file_path}:{start_line}-{end_line}")
            elif isinstance(start_line, int):
                formatted.append(f"- {file_path}:{start_line}")
        return "\n".join(formatted) if formatted else "Not provided."

    def _parse_result(self, response: str) -> Dict[str, Any]:
        """Parse the coordinator's final response."""
        # Try to extract JSON from the response
        try:
            if "```json" in response:
                start = response.index("```json") + 7
                end = response.index("```", start)
                json_str = response[start:end].strip()
                return json.loads(json_str)
            elif "{" in response and "}" in response:
                start = response.index("{")
                end = response.rindex("}") + 1
                return json.loads(response[start:end])
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback - check if response indicates success
        response_lower = response.lower()
        if "success" in response_lower or ("tests" in response_lower and "pass" in response_lower):
            return {
                "status": "success",
                "raw_response": response[:500]
            }

        return {
            "status": "unknown",
            "raw_response": response[:500]
        }
