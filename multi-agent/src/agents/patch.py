"""Patch Agent - Code modification implementation."""

from typing import Any, Dict, List, Optional
import json
import logging
import re

from .base import BaseAgent, AgentOutput
from ..config import LLMConfig
from ..tools import ToolRegistry


logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are a Security Patch Developer responsible for implementing vulnerability fixes.

**IMPORTANT**: When invoked via AskAgent, focus on your task and provide clear, concise feedback about the implementation.

## Role
You receive high-level guidance describing WHAT to fix, not HOW. You must implement the fix with correct, complete code.

## Rules

1. **ONLY edit the vulnerable file(s)**: You may ONLY modify files explicitly listed in the vulnerability location. Do NOT edit any other files.
2. **Complete Code Only**: Every variable, function, regex pattern, or constant you reference MUST be defined
3. **No Placeholders**: Never use placeholder names like `enhanced_pattern`, `new_validator`, `helper_function` without implementing them
4. **No Undefined References**: If you add `foo(x)`, the function `foo` must exist or you must define it
5. **Verify Before Edit**: After reading the file, mentally trace your new code to ensure all symbols resolve
6. **Rigor**: Be thorough, defensive and rigorous in your implementation. If you spot any issues the planner did not account for, fix them and report back in your patch summary.

## Guidelines
- Minimal changes only; preserve behavior.
- Use ReadFile before EditCode.
- Ensure every referenced symbol is defined.

## Output Format
Return a JSON summary with patch_applied and a short change description.
Be precise and careful. Incorrect patches waste verification cycles."""


class PatchAgent(BaseAgent):
    """Agent that implements code patches based on planner decisions."""
    
    name = "PatchAgent"
    description = "Implements vulnerability fixes based on planner decisions"
    
    def __init__(
        self,
        llm_config: LLMConfig,
        tool_registry: ToolRegistry
    ):
        super().__init__(
            llm_config=llm_config,
            tool_registry=tool_registry,
            allowed_tools=["EditCode", "ReadFile"]  # Write access
        )
    
    def get_system_prompt(self) -> str:
        return SYSTEM_PROMPT
    
    def run(self, context: Dict[str, Any]) -> AgentOutput:
        """
        Apply patch based on planner decision.
        
        Expected context:
        - decision_record: Output from PlannerAgent
        - file_path: Path to the file to patch
        - vulnerable_code: The vulnerable code snippet (for reference)
        """
        try:
            decision = context.get('decision_record', {})
            next_action = decision.get('next_action', {})
            
            if not next_action:
                return AgentOutput(
                    agent_name=self.name,
                    success=False,
                    content={},
                    error="No next_action in decision record",
                    token_usage={},
                    tool_calls_count=0
                )
            
            user_prompt = self._build_user_prompt(context, decision, next_action)

            response, tool_calls, token_usage = self._run_with_tools(user_prompt, max_iterations=-1)
            
            patch_result = self._parse_patch_result(response, tool_calls)
            
            # Check if edit was successful
            edit_success = any(
                tc.get('result', {}).get('success', False)
                for tc in tool_calls
                if tc.get('tool') == 'EditCode'
            )
            
            patch_result['patch_applied'] = edit_success
            
            return AgentOutput(
                agent_name=self.name,
                success=edit_success,
                content=patch_result,
                raw_response=response,
                tool_calls=tool_calls,
                token_usage=token_usage,
                tool_calls_count=len(tool_calls)
            )
            
        except Exception as e:
            logger.exception(f"PatchAgent failed: {e}")
            return AgentOutput(
                agent_name=self.name,
                success=False,
                content={},
                error=str(e),
                token_usage=getattr(self, "_last_token_usage", {}),
                tool_calls_count=0
            )
    
    def _build_user_prompt(
        self,
        context: Dict[str, Any],
        decision: Dict[str, Any],
        next_action: Dict[str, Any]
    ) -> str:
        """Build the user prompt from context and decision."""
        target_file = next_action.get('target_file', context.get('file_path', 'Unknown'))
        
        # Use problem_statement if available (contains rich vulnerability info)
        problem_statement = context.get('problem_statement', '')
        prior_patch_applied = context.get("last_patch_success", False) or \
            context.get("patch_result", {}).get("patch_applied", False)

        if prior_patch_applied:
            vuln_section = """### Vulnerable Code (Reference)
NOTE: A prior patch was already applied in this run. The vulnerable snippet below
may be stale. Do NOT use it for matching; rely on ReadFile output instead.
"""
        elif problem_statement:
            vuln_section = f"""### Problem Statement
{problem_statement}

### Vulnerable Code (Reference)
```python
{context.get('vulnerable_code', 'No code provided')}
```"""
        else:
            vuln_section = f"""### Vulnerable Code (Reference)
```python
{context.get('vulnerable_code', 'No code provided')}
```"""
        
        return f"""## Patch Task
Target file: {target_file}
Location: {next_action.get('target_location', 'See guidance')}

{vuln_section}

Guidance:
{next_action.get('guidance', next_action.get('instruction', 'No guidance provided'))}

Security requirements:
{self._format_list(next_action.get('security_requirements', ['See guidance above']))}

Must preserve:
{self._format_list(next_action.get('must_preserve', ['Existing API behavior']))}

Read the file, implement the minimal fix, then respond with a short JSON summary."""
    
    def _format_list(self, items: List[str]) -> str:
        """Format a list of items as bullet points."""
        if not items:
            return "- None specified"
        return "\n".join(f"- {item}" for item in items)
    
    def _parse_patch_result(
        self,
        response: str,
        tool_calls: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Parse patch result from response and tool calls."""
        result = {
            "patch_applied": False,
            "changes": [],
            "tool_calls_summary": []
        }
        
        # Extract edit operations from tool calls
        for tc in tool_calls:
            if tc.get('tool') == 'EditCode':
                args = tc.get('arguments', {})
                tc_result = tc.get('result', {})
                metadata = tc_result.get('metadata', {})
                
                change = {
                    "file": args.get('file_path', 'unknown'),
                    "success": tc_result.get('success', False),
                    "error": tc_result.get('error')
                }
                # Capture old_code and new_code for generating diffs
                if tc_result.get('success', False):
                    change['old_code'] = args.get('old_code', '')
                    change['new_code'] = args.get('new_code', '')
                    # Capture full file content for inspection
                    if 'full_file_content' in metadata:
                        change['full_file_content'] = metadata['full_file_content']
                    if 'diff' in metadata:
                        change['diff'] = metadata['diff']
                        
                result['changes'].append(change)
                result['tool_calls_summary'].append({
                    "tool": "EditCode",
                    "file": args.get('file_path'),
                    "success": tc_result.get('success', False),
                    "result": tc_result  # Include full result for metadata access
                })
        
        # Try to parse structured output from response
        json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                result.update(parsed)
            except json.JSONDecodeError:
                pass
        
        return result
