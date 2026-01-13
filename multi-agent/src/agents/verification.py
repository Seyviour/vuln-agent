"""Verification Agent - Dynamic validation and feedback."""

from typing import Any, Dict, List, Optional, Tuple
import json
import logging
import re

from .base import BaseAgent, AgentOutput
from ..config import LLMConfig
from ..tools import ToolRegistry
from ..utils.constants import DEFAULT_SCRIPT_TIMEOUT


logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are a Security Verification Engineer responsible for validating vulnerability patches.

**IMPORTANT**: When invoked via AskAgent, focus on your task and provide clear test results and feedback.

## Role

After a patch is applied, you verify it using PatchEval's validation scripts:
1. Run the PoC (Proof of Concept) test to verify the vulnerability is fixed
2. Run the unit test suite (if present) to verify no regressions were introduced
3. Produce structured feedback for the Planner if the patch fails

## Tools

### RunTest
Runs PatchEval validation scripts in sequence:
1. **prepare.sh** - Resets the repository to a clean state
2. **fix-run.sh** - Executes the PoC to verify the vulnerability is patched
3. **unit_test.sh** - (if present) Runs unit tests for functional correctness

Parameters:
- `run_prepare`: Whether to run prepare.sh first (default: true)
- `timeout`: Timeout in seconds for each script (default: 120)
 - `include_paths`: Optional list of file paths to limit the diff used to build /workspace/fix.patch. Pass the files you edited (e.g., from EditCode).

The tool automatically:
- Extracts the git diff from your applied changes
- Writes it to /workspace/fix.patch
- Runs the validation scripts
- Returns the raw stdout/stderr output

## Test Output Rules

**YOU must read the stdout/stderr output to determine if tests pass or fail.**

The RunTest tool returns raw output - it does NOT tell you if tests passed. You must analyze:

### For PoC (fix-run.sh):
- **PASS indicators**: "test passed", "vulnerability fixed", "OK", exit code 0 with no errors
- **FAIL indicators**: tracebacks, exceptions, "FAILED", "AssertionError", "vulnerability still present"

### For Unit Tests (unit_test.sh):
- **PASS indicators**: "OK", "passed", "0 failures", all tests green
- **FAIL indicators**: "FAILED", "ERROR", assertion failures, exceptions, non-zero failure count

### Exit Codes:
- Exit code 0 usually means success, but ALWAYS verify by reading the actual output
- Exit code non-zero usually means failure, but check the output for details

## Workflow

1. **Call RunTest**: Simply call the RunTest tool - it handles setup automatically
2. **READ THE OUTPUT CAREFULLY**: The tool returns raw stdout/stderr - analyze it to determine:
   - Did the PoC test pass? (vulnerability fixed?)
   - Did unit tests pass? (no regressions?)
3. **Provide Feedback**: Based on YOUR analysis of the output, provide actionable feedback
 4. When calling RunTest, if `edited_files` are provided in context, pass them via `include_paths` to restrict the patch to only those files.

## Output Format

After running the test and READING THE OUTPUT, provide your analysis:

```json
{
    "poc_result": {
        "passed": true/false, true if and only if the test conclusively shows the vulnerability is fixed
        "vulnerability_fixed": true/false,
        "analysis": "What you observed in the fix-run.sh output that led to this conclusion"
    },
    "regression_result": {
        "passed": true/false, true if and only if all unit tests passed
        "tests_present": true/false,
        "analysis": "What you observed in the unit_test.sh output (if present)"
    },
    "overall_verdict": "PASS" | "FAIL_POC" | "FAIL_REGRESSION",
    "feedback_for_planner": {
        "issues": ["List of specific issues from the test output"],
        "suggestions": ["Concrete suggestions for fixing the issues"],
        "suspected_cause": "Analysis of the root cause of failures",
        "output_excerpt": "Relevant portion of test output showing the failure"
    }
}
```

Be thorough in your analysis. Quote specific lines from the output to support your conclusions. If a test fails, you must mark it as such, there is no room for interpretation in that case. If either poc or unit tests are missing, you may mark them as passed"""


class VerificationAgent(BaseAgent):
    """Agent that validates patches through dynamic testing."""
    
    name = "VerificationAgent"
    description = "Validates patches through PoC and regression testing"
    
    def __init__(
        self,
        llm_config: LLMConfig,
        tool_registry: ToolRegistry
    ):
        super().__init__(
            llm_config=llm_config,
            tool_registry=tool_registry,
            allowed_tools=["RunTest"]  # Execution access
        )
    
    def get_system_prompt(self) -> str:
        return SYSTEM_PROMPT
    
    def run(self, context: Dict[str, Any]) -> AgentOutput:
        """
        Verify the patch through testing.
        
        Expected context:
        - patch_result: Output from PatchAgent
        - file_path: Path to the patched file
        - test_paths: Optional specific test paths to run
        - poc_test: Optional specific PoC test to run
        """
        try:
            user_prompt = self._build_user_prompt(context)

            # Optionally run RunTest upfront with include_paths=edited_files
            pre_tool_calls: List[Dict[str, Any]] = []
            edited_files = context.get('edited_files', []) or []
            if self.tool_registry and "RunTest" in self.allowed_tools:
                run_args: Dict[str, Any] = {"run_prepare": True, "timeout": DEFAULT_SCRIPT_TIMEOUT}
                if edited_files:
                    run_args["include_paths"] = edited_files
                # Execute tool; safe when include_paths is empty/not provided
                pre_result = self._execute_tool("RunTest", run_args)
                # Attach output to prompt for LLM interpretation
                pre_output = pre_result.output or pre_result.error or ""
                if pre_output:
                    # Truncate large outputs in prompt to keep tokens reasonable
                    truncated = pre_output[:8000]
                    user_prompt += f"\n\n### Test Output (pre-run)\n{truncated}\n\n"
                # Record tool call in our local log
                pre_tool_calls.append({
                    "tool": "RunTest",
                    "arguments": run_args,
                    "result": {
                        "success": pre_result.success,
                        "output": pre_result.output,
                        "error": pre_result.error,
                        "metadata": pre_result.metadata or {}
                    },
                    "success": pre_result.success,
                })

            # Let the LLM analyze stdout; it may choose to re-run tools if needed
            response, tool_calls, token_usage = self._run_with_tools(user_prompt, max_iterations=-1)
            tool_calls = pre_tool_calls + tool_calls
            
            verification_result = self._parse_verification_result(response, tool_calls)
            
            # Determine overall success
            success = verification_result.get('overall_verdict') == 'PASS'

            return AgentOutput(
                agent_name=self.name,
                success=success,
                content=verification_result,
                raw_response=response,
                tool_calls=tool_calls,
                token_usage=token_usage,
                tool_calls_count=len(tool_calls)
            )
            
        except Exception as e:
            logger.exception(f"VerificationAgent failed: {e}")
            return AgentOutput(
                agent_name=self.name,
                success=False,
                content={"error": str(e)},
                error=str(e),
                token_usage=getattr(self, "_last_token_usage", {}),
                tool_calls_count=0
            )
    
    def _build_user_prompt(self, context: Dict[str, Any]) -> str:
        """Build the user prompt from context."""
        patch_result = context.get('patch_result', {})
        edited_files = context.get('edited_files', [])
        
        test_hints = ""
        if context.get('test_paths'):
            test_hints = f"\n**Suggested test paths:** {', '.join(context['test_paths'])}"
        if context.get('poc_test'):
            test_hints += f"\n**PoC test:** {context['poc_test']}"
        
        edited_files_hint = ("\n**Edited files:** " + ", ".join(edited_files)) if edited_files else ""

        return f"""## Verification Task

### Patch Summary
{json.dumps(patch_result, indent=2)}

### Patched File
**Path:** {context.get('file_path', 'Unknown')}
{test_hints}
{edited_files_hint}

## Your Task

1. Run tests to verify the vulnerability is fixed
2. Run tests to check for regressions
3. Analyze any failures and provide actionable feedback

Start by running the tests, then analyze the results and provide your verification report.

Hint: Use the RunTest tool and pass `include_paths` with the list above if present to ensure /workspace/fix.patch only includes your code edits."""
    
    def _parse_verification_result(
        self,
        response: str,
        tool_calls: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Parse verification result from response and tool calls."""
        result = {
            "poc_result": {"passed": False},
            "regression_result": {"passed": False},
            "overall_verdict": "UNKNOWN",
            "feedback_for_planner": {"issues": [], "suggestions": [], "output_excerpt": ""}
        }
        
        # Extract raw tool output for LLM-driven interpretation
        for tc in tool_calls:
            if tc.get('tool') == 'RunTest':
                tc_result = tc.get('result', {})
                metadata = tc_result.get('metadata', {})
            validation_type = metadata.get('validation_type')
            output_preview = tc_result.get('output', '')[:2000]

            if validation_type is not None:
                # If upstream tooling provided a structured validation type, preserve it
                poc_result = metadata.get('poc_result')
                unittest_result = metadata.get('unittest_result')
                failure_details = metadata.get('failure_details')

                result['poc_result'] = {
                    "passed": bool(poc_result),
                    "output": output_preview,
                    "vulnerability_fixed": bool(poc_result),
                }
                result['regression_result'] = {
                    "passed": bool(unittest_result) if unittest_result is not None else False,
                    "total_tests": 0,
                    "passed_tests": 0,
                    "failed_tests": 0,
                    "output": output_preview,
                }

                # Let LLM decide pass/fail in its JSON; avoid hard decisions here
                result['overall_verdict'] = result['overall_verdict']

                if failure_details:
                    result.setdefault('feedback_for_planner', {}).setdefault('issues', []).append(
                        f"Test failure detail: {failure_details}"
                    )

                # Still attach output excerpt for downstream analysis
                result.setdefault('feedback_for_planner', {})['output_excerpt'] = output_preview
                continue

            # No structured metadata from tool; attach raw output for LLM interpretation
            result.setdefault('feedback_for_planner', {})['output_excerpt'] = output_preview
        
        # Try to parse structured output from response
        json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                result.update(parsed)
            except json.JSONDecodeError:
                pass
        
        # Determine overall verdict only from LLM-provided JSON; otherwise keep UNKNOWN
        if result['overall_verdict'] == 'UNKNOWN':
            pass
        
        return result
