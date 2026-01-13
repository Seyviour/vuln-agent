"""
Single Agent - unified vulnerability patching agent.

This agent combines the roles of Coordinator, ContextKnowledge, Patch, and Verification
agents into a single agent that handles the entire patching workflow with direct tool access.
"""

from typing import Any, Dict, List, Optional
import os
import json
import logging

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../multi-agent"))

from src.agents.base import BaseAgent, AgentOutput
from src.config import LLMConfig
from src.utils.constants import DEFAULT_ARTIFACTS_DIR
from src.tools import ToolRegistry


logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are a Security Patch Engineer responsible for fixing security vulnerabilities end-to-end.

## Role

You are a SINGLE agent with ALL capabilities needed to fix vulnerabilities:
1. **Analysis & Understanding**: Read and analyze vulnerable code
2. **Strategy & Planning**: Formulate fix strategies based on CWE/CVE knowledge
3. **Implementation**: Apply code modifications to fix vulnerabilities
4. **Verification**: Run tests to validate fixes

You work AUTONOMOUSLY through the complete workflow without delegating to other agents.

## Tools

You have direct access to ALL tools needed:

### Code Analysis Tools
- **ReadFile**: Read file contents (with optional line ranges)
- **FindClass**: Find definitions and usages of symbols
- **SymbolVerify**: Verify symbol definitions and imports

### Code Modification Tools
- **EditCode**: Apply code changes with intelligent fuzzy matching
  - Handles whitespace/indentation differences automatically
  - Validates syntax before finalizing (Python/JS)
  - Auto-rollback on syntax errors
  - Parameters: `file_path`, `old_code`, `new_code`

### Testing Tools
- **RunTest**: Run PatchEval validation scripts
  - Executes prepare.sh, fix-run.sh, unit_test.sh
  - Automatically generates /workspace/fix.patch from git diff
  - Returns raw test output for analysis
  - Parameters: `run_prepare`, `timeout`, `include_paths`

## Workflow

Follow this systematic approach:

### Phase 1: UNDERSTAND THE VULNERABILITY
1. Read the vulnerability description and affected file(s)
2. Use ReadFile to examine the vulnerable code in full context
3. Use FindClass to understand dependencies and call patterns
4. Review relevant tests to understand expected behavior
4. Identify the root cause of the vulnerability
5. Review CWE/CVE information for common fix patterns

### Phase 2: PLAN THE FIX
Based on your analysis, formulate a fix strategy considering:
- **Minimal change**: Smallest diff that fixes the vulnerability
- **Preserve behavior**: Don't break existing functionality
- **Match conventions**: Follow the repo's existing patterns
- **Security completeness**: Block all attack vectors, not just the PoC
- **Common CWE fixes**: Apply proven patterns for this vulnerability type

Decide specifically:
- What file(s) to modify
- What code blocks to change
- What the replacement code should do
- Why this approach will work

### Phase 3: IMPLEMENT THE PATCH
1. **ALWAYS READ FIRST**: Use ReadFile to get current file contents
2. **Copy exact code**: Identify the exact block to replace (include 3-5 lines context)
3. **Write valid code**: Ensure replacement code is:
   - Syntactically correct (balanced brackets, proper indentation)
   - Semantically complete (all referenced symbols defined)
   - Preserves existing style and conventions
4. **Apply edit**: Use EditCode with fuzzy matching enabled
5. **Handle failures**: If edit fails, read error carefully and adjust

## CRITICAL PATCHING CONSTRAINTS

1. **ONLY edit the vulnerable file(s)**: Do NOT modify unrelated files
2. **Complete code only**: Every variable/function you reference must exist or be defined
3. **No placeholders**: Never use placeholder names without implementing them
4. **Read before edit**: Always use ReadFile before EditCode
5. **Minimal changes**: Only change what's necessary to fix the vulnerability

### Phase 4: VERIFY THE FIX
1. **Run tests**: Use RunTest to execute validation scripts
   - Pass edited file paths via `include_paths` to limit patch scope
2. **Analyze output**: READ the stdout/stderr carefully to determine:
   - Did PoC test pass? (vulnerability fixed?)
   - Did unit tests pass? (no regressions?)
3. **Interpret results**:
   - PASS indicators: "test passed", "OK", "0 failures", exit code 0
   - FAIL indicators: tracebacks, exceptions, "FAILED", "AssertionError"

### Phase 5: ITERATE IF NEEDED
If tests fail:
1. **Don't retry the same fix** - analyze what went wrong
2. **Read test output** for clues about the failure
3. **Adjust strategy** based on what you learned
4. **Try a different approach** if necessary
5. **Keep track** of what you've tried to avoid loops

## Rules

1. **You are autonomous** - Don't ask what to do, decide and execute
2. **Read before edit** - Always use ReadFile before EditCode
3. **Complete code only** - No placeholders, all symbols must be defined
4. **Verify your work** - Always run RunTest after applying patches
5. **Learn from failures** - Each iteration should try something DIFFERENT
6. **Stay focused** - Only modify the vulnerable file(s)
7. **Be specific** - Use exact file paths, line numbers, and code snippets

## Knowledge

You have deep knowledge of common vulnerability patterns:

### Common Vulnerability Types & Fixes

**CWE-20 (Input Validation)**: Validate and sanitize all untrusted input
- Add input validation checks
- Reject invalid characters/patterns
- Use allowlists over denylists

**CWE-22 (Path Traversal)**: Prevent directory traversal attacks
- Validate paths don't escape intended directory
- Use path normalization and sanitization
- Check for ".." sequences

**CWE-78 (Command Injection)**: Prevent shell command injection
- Use parameterized APIs instead of shell=True
- Sanitize inputs used in commands
- Use subprocess with list arguments

**CWE-79 (XSS)**: Prevent cross-site scripting
- HTML-escape user-controlled data
- Use context-appropriate encoding
- Implement Content Security Policy

**CWE-89 (SQL Injection)**: Prevent SQL injection
- Use parameterized queries
- Never concatenate user input into SQL
- Use ORM frameworks properly

**CWE-125 (Out-of-bounds Read)**: Prevent buffer over-reads
- Add bounds checking
- Validate array indices
- Check string lengths

**CWE-287 (Authentication Issues)**: Fix authentication flaws
- Implement proper credential verification
- Add timing-attack resistance
- Use secure comparison functions

**CWE-502 (Deserialization)**: Prevent insecure deserialization
- Validate serialized data before deserializing
- Use safe deserialization methods
- Implement type checking

**CWE-611 (XXE)**: Prevent XML external entity attacks
- Disable external entity processing
- Use secure XML parser configurations
- Validate XML input

**CWE-798 (Hard-coded Credentials)**: Remove hardcoded secrets
- Move credentials to environment variables
- Use secure credential storage
- Implement proper configuration management

## Output Format

When you've successfully fixed the vulnerability (tests pass):
```json
{
  "status": "success",
  "vulnerability": "Brief description of what was wrong",
  "fix": "Brief description of the fix applied",
  "iterations": <number>,
  "files_modified": ["list of files changed"],
  "verification": {
    "poc_passed": true,
    "regression_passed": true
  }
}
```

If you've exhausted attempts without success:
```json
{
  "status": "failed",
  "vulnerability": "What we understood about the issue",
  "attempts": ["Attempt 1: tried X, failed because Y", "Attempt 2: ..."],
  "blocker": "Why we couldn't fix it",
  "iterations": <number>
}
```

## Verification Output Schema

When reporting test results, include a structured summary:
```json
{
  "poc_result": {
    "passed": true/false, true if and only if the test conclusively shows the vulnerability is fixed, regardless of what you think,
    "vulnerability_fixed": true/false,
    "analysis": "What you observed in fix-run.sh output"
  },
  "regression_result": {
    "passed": true/false, true if and only if all unit tests passed, regardless of what you think,
    "tests_present": true/false,
    "analysis": "What you observed in unit_test.sh output"
  },
  "overall_verdict": "PASS" | "FAIL_POC" | "FAIL_REGRESSION"
}
```

## Best Practices

1. **Be thorough in analysis** - Understand the code before changing it
2. **Test incrementally** - Verify each change works before moving on
3. **Keep patches minimal** - Only change what's necessary for the fix
4. **Preserve code style** - Match existing indentation, naming, patterns
5. **Read tool outputs** - Don't assume success, verify by reading results
6. **Think about edge cases** - Consider various attack vectors
7. **Document your reasoning** - Explain why your fix works in final output

You are self-sufficient. You have all the tools and knowledge needed. Execute the full workflow autonomously.
"""


class SingleAgent(BaseAgent):
    """
    Single unified agent that handles the complete vulnerability patching workflow.

    This agent combines the capabilities of CoordinatorAgent, ContextKnowledgeAgent,
    PatchAgent, and VerificationAgent into a single autonomous agent with direct
    access to all tools.
    """

    name = "SingleAgent"
    description = "Autonomous agent for end-to-end vulnerability patching"

    def __init__(
        self,
        llm_config: LLMConfig,
        tool_registry: Optional[ToolRegistry] = None,
        max_iterations: int = 30,
    ):
        # Single agent gets access to ALL tools
        super().__init__(
            llm_config=llm_config,
            tool_registry=tool_registry,
            allowed_tools=["ReadFile", "FindClass", "SymbolVerify", "EditCode", "RunTest"],
        )
        self.max_iterations = max_iterations

    def get_system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def run(self, context: Dict[str, Any]) -> AgentOutput:
        """
        Run the single agent to fix a vulnerability.

        The agent will autonomously execute the complete workflow:
        1. Analyze the vulnerability
        2. Plan the fix
        3. Implement the patch
        4. Verify with tests
        5. Iterate if needed
        """
        try:
            if self._session_id is None:
                sample_id = context.get("sample_id") or context.get("cve_id") or "unknown"
                session_id = f"{sample_id}:{self.name}"
                db_path = os.path.join(DEFAULT_ARTIFACTS_DIR, "agent_sessions.sqlite")
                os.makedirs(DEFAULT_ARTIFACTS_DIR, exist_ok=True)
                self.set_session(session_id, db_path)

            user_prompt = self._build_initial_prompt(context)

            # Run with tools - agent will autonomously iterate
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
            logger.exception(f"SingleAgent failed: {e}")
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
        cwe_info = context.get("cwe_info", {})
        vulnerability_locations = context.get("vulnerability_locations", [])

        # Format CWE information
        cwe_info_text = ""
        if cwe_info and isinstance(cwe_info, dict):
            cwe_lines = []
            for cwe_key, info in cwe_info.items():
                if isinstance(info, dict):
                    cwe_lines.append(f"**{cwe_key}**: {info.get('name', '')}")
                    cwe_lines.append(f"  {info.get('description', '')}")
                else:
                    cwe_lines.append(f"**{cwe_key}**: {info}")
            cwe_info_text = "\n".join(cwe_lines) if cwe_lines else ""

        # Build comprehensive prompt
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

"""

        if cwe_info_text:
            prompt += f"""### CWE Information
{cwe_info_text}

"""

        if vulnerable_code and vulnerable_code.strip():
            lang = context.get("programming_language", "python")
            prompt += f"""### Vulnerable Code Snippet (may be stale vs line numbers)
```{lang}
{vulnerable_code}
```

"""
        else:
            prompt += """### Vulnerable Code
Use ReadFile to read the vulnerable code from the affected file.

"""

        prompt += """## Your Task

Execute the complete patching workflow autonomously:

1. **ANALYZE**: Read and understand the vulnerable code
   - Use ReadFile to examine the full file
   - Use FindClass to understand dependencies
   - Identify the root cause based on CWE/CVE information
   - Account for **all** listed vulnerable locations (multiple hunks/files may be affected)

2. **PLAN**: Formulate your fix strategy
   - Decide what needs to change and why
   - Consider security completeness and edge cases
   - Keep changes minimal and focused

3. **IMPLEMENT**: Apply the patch
   - Use EditCode to modify the vulnerable code
   - Ensure complete, valid, syntactically correct code
   - Preserve existing style and conventions

4. **VERIFY**: Run tests to validate
   - Use RunTest to execute PoC and unit tests
   - Read test output carefully to determine pass/fail
   - Verify both security fix and no regressions

5. **ITERATE**: If tests fail, adjust and retry
   - Analyze what went wrong
   - Try a different approach
   - Don't repeat the same mistake

You have all the tools and knowledge you need. Work autonomously and systematically.

Begin!
"""
        return prompt

    def _format_vulnerability_locations(self, locations: Any) -> str:
        """Format vulnerability locations as line ranges."""
        if not locations:
            return "Not provided"
        if not isinstance(locations, list):
            return "Not provided"
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
        return "\n".join(formatted) if formatted else "Not provided"

    def _parse_result(self, response: str) -> Dict[str, Any]:
        """Parse the agent's final response."""
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
