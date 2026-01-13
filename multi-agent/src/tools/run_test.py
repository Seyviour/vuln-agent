"""
RunTest tool implementation.

Runs PatchEval validation scripts for vulnerability patch verification.
The tool returns raw stdout/stderr output for the LLM to analyze and determine
whether tests pass or fail.
"""

from typing import Any, Dict, Optional, List
import logging

from .base import BaseTool, ToolResult
from .docker import DockerExecutor
from ..utils.constants import DEFAULT_SCRIPT_TIMEOUT


logger = logging.getLogger(__name__)


class RunTestTool(BaseTool):
    """
    Run PatchEval validation scripts for vulnerability patch verification.
    
    This tool executes the PatchEval Docker container scripts:
    1. prepare.sh - Resets all changes in the repository
    2. fix-run.sh - Executes the PoC to verify the vulnerability is fixed
    3. prepare.sh - Resets before unit tests to ensure a clean state
    4. unit_test.sh - (if present) Executes unit tests for functional correctness
    
    The patch must be written to /workspace/fix.patch before running fix-run.sh.
    
    NOTE: This tool returns the raw output from the scripts. The LLM should
    analyze the stdout/stderr to determine if tests pass or fail.
    """
    
    name = "RunTest"
    description = (
        "Run PatchEval validation scripts and return their output. "
        "Executes prepare.sh (reset), fix-run.sh (PoC validation), "
        "and unit_test.sh (if present). "
        "YOU must read the stdout/stderr output to determine if tests pass or fail. "
        "Look for error messages, assertion failures, exceptions, or success indicators."
    )
    
    def __init__(
        self,
        docker_executor: Optional[DockerExecutor],
        cve_id: Optional[str] = None
    ):
        """
        Initialize RunTest tool.
        
        Args:
            docker_executor: Docker executor for container operations
            cve_id: CVE ID for context
        """
        self.docker = docker_executor
        self.cve_id = cve_id
    
    def execute(
        self,
        run_prepare: bool = True,
        timeout: int = DEFAULT_SCRIPT_TIMEOUT,
        include_paths: Optional[List[str]] = None,
        run_unittest: bool = True,
    ) -> ToolResult:
        """
        Run PatchEval validation scripts.
        
        Args:
            run_prepare: Whether to run prepare.sh first to reset the repo
            timeout: Timeout in seconds for each script
            include_paths: Limit diff to specific file paths (e.g., those EditCode modified)
            run_unittest: Whether to run unit_test.sh (default: True)
        
        Returns:
            ToolResult with:
            - success: True if PoC passes AND unit tests pass (or don't exist)
            - output: Combined output from all scripts
            - metadata: Detailed results including poc_result, unittest_result
        """
        run_prepare = True
        # run_unittest = False
        if self.docker is None:
            return ToolResult(
                success=False,
                output="",
                error="No Docker executor available. RunTest requires a Docker container."
            )
        
        # Check that fix-run.sh exists (required for PatchEval)
        if not self.docker.file_exists("/workspace/fix-run.sh"):
            return ToolResult(
                success=False,
                output="",
                error=(
                    "fix-run.sh not found in /workspace. "
                    "This container may not be a valid PatchEval Docker image."
                )
            )
        
        output_parts = []
        
        # Step 1: Extract the git patch from current changes
        patch = self._extract_git_patch(include_paths=include_paths)
        if not patch:
            return ToolResult(
                success=False,
                output="",
                error=(
                    "No patch diff found. Please apply code changes using EditCode before running tests. "
                    "The fix-run.sh script expects a patch at /workspace/fix.patch."
                )
            )
        
        # Step 2: Run prepare.sh if requested (after extracting the patch)
        if run_prepare:
            prepare_result = self._run_prepare_script(timeout)
            if prepare_result:
                output_parts.append(prepare_result["output"])
                if not prepare_result["success"]:
                    return ToolResult(
                        success=False,
                        output="\n\n".join(output_parts),
                        error=f"prepare.sh failed with exit code {prepare_result['exit_code']}",
                        metadata={
                            "prepare_result": False,
                            "poc_result": None,
                            "unittest_result": None,
                            "validation_type": "patcheval"
                        }
                    )
        
        # Step 3: Write the patch to /workspace/fix.patch
        write_code, write_output = self.docker.write_file("/workspace/fix.patch", patch)
        if write_code != 0:
            return ToolResult(
                success=False,
                output="\n\n".join(output_parts) if output_parts else "",
                error=f"Failed to write /workspace/fix.patch: {write_output}"
            )
        
        # Step 4: Run fix-run.sh for PoC validation
        poc_result = self._run_fix_script(timeout)
        output_parts.append(poc_result["output"])
        
        # Step 5: Run unit_test.sh if enabled and exists
        unittest_result = None
        if run_unittest:
            if run_prepare:
                prepare_result = self._run_prepare_script(timeout)
                if prepare_result:
                    output_parts.append(prepare_result["output"])
                    if not prepare_result["success"]:
                        return ToolResult(
                            success=False,
                            output="\n\n".join(output_parts),
                            error=f"prepare.sh failed with exit code {prepare_result['exit_code']}",
                            metadata={
                                "prepare_result": False,
                                "poc_result": poc_result["exit_code"] == 0,
                                "unittest_result": None,
                                "validation_type": "patcheval"
                            }
                        )
                write_code, write_output = self.docker.write_file("/workspace/fix.patch", patch)
                if write_code != 0:
                    return ToolResult(
                        success=False,
                        output="\n\n".join(output_parts) if output_parts else "",
                        error=f"Failed to write /workspace/fix.patch: {write_output}"
                    )

            unittest_result = self._run_unittest_script(timeout)
            if unittest_result:
                output_parts.append(unittest_result["output"])
            else:
                output_parts.append("=== unit_test.sh not present (skipped) ===")
        else:
            output_parts.append("=== unit_test.sh skipped (run_unittest=False) ===")
        
        # Combine all output
        full_output = "\n\n".join(output_parts)
        
        # Build result summary with exit codes (LLM determines pass/fail from output)
        result_summary = [
            f"=== Test Execution Complete ===",
            f"PoC Script (fix-run.sh) Exit Code: {poc_result['exit_code']}",
        ]
        if run_unittest:
            if unittest_result is not None:
                result_summary.append(f"Unit Test Script (unit_test.sh) Exit Code: {unittest_result['exit_code']}")
            else:
                result_summary.append("Unit Tests: N/A (no unit_test.sh found)")
        else:
            result_summary.append("Unit Tests: Skipped (run_unittest=False)")
        
        result_summary.append("")
        result_summary.append(">>> READ THE OUTPUT BELOW to determine if tests PASS or FAIL <<<")
        result_summary.append("Look for: error messages, assertion failures, exceptions, tracebacks, or success indicators.")
        
        # Always return success=True for tool execution - let LLM interpret results
        return ToolResult(
            success=True,  # Tool executed successfully; LLM interprets test results
            output=f"{chr(10).join(result_summary)}\n\n{full_output}",
            metadata={
                "poc_exit_code": poc_result["exit_code"],
                "unittest_exit_code": unittest_result["exit_code"] if unittest_result else None,
                "validation_type": "patcheval",
                "patch_written": True,
                "note": "LLM should analyze output to determine pass/fail"
            }
        )
    
    def _extract_git_patch(self, include_paths: Optional[List[str]] = None) -> Optional[str]:
        """Extract a unified diff from the container workspace, excluding test patch paths.

        PatchEval supplies /workspace/test.patch for test updates. To avoid leaking those
        hunks into /workspace/fix.patch, we exclude any paths mentioned in test.patch when
        generating the diff. This works even when tests are not under tests/.
        """
        if not self.docker:
            return None

        exclude_paths = self._get_test_patch_paths()
        logger.info(f"Generating git diff for fix.patch")
        logger.info(f"  include_paths: {include_paths or 'all non-test files'}")
        logger.info(f"  exclude_paths (from test.patch): {list(exclude_paths) if exclude_paths else 'none'}")
        
        exclude_args = " ".join(f"':(exclude){p}'" for p in exclude_paths) if exclude_paths else ""

        # Limit diff to explicitly edited files if provided
        include_spec = ""
        if include_paths:
            # Quote each pathspec and allow nested exclusions to apply
            include_spec = " ".join(f"'{p}'" for p in include_paths)

        if include_spec:
            diff_cmd = f"git diff HEAD -- {include_spec} {exclude_args}".strip()
        else:
            diff_cmd = f"git diff HEAD -- . {exclude_args}".strip()

        logger.info(f"  git diff command: {diff_cmd}")
        exit_code, output = self.docker.exec_command(diff_cmd)
        
        if exit_code == 0 and output.strip():
            logger.info(f"  Generated patch: {len(output)} bytes, {output.count(chr(10))} lines")
            logger.info(f"  Patch content:\n{output}")
            return output + "\n"
        
        logger.warning(f"  No diff generated (exit_code={exit_code}, output_len={len(output)})")
        return None

    def _get_test_patch_paths(self) -> set[str]:
        """Collect file paths touched by /workspace/test.patch to exclude from fix.patch."""
        paths: set[str] = set()
        if not self.docker or not self.docker.file_exists("/workspace/test.patch"):
            logger.debug("No /workspace/test.patch found; no paths to exclude")
            return paths

        exit_code, patch_contents = self.docker.read_file("/workspace/test.patch")
        if exit_code != 0 or not patch_contents:
            logger.warning(f"Failed to read /workspace/test.patch (exit_code={exit_code})")
            return paths

        for line in patch_contents.splitlines():
            if line.startswith("+++ b/") or line.startswith("--- a/"):
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[1].replace("a/", "", 1).replace("b/", "", 1)
                    # Only track non-devnull entries
                    if path != "/dev/null":
                        paths.add(path)
        
        logger.info(f"Extracted {len(paths)} file paths from /workspace/test.patch: {list(paths)}")
        return paths
    
    def _run_prepare_script(self, timeout: int) -> Optional[Dict[str, Any]]:
        """Run prepare.sh to reset the repository."""
        if not self.docker.file_exists("/workspace/prepare.sh"):
            return None
        
        logger.info("Running prepare.sh to reset repository...")
        exit_code, output = self.docker.exec_command(
            f"timeout {timeout} bash /workspace/prepare.sh 2>&1"
        )
        
        return {
            "success": exit_code == 0,
            "exit_code": exit_code,
            "output": f"=== prepare.sh (exit: {exit_code}) ===\n{output}"
        }
    
    def _run_fix_script(self, timeout: int) -> Dict[str, Any]:
        """Run fix-run.sh for PoC validation."""
        logger.info("Running fix-run.sh for PoC validation...")
        exit_code, output = self.docker.exec_command(f"cat /workspace/fix.patch 2>&1")
        logger.info(f"Patch being tested:\n{output}")

        # exit()

        exit_code, output = self.docker.exec_command(
            f"timeout {timeout} bash /workspace/fix-run.sh 2>&1"
        )

        logger.info(f"fix-run.sh completed with exit code {exit_code}")
        logger.info(f"fix-run.sh output:\n{output}")

        # exit()
        
        return {
            "exit_code": exit_code,
            "output": f"=== fix-run.sh (exit: {exit_code}) ===\n{output}"
        }
    
    def _run_unittest_script(self, timeout: int) -> Optional[Dict[str, Any]]:
        """Run unit_test.sh if it exists."""
        if not self.docker.file_exists("/workspace/unit_test.sh"):
            return None
        
        logger.info("Running unit_test.sh for regression testing...")
        exit_code, output = self.docker.exec_command(
            f"timeout {timeout} bash /workspace/unit_test.sh 2>&1"
        )
        logger.info(f"unit_test.sh completed with exit code {exit_code}")
        logger.info(f"unit_test.sh output:\n{output}")
        
        return {
            "exit_code": exit_code,
            "output": f"=== unit_test.sh (exit: {exit_code}) ===\n{output}"
        }
    
    def get_schema(self) -> Dict[str, Any]:
        """Get JSON schema for LLM function calling."""
        return {
            "name": self.name,
            "description": (
                "Run PatchEval validation scripts and return their stdout/stderr output. "
                "YOU must read the output to determine if tests pass or fail. "
                "Look for: tracebacks, assertion errors, 'FAILED', 'PASSED', exceptions, etc. "
                "Exit code 0 usually means success, but ALWAYS verify by reading the output."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "run_prepare": {
                        "type": "boolean",
                        "description": (
                            "Whether to run prepare.sh first to reset the repository. "
                            "Default: true. Set to false only if you want to preserve previous state."
                        )
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds for each script (default: 120)"
                    },
                    "include_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Limit the diff to specific file paths (e.g., those EditCode modified). "
                            "If omitted, diff includes all non-test changes."
                        )
                    },
                    "run_unittest": {
                        "type": "boolean",
                        "description": (
                            "Whether to run unit_test.sh for regression testing (default: true). "
                            "Set to false to skip unit tests and only run fix-run.sh."
                        )
                    }
                },
                "required": []
            }
        }
