"""Symbol verification tool.

Checks whether symbols introduced in a patch exist in the repository and are not obviously undefined.
"""

from typing import Any, Dict, List, Set, Tuple, Optional
import ast
import logging
import re

from .base import BaseTool, ToolResult
from .docker import DockerExecutor


logger = logging.getLogger(__name__)


class SymbolVerifyTool(BaseTool):
    """Verify symbols used in new code blocks by searching the repo for definitions."""

    name = "SymbolVerify"
    description = "Check whether symbols introduced in a patch are defined in the repository."

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "changes": {
                        "type": "array",
                        "description": "List of patch change objects containing new_code/new_code_summary",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {
                                    "type": "string",
                                    "description": "File path for the change",
                                },
                                "new_code": {
                                    "type": "string",
                                    "description": "New code added by the patch",
                                },
                                "new_code_summary": {
                                    "type": "string",
                                    "description": "Summary of new code when full code is omitted",
                                },
                            },
                        },
                    },
                    "vulnerable_code": {
                        "type": "string",
                        "description": "Original vulnerable code for baseline symbol comparison",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Primary file being patched (for reporting)",
                    },
                },
                # All parameters are marked required because OpenAI's function schema validator
                # expects the required list to include every declared property.
                "required": ["changes", "vulnerable_code", "file_path"],
            },
        }

    def __init__(self, docker_executor: Optional[DockerExecutor]):
        self.docker = docker_executor

    def execute(
        self,
        changes: List[Dict[str, Any]],
        vulnerable_code: str = "",
        file_path: str = "",
    ) -> ToolResult:
        if self.docker is None:
            return ToolResult(success=False, output="", error="No Docker executor available")

        try:
            if not changes:
                return ToolResult(success=True, output="no changes", metadata={"status": "no_changes", "issues": []})

            baseline_symbols = self._extract_symbols(vulnerable_code or "")
            issues: List[Dict[str, Any]] = []
            checked = 0
            found = 0

            for change in changes:
                new_code = change.get("new_code") or change.get("new_code_summary") or ""
                if not new_code.strip():
                    continue

                new_symbols = self._extract_symbols(new_code)
                unknown_symbols = self._filter_unknown_symbols(new_symbols, baseline_symbols)

                for symbol in unknown_symbols:
                    checked += 1
                    exists, evidence = self._lookup_symbol(symbol)
                    if exists:
                        found += 1
                        continue
                    issues.append({
                        "symbol": symbol,
                        "issue": "undefined_symbol",
                        "description": f"Symbol '{symbol}' is referenced in the patch but no definition was found in the repo",
                        "file": change.get("file", file_path or "unknown"),
                        "context_excerpt": new_code[:200]
                    })

            status = "verified" if not issues else "issues_found"
            metadata = {
                "status": status,
                "issues": issues,
                "symbols_checked": checked,
                "symbols_found": found,
            }
            return ToolResult(success=True, output=status, metadata=metadata)
        except Exception as e:
            logger.debug(f"SymbolVerifyTool failed: {e}")
            return ToolResult(success=True, output="verification_failed", metadata={"status": "verification_failed", "error": str(e), "issues": []})

    # -------------------- helpers --------------------
    def _extract_symbols(self, code: str) -> Set[str]:
        symbols: Set[str] = set()
        if not code:
            return symbols
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name):
                        symbols.add(fn.id)
                    elif isinstance(fn, ast.Attribute):
                        symbols.add(fn.attr)
                elif isinstance(node, ast.Attribute):
                    symbols.add(node.attr)
                elif isinstance(node, ast.Name):
                    symbols.add(node.id)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        symbols.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        symbols.add(node.module.split('.')[0])
                    for alias in node.names:
                        symbols.add(alias.name)
        except SyntaxError:
            symbols |= self._extract_symbols_regex(code)
        return symbols

    def _extract_symbols_regex(self, code: str) -> Set[str]:
        symbols: Set[str] = set()
        symbols.update(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code))
        symbols.update(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=", code))
        symbols.update(re.findall(r"from\s+([A-Za-z_][A-Za-z0-9_.]*)", code))
        symbols.update(re.findall(r"import\s+([A-Za-z_][A-Za-z0-9_.]*)", code))
        symbols.update(re.findall(r"\.([A-Za-z_][A-Za-z0-9_]*)", code))
        return symbols

    def _filter_unknown_symbols(self, new_symbols: Set[str], baseline_symbols: Set[str]) -> List[str]:
        known = {
            'print','len','str','int','float','bool','dict','list','tuple','set','range','enumerate','zip','map','filter','sorted','reversed','sum','any','all','min','max','abs','round','open','type','isinstance','hasattr','getattr','setattr','delattr','super','property','staticmethod','classmethod','Exception','ValueError','TypeError','KeyError','IndexError','AttributeError','RuntimeError','OSError','IOError','NotImplementedError','re','os','sys','json','time','datetime','collections','itertools','functools','pathlib','logging','typing','dataclasses','enum','self','cls','args','kwargs','True','False','None'
        }
        unknown: List[str] = []
        for symbol in new_symbols:
            if (
                symbol not in baseline_symbols
                and symbol not in known
                and not symbol.startswith('__')
                and not symbol.startswith('_')
                and len(symbol) > 2
            ):
                unknown.append(symbol)
        return unknown

    def _lookup_symbol(self, symbol: str) -> Tuple[bool, str]:
        """Grep for symbol definitions in the repo using Docker executor."""
        if self.docker is None:
            return True, "tool_unavailable"
        patterns = [
            f"class {symbol}",
            f"def {symbol}",
            f"async def {symbol}",
            f"^{symbol} =",
        ]
        total_matches = 0
        outputs: List[str] = []
        for pat in patterns:
            cmd = (
                f"grep -rn '{pat}' --include='*.py' . 2>/dev/null | head -20 || true"
            )
            exit_code, output = self.docker.exec_command(cmd)
            if output.strip():
                outputs.append(f"# Definitions matching '{pat}':\n{output.strip()}")
                total_matches += output.strip().count('\n') + 1
        if total_matches > 0:
            return True, "\n\n".join(outputs)
        return False, ""
