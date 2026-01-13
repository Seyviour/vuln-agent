# Multi-Agent System Architecture

This document provides detailed technical documentation of the multi-agent vulnerability patching system architecture.

## System Overview

The system uses a **Coordinator-based architecture** where a central CoordinatorAgent orchestrates specialist agents to automatically patch security vulnerabilities. The system is built on the [OpenAI Agents SDK](https://github.com/openai/openai-agents-sdk) and designed for the [PatchEval benchmark](https://github.com/patcheval/patcheval).

## Architecture Pattern: Coordinator-Specialist

```
                    ┌─────────────────────────────┐
                    │    CoordinatorAgent         │
                    │  (Strategic Orchestrator)   │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │    AskAgent Tool    │ (Inter-agent communication)
                    └──────────┬──────────┘
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                  │
            ▼                  ▼                  ▼
    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │   Context    │   │    Patch     │   │ Verification │
    │  Knowledge   │   │    Agent     │   │    Agent     │
    │    Agent     │   │              │   │              │
    └──────────────┘   └──────────────┘   └──────────────┘
```

### Key Architectural Principles

1. **Centralized Coordination**: CoordinatorAgent makes all strategic decisions
2. **Specialist Delegation**: Specialist agents focus on specific tasks
3. **Tool-Based Communication**: AskAgent tool enables structured inter-agent calls
4. **Session Persistence**: OpenAI Agents SDK SQLiteSession maintains conversation history
5. **Iterative Refinement**: Feedback loops allow learning from failures

## Agent Roles and Responsibilities

### CoordinatorAgent
**Purpose**: Strategic orchestrator that leads the patching workflow

**Responsibilities**:
- Coordinate the overall patching workflow
- Decide when to call which specialist agents
- Synthesize information from multiple specialists
- Determine when the patch is complete or failed
- Manage the repair loop iterations

**Tools Available**:
- `AskAgent` - Call specialist agents
- `ReadFile` - Read repository files for context
- `EditCode` - Apply patches (delegated from PatchAgent recommendations)
- `RunTest` - Execute validation (delegated from VerificationAgent)

**Communication Pattern**:
```python
# Coordinator calls specialist via AskAgent
result = coordinator.ask_agent(
    agent_name="ContextKnowledgeAgent",
    user_prompt="Analyze the vulnerable function..."
)
```

### ContextKnowledgeAgent
**Purpose**: Repository expert providing deep codebase understanding

**Responsibilities**:
- Build comprehensive repository understanding at initialization
- Analyze vulnerable code in context of the entire codebase
- Extract function semantics, API contracts, and security constraints
- Identify repository conventions and coding patterns
- Generate constraint sheet for patching

**Tools Available**:
- `ReadFile` - Read source files
- `FindClass` - Locate class/function definitions
- `GrepSearch` - Search codebase patterns

**Output Format**:
```python
{
    "constraint_sheet": {
        "function_semantics": {...},
        "api_contract": {...},
        "security_analysis": {...},
        "repo_conventions": {...},
        "patch_constraints": {...}
    }
}
```

**Design Philosophy**: Acts as the "go-to expert" for understanding the codebase. Other agents can ask it questions about the repository structure, patterns, and constraints.

### PatchAgent
**Purpose**: Code modification specialist

**Responsibilities**:
- Apply specific code changes based on coordinator's strategy
- Ensure syntax correctness
- Maintain code style consistency
- Generate unified diffs
- Handle multi-file patches

**Tools Available**:
- `EditCode` - Apply old_code → new_code transformations
- `ReadFile` - Verify current file state before editing

**Output Format**:
```python
{
    "patch_applied": bool,
    "changes": [
        {
            "file": "path/to/file.py",
            "description": "Added input validation",
            "old_code_summary": "...",
            "new_code_summary": "...",
            "success": bool,
            "diff": "unified diff"
        }
    ],
    "diff": "complete unified diff"
}
```

**Key Features**:
- Fuzzy matching for robust code location
- Syntax validation before finalizing edits
- Auto-rollback on syntax errors
- Symbol verification to prevent breaking changes

### VerificationAgent
**Purpose**: Test execution and validation specialist

**Responsibilities**:
- Execute PoC (proof-of-concept) tests to verify vulnerability is fixed
- Run regression/unit tests to ensure no breakage
- Analyze test failures and provide actionable feedback
- Generate structured feedback for the next repair iteration

**Tools Available**:
- `RunTest` - Execute pytest in Docker containers
- `ReadFile` - Read test files to understand failures

**Output Format**:
```python
{
    "poc_result": {
        "passed": bool,
        "output": "...",
        "exit_code": int
    },
    "regression_result": {
        "passed": bool,
        "output": "...",
        "exit_code": int
    },
    "overall_verdict": "pass|fail_poc|fail_regression|fail_error",
    "feedback_for_planner": {
        "issues": [...],
        "suggestions": [...]
    }
}
```

## System Workflow

### Phase 1: Initialization
```
1. Load sample from PatchEval dataset
2. Initialize Docker container for test execution
3. Create session for CoordinatorAgent
```

### Phase 2: Context Gathering
```
CoordinatorAgent → AskAgent(ContextKnowledgeAgent) → Constraint Sheet
```

The coordinator asks the ContextKnowledgeAgent to build deep understanding:
- Analyze vulnerable function
- Map dependencies and call sites
- Extract security-critical patterns
- Identify repository conventions

### Phase 3: Repair Loop (up to max_rounds)
```
┌─────────────────────────────────────────────────────┐
│  Round N                                            │
│                                                     │
│  1. CoordinatorAgent synthesizes:                  │
│     - Constraint sheet (from ContextKnowledge)     │
│     - Previous feedback (if any)                   │
│     - Vulnerability description                    │
│     → Generates patch strategy                     │
│                                                     │
│  2. CoordinatorAgent → AskAgent(PatchAgent)        │
│     → Apply patch based on strategy                │
│                                                     │
│  3. CoordinatorAgent → AskAgent(VerificationAgent) │
│     → Run tests and provide feedback               │
│                                                     │
│  4. Decision:                                      │
│     - If tests pass → SUCCESS                      │
│     - If tests fail + rounds < max → Next round    │
│     - If rounds >= max → FAILURE                   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Phase 4: Finalization
```
1. Record final status (success/failure)
2. Save artifacts (patches, test results, logs)
3. Clean up Docker container
4. Return RunResult
```

## Session Management

The system uses **SQLiteSession** from OpenAI Agents SDK for conversation persistence:

```python
session = SQLiteSession(
    db_path="./artifacts/agent_sessions.sqlite",
    session_id=f"{sample_id}:{agent_name}"
)
```

### Session Design Decisions

1. **Shared Session IDs**: Nested agents (called via AskAgent) share the coordinator's session ID
   - Example: `CVE-2021-1234:coordinator` → calls → `CVE-2021-1234:coordinator` (same ID)
   - **Why**: Maintain full conversation context across agent calls

2. **History Persistence**: Session history persists across runs
   - **Why**: Experimental - allows agents to learn from previous attempts
   - **Note**: Can be disabled by clearing the database between runs

3. **System Prompt Storage**: System prompts stored as developer messages in session
   ```python
   if not history:
       system_message = {
           "role": "developer",
           "content": f"[SYSTEM_PROMPT]\n{system_prompt}"
       }
       return [system_message] + new_input
   ```

## Tool System

### Tool Categories

1. **Code Reading Tools**
   - `ReadFile` - Read file contents with line range filtering
   - `FindClass` - Locate definitions via AST/grep
   - `GrepSearch` - Search patterns across codebase

2. **Code Writing Tools**
   - `EditCode` - Apply old_code → new_code transformations
   - Supports fuzzy matching for robustness
   - Automatic syntax validation

3. **Execution Tools**
   - `RunTest` - Execute pytest in Docker containers
   - Structured output parsing
   - Timeout protection

4. **Inter-Agent Tools**
   - `AskAgent` - Call specialist agents
   - Structured request/response format

### Tool Access Control

Tools are granted to agents based on their role:

```python
AGENT_TOOL_ACCESS = {
    "CoordinatorAgent": ["AskAgent", "ReadFile", "EditCode", "RunTest"],
    "ContextKnowledgeAgent": ["ReadFile", "FindClass", "GrepSearch"],
    "PatchAgent": ["EditCode", "ReadFile"],
    "VerificationAgent": ["RunTest", "ReadFile"],
}
```

## Data Flow

### Input: PatchEval Sample
```json
{
    "sample_id": "CVE-2021-1234",
    "cve_id": "CVE-2021-1234",
    "cwe_id": ["CWE-79"],
    "file_path": "src/vulnerable.py",
    "vulnerable_code": "...",
    "problem_statement": "...",
    "docker_image": "ghcr.io/...",
    "test_paths": ["tests/test_vuln.py"],
    "poc_test": "tests/test_poc.py"
}
```

### Internal State (AgentState)
```python
{
    # Input data
    "sample_id": str,
    "cve_id": str,
    "problem_statement": str,

    # Agent outputs
    "constraint_sheet": ConstraintSheet,
    "decision_record": DecisionRecord,
    "patch_result": PatchResult,
    "verification_result": VerificationResult,

    # Loop state
    "current_round": int,
    "prev_feedback": Optional[Dict],

    # Accumulated results
    "rounds": List[RoundResult],

    # Final status
    "status": RunStatus,
    "final_patch": Optional[Dict]
}
```

### Output: RunResult
```python
{
    "sample_id": "CVE-2021-1234",
    "status": "success",  # or fail_*
    "rounds": [
        {
            "round_number": 1,
            "decision_record": {...},
            "patch_result": {...},
            "verification_result": {...}
        }
    ],
    "constraint_sheet": {...},
    "final_patch": {...},
    "total_duration_seconds": 45.2,
    "total_llm_calls": 12,
    "total_tool_calls": 8
}
```

## Error Handling

### Exception Hierarchy
```
VulnAgentError (base)
├── ConfigurationError
│   ├── MissingAPIKeyError
│   └── InvalidConfigurationError
├── AgentError
│   ├── AgentExecutionError
│   └── AgentOutputParsingError
├── ToolError
│   ├── ToolNotFoundError
│   ├── ToolNotAllowedError
│   └── ToolExecutionError
├── DockerError
│   ├── DockerNotAvailableError
│   ├── ContainerNotFoundError
│   └── ContainerExecutionError
├── WorkflowError
├── LLMError
└── PatchError
```

### Failure Modes

1. **FAIL_NO_FIX**: Patch applied but PoC tests still fail
2. **FAIL_REGRESSION**: PoC passes but regression tests fail
3. **FAIL_MAX_ROUNDS**: Max repair iterations reached without success
4. **FAIL_MAX_INTERACTIONS**: Tool call limit exceeded
5. **FAIL_ERROR**: System error (Docker, LLM, etc.)
6. **FAIL_PATCH**: Patch application failed
7. **FAIL_TEST**: Test execution failed

## Configuration System

### LLMConfig
```python
@dataclass
class LLMConfig:
    model: str = "gpt-4.1-2025-04-14"
    temperature: float = 0.0
    max_tokens: int = 4096
    api_key: Optional[str] = None  # Defaults to env OPENAI_API_KEY
```

### OrchestratorConfig
```python
@dataclass
class OrchestratorConfig:
    max_rounds: int = 3
    max_total_interactions: int = -1  # -1 = unlimited
    timeout_seconds: int = 600
```

### ExperimentConfig
```python
@dataclass
class ExperimentConfig:
    ablation_mode: AblationMode = AblationMode.FULL
    line_hint_precision: LineHintPrecision = LineHintPrecision.PRECISE
    experiment_name: str = "baseline"
```

### Ablation Modes

- **FULL**: All agents active, all features enabled (default)
- **WITHOUT_KNOWLEDGE**: Skip ContextKnowledgeAgent
- **SINGLE_TURN**: No repair loop (max_rounds=1)
- **WITHOUT_CONTEXT**: Skip repository context gathering

## Performance Characteristics

### Token Usage
- **Initialization**: ~2-5K tokens (context gathering)
- **Per Round**: ~3-8K tokens (strategy + patch + verification)
- **Total (3 rounds)**: ~15-30K tokens per sample

### Latency
- **Context Gathering**: 10-30 seconds
- **Per Round**: 15-45 seconds
- **Total**: 1-3 minutes per sample (for successful patches)

### Success Rate Factors
1. **Vulnerability Complexity**: Simple input validation > complex logic flaws
2. **Test Quality**: Clear PoC tests → higher success
3. **Code Clarity**: Well-structured code → easier patching
4. **Max Rounds**: More rounds → more opportunities to fix

## Extending the System

### Adding a New Agent

1. Create agent class in `src/agents/`:
```python
from .base import BaseAgent

class MyAgent(BaseAgent):
    def get_system_prompt(self) -> str:
        return "You are MyAgent..."

    def run(self, user_prompt: str) -> AgentOutput:
        response, tool_calls, token_usage = self._run_with_tools(
            user_prompt,
            max_iterations=10
        )
        return AgentOutput(
            agent_name="MyAgent",
            success=True,
            content={"result": response}
        )
```

2. Register in coordinator's AskAgent tool access
3. Call via `coordinator.ask_agent(agent_name="MyAgent", ...)`

### Adding a New Tool

1. Create tool class in `src/tools/`:
```python
from .base import BaseTool

class MyTool(BaseTool):
    name = "MyTool"
    description = "Does something useful"

    parameters = {
        "type": "object",
        "properties": {
            "param": {"type": "string"}
        },
        "required": ["param"]
    }

    def execute(self, param: str, **kwargs) -> ToolResult:
        # Implementation
        return ToolResult(
            success=True,
            output="Result"
        )
```

2. Register in `ToolRegistry`
3. Grant access to agents via `allowed_tools`

## Future Enhancements

### Potential Improvements
1. **Multi-file patch synthesis**: Better handling of changes across multiple files
2. **Test generation**: Automatically generate additional test cases
3. **Incremental patching**: Apply partial fixes and test incrementally
4. **Parallel agent execution**: Run independent analyses in parallel
5. **Adaptive round limits**: Dynamically adjust max_rounds based on progress
6. **Learning from failures**: Analyze common failure patterns across samples

### Research Questions
1. Does repository context improve patch quality?
2. What's the optimal max_rounds value?
3. Can we predict patchability from sample features?
4. How does model choice affect success rate?
5. What role does test quality play in patching success?
