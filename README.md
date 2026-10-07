# MCP Security Gateway & Proxy (`mcp-proxy`)

A transparent, high-performance security gateway and wire-tap proxy for Model Context Protocol (MCP) servers. Interposes on stdin/stdout JSON-RPC communication between LLM agent clients (Claude Desktop, Cursor, Antigravity, custom agents) and backend MCP servers.

---

## Architecture Overview

```text
[ MCP Client ] (e.g. Claude Desktop / Cursor / Agent)
       │  ▲
       │  │  stdin / stdout (JSON-RPC 2.0 lines)
       ▼  │
┌───────────────────────────────────────────────────────────────────┐
│                          MCP-PROXY GATEWAY                        │
│                                                                   │
│ Phase 1: Duplex Wire Tap & Child Process Spawner                  │
│    - CLI launcher (--target <binary> [args...])                   │
│    - Transparent demultiplexing & routing                         │
│                                                                   │
│ Phase 2: Schema Validation & Circuit Breaker                      │
│    - Tool JSON Schema caching from tools/list responses           │
│    - Strict argument validation (jsonschema)                      │
│    - Synthetic error framing (JSON-RPC 2.0 -32602)                │
│    - Sliding window anti-loop circuit breaker (60s, threshold 3)  │
│                                                                   │
│ Phase 3: AST Deep Parameter Inspection & Policy Engine            │
│    - Shell AST Inspector (bashlex): allowlist, no pipes/subshells │
│    - Path Traversal Guard (pathlib.Path): canonical boundaries    │
│    - SQL AST Inspector (sqlglot): read-only, table allowlist      │
│    - Python AST Inspector (ast): no os/sys/exec/eval/open/escape  │
│    - Rego / OPA-style Policy-as-Code evaluation rules             │
│                                                                   │
│ Phase 4: Data Loss Prevention (DLP) & Flight Recorder             │
│    - Outgoing tool response redaction (AWS, GitHub, JWT, Keys)    │
│    - Append-only structured JSON audit log with latency tracking  │
└───────────────────────────────────────────────────────────────────┘
       │  ▲
       │  │  stdin / stdout (sanitized frames forwarded)
       ▼  │
[ Target Child MCP Server ] (e.g. python main.py)
```

---

## 5-Phase Implementation Breakdown

### Phase 1: Wire Tap & Proxy Foundation
- **Child Process Spawner (`mcp_proxy.gateway.Gateway`)**: Launches the target MCP server as a subprocess and wires duplex stdio pipes.
- **Duplex JSON-RPC Pipe**: Streams JSON-RPC lines between client and server concurrently with zero thread blocking.
- **Message Type Router**:
  - Immediately passes through `initialize`, `ping`, and notifications (`notifications/*`).
  - Intercepts and caches tool definitions and input schemas from `tools/list` responses.
  - Demultiplexes and routes `tools/call` into the inspection and policy validation pipeline.

### Phase 2: Schema Validation & Circuit Breaker
- **Strict Schema Checking (`mcp_proxy.schema_validator.SchemaValidator`)**: Validates input arguments against the cached tool schema using `jsonschema`.
- **Synthetic Error Framing**: If schema validation fails, the proxy suppresses the upstream call and immediately returns a native JSON-RPC 2.0 error frame (`code: -32602`).
- **Anti-Loop Circuit Breaker (`mcp_proxy.circuit_breaker.CircuitBreaker`)**:
  - Tracks invocation signatures (`tool:sha256(args)`) across a 60-second sliding window.
  - If identical failing arguments are invoked 3 consecutive times, trips the circuit breaker and returns a halting error frame (`code: -32000`).

### Phase 3: AST Parameter Inspection & Policy Engine
- **Shell AST Sanitizer (`mcp_proxy.inspectors.shell.ShellASTInspector`)**:
  - Uses `bashlex` to parse concrete syntax trees.
  - Blocks compound chaining (`;`, `&&`, `||`), subshells (`$()`, `` ` ``), redirections (`>`, `<`), and unauthorized pipes (`|`).
  - Enforces an explicit binary allowlist (e.g., `git`, `ls`, `grep`, `pwd`, `echo`).
- **Path Traversal Guard (`mcp_proxy.inspectors.path.PathTraversalInspector`)**:
  - Canonicalizes paths using `pathlib.Path.resolve()`.
  - Enforces strict boundary checks (`is_relative_to(root)`).
  - Blocks traversal escapes (`../../../../etc/passwd`), null bytes, symlink bypasses, and access to hidden files (`.env`, `.git`).
- **SQL AST Inspector (`mcp_proxy.inspectors.sql.SQLASTInspector`)**:
  - Uses `sqlglot` across SQLite, PostgreSQL, and MySQL.
  - Enforces read-only operations (`SELECT`, `UNION`).
  - Blocks destructive commands (`DROP`, `ALTER`, `TRUNCATE`, `DELETE`, `UPDATE`, `INSERT`).
  - Blocks stacked query injection and limits queries to an explicit table allowlist (e.g., `empl`).
- **Python AST Inspector (`mcp_proxy.inspectors.python_ast.PythonASTInspector`)**:
  - Uses native `ast`.
  - Blocks forbidden modules (`os`, `sys`, `subprocess`, `socket`, `shutil`, `ctypes`, etc.).
  - Blocks dangerous calls (`eval`, `exec`, `compile`, `open`, `__import__`).
  - Blocks reflection / sandbox escape attributes (`__subclasses__`, `__builtins__`, `__globals__`).
- **Policy-as-Code Engine (`mcp_proxy.policy.PolicyEngine`)**:
  - OPA / Rego-style declarative rule evaluation against tool inputs and arguments.

### Phase 4: Data Loss Prevention (DLP) & Audit Flight Recorder
- **Response Stream Redaction (`mcp_proxy.dlp.DLPRedactor`)**:
  - Scans outgoing server responses for sensitive tokens:
    - AWS Access Keys (`AKIA[0-9A-Z]{16}`) and Secret Keys
    - GitHub PATs (`ghp_...`, `github_pat_...`)
    - JWT Tokens (`eyJ...`)
    - Private Keys (`-----BEGIN RSA/OPENSSH PRIVATE KEY-----`)
    - Generic high-entropy API keys
  - Replaces detected tokens with `[REDACTED_BY_GATEWAY]`.
- **Structured Flight Recorder (`mcp_proxy.flight_recorder.FlightRecorder`)**:
  - Emits append-only JSON audit log lines:
    ```json
    {
      "timestamp": "2026-10-02T17:15:26Z",
      "session_id": "sess_91823",
      "tool": "read_file",
      "arguments": {"path": "/etc/shadow"},
      "verdict": "DENIED",
      "reason": "Path traversal detected: path '/etc/shadow' escapes root directory boundary",
      "latency_ms": 0.512
    }
    ```

### Phase 5: Adversarial Red-Teaming & Performance Profiling
- **Adversarial Test Suite (`tests/test_adversarial.py`)**: 21 attack tests verifying resilience against shell escapes, subshell injections, path traversal, SQL injection, Python sandbox escapes, circuit-breaker loops, and DLP leaks.
- **Microbenchmark Suite (`tests/test_benchmark.py`)**: Demonstrates **~0.5ms added latency per tool call** (well below the 1.5ms threshold) and bounded memory.

---

## Quickstart & Usage

### 1. Launching via CLI

```bash
# Start proxy wrapping main.py
python -m mcp_proxy.cli --target python3 -- main.py

# Optional parameters:
python -m mcp_proxy.cli \
  --target python3 \
  --log-file audit.jsonl \
  --root-dir /path/to/project \
  --allow-binaries "git,ls,grep,pwd,echo" \
  --allowed-tables "empl" \
  -- main.py
```

### 2. Client Configuration (e.g. Claude Desktop / Cursor)

Configure `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "secure-tools": {
      "command": "python",
      "args": [
        "-m", "mcp_proxy.cli",
        "--target", "python",
        "--log-file", "mcp_audit.jsonl",
        "--", "main.py"
      ]
    }
  }
}
```

### 3. Running Test Suites

```bash
# Run adversarial red-teaming tests
python -m unittest tests/test_adversarial.py

# Run performance microbenchmark
python -m unittest tests/test_benchmark.py

# Run end-to-end integration test
python -m unittest tests/test_e2e.py
```
