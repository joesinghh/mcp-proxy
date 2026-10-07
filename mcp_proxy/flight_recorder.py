import json
import time
import os
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pathlib import Path


class FlightRecorder:
    """
    Append-only structured audit logger for recording tool invocation verdicts,
    rejection reasons, arguments, and latency overhead.
    """
    def __init__(self, log_path: Optional[str] = None, session_id: Optional[str] = None):
        self.session_id = session_id or f"sess_{os.urandom(4).hex()}"
        self.log_path = Path(log_path).resolve() if log_path else None
        self._lock = threading.Lock()

        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        tool: str,
        arguments: Dict[str, Any],
        verdict: str,
        reason: Optional[str] = None,
        latency_ms: float = 0.0
    ) -> Dict[str, Any]:
        """
        Emits a structured audit entry and appends to log file if configured.
        Returns the emitted log entry dict.
        """
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session_id": self.session_id,
            "tool": tool,
            "arguments": arguments,
            "verdict": verdict,
            "reason": reason if reason is not None else "OK",
            "latency_ms": round(latency_ms, 3)
        }

        if self.log_path:
            with self._lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
                    f.flush()

        return entry
