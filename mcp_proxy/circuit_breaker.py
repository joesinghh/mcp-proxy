import time
import json
import hashlib
from typing import Dict, Any, Tuple, Optional
from collections import defaultdict, deque


class CircuitBreakerError(Exception):
    """Raised when the anti-loop circuit breaker is tripped."""
    def __init__(self, tool: str, consecutive_failures: int, window_seconds: float):
        super().__init__(
            f"Circuit breaker tripped: Tool '{tool}' was called with identical failing inputs "
            f"{consecutive_failures} consecutive times within {int(window_seconds)}s."
        )
        self.tool = tool
        self.consecutive_failures = consecutive_failures
        self.window_seconds = window_seconds


class CircuitBreaker:
    """
    Sliding window anti-loop circuit breaker.
    Tracks invocation signatures (tool_name + hash(arguments)) and trips if
    identical failing inputs are called N times in a row within the window.
    """
    def __init__(self, failure_threshold: int = 3, window_seconds: float = 60.0):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        # signature -> deque of failure timestamps within window (bounded size)
        self._failures: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.failure_threshold))
        self._tripped: Dict[str, bool] = {}

    def compute_signature(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Computes a deterministic hash of the tool name and arguments."""
        try:
            serialized = json.dumps(args, sort_keys=True, default=str)
        except Exception:
            serialized = str(sorted(args.items()))
        arg_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return f"{tool_name}:{arg_hash}"

    def is_tripped(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Checks if calling this tool with these arguments is currently blocked by circuit breaker."""
        sig = self.compute_signature(tool_name, args)
        if self._tripped.get(sig):
            now = time.monotonic()
            cutoff = now - self.window_seconds
            # Check if failures have expired
            q = self._failures.get(sig)
            if q and any(t >= cutoff for t in q):
                msg = (
                    f"Circuit breaker tripped: Tool '{tool_name}' was invoked with identical failing "
                    f"parameters {len(q)} times consecutively within {int(self.window_seconds)}s window."
                )
                return True, msg
            else:
                self._tripped[sig] = False
        return False, None

    def record_success(self, tool_name: str, args: Dict[str, Any]) -> None:
        """Records a successful tool invocation, resetting consecutive failures for this signature."""
        sig = self.compute_signature(tool_name, args)
        self._failures.pop(sig, None)
        self._tripped.pop(sig, None)

    def record_failure(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """
        Records a failed tool invocation.
        Returns True if this failure trips the circuit breaker (reaches or exceeds threshold).
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds
        sig = self.compute_signature(tool_name, args)

        q = self._failures[sig]
        # Remove expired timestamps from the left
        while q and q[0] < cutoff:
            q.popleft()

        q.append(now)

        if len(q) >= self.failure_threshold:
            self._tripped[sig] = True
            return True

        return False

    def reset(self) -> None:
        """Resets all state."""
        self._failures.clear()
        self._tripped.clear()
