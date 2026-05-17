from dataclasses import dataclass, field
import os
import re
import subprocess
import time


DEFAULT_TIMEOUT_SECONDS = 20
REDACTED = "[redacted]"
SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "psk",
    "secret",
    "token",
    "apikey",
    "api_key",
    "ssid",
)


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass(frozen=True)
class CommandRunner:
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    redact_keywords: tuple[str, ...] = field(default_factory=lambda: SENSITIVE_KEYWORDS)

    def preview(self, command: list[str]) -> str:
        return " ".join(self._redact_tokens(command))

    def run(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        timeout_seconds: int | None = None,
    ) -> CommandResult:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        started = time.perf_counter()
        try:
            result = subprocess.run(
                command,
                input=input_text,
                capture_output=True,
                text=True,
                env=merged_env,
                timeout=timeout_seconds or self.timeout_seconds,
            )
            return CommandResult(
                command=self._redact_tokens(command),
                returncode=result.returncode,
                stdout=self._redact_text(result.stdout.strip()),
                stderr=self._redact_text(result.stderr.strip()),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command=self._redact_tokens(command),
                returncode=124,
                stdout=self._redact_text((exc.stdout or "").strip() if isinstance(exc.stdout, str) else ""),
                stderr="Command timed out",
                timed_out=True,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:
            return CommandResult(
                command=self._redact_tokens(command),
                returncode=1,
                stdout="",
                stderr=self._redact_text(str(exc)),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

    def _redact_tokens(self, tokens: list[str]) -> list[str]:
        redacted: list[str] = []
        redact_next = False
        for token in tokens:
            lower = token.lower()
            if redact_next:
                redacted.append(REDACTED)
                redact_next = any(keyword in lower for keyword in self.redact_keywords) and "=" not in token
                continue
            if any(keyword in lower for keyword in self.redact_keywords):
                if "=" in token:
                    key, _ = token.split("=", 1)
                    redacted.append(f"{key}={REDACTED}")
                else:
                    redacted.append(token)
                    redact_next = True
                continue
            redacted.append(token)
        return redacted

    def _redact_text(self, value: str) -> str:
        redacted = value
        for keyword in self.redact_keywords:
            redacted = re.sub(
                rf"({re.escape(keyword)}\s*[=:]\s*)([^\s,;]+)",
                rf"\1{REDACTED}",
                redacted,
                flags=re.IGNORECASE,
            )
        return redacted
