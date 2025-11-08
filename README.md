# model-firewall

`model-firewall` is a small, deterministic input/output firewall for LLM applications. It evaluates text against configurable regex rules and returns a structured verdict: `allow`, `flag`, or `block`.

The project is intentionally lightweight: the core library and CLI use the Python standard library, with tests runnable offline.

## Features

- **Direction-aware rules**: rules can target `input`, `output`, or `both`.
- **Built-in security rules**: prompt-injection/jailbreak patterns, secret/credential leakage, PII, and dangerous command requests.
- **Custom rules**: load additional JSON rule files and optionally disable built-ins.
- **Structured reports**: JSON output with verdict, findings, spans, and metadata.
- **CLI + library API**: use it in scripts/CI or embed it in Python applications.
- **Deterministic/offline**: no network calls, no external model dependencies.

## Install

