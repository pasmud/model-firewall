# model-firewall

`model-firewall` is a small, deterministic input/output firewall for LLM applications. It evaluates text against configurable regex rules and returns a structured verdict: `allow`, `flag`, or `block`.

The project is intentionally lightweight: the core library and CLI use the Python standard library, with tests runnable offline.

## Features

