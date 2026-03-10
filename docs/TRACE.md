# Action trace

The MVP now records an audit trace.

## What gets tracked

- project discovery
- compile database detection
- verification attempts
- rebuild-and-verify pipeline execution
- key return codes and signals

## Why it matters

An agent-style security tool should leave behind a readable trail of what it actually did. That trail is useful for debugging, trust, reproducibility, and future training data.
