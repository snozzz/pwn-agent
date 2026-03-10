# Input surface detection

The MVP can now detect likely input surfaces in C/C++ projects.

## Current surface categories

- CLI argument handling
- filesystem input
- network input
- environment input
- parser-like code signals

## Why it matters

Security review is more efficient when the agent can quickly identify where untrusted data may enter the program.
