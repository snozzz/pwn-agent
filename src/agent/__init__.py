"""Agent v2 reasoning layer.

This package holds the agent-reasoning components that sit *above* the executor:
structured state, an evidence ledger, the controller (model) abstraction, loop
protection, and trajectory evaluation.

Nothing in this package executes commands. The executor (``src.executor``) and the
command policy (``src.policy`` / ``src.command_registry``) remain the sole authority
over what can run. Controllers select among bounded candidate action ids only; they
never emit shell commands.
"""
