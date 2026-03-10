# Roadmap

## Next engineering steps

1. AST-backed code navigation via libclang or tree-sitter
2. compile_commands.json ingestion
3. sanitizer build orchestration
4. fuzz target generation assistance
5. finding deduplication and ranking
6. SARIF export
7. review memory / multi-step planning loop

## Security controls to preserve

- keep execution local and bounded
- no network actions in the agent loop
- require explicit approval before any write outside workspace
- keep heuristic findings distinct from verified findings
