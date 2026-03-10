# Audit reports

Audit reports now aggregate three evidence classes:

1. heuristic source findings
2. compile database context
3. rebuild / verification evidence

They also summarize function-level focus when scanner findings or detected input surfaces can be mapped to an enclosing C/C++ function.

## Why this matters

A useful security agent should not produce a flat wall of grep hits. It should preserve the path from suspicion to validation so a human reviewer can quickly decide what to trust and what to investigate next.
