# SARIF export

The MVP can now export findings as SARIF.

## Why this matters

SARIF makes it easier to plug the project into:

- CI pipelines
- GitHub code scanning
- internal triage dashboards
- other static-analysis consumers

## Current mapping

Each finding is exported with:

- rule id
- severity-derived level
- confidence
- status
- score
- file and line location
