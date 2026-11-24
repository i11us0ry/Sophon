# Sophon Custom Tools

`customTools/` contains tools maintained by the Sophon project rather than an
upstream GitHub release.

- `definitions/` holds MCP YAML definitions. Deployment copies these files into
  the runtime `tools/` directory so the MCP tool runner can discover them.
- `scripts/` holds Python entrypoints referenced by those definitions.

Release and deployment scripts must include this directory. Tool Catalog
source-build manifests must not overwrite files under `customTools/`.
