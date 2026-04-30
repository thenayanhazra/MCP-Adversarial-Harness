# Releasing

Use this checklist for every release.

## Versioning and release checklist

1. Bump `project.version` in `pyproject.toml`.
2. Regenerate the changelog/release notes for the new version.
3. Run quality gates locally:
   - `ruff check .`
   - `pyright`
   - `pytest`
4. Build distribution artifacts:
   - `python -m build`
5. Commit release prep changes.
6. Create and push a Git tag in the format `v*` (for example, `v0.2.0`).
7. Verify the tag-triggered release workflow succeeds.
8. Publish artifacts to PyPI (via trusted publishing or `PYPI_API_TOKEN`).
9. Publish GitHub release notes that match the changelog.
