# NYX D2R patch-ready fork

This fork contains dynamic offset diagnostics, a guarded read-only runtime, a full client unit-table scanner, and UI/runtime fixes for the current D2R patch.

Start with [NYX_OFFSET_SCANNER_SUMMARY.md](NYX_OFFSET_SCANNER_SUMMARY.md) for the complete project history, verified offsets, OverlayTool integration, build commands, Retcheck limitations, and repository layout.

The concise technical status is available in [GITHUB_RELEASE_STATUS.md](GITHUB_RELEASE_STATUS.md).

Quick preparation:

```bat
git submodule update --init --recursive
apply_nyx_patch.bat
```

Private signing keys, runtime logs, build products, and game files are not part of this repository.
