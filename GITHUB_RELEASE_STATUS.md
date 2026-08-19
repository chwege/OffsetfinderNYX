# NYX D2R patch-ready status

## Scope

This repository contains a patch-adapted, guarded NYX D2R build. It resolves offsets dynamically for the running D2R executable and does not use the supplied static reference offsets as runtime values.

The final runtime profile is intentionally read-only:

- complete client unit-table scan every 20 ms;
- all six unit types and all 128 hash buckets per type;
- Player and Monster tables are scanned first;
- flat `0x160` unit-header reads instead of recursive object-model loading;
- no server unit-table getter;
- no game lock during the read-only unit scan;
- no protected game calls and no game-state mutation.

## Current offset status

The latest validated patch run resolved:

- 29/29 effective offsets;
- 25/25 core runtime offsets;
- the client unit table dynamically;
- the local player identity through the client unit table.

The guarded full-table scan does not depend on the local-player slot being
ready. It scans first, prefers the validated local ID when available, and uses
the sole Player entry as an offline-only unambiguous fallback.

The previously supplied values, including `0x01EB9430` for the unit table, are diagnostic references only. They are never used as fallback runtime assignments.

The old encrypted player-slot transform was removed from the required set because the corresponding structure and callsites are absent in the current patch. Non-local player identities are enumerated through the dynamically resolved unit table.

## Retcheck status

Retcheck V2 is implemented only as a read-only structural diagnostic and dry-run validator.

The extended patch diagnostic identified the current V2 topology and reached `READY_DRY_RUN` during a naturally readable verifier window. The fast startup cache currently stores the normal offset set but not the transient V2 runtime metadata, so a normal cached start reports `NOT_READY` for Retcheck V2.

No Retcheck bypass is included. The adapter does not invoke the allocator, submit function, dispatcher, hooks, swaps, or protected game functions. This avoids the deliberate null-dereference anti-tamper crash observed in the patched game.

Consequently, these functions remain blocked:

- `automapGetMode`;
- `worldToAutomap`;
- `revealLevel` and other mutation paths.

The demo no longer requires these bindings for its read-only overview map. It
projects world coordinates locally and renders the current level without
changing D2R's native automap state.

## UI and runtime fixes

- ImGui receives an independent 16 ms frame heartbeat.
- Initial display size is valid before the first game `Present` call.
- The Unit Explorer starts at 440 x 520 pixels with a minimum width of 360 pixels.
- Panel refresh uses the original 100/250/500 ms request/panel/detail cadence.
- Room geometry is read from the current level's `Room2` list and redrawn only
  after a level change, a delayed room-data rebuild, or a viewport resize.
- POIs use a local level-centered projection and redraw at a capped 100 ms
  cadence without a game lock.
- Player and monster markers use the same local projection; `WorldObject`
  updates no longer call the protected `worldToAutomap` binding.
- Unit performance logs include separate Player, Monster, Object, Missile, Item, and Tile counts.
- The default test logging profile records compact `map_rebuild` lines and
  disables the old periodic unit-explorer performance log.

## Build

Requirements:

- Windows x64;
- Visual Studio with Desktop C++ tools;
- CMake and Ninja;
- repository cloned with submodules.

Prepare the NYX submodule modifications:

```bat
git submodule update --init --recursive
apply_nyx_patch.bat
```

Configure the guarded debug profile from a Visual Studio developer shell:

```bat
cmake --preset x64-debug ^
  -DNYX_D2R_SAFE_DIAGNOSTIC_MODE=ON ^
  -DNYX_D2R_SAFE_NO_THREAD_SUSPEND=ON ^
  -DNYX_D2R_SAFE_NO_DECRYPT_TOUCH=ON ^
  -DNYX_D2R_SAFE_READ_ONLY_RUNTIME=ON ^
  -DNYX_D2R_FAST_DIAGNOSTIC=ON

cmake --build out\build\x64-debug --target nyx.d2r --parallel 8
```

The source build completes without a signing certificate. Optional local signing can be enabled without committing private material:

```bat
cmake --preset x64-debug ^
  -DNYX_D2R_SIGN_PFX=C:\private\local-signing.pfx ^
  -DNYX_D2R_SIGN_PASSWORD=your-password
```

Never commit PFX or PVK files.

## Verification record

- CMake configuration: successful.
- JavaScript builtin generation: successful.
- C++ compilation and DLL link: successful.
- Local overview-map JavaScript syntax and install-package parity: successful.
- Guarded incremental debug build with the local overview map: successful on
  2026-08-11.
- Final clean unsigned source build: successful on 2026-08-11 (143 build steps, fresh CMake cache, guarded defaults).
- Previous incremental runtime: stable, with dynamic Player and Monster discovery.
- Final full client scan: runtime-verified on 2026-08-18 with `29/29` offsets, a structurally confirmed client table at `0x01EAD470`, and 360 valid client-table nodes in the verification sample.
- OverlayTool: the seven current-patch RVAs were integrated and the rebuilt overlay was confirmed functional.

## Repository hygiene

The GitHub-ready export excludes:

- `.git` working metadata from the development checkout;
- `out/` builds and installed binaries;
- runtime and diagnostic logs;
- certificates and private keys;
- temporary diagnostic archives.

The NYX submodule changes are stored in `patches/nyx-local.patch` and applied with `apply_nyx_patch.bat`.
