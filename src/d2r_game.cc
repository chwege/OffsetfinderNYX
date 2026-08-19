#include "d2r_game.h"

#include <dolos/dolos.h>
#include <nyx/extension.h>
#include <nyx/nyx.h>

#include "d2r_binding.h"
#include "d2r_builtins.h"
#include "d2r_feature_check.h"
#include "d2r_player_id.h"
#include "offsets.h"
#include "reference_offset_diagnostics.h"
#include "retcheck_bypass.h"
#include "retcheck_v2_adapter.h"
#include "unit_table_diagnostics.h"

#include <dolos/pipe_log.h>

dolos::Game* dolos::Game::Create() {
  return new d2r::D2rGame();
}

namespace d2r {

bool D2rGame::OnInitialize() {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  PIPE_LOG_WARN("[nyx.d2r] SAFE DIAGNOSTIC MODE active");
#ifdef NYX_D2R_SAFE_READ_ONLY_RUNTIME
  PIPE_LOG_WARN("[nyx.d2r] Guarded read-only runtime requested; protected calls and mutation are disabled");
#else
  PIPE_LOG_WARN("[nyx.d2r] Retcheck bypass, D2R bindings, scripts, and runtime features are disabled");
#endif
#endif

#if defined(NYX_D2R_SAFE_DIAGNOSTIC_MODE) && defined(NYX_D2R_SAFE_SKIP_OFFSET_SCAN)
  PIPE_LOG_WARN("[nyx.d2r] Safe diagnostic ping-only mode: offset scan and player-id constants skipped");
  PIPE_LOG_WARN("[nyx.d2r] Safe diagnostic complete; skipping retcheck initialization");
  return true;
#else
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
#ifndef NYX_D2R_FAST_DIAGNOSTIC
  MonitorCurrentPatchReferenceTargets();
#else
  PIPE_LOG_WARN("[nyx.d2r] Fast diagnostic mode: skipping 30-second reference monitor");
#endif
#endif
  PIPE_LOG("[nyx.d2r] Initializing offsets...");
  if (!InitializeOffsets()) {
    PIPE_LOG_WARN("[nyx.d2r] Some offsets could not be resolved - features may be limited");
  }

  if (!InitializePlayerIdConstants()) {
    PIPE_LOG_WARN("[nyx.d2r] Player ID constants not found - GetPlayerId may not work");
  }

#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  LogUnitTableBlockDiagnostics();
  LogLocalPlayerIdentityDiagnostic();
  LogCurrentPatchReferenceDiagnostics();
  const bool retcheck_v2_live_ready = RetcheckV2Adapter::ValidateReadOnly();
  LogFeatureCapabilityDiagnostics(RetcheckV2Adapter::HasResolvedMetadata(),
                                  retcheck_v2_live_ready);
  if (!retcheck_v2_live_ready) {
    PIPE_LOG_WARN("[nyx.d2r] Retcheck V2 adapter dry-run is not ready");
  }
#ifdef NYX_D2R_SAFE_READ_ONLY_RUNTIME
  PIPE_LOG_WARN("[nyx.d2r] Starting guarded read-only NYX runtime; protected calls and mutation remain blocked");
  nyx::RegisterBinding("d2r", InitD2RBinding);
  d2r_builtins::RegisterBuiltins();
  nyx::SetScriptDirectory(dolos::get_module_cwd() + "\\scripts");
  return true;
#else
  PIPE_LOG_WARN("[nyx.d2r] Safe diagnostic complete; skipping retcheck initialization");
  return true;
#endif
#else
  if (!RetcheckBypass::Initialize()) {
    PIPE_LOG_WARN("[nyx.d2r] Failed to install retcheck bypass - game function calls may crash");
  }

  nyx::RegisterBinding("d2r", InitD2RBinding);
  d2r_builtins::RegisterBuiltins();
  nyx::SetScriptDirectory(dolos::get_module_cwd() + "\\scripts");

  return true;
#endif
#endif
}

void D2rGame::OnShutdown() {
#ifndef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  RetcheckBypass::Shutdown();
#endif
}

}  // namespace d2r
