#include "d2r_feature_check.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <dolos/pipe_log.h>

#include "d2r_safety.h"
#include "offsets.h"

namespace d2r {
namespace {

bool IsReadableRange(const void* address, std::size_t size) {
  if (address == nullptr || size == 0) {
    return false;
  }

  MEMORY_BASIC_INFORMATION info{};
  if (VirtualQuery(address, &info, sizeof(info)) == 0 ||
      info.State != MEM_COMMIT ||
      (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
    return false;
  }

  const auto start = reinterpret_cast<std::uintptr_t>(address);
  const auto region_start = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
  const auto region_end = region_start + info.RegionSize;
  return start >= region_start && size <= region_end - start;
}

bool TryReadLocalPlayerIndex(std::uint32_t* value) {
  if (value == nullptr ||
      !IsReadableRange(s_PlayerUnitIndex, sizeof(*s_PlayerUnitIndex))) {
    return false;
  }

  std::memcpy(value, s_PlayerUnitIndex, sizeof(*value));
  return true;
}

void LogCapability(const char* name, const char* state, const char* reason) {
  PIPE_LOG_WARN("[FunctionCheck] feature={} state={} reason={}", name, state,
                reason);
}

}  // namespace

void LogFeatureCapabilityDiagnostics(bool retcheck_v2_metadata_ready,
                                     bool retcheck_v2_live_ready) {
  std::array<OffsetInfo, kOffsetCount> offsets{};
  GetOffsetInfo(offsets.data(), offsets.size());

  std::size_t found = 0;
  std::size_t core_found = 0;
  std::size_t core_total = 0;
  std::size_t legacy_player_id_found = 0;
  std::size_t legacy_player_id_total = 0;
  const char* missing_name = "none";
  for (const auto& offset : offsets) {
    const bool is_retcheck_gate = std::strcmp(offset.name, "kCheckData") == 0;
    const bool is_legacy_player_id =
        std::strcmp(offset.name, "EncTransformValue") == 0 ||
        std::strcmp(offset.name, "PlayerIndexToIDEncryptedTable") == 0;
    const bool is_optional_reference =
        std::strncmp(offset.name, "Reference_", 10) == 0;

    if (offset.found) {
      ++found;
    } else {
      missing_name = offset.name;
    }
    if (is_legacy_player_id) {
      ++legacy_player_id_total;
      if (offset.found) ++legacy_player_id_found;
    } else if (!is_retcheck_gate && !is_optional_reference) {
      ++core_total;
      if (offset.found) ++core_found;
    }
  }
  const std::size_t effective_found =
      found + (retcheck_v2_metadata_ready && kCheckData == nullptr ? 1 : 0);

  const bool client_table_ready =
      sgptClientSideUnitHashTable != nullptr &&
      IsReadableRange(sgptClientSideUnitHashTable, sizeof(void*));
  const bool player_units_present =
      client_table_ready && HasAnyPlayerUnits();

  std::uint32_t local_index = UINT32_MAX;
  const bool local_index_readable = TryReadLocalPlayerIndex(&local_index);
  const bool local_index_valid = local_index_readable && local_index < 8;

  PIPE_LOG_WARN(
      "[FunctionCheck] begin offsets={}/{} effective={}/{} missing={} safe_mode=yes "
      "protected_calls_invoked=no",
      found, offsets.size(), effective_found, offsets.size(), missing_name);
  PIPE_LOG_WARN(
      "[FunctionCheck] offset-groups core={}/{} retcheck_v2={} legacy_player_id={}/{}",
      core_found,
      core_total,
      retcheck_v2_live_ready
          ? "READY_DRY_RUN"
          : retcheck_v2_metadata_ready ? "READY_WAITING_WINDOW" : "NOT_READY",
      legacy_player_id_found,
      legacy_player_id_total);

  LogCapability("dll-load-and-native-logging", "READY",
                "diagnostic code is executing");
  LogCapability("dynamic-offset-resolution",
                core_found == core_total && retcheck_v2_metadata_ready
                    ? "READY_CORE"
                    : "DEGRADED",
                core_found == core_total && retcheck_v2_metadata_ready
                    ? "all current core offsets resolved; Retcheck V2 supersedes "
                      "legacy kCheckData; encrypted player-id fallback is optional"
                    : "a current core offset or Retcheck V2 metadata is missing");
  LogCapability("retcheck-v2-adapter",
                retcheck_v2_live_ready
                    ? "READY_DRY_RUN"
                    : retcheck_v2_metadata_ready ? "READY_WAITING_WINDOW"
                                                 : "NOT_READY",
                retcheck_v2_live_ready
                    ? "layout, request functions, contracts, and dispatcher passed "
                      "read-only validation; no protected call was invoked"
                    : retcheck_v2_metadata_ready
                          ? "all V2 metadata is resolved; a protected code page was "
                            "temporarily sealed during live validation"
                          : "read-only structural validation is incomplete");
  LogCapability("getLocalPlayerIndex",
                local_index_valid ? "READY" : "NOT_READY",
                local_index_valid ? "global is readable and value is in range"
                                  : "global is missing, unreadable, or out of range");
  LogCapability("getPlayerIdByIndex(local)",
                player_units_present && local_index_valid ? "READY_READ_ONLY"
                                                          : "NOT_READY",
                player_units_present && local_index_valid
                    ? "direct client unit-table path is available"
                    : "requires a valid local slot and populated client unit table");
  LogCapability("getPlayerIdByIndex(non-local)", "PARTIAL",
                "legacy encrypted slot mapping is absent in this patch; enumerate "
                "player identities through the dynamically resolved unit table");
  LogCapability("getClientSideUnitHashTableAddress",
                client_table_ready ? "READY_READ_ONLY" : "NOT_READY",
                client_table_ready ? "resolved table is naturally readable"
                                   : "resolved table is missing or unreadable");
  LogCapability("getServerSideUnitHashTableAddress",
                GetServerSideUnitHashTableByType != nullptr
                    ? "UNVERIFIED_GAME_CALL"
                    : "NOT_READY",
                GetServerSideUnitHashTableByType != nullptr
                    ? "target resolved but is not invoked by safe diagnostics"
                    : "target offset is missing");
  LogCapability("Unit-models-and-memory-readers",
                client_table_ready ? "PREREQUISITES_READY_RUNTIME_DISABLED"
                                   : "NOT_READY",
                client_table_ready
                    ? "read-only data source is ready; NYX runtime is disabled "
                      "by this build"
                    : "client unit table is unavailable");
  LogCapability("ObjectManager",
                client_table_ready ? "PARTIAL_RUNTIME_DISABLED" : "NOT_READY",
                client_table_ready
                    ? "client scan is available; server getter is unverified and "
                      "NYX runtime is disabled"
                    : "client unit table is unavailable");
#ifdef NYX_D2R_SAFE_READ_ONLY_RUNTIME
  LogCapability("runtime-mode-api", "GUARDED_READ_ONLY",
                "binding will be registered; active mutation is compile-time blocked");
  LogCapability("DebugPanel-and-overlay", "PENDING_RUNTIME_START",
                "NYX runtime and D3D/window hooks start after diagnostics");
#else
  LogCapability("runtime-mode-api", "RUNTIME_DISABLED",
                "binding is not registered in safe diagnostic mode");
  LogCapability("DebugPanel-and-overlay", "RUNTIME_DISABLED",
                "NYX runtime and D3D/window hooks are disabled");
#endif
  LogCapability("automapGetMode", "BLOCKED_RETCHECK",
                "calls protected AutoMapPanel_GetMode");
  LogCapability("worldToAutomap", "BLOCKED_RETCHECK",
                "calls protected GetMode and PrecisionToAutomap");
  LogCapability("revealLevel", "BLOCKED_RETCHECK_AND_MUTATION",
                "invokes protected pfnAutomap and mutates automap/room state");

#ifdef NYX_D2R_SAFE_READ_ONLY_RUNTIME
  constexpr const char* kNyxRuntimeState = "GUARDED_PENDING_START";
#else
  constexpr const char* kNyxRuntimeState = "DISABLED";
#endif
  PIPE_LOG_WARN(
      "[FunctionCheck] summary native_diagnostics=READY "
      "read_only_core={} nyx_runtime={} retcheck_v2={} automap=BLOCKED_RETCHECK "
      "reveal=BLOCKED_RETCHECK_AND_MUTATION",
      client_table_ready && local_index_valid ? "READY" : "NOT_READY",
      kNyxRuntimeState,
      retcheck_v2_live_ready
          ? "READY_DRY_RUN"
          : retcheck_v2_metadata_ready ? "READY_WAITING_WINDOW" : "NOT_READY");
  PIPE_LOG_WARN("[FunctionCheck] end action=none");
}

}  // namespace d2r
