#include "offsets.h"
#include "retcheck_bypass.h"

#include <dolos/offset_cache.h>
#include <dolos/offset_registry.h>
#include <dolos/pattern_scanner.h>
#include <dolos/pe_builder.h>
#include <dolos/pipe_log.h>
#include <hde/hde64.h>

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace d2r {

using dolos::OffsetCache;
using dolos::OffsetCacheManager;
using dolos::PatternScanner;
using dolos::PEBuilder;
using dolos::SignatureDef;

namespace {

void* g_diagnostic_only_target = nullptr;
bool g_retcheck_protected_layout_dry_run_done = false;
std::uint32_t g_retcheck_v2_slot_rva = 0;
std::size_t g_retcheck_v2_evidence_callsites = 0;
std::size_t g_retcheck_v2_protected_layout_votes = 0;
std::size_t g_retcheck_v2_equation_total = 0;
std::size_t g_retcheck_v2_equation_clean = 0;
std::size_t g_retcheck_v2_equation_trap = 0;
std::size_t g_retcheck_v2_equation_skipped = 0;

bool IsPatchDiagnosticRequested() {
  HMODULE module = nullptr;
  if (!GetModuleHandleExA(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          reinterpret_cast<LPCSTR>(&g_diagnostic_only_target),
          &module)) {
    return false;
  }

  char module_path[MAX_PATH]{};
  const DWORD length = GetModuleFileNameA(module, module_path, MAX_PATH);
  if (length == 0 || length >= MAX_PATH) {
    return false;
  }
  std::string marker_path(module_path, length);
  const auto separator = marker_path.find_last_of("\\/");
  if (separator == std::string::npos) {
    return false;
  }
  marker_path.resize(separator + 1);
  marker_path += "patch-diagnostics.enabled";
  return GetFileAttributesA(marker_path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::vector<SignatureDef> BuildSignatureList() {
  std::vector<SignatureDef> signatures;

#define ADD_SIGNATURE(...)                                                                                             \
  signatures.push_back({                                                                                               \
      D2R_GET_NAME(__VA_ARGS__),                                                                                       \
      D2R_GET_PATTERN(__VA_ARGS__),                                                                                    \
      D2R_GET_TYPE(__VA_ARGS__),                                                                                       \
      (void**)&D2R_GET_VAR(__VA_ARGS__),                                                                               \
      0,                                                                                                               \
      std::nullopt, /* parsed pattern - lazy init */                                                                   \
  });
  D2R_OFFSET_LIST(ADD_SIGNATURE)
#undef ADD_SIGNATURE

  return signatures;
}

void ApplyCachedOffsets(const OffsetCache& cache, std::vector<SignatureDef>& signatures) {
  HMODULE module = GetModuleHandle(NULL);
  uint64_t module_base = reinterpret_cast<uint64_t>(module);
  for (const auto& entry : cache.entries) {
    auto it = std::find_if(
        signatures.begin(), signatures.end(), [&entry](const SignatureDef& sig) { return entry.name == sig.name; });
    if (it != signatures.end()) {
      *it->target = reinterpret_cast<void*>(module_base + entry.offset);
    }
  }
}

OffsetCache BuildCache(std::uint64_t exe_hash, std::uint32_t sig_hash, const std::vector<SignatureDef>& signatures) {
  OffsetCache cache;
  cache.exe_hash = exe_hash;
  cache.signature_hash = sig_hash;

  for (const auto& sig : signatures) {
    cache.entries.push_back({
        sig.name,
        sig.offset,
    });
  }

  return cache;
}

void RegisterOffsetsWithDolos() {
#define REGISTER_OFFSET(...) dolos::RegisterOffset(D2R_GET_NAME(__VA_ARGS__), D2R_GET_VAR(__VA_ARGS__));
  D2R_OFFSET_LIST(REGISTER_OFFSET)
#undef REGISTER_OFFSET
}

bool IsRetcheckGateOffset(const char* name) {
  return std::strcmp(name, "kCheckData") == 0;
}

bool IsRetcheckV2ResolvedDiagnostic() {
  return g_retcheck_v2_slot_rva != 0 && g_retcheck_v2_evidence_callsites >= 8 &&
         g_retcheck_v2_protected_layout_votes >= 8;
}

bool IsRetcheckV2RuntimeResolvedDiagnostic() {
  return IsRetcheckV2ResolvedDiagnostic() && kCheckRuntimeV2.protected_code_begin != nullptr &&
         kCheckRuntimeV2.protected_code_end > kCheckRuntimeV2.protected_code_begin &&
         kCheckRuntimeV2.entry_contract_ok && kCheckRuntimeV2.request_contract_ok &&
         kCheckRuntimeV2.dispatcher_contract_ok &&
         kCheckRuntimeV2.request_allocator != nullptr && kCheckRuntimeV2.request_submit != nullptr &&
         kCheckRuntimeV2.dispatcher_slot != nullptr && kCheckRuntimeV2.dispatcher_object != nullptr &&
         kCheckRuntimeV2.dispatcher_method != nullptr && kCheckRuntimeV2.dispatcher_method_offset != 0;
}

bool IsRetcheckV2EquationCleanDiagnostic() {
  return IsRetcheckV2ResolvedDiagnostic() && kCheckDataV2 != nullptr && g_retcheck_v2_equation_total >= 8 &&
         g_retcheck_v2_equation_clean == g_retcheck_v2_equation_total && g_retcheck_v2_equation_trap == 0 &&
         g_retcheck_v2_equation_skipped == 0;
}

bool IsLegacyPlayerIdOffset(const char* name) {
  return std::strcmp(name, "PlayerIndexToIDEncryptedTable") == 0 || std::strcmp(name, "EncTransformValue") == 0;
}

bool IsOptionalReferenceOffset(const char* name) {
  return std::strncmp(name, "Reference_", 10) == 0;
}

bool IsRuntimeRequiredOffset(const char* name) {
  return !IsRetcheckGateOffset(name) && !IsLegacyPlayerIdOffset(name) &&
         !IsOptionalReferenceOffset(name);
}

void LogMissingOffsets(const std::vector<SignatureDef>& signatures) {
  std::size_t missing_count = 0;
  std::size_t missing_required_count = 0;
  std::size_t missing_retcheck_count = 0;
  std::size_t superseded_retcheck_count = 0;
  std::size_t missing_legacy_player_id_count = 0;
  for (const auto& sig : signatures) {
    if (*sig.target == nullptr) {
      ++missing_count;
      if (IsRetcheckGateOffset(sig.name)) {
        if (IsRetcheckV2ResolvedDiagnostic()) {
          ++superseded_retcheck_count;
        } else {
          ++missing_retcheck_count;
        }
      } else if (IsLegacyPlayerIdOffset(sig.name)) {
        ++missing_legacy_player_id_count;
      } else if (IsRuntimeRequiredOffset(sig.name)) {
        ++missing_required_count;
      }
    }
  }

  if (missing_count == 0) {
    return;
  }

  PIPE_LOG_WARN("[Offsets] {} unresolved offsets:", missing_count);
  PIPE_LOG_WARN(
      "[Offsets] unresolved classification: required={} retcheck_gate={} retcheck_v2_superseded={} legacy_player_id={}",
                missing_required_count,
                missing_retcheck_count,
                superseded_retcheck_count,
                missing_legacy_player_id_count);
  for (const auto& sig : signatures) {
    if (*sig.target == nullptr) {
      const char* category = IsRetcheckGateOffset(sig.name)
                                 ? (IsRetcheckV2ResolvedDiagnostic() ? "retcheck-v2-resolved-old-gate"
                                                                     : "retcheck-gate")
                                 : (IsLegacyPlayerIdOffset(sig.name)
                                        ? "legacy-player-id"
                                        : (IsOptionalReferenceOffset(sig.name)
                                               ? "optional-reference"
                                               : "required-runtime"));
      PIPE_LOG_WARN("[Offsets]   - {} | category={} | pattern: {}", sig.name, category, sig.pattern);
    }
  }
}

const SignatureDef* FindSignature(const std::vector<SignatureDef>& signatures, const char* name) {
  auto it = std::find_if(signatures.begin(), signatures.end(), [name](const SignatureDef& sig) {
    return std::strcmp(sig.name, name) == 0;
  });
  return it == signatures.end() ? nullptr : &*it;
}

SignatureDef* FindMutableSignature(std::vector<SignatureDef>& signatures, const char* name) {
  auto it = std::find_if(signatures.begin(), signatures.end(), [name](const SignatureDef& sig) {
    return std::strcmp(sig.name, name) == 0;
  });
  return it == signatures.end() ? nullptr : &*it;
}

bool IsReadableRange(const void* address, std::size_t size);

constexpr std::size_t kUnitTypeTableBytes = sizeof(EntityHashTable);
constexpr std::size_t kUnitTableBlockBytes = kUnitTypeCount * kUnitTypeTableBytes;

static_assert(kUnitTypeTableBytes == 0x400);
static_assert(kUnitTableBlockBytes == 0x1800);

bool ValidateUnitTableBlock(const void* address, std::size_t* node_count) {
  if (node_count != nullptr) {
    *node_count = 0;
  }
  if (!IsReadableRange(address, kUnitTableBlockBytes)) {
    return false;
  }

  auto* block = reinterpret_cast<EntityHashTable*>(const_cast<void*>(address));
  std::size_t nodes = 0;
  __try {
    for (std::uint32_t type = 0; type < kUnitTypeCount; ++type) {
      for (std::size_t bucket = 0; bucket < kUnitHashTableCount; ++bucket) {
        D2UnitStrc* current = block[type][bucket];
        std::size_t chain_nodes = 0;
        while (current != nullptr && chain_nodes < 4096) {
          if (!IsReadableRange(current, offsetof(D2UnitStrc, pUnitNext) + sizeof(current->pUnitNext)) ||
              current->dwUnitType != type) {
            return false;
          }

          ++nodes;
          ++chain_nodes;
          D2UnitStrc* next = current->pUnitNext;
          if (next == current) {
            return false;
          }
          current = next;
        }
        if (current != nullptr) {
          return false;
        }
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }

  if (node_count != nullptr) {
    *node_count = nodes;
  }
  return nodes != 0;
}

bool ValidateUnitTableBlockWithRetries(const void* address, std::size_t* node_count) {
  std::size_t best_node_count = 0;
  for (std::size_t attempt = 0; attempt < 5; ++attempt) {
    std::size_t current_node_count = 0;
    if (ValidateUnitTableBlock(address, &current_node_count)) {
      if (node_count != nullptr) {
        *node_count = current_node_count;
      }
      return true;
    }
    best_node_count = std::max(best_node_count, current_node_count);
    Sleep(2);
  }
  if (node_count != nullptr) {
    *node_count = best_node_count;
  }
  return false;
}

std::uint32_t GetNearestBeforeServerUnitTableHint(const std::vector<SignatureDef>& signatures) {
  const SignatureDef* client_table = FindSignature(signatures, "sgptClientSideUnitHashTable");
  const SignatureDef* server_func = FindSignature(signatures, "GetServerSideUnitHashTableByType");
  if (client_table == nullptr || server_func == nullptr || server_func->target == nullptr ||
      *server_func->target == nullptr) {
    return 0;
  }

  const dolos::SignatureMatchDiagnostic* nearest_before_server = nullptr;
  std::int64_t nearest_before_delta = 0;
  for (const auto& candidate : client_table->diagnostics) {
    const auto delta = static_cast<std::int64_t>(candidate.match_offset) - static_cast<std::int64_t>(server_func->offset);
    if (delta < 0 && candidate.in_image && (nearest_before_server == nullptr || delta > nearest_before_delta)) {
      nearest_before_server = &candidate;
      nearest_before_delta = delta;
    }
  }

  return nearest_before_server == nullptr ? 0 : static_cast<std::uint32_t>(nearest_before_server->resolved_offset);
}

void AssignClientSideUnitTableCandidate(std::vector<SignatureDef>& signatures,
                                        SignatureDef& client_table,
                                        const dolos::SignatureMatchDiagnostic& candidate,
                                        const char* reason) {
  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  client_table.offset = candidate.resolved_offset;
  *client_table.target = reinterpret_cast<void*>(module_base + candidate.resolved_offset);
  PIPE_LOG_WARN(
      "[Offsets] sgptClientSideUnitHashTable resolved by {}: table RVA=0x{:08X} match RVA=0x{:08X}",
      reason,
      static_cast<std::uint32_t>(candidate.resolved_offset),
      static_cast<std::uint32_t>(candidate.match_offset));

  SignatureDef* client_accessor = FindMutableSignature(signatures, "GetClientSideUnitHashTableByType");
  if (client_accessor != nullptr && client_accessor->target != nullptr && *client_accessor->target == nullptr) {
    client_accessor->offset = candidate.match_offset;
    *client_accessor->target = reinterpret_cast<void*>(module_base + candidate.match_offset);
    PIPE_LOG_WARN(
        "[Offsets] GetClientSideUnitHashTableByType resolved by {}: function RVA=0x{:08X} table RVA=0x{:08X}",
        reason,
        static_cast<std::uint32_t>(candidate.match_offset),
        static_cast<std::uint32_t>(candidate.resolved_offset));
  }
}

bool ResolveClientSideUnitTableFromAccessorPair(std::vector<SignatureDef>& signatures) {
  SignatureDef* client_table = FindMutableSignature(signatures, "sgptClientSideUnitHashTable");
  if (client_table == nullptr || client_table->target == nullptr || *client_table->target != nullptr) {
    return false;
  }

  std::vector<dolos::SignatureMatchDiagnostic> candidates;
  for (const auto& candidate : client_table->diagnostics) {
    if (candidate.in_image && candidate.match_offset != 0 && candidate.resolved_offset != 0) {
      candidates.push_back(candidate);
    }
  }
  std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
    return a.match_offset < b.match_offset;
  });
  candidates.erase(std::unique(candidates.begin(),
                               candidates.end(),
                               [](const auto& a, const auto& b) {
                                 return a.match_offset == b.match_offset &&
                                        a.resolved_offset == b.resolved_offset;
                               }),
                   candidates.end());

  if (candidates.size() != 2) {
    PIPE_LOG_WARN("[Offsets] sgptClientSideUnitHashTable accessor-pair discriminator not applied: candidate_count={}",
                  candidates.size());
    return false;
  }

  const auto& first = candidates[0];
  const auto& second = candidates[1];
  const auto match_delta = second.match_offset - first.match_offset;
  const auto table_delta = second.resolved_offset > first.resolved_offset ? second.resolved_offset - first.resolved_offset
                                                                         : first.resolved_offset - second.resolved_offset;
  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  const auto* first_table = reinterpret_cast<const void*>(module_base + first.resolved_offset);
  const auto* second_table = reinterpret_cast<const void*>(module_base + second.resolved_offset);
  std::size_t first_nodes = 0;
  std::size_t second_nodes = 0;
  const bool first_layout_valid = ValidateUnitTableBlockWithRetries(first_table, &first_nodes);
  const bool second_layout_valid = ValidateUnitTableBlockWithRetries(second_table, &second_nodes);
  const bool first_table_readable = IsReadableRange(first_table, kUnitTableBlockBytes);
  const bool second_table_readable = IsReadableRange(second_table, kUnitTableBlockBytes);
  const SignatureDef* player_index = FindSignature(signatures, "s_PlayerUnitIndex");
  const std::uint64_t player_index_rva =
      player_index != nullptr && player_index->target != nullptr && *player_index->target != nullptr
          ? player_index->offset
          : 0;
  const bool client_follows_player_index =
      player_index_rva != 0 && first.resolved_offset == player_index_rva + sizeof(std::uint32_t);
  const SignatureDef* server_func = FindSignature(signatures, "GetServerSideUnitHashTableByType");
  const std::uint64_t server_rva =
      server_func != nullptr && server_func->target != nullptr && *server_func->target != nullptr
          ? server_func->offset
          : 0;
  const bool second_is_server_accessor =
      server_rva != 0 && second.match_offset >= server_rva && second.match_offset - server_rva <= 0x100;
  const bool adjacent_pair_corroborated =
      client_follows_player_index && first_table_readable && second_table_readable;
  const bool first_layout_corroborated = first_layout_valid || adjacent_pair_corroborated;
  const bool second_layout_corroborated =
      second_layout_valid || adjacent_pair_corroborated || (second_table_readable && second_is_server_accessor);
  const bool layout_ok = first.resolved_offset < second.resolved_offset && match_delta >= 0x40 && match_delta <= 0x100 &&
                         table_delta == kUnitTableBlockBytes && first_layout_corroborated && second_layout_corroborated;
  if (!layout_ok) {
    PIPE_LOG_WARN(
        "[Offsets] sgptClientSideUnitHashTable structural-pair discriminator rejected: first_match=0x{:08X} first_table=0x{:08X} second_match=0x{:08X} second_table=0x{:08X} match_delta=0x{:X} table_delta=0x{:X} first_layout={} first_nodes={} first_readable={} second_layout={} second_nodes={} second_readable={} player_index_adjacent={} server_accessor_relation={}",
        static_cast<std::uint32_t>(first.match_offset),
        static_cast<std::uint32_t>(first.resolved_offset),
        static_cast<std::uint32_t>(second.match_offset),
        static_cast<std::uint32_t>(second.resolved_offset),
        static_cast<std::uint32_t>(match_delta),
        static_cast<std::uint32_t>(table_delta),
        first_layout_valid ? "valid" : "invalid",
        first_nodes,
        first_table_readable ? "yes" : "no",
        second_layout_valid ? "valid" : "invalid",
        second_nodes,
        second_table_readable ? "yes" : "no",
        client_follows_player_index ? "yes" : "no",
        second_is_server_accessor ? "yes" : "no");
    return false;
  }

  PIPE_LOG_WARN(
      "[Offsets] sgptClientSideUnitHashTable structural pair confirmed: first_table=0x{:08X} first_nodes={} second_table=0x{:08X} second_nodes={} second_layout={} player_index_adjacent={} server_accessor_relation={} delta=0x{:X}",
      static_cast<std::uint32_t>(first.resolved_offset),
      first_nodes,
      static_cast<std::uint32_t>(second.resolved_offset),
      second_nodes,
      second_layout_valid ? "live-valid" : "transient-corroborated",
      client_follows_player_index ? "yes" : "no",
      second_is_server_accessor ? "yes" : "no",
      static_cast<std::uint32_t>(table_delta));
  AssignClientSideUnitTableCandidate(signatures, *client_table, first, "six-type structural-pair discriminator");

  SignatureDef* server_accessor = FindMutableSignature(signatures, "GetServerSideUnitHashTableByType");
  if (server_accessor != nullptr && server_accessor->target != nullptr && *server_accessor->target == nullptr) {
    server_accessor->offset = second.match_offset;
    *server_accessor->target = reinterpret_cast<void*>(module_base + second.match_offset);
    PIPE_LOG_WARN(
        "[Offsets] GetServerSideUnitHashTableByType resolved by six-type structural-pair discriminator: function RVA=0x{:08X} table RVA=0x{:08X}",
        static_cast<std::uint32_t>(second.match_offset),
        static_cast<std::uint32_t>(second.resolved_offset));
  }
  return true;
}

void ResolveClientSideUnitTableFromServerNeighbor(std::vector<SignatureDef>& signatures) {
  SignatureDef* client_table = FindMutableSignature(signatures, "sgptClientSideUnitHashTable");
  const SignatureDef* server_func = FindSignature(signatures, "GetServerSideUnitHashTableByType");
  if (client_table == nullptr || client_table->target == nullptr || *client_table->target != nullptr) {
    return;
  }
  if (ResolveClientSideUnitTableFromAccessorPair(signatures)) {
    return;
  }
  if (server_func == nullptr || server_func->target == nullptr || *server_func->target == nullptr) {
    return;
  }

  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  std::uint32_t server_rva = static_cast<std::uint32_t>(server_func->offset);
  if (server_rva == 0) {
    server_rva = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(*server_func->target) - module_base);
  }

  const dolos::SignatureMatchDiagnostic* nearest_before_server = nullptr;
  std::int64_t nearest_before_delta = 0;
  std::size_t nearby_before_count = 0;
  for (const auto& candidate : client_table->diagnostics) {
    const auto delta = static_cast<std::int64_t>(candidate.match_offset) - static_cast<std::int64_t>(server_rva);
    if (!candidate.in_image || delta >= 0 || delta < -0x80) {
      continue;
    }

    ++nearby_before_count;
    if (nearest_before_server == nullptr || delta > nearest_before_delta) {
      nearest_before_server = &candidate;
      nearest_before_delta = delta;
    }
  }

  if (nearest_before_server == nullptr || nearby_before_count != 1) {
    PIPE_LOG_WARN(
        "[Offsets] sgptClientSideUnitHashTable neighbor discriminator not applied: nearby_before_count={} server=0x{:08X}",
        nearby_before_count,
        server_rva);
    return;
  }

  PIPE_LOG_WARN(
      "[Offsets] sgptClientSideUnitHashTable resolved by server-neighbor discriminator: table RVA=0x{:08X} match RVA=0x{:08X} server RVA=0x{:08X} delta={}",
      static_cast<std::uint32_t>(nearest_before_server->resolved_offset),
      static_cast<std::uint32_t>(nearest_before_server->match_offset),
      server_rva,
      nearest_before_delta);
  AssignClientSideUnitTableCandidate(signatures,
                                     *client_table,
                                     *nearest_before_server,
                                     "server-neighbor discriminator");
}

std::uint32_t GetAutomapCreateDataClusterHint(const std::vector<SignatureDef>& signatures) {
  const SignatureDef* create_data = FindSignature(signatures, "AutoMapPanel_CreateAutoMapData");
  if (create_data == nullptr || create_data->diagnostics.empty()) {
    return 0;
  }

  const char* reference_names[] = {
      "AutoMapPanel_GetMode",
      "AutoMapPanel_PrecisionToAutomap",
      "DATATBLS_GetAutomapCellId",
  };

  std::vector<std::uint32_t> reference_rvas;
  for (const char* reference_name : reference_names) {
    const SignatureDef* reference = FindSignature(signatures, reference_name);
    if (reference != nullptr && reference->target != nullptr && *reference->target != nullptr) {
      reference_rvas.push_back(static_cast<std::uint32_t>(reference->offset));
    }
  }

  if (reference_rvas.empty()) {
    return 0;
  }

  const dolos::SignatureMatchDiagnostic* nearest = nullptr;
  std::uint64_t nearest_delta = 0;
  for (const auto& candidate : create_data->diagnostics) {
    if (!candidate.in_image) {
      continue;
    }

    for (std::uint32_t reference_rva : reference_rvas) {
      const auto delta = candidate.resolved_offset > reference_rva ? candidate.resolved_offset - reference_rva
                                                                  : reference_rva - candidate.resolved_offset;
      if (delta <= 0x2000 && (nearest == nullptr || delta < nearest_delta)) {
        nearest = &candidate;
        nearest_delta = delta;
      }
    }
  }

  return nearest == nullptr ? 0 : static_cast<std::uint32_t>(nearest->resolved_offset);
}

void LogUnitHashTableCandidateDiagnostics(const std::vector<SignatureDef>& signatures) {
  const SignatureDef* client_table = FindSignature(signatures, "sgptClientSideUnitHashTable");
  if (client_table == nullptr || client_table->diagnostics.size() < 2) {
    return;
  }

  const SignatureDef* server_func = FindSignature(signatures, "GetServerSideUnitHashTableByType");
  const bool has_server_func = server_func != nullptr && *server_func->target != nullptr;

  PIPE_LOG_INFO("[Offsets] sgptClientSideUnitHashTable candidate diagnostics:");
  if (has_server_func) {
    PIPE_LOG_INFO("[Offsets]   reference GetServerSideUnitHashTableByType RVA=0x{:08X}",
                  static_cast<std::uint32_t>(server_func->offset));
  }

  const dolos::SignatureMatchDiagnostic* nearest_before_server = nullptr;
  std::int64_t nearest_before_delta = 0;
  for (const auto& candidate : client_table->diagnostics) {
    const char* relation = "unknown";
    std::int64_t delta = 0;
    if (has_server_func) {
      delta = static_cast<std::int64_t>(candidate.match_offset) - static_cast<std::int64_t>(server_func->offset);
      relation = delta < 0 ? "before-server-func" : (delta > 0 ? "after-server-func" : "at-server-func");
      if (delta < 0 && candidate.in_image &&
          (nearest_before_server == nullptr || delta > nearest_before_delta)) {
        nearest_before_server = &candidate;
        nearest_before_delta = delta;
      }
    }

    PIPE_LOG_INFO("[Offsets]   candidate match RVA=0x{:08X} resolved table RVA=0x{:08X} in_image={} accepted={} relation={} delta={}",
                  static_cast<std::uint32_t>(candidate.match_offset),
                  static_cast<std::uint32_t>(candidate.resolved_offset),
                  candidate.in_image ? "yes" : "no",
                  candidate.accepted ? "yes" : "no",
                  relation,
                  delta);
  }

  if (nearest_before_server != nullptr) {
    PIPE_LOG_WARN(
        "[Offsets] diagnostic hint: nearest in-image candidate before server accessor resolves table RVA=0x{:08X} (match delta={}); still not assigning without a stronger unique pattern",
        static_cast<std::uint32_t>(nearest_before_server->resolved_offset),
        nearest_before_delta);
  }
  if (client_table->target != nullptr && *client_table->target != nullptr) {
    PIPE_LOG_WARN("[Offsets] sgptClientSideUnitHashTable is assigned by discriminator; exact-match ambiguity remains diagnostic-only");
  } else {
    PIPE_LOG_WARN("[Offsets] sgptClientSideUnitHashTable remains unresolved: multiple plausible exact matches require a stronger dynamic pattern");
  }
}

void LogRetcheckSafetyDiagnostics(const std::vector<SignatureDef>& signatures) {
  const SignatureDef* check_data = FindSignature(signatures, "kCheckData");
  if (check_data == nullptr || *check_data->target != nullptr) {
    return;
  }

  if (IsRetcheckV2ResolvedDiagnostic()) {
    PIPE_LOG_WARN(
        "[Offsets] legacy kCheckData unresolved, but Retcheck V2 layout is diagnostically resolved: slot=0x{:08X} evidence_callsites={} protected_layout_votes={} v2_layout_votes={} equation_clean={}/{} equation_trap={} equation_skipped={} v2_ptr={:p}; old RetcheckBypass remains disabled",
        g_retcheck_v2_slot_rva,
        g_retcheck_v2_evidence_callsites,
        g_retcheck_v2_protected_layout_votes,
        g_retcheck_v2_protected_layout_votes,
        g_retcheck_v2_equation_clean,
        g_retcheck_v2_equation_total,
        g_retcheck_v2_equation_trap,
        g_retcheck_v2_equation_skipped,
        static_cast<void*>(kCheckDataV2));
    if (IsRetcheckV2EquationCleanDiagnostic()) {
      PIPE_LOG_WARN("[Offsets] Retcheck V2 equation gate is clean in diagnostic mode; activation remains blocked pending a V2-safe implementation");
    }
  } else {
    PIPE_LOG_WARN("[Offsets] kCheckData unresolved: retcheck initialization must remain disabled");
  }
  PIPE_LOG_WARN("[Offsets] kCheckData note: weak or stale candidates can trigger the anti-tamper trap path shown in the supplied disassembly");
}

bool IsReadableRange(const void* address, std::size_t size) {
  if (address == nullptr || size == 0) {
    return false;
  }

  const auto start = reinterpret_cast<std::uintptr_t>(address);
  if (size > std::numeric_limits<std::uintptr_t>::max() - start) {
    return false;
  }

  const auto end = start + size;
  auto cursor = start;
  while (cursor < end) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) == 0 ||
        info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD) != 0 ||
        (info.Protect & PAGE_NOACCESS) != 0) {
      return false;
    }

    const auto region_start = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    const auto region_end = region_start + info.RegionSize;
    if (cursor < region_start || region_end <= cursor) {
      return false;
    }
    cursor = std::min(end, region_end);
  }
  return true;
}

void ResolveReferenceUiOffsetFromDataLayout(std::vector<SignatureDef>& signatures) {
  SignatureDef* ui = FindMutableSignature(signatures, "Reference_UIOffset");
  if (ui == nullptr || ui->target == nullptr || *ui->target != nullptr) {
    return;
  }

  const auto* module = reinterpret_cast<const std::uint8_t*>(GetModuleHandle(NULL));
  if (module == nullptr) {
    return;
  }
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(module + dos->e_lfanew);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  const auto module_end = module_base + nt->OptionalHeader.SizeOfImage;

  struct Candidate {
    std::uint32_t rva = 0;
    std::size_t writer_count = 0;
  };
  std::vector<Candidate> candidates;
  auto cursor = module_base;
  while (cursor < module_end) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) == 0) {
      break;
    }
    const auto region_begin = std::max(cursor, reinterpret_cast<std::uintptr_t>(info.BaseAddress));
    const auto region_end = std::min(module_end,
                                     reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize);
    const bool readable = info.State == MEM_COMMIT && (info.Protect & PAGE_GUARD) == 0 &&
                          (info.Protect & PAGE_NOACCESS) == 0;
    if (readable && region_end > region_begin) {
      const auto* bytes = reinterpret_cast<const std::uint8_t*>(region_begin);
      const auto size = static_cast<std::size_t>(region_end - region_begin);
      for (std::size_t i = 0; i + 0x21 <= size; ++i) {
        const auto candidate_rva = static_cast<std::uint32_t>(
            region_begin + i - module_base);
        if ((candidate_rva & 0x7) != 0) {
          continue;
        }
        std::size_t enabled_flags = 0;
        bool flags_valid = true;
        for (std::size_t flag = 0; flag < 0x20; ++flag) {
          const auto value = bytes[i + flag];
          if (value > 1) {
            flags_valid = false;
            break;
          }
          enabled_flags += value;
        }
        if (flags_valid && enabled_flags >= 2 && bytes[i + 0x20] > 1) {
          candidates.push_back({candidate_rva, 0});
        }
      }
    }
    cursor = region_end > cursor ? region_end : module_end;
  }

  cursor = module_base;
  while (cursor < module_end && !candidates.empty()) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) == 0) {
      break;
    }
    const auto region_begin = std::max(cursor, reinterpret_cast<std::uintptr_t>(info.BaseAddress));
    const auto region_end = std::min(module_end,
                                     reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize);
    const auto protection = info.Protect & 0xFF;
    const bool executable = info.State == MEM_COMMIT && (info.Protect & PAGE_GUARD) == 0 &&
                            (protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE ||
                             protection == PAGE_EXECUTE_WRITECOPY);
    if (executable && region_end > region_begin) {
      const auto* bytes = reinterpret_cast<const std::uint8_t*>(region_begin);
      const auto size = static_cast<std::size_t>(region_end - region_begin);
      for (std::size_t i = 0; i + 10 <= size; ++i) {
        if (bytes[i] != 0x40 || bytes[i + 1] != 0x84 || bytes[i + 2] != 0xED ||
            bytes[i + 3] != 0x0F || bytes[i + 4] != 0x94 || bytes[i + 5] != 0x05) {
          continue;
        }
        std::int32_t displacement = 0;
        std::memcpy(&displacement, bytes + i + 6, sizeof(displacement));
        const auto write_target = region_begin + i + 10 + displacement;
        for (auto& candidate : candidates) {
          const auto candidate_begin = module_base + candidate.rva;
          if (write_target >= candidate_begin && write_target < candidate_begin + 0x20) {
            ++candidate.writer_count;
          }
        }
      }
    }
    cursor = region_end > cursor ? region_end : module_end;
  }

  candidates.erase(std::remove_if(candidates.begin(), candidates.end(), [](const Candidate& candidate) {
                     return candidate.writer_count < 2;
                   }),
                   candidates.end());
  if (candidates.size() != 1) {
    PIPE_LOG_WARN(
        "[Offsets] Reference_UIOffset data-layout resolver rejected: corroborated_candidates={}",
        candidates.size());
    return;
  }

  ui->offset = candidates.front().rva;
  *ui->target = const_cast<std::uint8_t*>(module) + ui->offset;
  PIPE_LOG_WARN(
      "[Offsets] Reference_UIOffset resolved by 32-byte flag-tail/writer structure: RVA=0x{:08X} writer_count={}",
      static_cast<std::uint32_t>(ui->offset),
      candidates.front().writer_count);
}

void LogMemoryRegionProbe(const char* source_name,
                          std::uint32_t slot_rva,
                          const char* label,
                          const void* address,
                          std::size_t size) {
  MEMORY_BASIC_INFORMATION info{};
  if (address == nullptr || VirtualQuery(address, &info, sizeof(info)) == 0) {
    PIPE_LOG_WARN("[Offsets] memory region probe {} slot=0x{:08X} {} address={:p} size=0x{:X} virtual_query=failed",
                  source_name,
                  slot_rva,
                  label,
                  address,
                  size);
    return;
  }

  const auto start = reinterpret_cast<std::uintptr_t>(address);
  const auto region_start = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
  const auto region_end = region_start + info.RegionSize;
  const bool single_region = start >= region_start && size <= region_end - start;
  const bool committed = info.State == MEM_COMMIT;
  const bool accessible = (info.Protect & PAGE_GUARD) == 0 && (info.Protect & PAGE_NOACCESS) == 0;
  PIPE_LOG_WARN(
      "[Offsets] memory region probe {} slot=0x{:08X} {} address={:p} size=0x{:X} base={:p} region_size=0x{:X} state=0x{:X} protect=0x{:X} alloc_protect=0x{:X} type=0x{:X} single_region={} committed={} accessible={} readable_range={}",
      source_name,
      slot_rva,
      label,
      address,
      size,
      info.BaseAddress,
      static_cast<std::size_t>(info.RegionSize),
      info.State,
      info.Protect,
      info.AllocationProtect,
      info.Type,
      single_region ? "yes" : "no",
      committed ? "yes" : "no",
      accessible ? "yes" : "no",
      IsReadableRange(address, size) ? "yes" : "no");
}

template <typename T>
bool TryReadValue(const void* address, T* value) {
  if (!IsReadableRange(address, sizeof(T))) {
    return false;
  }

  std::memcpy(value, address, sizeof(T));
  return true;
}

bool IsPlausibleAutomapLayerPointer(D2AutomapLayerStrc* layer) {
  if (layer == nullptr) {
    return true;
  }
  if (!IsReadableRange(layer, sizeof(D2AutomapLayerStrc))) {
    return false;
  }

  int32_t layer_id = 0;
  if (!TryReadValue(&layer->dwLayerID, &layer_id)) {
    return false;
  }
  return layer_id >= 0 && layer_id < 1000;
}

void ResolveCurrentAutomapLayerFromLayerLink(std::vector<SignatureDef>& signatures) {
  SignatureDef* current = FindMutableSignature(signatures, "s_currentAutomapLayer");
  const SignatureDef* link = FindSignature(signatures, "s_automapLayerLink");
  if (current == nullptr || current->target == nullptr || *current->target != nullptr ||
      link == nullptr || link->target == nullptr || *link->target == nullptr) {
    return;
  }

  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
  auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
  const auto module_end = module_base + nt->OptionalHeader.SizeOfImage;

  constexpr std::uintptr_t kAutomapLayerGlobalPairDelta = 0x2038;
  const auto link_global = reinterpret_cast<std::uintptr_t>(*link->target);
  const auto candidate_global = link_global + kAutomapLayerGlobalPairDelta;
  if (candidate_global < module_base || candidate_global + sizeof(D2AutomapLayerStrc*) > module_end ||
      !IsReadableRange(reinterpret_cast<void*>(candidate_global), sizeof(D2AutomapLayerStrc*))) {
    PIPE_LOG_WARN(
        "[Offsets] s_currentAutomapLayer pair fallback rejected: link RVA=0x{:08X} candidate RVA=0x{:08X} readable=no",
        static_cast<std::uint32_t>(link_global - module_base),
        static_cast<std::uint32_t>(candidate_global - module_base));
    return;
  }

  D2AutomapLayerStrc* link_value = nullptr;
  D2AutomapLayerStrc* current_value = nullptr;
  TryReadValue(reinterpret_cast<void*>(link_global), &link_value);
  TryReadValue(reinterpret_cast<void*>(candidate_global), &current_value);

  if (!IsPlausibleAutomapLayerPointer(link_value) || !IsPlausibleAutomapLayerPointer(current_value)) {
    PIPE_LOG_WARN(
        "[Offsets] s_currentAutomapLayer pair fallback rejected: link_value={:p} current_value={:p} plausible=no",
        static_cast<void*>(link_value),
        static_cast<void*>(current_value));
    return;
  }

  current->offset = static_cast<std::uint32_t>(candidate_global - module_base);
  *current->target = reinterpret_cast<void*>(candidate_global);
  PIPE_LOG_WARN(
      "[Offsets] s_currentAutomapLayer resolved by automap-global-pair fallback: current RVA=0x{:08X} link RVA=0x{:08X} delta=0x{:X} link_value={:p} current_value={:p}",
      current->offset,
      static_cast<std::uint32_t>(link_global - module_base),
      static_cast<unsigned>(kAutomapLayerGlobalPairDelta),
      static_cast<void*>(link_value),
      static_cast<void*>(current_value));
}

void LogPlayerIdEncryptedTableCandidate(std::uint32_t rva, const char* source_name) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  const auto candidate_address = module_base + rva;
  auto* table = reinterpret_cast<const std::uint32_t*>(module_base + rva);

  std::uint32_t values[16]{};
  std::uint32_t extended_values[64]{};
  const bool table_readable = IsReadableRange(table, sizeof(values));
  const bool extended_readable = IsReadableRange(table, sizeof(extended_values));
  std::uint32_t nonzero_count = 0;
  std::uint32_t repeated_pairs = 0;
  std::uint32_t ascii_like_dwords = 0;
  std::uint32_t pointer_pair_count = 0;
  std::uint32_t small_dword_count = 0;
  std::vector<std::uint32_t> unique_values;
  if (table_readable) {
    std::memcpy(values, table, sizeof(values));
    for (std::size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
      if (values[i] != 0) {
        ++nonzero_count;
      }
      if (values[i] != 0 && values[i] < 0x10000) {
        ++small_dword_count;
      }
      if (i > 0 && values[i] == values[i - 1]) {
        ++repeated_pairs;
      }
      std::uint32_t printable_bytes = 0;
      std::uint32_t zero_bytes = 0;
      for (std::size_t byte = 0; byte < sizeof(std::uint32_t); ++byte) {
        const auto ch = static_cast<std::uint8_t>((values[i] >> (byte * 8)) & 0xFFu);
        if (ch >= 0x20 && ch <= 0x7E) {
          ++printable_bytes;
        } else if (ch == 0) {
          ++zero_bytes;
        }
      }
      if (printable_bytes >= 3 && zero_bytes <= 1) {
        ++ascii_like_dwords;
      }
      if (std::find(unique_values.begin(), unique_values.end(), values[i]) == unique_values.end()) {
        unique_values.push_back(values[i]);
      }
    }
    for (std::size_t i = 0; i + 1 < sizeof(values) / sizeof(values[0]); i += 2) {
      const bool low_nonzero = values[i] != 0;
      const bool high_pointerish = values[i + 1] >= 0x00000100 && values[i + 1] <= 0x00007FFF;
      if (low_nonzero && high_pointerish) {
        ++pointer_pair_count;
      }
    }
  }
  std::uint32_t extended_nonzero_count = 0;
  std::uint32_t extended_unique_count = 0;
  if (extended_readable) {
    std::memcpy(extended_values, table, sizeof(extended_values));
    std::vector<std::uint32_t> extended_unique_values;
    for (std::uint32_t value : extended_values) {
      if (value != 0) {
        ++extended_nonzero_count;
      }
      if (std::find(extended_unique_values.begin(), extended_unique_values.end(), value) ==
          extended_unique_values.end()) {
        extended_unique_values.push_back(value);
      }
    }
    extended_unique_count = static_cast<std::uint32_t>(extended_unique_values.size());
  }

  const char* known_role = "none";
  auto mark_known_global = [&](const char* name, const void* address) {
    if (address != nullptr && reinterpret_cast<std::uintptr_t>(address) == candidate_address) {
      known_role = name;
    }
  };
  mark_known_global("D2Allocator", D2Allocator);
  mark_known_global("kCheckData", kCheckData);
  mark_known_global("kCheckDataV2", kCheckDataV2);
  mark_known_global("s_automapLayerLink", s_automapLayerLink);
  mark_known_global("s_currentAutomapLayer", s_currentAutomapLayer);
  mark_known_global("s_panelManager", s_panelManager);
  mark_known_global("AutoMapPanel_spdwShift", AutoMapPanel_spdwShift);
  mark_known_global("sgptDataTbls", sgptDataTbls);
  mark_known_global("s_PlayerUnitIndex", s_PlayerUnitIndex);
  mark_known_global("sgptClientSideUnitHashTable", sgptClientSideUnitHashTable);
  mark_known_global("EncEncryptionKeys", EncEncryptionKeys);
  mark_known_global("PlayerIndexToIDEncryptedTable", PlayerIndexToIDEncryptedTable);

  const char* verdict = "unreadable";
  if (table_readable) {
    if (std::strcmp(known_role, "none") != 0 && std::strcmp(known_role, "PlayerIndexToIDEncryptedTable") != 0) {
      verdict = "reject-known-global";
    } else if (ascii_like_dwords >= 4) {
      verdict = "reject-likely-text";
    } else if (nonzero_count <= 2) {
      verdict = "reject-too-sparse";
    } else if (repeated_pairs >= 8) {
      verdict = "reject-repeated";
    } else if (pointer_pair_count >= 3) {
      verdict = "reject-pointer-pairs";
    } else if (small_dword_count >= 10) {
      verdict = "reject-small-index-state";
    } else if (extended_readable && extended_nonzero_count >= 16 && extended_unique_count >= 8) {
      verdict = "plausible-needs-code-xref";
    } else {
      verdict = "weak-needs-code-xref";
    }
  }

  PIPE_LOG_WARN(
      "[Offsets] player-id encrypted-table candidate source={} rva=0x{:08X} table={:p} readable16={} readable64={} nonzero16={} unique16={} repeated_pairs16={} ascii_like16={} pointer_pairs16={} small16={} nonzero64={} unique64={} known_role={} verdict={} values=[0]=0x{:08X} [1]=0x{:08X} [2]=0x{:08X} [3]=0x{:08X} [4]=0x{:08X} [5]=0x{:08X} [6]=0x{:08X} [7]=0x{:08X} [8]=0x{:08X} [9]=0x{:08X} [10]=0x{:08X} [11]=0x{:08X} [12]=0x{:08X} [13]=0x{:08X} [14]=0x{:08X} [15]=0x{:08X}",
      source_name,
      rva,
      static_cast<const void*>(table),
      table_readable ? "yes" : "no",
      extended_readable ? "yes" : "no",
      nonzero_count,
      static_cast<std::uint32_t>(unique_values.size()),
      repeated_pairs,
      ascii_like_dwords,
      pointer_pair_count,
      small_dword_count,
      extended_nonzero_count,
      extended_unique_count,
      known_role,
      verdict,
      values[0],
      values[1],
      values[2],
      values[3],
      values[4],
      values[5],
      values[6],
      values[7],
      values[8],
      values[9],
      values[10],
      values[11],
      values[12],
      values[13],
      values[14],
      values[15]);
#else
  (void)rva;
  (void)source_name;
#endif
}

std::vector<std::uint32_t> CollectResolvedRvas(const std::vector<SignatureDef>& signatures, const char* name) {
  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  std::vector<std::uint32_t> rvas;
  const SignatureDef* sig = FindSignature(signatures, name);
  if (sig == nullptr) {
    return rvas;
  }
  if (sig->target != nullptr && *sig->target != nullptr) {
    const auto address = reinterpret_cast<std::uintptr_t>(*sig->target);
    if (address >= module_base) {
      rvas.push_back(static_cast<std::uint32_t>(address - module_base));
    }
  }
  for (const auto& diagnostic : sig->diagnostics) {
    if (diagnostic.in_image) {
      rvas.push_back(static_cast<std::uint32_t>(diagnostic.resolved_offset));
    }
  }
  std::sort(rvas.begin(), rvas.end());
  rvas.erase(std::unique(rvas.begin(), rvas.end()), rvas.end());
  return rvas;
}

void LogPlayerIdTransformXrefDiagnostics(const std::vector<SignatureDef>& signatures) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  HMODULE module = GetModuleHandle(NULL);
  if (module == nullptr) {
    return;
  }

  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
  auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
  const auto module_end = module_base + nt->OptionalHeader.SizeOfImage;

  std::vector<std::uint32_t> transform_rvas = CollectResolvedRvas(signatures, "EncTransformValue");
  for (std::uint32_t rva : CollectResolvedRvas(signatures, "Diagnostic_EncTransformValue_CallA")) {
    transform_rvas.push_back(rva);
  }
  for (std::uint32_t rva : CollectResolvedRvas(signatures, "Diagnostic_EncTransformValue_CallB")) {
    transform_rvas.push_back(rva);
  }

  // The old player-id call shapes can partially match the common Retcheck V2
  // verifier.  It is an anti-tamper helper, not EncTransformValue.
  const auto retcheck_verifier_rvas =
      CollectResolvedRvas(signatures, "Diagnostic_RetcheckTrap_VerificationCall");
  transform_rvas.erase(
      std::remove_if(transform_rvas.begin(), transform_rvas.end(),
                     [&retcheck_verifier_rvas](std::uint32_t rva) {
                       return std::find(retcheck_verifier_rvas.begin(),
                                        retcheck_verifier_rvas.end(),
                                        rva) != retcheck_verifier_rvas.end();
                     }),
      transform_rvas.end());
  std::sort(transform_rvas.begin(), transform_rvas.end());
  transform_rvas.erase(std::unique(transform_rvas.begin(), transform_rvas.end()), transform_rvas.end());

  if (transform_rvas.empty()) {
    PIPE_LOG_WARN("[Offsets] player-id transform-xref scan skipped: EncTransformValue unresolved");
    return;
  }

  PIPE_LOG_WARN("[Offsets] player-id transform-xref scan: {} EncTransformValue target(s)", transform_rvas.size());
  const auto* section = IMAGE_FIRST_SECTION(nt);
  std::size_t logged_calls = 0;
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections && logged_calls < 32; ++i, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }

    const auto* start = reinterpret_cast<const std::uint8_t*>(module_base + section->VirtualAddress);
    const auto* end = start + section->Misc.VirtualSize;
    for (const std::uint8_t* p = start; p + 5 <= end && logged_calls < 32; ++p) {
      if (p[0] != 0xE8) {
        continue;
      }

      std::int32_t rel = 0;
      std::memcpy(&rel, p + 1, sizeof(rel));
      const auto call_target = reinterpret_cast<std::uintptr_t>(p + 5) + rel;
      if (call_target < module_base || call_target >= module_end) {
        continue;
      }

      const auto target_rva = static_cast<std::uint32_t>(call_target - module_base);
      if (std::find(transform_rvas.begin(), transform_rvas.end(), target_rva) == transform_rvas.end()) {
        continue;
      }

      const auto callsite_rva = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(p) - module_base);
      PIPE_LOG_WARN("[Offsets] player-id transform-xref callsite=0x{:08X} target=0x{:08X}",
                    callsite_rva,
                    target_rva);

      const std::uint8_t* window_begin = p > start + 96 ? p - 96 : start;
      std::size_t logged_refs = 0;
      for (const std::uint8_t* q = window_begin; q + 7 <= p && logged_refs < 8; ++q) {
        if (q[0] != 0x48 || (q[1] != 0x8D && q[1] != 0x8B) || (q[2] & 0xC7) != 0x05) {
          continue;
        }

        std::int32_t rip_rel = 0;
        std::memcpy(&rip_rel, q + 3, sizeof(rip_rel));
        const auto ref_target = reinterpret_cast<std::uintptr_t>(q + 7) + rip_rel;
        if (ref_target < module_base || ref_target >= module_end) {
          continue;
        }

        const auto ref_rva = static_cast<std::uint32_t>(ref_target - module_base);
        const auto insn_rva = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(q) - module_base);
        const char* op = q[1] == 0x8D ? "lea" : "mov";
        PIPE_LOG_WARN(
            "[Offsets] player-id transform-xref nearby-rip callsite=0x{:08X} insn=0x{:08X} before_call=0x{:02X} op={} modrm=0x{:02X} target=0x{:08X}",
            callsite_rva,
            insn_rva,
            static_cast<unsigned>(p - q),
            op,
            static_cast<unsigned>(q[2]),
            ref_rva);
        ++logged_refs;
      }
      ++logged_calls;
    }
  }

  if (logged_calls == 0) {
    PIPE_LOG_WARN("[Offsets] player-id transform-xref scan found no direct callsites");
  }
#else
  (void)signatures;
#endif
}

void LogPlayerIndexInitializerSeriesDiagnostics() {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  HMODULE module = GetModuleHandle(NULL);
  if (module == nullptr) {
    return;
  }

  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
  auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
  const auto module_end = module_base + nt->OptionalHeader.SizeOfImage;
  const auto* section = IMAGE_FIRST_SECTION(nt);
  std::size_t logged = 0;

  for (WORD i = 0; i < nt->FileHeader.NumberOfSections && logged < 16; ++i, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }

    const auto* start = reinterpret_cast<const std::uint8_t*>(module_base + section->VirtualAddress);
    const auto* end = start + section->Misc.VirtualSize;
    for (const std::uint8_t* p = start; p + 45 <= end && logged < 16; ++p) {
      if (p[0] != 0x48 || p[1] != 0x83 || p[2] != 0xEC || p[3] != 0x28 || p[4] != 0x41 ||
          p[5] != 0xB8 || p[7] != 0x00 || p[8] != 0x00 || p[9] != 0x00 || p[10] != 0x48 ||
          p[11] != 0x8D || p[12] != 0x15 || p[17] != 0x48 || p[18] != 0x8D || p[19] != 0x0D ||
          p[24] != 0xE8 || p[29] != 0x48 || p[30] != 0x8D || p[31] != 0x0D || p[36] != 0x48 ||
          p[37] != 0x83 || p[38] != 0xC4 || p[39] != 0x28 || p[40] != 0xE9) {
        continue;
      }

      std::int32_t table_rel = 0;
      std::int32_t context_rel = 0;
      std::int32_t call_rel = 0;
      std::int32_t after_rel = 0;
      std::memcpy(&table_rel, p + 13, sizeof(table_rel));
      std::memcpy(&context_rel, p + 20, sizeof(context_rel));
      std::memcpy(&call_rel, p + 25, sizeof(call_rel));
      std::memcpy(&after_rel, p + 32, sizeof(after_rel));

      const auto table_target = reinterpret_cast<std::uintptr_t>(p + 17) + table_rel;
      const auto context_target = reinterpret_cast<std::uintptr_t>(p + 24) + context_rel;
      const auto call_target = reinterpret_cast<std::uintptr_t>(p + 29) + call_rel;
      const auto after_target = reinterpret_cast<std::uintptr_t>(p + 36) + after_rel;
      if (table_target < module_base || table_target >= module_end || call_target < module_base ||
          call_target >= module_end) {
        continue;
      }

      const auto site_rva = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(p) - module_base);
      const auto table_rva = static_cast<std::uint32_t>(table_target - module_base);
      PIPE_LOG_WARN(
          "[Offsets] player-index init-series candidate site=0x{:08X} selector={} table=0x{:08X} context=0x{:08X} call=0x{:08X} after=0x{:08X}",
          site_rva,
          static_cast<unsigned>(p[6]),
          table_rva,
          context_target >= module_base && context_target < module_end ? static_cast<std::uint32_t>(context_target - module_base) : 0,
          static_cast<std::uint32_t>(call_target - module_base),
          after_target >= module_base && after_target < module_end ? static_cast<std::uint32_t>(after_target - module_base) : 0);
      LogPlayerIdEncryptedTableCandidate(table_rva, "Diagnostic_PlayerIndex_InitSeries");
      ++logged;
      p += 39;
    }
  }

  if (logged == 0) {
    PIPE_LOG_WARN("[Offsets] player-index init-series scan found no candidates");
  }
#endif
}

void LogPlayerIdOffsetCandidateDiagnostics(const std::vector<SignatureDef>& signatures) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);

  auto collect_rvas = [module_base](const SignatureDef* sig) {
    std::vector<std::uint32_t> rvas;
    if (sig == nullptr) {
      return rvas;
    }
    if (sig->target != nullptr && *sig->target != nullptr) {
      rvas.push_back(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(*sig->target) - module_base));
    }
    for (const auto& diagnostic : sig->diagnostics) {
      if (diagnostic.in_image) {
        rvas.push_back(static_cast<std::uint32_t>(diagnostic.resolved_offset));
      }
    }
    std::sort(rvas.begin(), rvas.end());
    rvas.erase(std::unique(rvas.begin(), rvas.end()), rvas.end());
    return rvas;
  };

  const SignatureDef* enc_keys = FindSignature(signatures, "EncEncryptionKeys");
  for (std::uint32_t rva : collect_rvas(enc_keys)) {
    auto* global = reinterpret_cast<const void*>(module_base + rva);
    std::uintptr_t keys_base = 0;
    const bool global_readable = TryReadValue(global, &keys_base);
    std::uint32_t key = 0;
    const bool key_readable = global_readable && keys_base != 0 &&
                              TryReadValue(reinterpret_cast<const void*>(keys_base + 0x146), &key);
    PIPE_LOG_WARN(
        "[Offsets] player-id EncEncryptionKeys candidate rva=0x{:08X} global={:p} global_readable={} keys_base=0x{:016X} key_0146_readable={} key_0146=0x{:08X}",
        rva,
        global,
        global_readable ? "yes" : "no",
        keys_base,
        key_readable ? "yes" : "no",
        key);
  }

  constexpr const char* kPlayerIdTableCandidateNames[] = {
      "Diagnostic_PlayerIndex_LegacyEncryptedTable",
      "Diagnostic_PlayerIndex_TableCandidate_CallA",
      "Diagnostic_PlayerIndex_TableCandidate_CallB",
      "Diagnostic_PlayerIndex_TableCandidate_CallC",
      "Diagnostic_TableRange_StartupAccumulator",
      "Diagnostic_TableRange_AutomapMessageA",
      "Diagnostic_TableRange_AutomapMessageB",
  };
  for (const char* name : kPlayerIdTableCandidateNames) {
    const SignatureDef* index_table = FindSignature(signatures, name);
    for (std::uint32_t rva : collect_rvas(index_table)) {
      LogPlayerIdEncryptedTableCandidate(rva, name);
    }
  }
  PIPE_LOG_WARN("[Offsets] player-index init-series wide scan disabled in default diagnostic path; using bounded signature candidates only");
#else
  (void)signatures;
#endif
}

void LogClientPlayerUnitTableDiagnostics() {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  if (sgptClientSideUnitHashTable == nullptr) {
    PIPE_LOG_WARN("[Offsets] client player-unit table probe skipped: sgptClientSideUnitHashTable is null");
    return;
  }

  EntityHashTable* client_units = sgptClientSideUnitHashTable;
  if (!IsReadableRange(&client_units[0][0], sizeof(EntityHashTable))) {
    PIPE_LOG_WARN("[Offsets] client player-unit table probe skipped: player table is not readable ({:p})",
                  static_cast<void*>(client_units));
    return;
  }

  std::uint32_t player_count = 0;
  std::uint32_t plausible_local_count = 0;
  std::uint32_t first_plausible_id = 0;
  std::uint32_t single_id = 0;
  bool single_id_consistent = true;
  std::size_t logged = 0;

  for (std::size_t bucket = 0; bucket < kUnitHashTableCount; ++bucket) {
    D2UnitStrc* current = nullptr;
    if (!TryReadValue(&client_units[0][bucket], &current)) {
      PIPE_LOG_WARN("[Offsets] client player-unit table bucket={} pointer unreadable", bucket);
      continue;
    }

    std::size_t traversed = 0;
    while (current != nullptr && traversed++ < 256) {
      if (!IsReadableRange(current, sizeof(D2UnitStrc))) {
        PIPE_LOG_WARN("[Offsets] client player-unit table bucket={} unreadable node={:p}",
                      bucket,
                      static_cast<void*>(current));
        break;
      }

      const bool type_ok = current->dwUnitType == 0;
      const bool id_ok = current->dwId != 0 && current->dwId != 0xFFFFFFFFu;
      const bool act_ok = current->pDrlgAct != nullptr && IsReadableRange(current->pDrlgAct, sizeof(D2DrlgActStrc));
      const bool drlg_ok = act_ok && current->pDrlgAct->ptDrlg != nullptr &&
                           IsReadableRange(current->pDrlgAct->ptDrlg, sizeof(D2DrlgStrc));
      const bool path_ok = current->pDynamicPath != nullptr &&
                           IsReadableRange(current->pDynamicPath, sizeof(D2DynamicPathStrc));
      const bool coords_ok = current->wPosX > 0 && current->wPosY > 0;
      const bool plausible_local = type_ok && id_ok && act_ok && drlg_ok && coords_ok;

      if (type_ok) {
        ++player_count;
        if (single_id == 0) {
          single_id = current->dwId;
        } else if (current->dwId != single_id) {
          single_id_consistent = false;
        }
      }

      if (plausible_local) {
        ++plausible_local_count;
        if (first_plausible_id == 0) {
          first_plausible_id = current->dwId;
        }
      }

      if (logged < 16) {
        PIPE_LOG_WARN(
            "[Offsets] client player-unit candidate bucket={} node={:p} id=0x{:08X} type={} class={} mode={} pos=({}, {}) act={:p}/{} drlg={:p}/{} path={:p}/{} dataTblIdx={} plausible_local={}",
            bucket,
            static_cast<void*>(current),
            current->dwId,
            current->dwUnitType,
            current->dwClassId,
            current->dwMode,
            current->wPosX,
            current->wPosY,
            static_cast<void*>(current->pDrlgAct),
            act_ok ? "readable" : "bad",
            act_ok ? static_cast<void*>(current->pDrlgAct->ptDrlg) : nullptr,
            drlg_ok ? "readable" : "bad",
            static_cast<void*>(current->pDynamicPath),
            path_ok ? "readable" : "bad",
            static_cast<unsigned>(current->nDataTblsIndex),
            plausible_local ? "yes" : "no");
        ++logged;
      }

      current = current->pUnitNext;
    }
  }

  PIPE_LOG_WARN(
      "[Offsets] client player-unit table summary players={} plausible_local={} first_plausible_id=0x{:08X} single_id=0x{:08X} single_id_consistent={}",
      player_count,
      plausible_local_count,
      first_plausible_id,
      single_id,
      single_id_consistent ? "yes" : "no");
#endif
}

std::uint32_t ReadU32Unaligned(const std::uint8_t* p) {
  std::uint32_t value = 0;
  std::memcpy(&value, p, sizeof(value));
  return value;
}

std::int32_t ReadI32Unaligned(const std::uint8_t* p) {
  std::int32_t value = 0;
  std::memcpy(&value, p, sizeof(value));
  return value;
}

bool LooksLikeNonTrivialCode(const std::uint8_t* p, std::size_t size) {
  if (!IsReadableRange(p, size)) {
    return false;
  }

  bool all_zero = true;
  bool all_int3 = true;
  for (std::size_t i = 0; i < size; ++i) {
    all_zero = all_zero && p[i] == 0x00;
    all_int3 = all_int3 && p[i] == 0xCC;
  }
  return !all_zero && !all_int3;
}

bool LooksLikeAutomapCreateData(const std::uint8_t* p) {
  return IsReadableRange(p, 22) && p[0] == 0x4C && p[1] == 0x89 && p[2] == 0x44 && p[3] == 0x24 &&
         p[5] == 0x53 && p[6] == 0x55 && p[7] == 0x56 && p[8] == 0x57 && p[9] == 0x41 &&
         p[10] == 0x54 && p[11] == 0x41 && p[12] == 0x56 && p[13] == 0x41 && p[14] == 0x57 &&
         p[15] == 0x48 && p[16] == 0x83 && p[17] == 0xEC && p[19] == 0x0F && p[20] == 0x28 &&
         p[21] == 0x02;
}

bool LooksLikeAutomapPrecision(const std::uint8_t* p) {
  return IsReadableRange(p, 18) && p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24 &&
         p[5] == 0x55 && p[6] == 0x56 && p[7] == 0x57 && p[8] == 0x48 && p[9] == 0x8B &&
         p[10] == 0xEC && p[11] == 0x48 && p[12] == 0x83 && p[13] == 0xEC && p[15] == 0x49 &&
         p[16] == 0x8B && p[17] == 0xD8;
}

bool LooksLikeDatatblsGetAutomapCellId(const std::uint8_t* p) {
  return IsReadableRange(p, 21) && p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24 &&
         p[5] == 0x48 && p[6] == 0x89 && p[7] == 0x74 && p[8] == 0x24 && p[10] == 0x57 &&
         p[11] == 0x48 && p[12] == 0x83 && p[13] == 0xEC && p[15] == 0x48 && p[16] == 0x63 &&
         p[17] == 0xD9 && p[18] == 0x45 && p[19] == 0x8B && p[20] == 0xD9;
}

bool ResolveRelativeCallRva(std::uintptr_t module_base, const std::uint8_t* call, std::uint32_t& out_rva) {
  if (!IsReadableRange(call, 5) || call[0] != 0xE8) {
    return false;
  }

  const auto rel = ReadI32Unaligned(call + 1);
  const auto target = reinterpret_cast<std::uintptr_t>(call + 5) + rel;
  if (target < module_base || !LooksLikeNonTrivialCode(reinterpret_cast<const std::uint8_t*>(target), 8)) {
    return false;
  }

  out_rva = static_cast<std::uint32_t>(target - module_base);
  return true;
}

bool AssignMissingRuntimeOffsetFromRva(std::vector<SignatureDef>& signatures,
                                       const char* name,
                                       std::uint32_t rva,
                                       const char* reason) {
  SignatureDef* sig = FindMutableSignature(signatures, name);
  if (sig == nullptr || sig->target == nullptr || *sig->target != nullptr || !IsRuntimeRequiredOffset(name)) {
    return false;
  }

  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  auto* address = reinterpret_cast<std::uint8_t*>(module_base + rva);
  if (!LooksLikeNonTrivialCode(address, 8)) {
    PIPE_LOG_WARN("[Offsets] automap cluster fallback rejected {:<36} RVA=0x{:08X}: code bytes not readable/plausible",
                  name,
                  rva);
    return false;
  }

  sig->offset = rva;
  *sig->target = address;
  PIPE_LOG_WARN("[Offsets] automap cluster fallback resolved {:<36} RVA=0x{:08X} reason={}",
                name,
                rva,
                reason);
  return true;
}

void ResolveAutomapOffsetsFromCreateDataCluster(std::vector<SignatureDef>& signatures) {
  const SignatureDef* create_data = FindSignature(signatures, "AutoMapPanel_CreateAutoMapData");
  if (create_data == nullptr || create_data->target == nullptr || *create_data->target == nullptr) {
    return;
  }

  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  const auto create_address = reinterpret_cast<std::uintptr_t>(*create_data->target);
  const auto create_rva = static_cast<std::uint32_t>(create_address - module_base);
  auto* create_code = reinterpret_cast<const std::uint8_t*>(create_address);
  if (!LooksLikeAutomapCreateData(create_code)) {
    PIPE_LOG_WARN("[Offsets] automap cluster fallback skipped: CreateAutoMapData RVA=0x{:08X} failed byte validation",
                  create_rva);
    return;
  }

  const auto precision_rva = create_rva + 0x9F0;
  auto* precision_code = reinterpret_cast<const std::uint8_t*>(module_base + precision_rva);
  if (LooksLikeAutomapPrecision(precision_code)) {
    AssignMissingRuntimeOffsetFromRva(
        signatures, "AutoMapPanel_PrecisionToAutomap", precision_rva, "validated-near-CreateAutoMapData+0x9F0");
  } else {
    PIPE_LOG_WARN("[Offsets] automap cluster fallback did not validate PrecisionToAutomap at RVA=0x{:08X}",
                  precision_rva);
  }

  const auto get_mode_rva = create_rva + 0xDD0;
  auto* get_mode_code = reinterpret_cast<const std::uint8_t*>(module_base + get_mode_rva);
  if (LooksLikeNonTrivialCode(get_mode_code, 16)) {
    AssignMissingRuntimeOffsetFromRva(
        signatures, "AutoMapPanel_GetMode", get_mode_rva, "validated-near-CreateAutoMapData+0xDD0");
  } else {
    PIPE_LOG_WARN("[Offsets] automap cluster fallback did not validate GetMode at RVA=0x{:08X}", get_mode_rva);
  }

  const auto cell_id_rva = create_rva + 0x1F5210;
  auto* cell_id_code = reinterpret_cast<const std::uint8_t*>(module_base + cell_id_rva);
  if (LooksLikeDatatblsGetAutomapCellId(cell_id_code)) {
    AssignMissingRuntimeOffsetFromRva(
        signatures, "DATATBLS_GetAutomapCellId", cell_id_rva, "validated-relative-to-CreateAutoMapData");
  } else {
    PIPE_LOG_WARN("[Offsets] automap cluster fallback did not validate DATATBLS_GetAutomapCellId at RVA=0x{:08X}",
                  cell_id_rva);
  }

  const auto caller_search_begin = create_address + 0x1F00;
  const auto caller_search_size = 0x180;
  if (!IsReadableRange(reinterpret_cast<const void*>(caller_search_begin), caller_search_size)) {
    PIPE_LOG_WARN("[Offsets] automap cluster fallback skipped New/Add caller scan: cluster window unreadable");
    return;
  }

  for (std::size_t i = 0; i + 26 <= caller_search_size; ++i) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(caller_search_begin + i);
    if (p[0] == 0xE8 && p[5] == 0x48 && p[6] == 0x8B && p[7] == 0x75 && p[9] == 0x48 &&
        p[10] == 0x85 && p[11] == 0xF6 && p[12] == 0x0F && p[13] == 0x84 && p[18] == 0xE8 &&
        p[23] == 0x8D && p[24] == 0x57 && p[25] == 0x30) {
      std::uint32_t new_cell_rva = 0;
      std::uint32_t add_cell_rva = 0;
      if (ResolveRelativeCallRva(module_base, p, new_cell_rva) &&
          ResolveRelativeCallRva(module_base, p + 18, add_cell_rva)) {
        AssignMissingRuntimeOffsetFromRva(
            signatures, "AUTOMAP_NewAutomapCell", new_cell_rva, "validated-CreateAutoMapData-cluster-caller");
        AssignMissingRuntimeOffsetFromRva(
            signatures, "AUTOMAP_AddAutomapCell", add_cell_rva, "validated-CreateAutoMapData-cluster-caller");
        PIPE_LOG_WARN(
            "[Offsets] automap cluster fallback New/Add caller RVA=0x{:08X} new=0x{:08X} add=0x{:08X}",
            static_cast<std::uint32_t>((caller_search_begin + i) - module_base),
            new_cell_rva,
            add_cell_rva);
        return;
      }
    }
  }

  PIPE_LOG_WARN("[Offsets] automap cluster fallback did not find validated New/Add caller near CreateAutoMapData");
}

std::uint32_t RvaFromAddress(std::uintptr_t module_base, const std::uint8_t* p) {
  return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(p) - module_base);
}

std::string HexBytes(const std::uint8_t* begin, const std::uint8_t* end) {
  std::ostringstream out;
  out << std::uppercase << std::hex << std::setfill('0');
  for (const std::uint8_t* p = begin; p < end; ++p) {
    if (p != begin) {
      out << ' ';
    }
    out << std::setw(2) << static_cast<unsigned>(*p);
  }
  return out.str();
}

void LogCodeWindow(const char* label,
                   const std::uint8_t* window_begin,
                   const std::uint8_t* window_end,
                   const std::uint8_t* site,
                   std::uintptr_t module_base) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  PIPE_LOG_WARN("[Offsets] {} site=0x{:08X} window=0x{:08X}..0x{:08X} site_offset={} bytes={}",
                label,
                RvaFromAddress(module_base, site),
                RvaFromAddress(module_base, window_begin),
                RvaFromAddress(module_base, window_end),
                static_cast<long long>(site - window_begin),
                HexBytes(window_begin, window_end));
#else
  (void)label;
  (void)window_begin;
  (void)window_end;
  (void)site;
  (void)module_base;
#endif
}

void LogNearbyPlayerIdDecodeReferences(const std::uint8_t* window_begin,
                                       const std::uint8_t* window_end,
                                       const std::uint8_t* site,
                                       std::uintptr_t module_base,
                                       std::uintptr_t module_end,
                                       std::uint32_t enc_transform_rva) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  std::size_t logged = 0;
  for (const std::uint8_t* q = window_begin; q + 7 <= window_end && logged < 32; ++q) {
    std::uint8_t opcode0 = q[0];
    std::uint8_t opcode1 = q[1];
    bool has_rex = opcode0 >= 0x40 && opcode0 <= 0x4F;
    std::uint8_t opcode = has_rex ? opcode1 : opcode0;
    std::uint8_t modrm = has_rex ? q[2] : q[1];
    const bool has_full_instruction = has_rex ? (q + 7 <= window_end) : (q + 6 <= window_end);
    bool is_rip_relative = has_full_instruction && (opcode == 0x8D || opcode == 0x8B) && (modrm & 0xC7) == 0x05;
    if (is_rip_relative) {
      const std::uint8_t* disp = has_rex ? q + 3 : q + 2;
      const std::uint8_t* next = has_rex ? q + 7 : q + 6;
      std::int32_t rel = 0;
      std::memcpy(&rel, disp, sizeof(rel));
      const auto target = reinterpret_cast<std::uintptr_t>(next) + rel;
      if (target >= module_base && target < module_end) {
        PIPE_LOG_WARN(
            "[Offsets] player-id decode nearby-ref site=0x{:08X} instr=0x{:08X} delta={} kind={} rex=0x{:02X} opcode=0x{:02X} modrm=0x{:02X} target=0x{:08X}",
            RvaFromAddress(module_base, site),
            RvaFromAddress(module_base, q),
            static_cast<long long>(q - site),
            has_rex ? (opcode == 0x8D ? "lea-rex" : "mov-rex") : "mov32",
            has_rex ? opcode0 : 0,
            opcode,
            modrm,
            static_cast<std::uint32_t>(target - module_base));
        LogPlayerIdEncryptedTableCandidate(static_cast<std::uint32_t>(target - module_base),
                                           "Diagnostic_PlayerId_TransformXref_NearbyRef");
        ++logged;
        if (has_rex) {
          q += 6;
        } else {
          q += 5;
        }
        continue;
      }
    }

    if (q[0] == 0xE8) {
      std::int32_t rel = 0;
      std::memcpy(&rel, q + 1, sizeof(rel));
      const auto target = reinterpret_cast<std::uintptr_t>(q + 5) + rel;
      if (target >= module_base && target < module_end) {
        const auto target_rva = static_cast<std::uint32_t>(target - module_base);
        PIPE_LOG_WARN(
            "[Offsets] player-id decode nearby-call site=0x{:08X} instr=0x{:08X} delta={} target=0x{:08X} matches_enc_transform={}",
            RvaFromAddress(module_base, site),
            RvaFromAddress(module_base, q),
            static_cast<long long>(q - site),
            target_rva,
            enc_transform_rva != 0 && target_rva == enc_transform_rva ? "yes" : "no");
        ++logged;
      }
    }
  }
#else
  (void)window_begin;
  (void)window_end;
  (void)site;
  (void)module_base;
  (void)module_end;
  (void)enc_transform_rva;
#endif
}

void LogPlayerIdDecodeSiteDiagnostics(const std::vector<SignatureDef>& signatures) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  HMODULE module = GetModuleHandle(NULL);
  if (module == nullptr) {
    return;
  }

  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
  auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
  const auto module_end = module_base + nt->OptionalHeader.SizeOfImage;

  std::uint32_t enc_transform_rva = 0;
  const SignatureDef* enc_transform = FindSignature(signatures, "EncTransformValue");
  if (enc_transform != nullptr && enc_transform->target != nullptr && *enc_transform->target != nullptr) {
    enc_transform_rva =
        static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(*enc_transform->target) - module_base);
  }

  if (enc_transform_rva != 0) {
    constexpr std::size_t kMaxLoggedCallsites = 6;
    constexpr DWORD kMaxScanMs = 12000;
    PIPE_LOG_WARN(
        "[Offsets] player-id EncTransformValue callsite scan: compact reference inventory for table recovery (enc=0x{:08X})",
        enc_transform_rva);
    std::size_t logged_calls = 0;
    const DWORD scan_start = GetTickCount();
    bool stopped_by_time_budget = false;
    const auto* call_section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && logged_calls < kMaxLoggedCallsites;
         ++i, ++call_section) {
      if (GetTickCount() - scan_start > kMaxScanMs) {
        stopped_by_time_budget = true;
        break;
      }
      if ((call_section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
        continue;
      }

      const auto* start = reinterpret_cast<const std::uint8_t*>(module_base + call_section->VirtualAddress);
      const auto* end = start + call_section->Misc.VirtualSize;
      for (const std::uint8_t* p = start; p + 5 <= end && logged_calls < kMaxLoggedCallsites; ++p) {
        if (GetTickCount() - scan_start > kMaxScanMs) {
          stopped_by_time_budget = true;
          break;
        }
        if (p[0] != 0xE8) {
          continue;
        }

        const auto rel = ReadI32Unaligned(p + 1);
        const auto target = reinterpret_cast<std::uintptr_t>(p + 5) + rel;
        if (target < module_base || target >= module_end ||
            static_cast<std::uint32_t>(target - module_base) != enc_transform_rva) {
          continue;
        }

        const auto* window_begin = p > start + 160 ? p - 160 : start;
        const auto* window_end = p + 96 < end ? p + 96 : end;
        PIPE_LOG_WARN("[Offsets] player-id EncTransformValue callsite rva=0x{:08X}", RvaFromAddress(module_base, p));
        LogNearbyPlayerIdDecodeReferences(window_begin, window_end, p, module_base, module_end, enc_transform_rva);
        ++logged_calls;
      }
    }
    if (logged_calls == 0) {
      PIPE_LOG_WARN("[Offsets] player-id EncTransformValue callsite scan: no direct callsites found");
    } else if (stopped_by_time_budget) {
      PIPE_LOG_WARN(
          "[Offsets] player-id EncTransformValue callsite scan stopped by {}ms time budget after {} callsites",
          kMaxScanMs,
          logged_calls);
    } else if (logged_calls == kMaxLoggedCallsites) {
      PIPE_LOG_WARN(
          "[Offsets] player-id EncTransformValue callsite scan stopped after {} relevant callsites to keep diagnostics bounded",
          kMaxLoggedCallsites);
    }
    PIPE_LOG_WARN(
        "[Offsets] player-id EncTransformValue callsite scan note: raw byte windows suppressed; previous runs showed "
        "known globals/pointer-state candidates, not a valid PlayerIndex table");
  } else {
    PIPE_LOG_WARN("[Offsets] player-id EncTransformValue callsite scan skipped: EncTransformValue unresolved");
  }

  PIPE_LOG_WARN(
      "[Offsets] player-id decode-site scan skipped: strict XOR/ADD/ROL inventory was negative and too slow; "
      "direct local-player unit identity path remains preferred");
  (void)signatures;
  return;

  PIPE_LOG_WARN("[Offsets] player-id decode-site scan: searching strict XOR/ADD/ROL instruction context");
  std::size_t logged_sites = 0;
  const auto* section = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }

    const auto* start = reinterpret_cast<const std::uint8_t*>(module_base + section->VirtualAddress);
    const auto* end = start + section->Misc.VirtualSize;
    for (const std::uint8_t* p = start; p + 16 <= end && logged_sites < 24; ++p) {
      const bool strict = p[0] == 0x35 && p[5] == 0x05 && p[10] == 0xC1 && p[11] == 0xC0 && p[12] == 0x09 &&
                          p[13] == 0xC1 && p[14] == 0xC0 && p[15] == 0x07;
      if (!strict) {
        continue;
      }

      const auto site_rva = RvaFromAddress(module_base, p);
      const auto xor_const = ReadU32Unaligned(p + 1);
      const auto add_const = ReadU32Unaligned(p + 6);
      PIPE_LOG_WARN(
          "[Offsets] player-id decode-site candidate rva=0x{:08X} mode={} xor=0x{:08X} add=0x{:08X} enc_transform_rva=0x{:08X}",
          site_rva,
          "strict",
          xor_const,
          add_const,
          enc_transform_rva);

      const auto* window_begin = p > start + 192 ? p - 192 : start;
      const auto* window_end = p + 128 < end ? p + 128 : end;
      LogNearbyPlayerIdDecodeReferences(window_begin, window_end, p, module_base, module_end, enc_transform_rva);
      ++logged_sites;
    }
  }

  if (logged_sites == 0) {
    PIPE_LOG_WARN("[Offsets] player-id decode-site scan: no strict XOR/ADD/ROL candidates found; relaxed scan skipped to keep diagnostics bounded");
  }
#else
  (void)signatures;
#endif
}

void ValidateRetcheckDataSlot(const char* source_name, std::uint32_t slot_rva);

void LogRetcheckVerificationWindow(std::uintptr_t module_base,
                                   std::uintptr_t module_end,
                                   std::uint32_t window_rva,
                                   std::size_t window_size,
                                   const char* label) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  const auto* function = reinterpret_cast<const std::uint8_t*>(module_base + window_rva);
  if (window_rva == 0 || reinterpret_cast<std::uintptr_t>(function) < module_base ||
      reinterpret_cast<std::uintptr_t>(function) >= module_end || !IsReadableRange(function, window_size)) {
    PIPE_LOG_WARN("[Offsets] retcheck verification window skipped: label={} target unreadable rva=0x{:08X} size=0x{:X}",
                  label,
                  window_rva,
                  static_cast<unsigned>(window_size));
    return;
  }

  const auto* window_end = function + window_size;
  PIPE_LOG_WARN("[Offsets] retcheck verification window label={} rva=0x{:08X} size=0x{:X} bytes={}",
                label,
                window_rva,
                static_cast<unsigned>(window_size),
                HexBytes(function, window_end));

  std::size_t logged_rets = 0;
  for (const std::uint8_t* p = function; p < window_end && logged_rets < 12; ++p) {
    if (*p == 0xC3 || *p == 0xC2) {
      PIPE_LOG_WARN("[Offsets] retcheck verification window ret label={} instr=0x{:08X} delta=0x{:X} opcode=0x{:02X}",
                    label,
                    RvaFromAddress(module_base, p),
                    static_cast<unsigned>(p - function),
                    static_cast<unsigned>(*p));
      ++logged_rets;
    }
  }

  std::size_t logged_refs = 0;
  for (const std::uint8_t* p = function; p + 7 <= window_end && logged_refs < 24; ++p) {
    if (p > function && p[-1] >= 0x40 && p[-1] <= 0x4F) {
      continue;
    }

    const bool has_rex = p[0] >= 0x40 && p[0] <= 0x4F;
    const std::uint8_t opcode = has_rex ? p[1] : p[0];
    const std::uint8_t modrm = has_rex ? p[2] : p[1];
    const bool rip_relative = (opcode == 0x8B || opcode == 0x8D || opcode == 0x03 || opcode == 0x33) &&
                              (modrm & 0xC7) == 0x05;
    if (rip_relative) {
      const auto* disp = has_rex ? p + 3 : p + 2;
      const auto* next = has_rex ? p + 7 : p + 6;
      const auto target = reinterpret_cast<std::uintptr_t>(next) + ReadI32Unaligned(disp);
      if (target >= module_base && target < module_end) {
        PIPE_LOG_WARN(
            "[Offsets] retcheck verification window ref label={} instr=0x{:08X} kind={} rex=0x{:02X} opcode=0x{:02X} modrm=0x{:02X} target=0x{:08X}",
            label,
            RvaFromAddress(module_base, p),
            opcode == 0x8D ? "lea" : (opcode == 0x8B ? "mov" : (opcode == 0x03 ? "add" : "xor")),
            has_rex ? p[0] : 0,
            opcode,
            modrm,
            static_cast<std::uint32_t>(target - module_base));
        ++logged_refs;
      }
      continue;
    }

    if (p[0] == 0xE8 || p[0] == 0xE9 || p[0] == 0x0F) {
      const bool near_conditional = p[0] == 0x0F && p + 6 <= window_end && p[1] >= 0x80 && p[1] <= 0x8F;
      const bool direct_branch = p[0] == 0xE8 || p[0] == 0xE9 || near_conditional;
      if (!direct_branch) {
        continue;
      }

      const auto* rel_ptr = near_conditional ? p + 2 : p + 1;
      const auto* next = near_conditional ? p + 6 : p + 5;
      const auto target = reinterpret_cast<std::uintptr_t>(next) + ReadI32Unaligned(rel_ptr);
      if (target >= module_base && target < module_end) {
        PIPE_LOG_WARN("[Offsets] retcheck verification window branch label={} instr=0x{:08X} opcode=0x{:02X}{:02X} target=0x{:08X}",
                      label,
                      RvaFromAddress(module_base, p),
                      p[0],
                      near_conditional ? p[1] : 0,
                      static_cast<std::uint32_t>(target - module_base));
        ++logged_refs;
      }
    }
  }

  if (logged_refs == 0) {
    PIPE_LOG_WARN("[Offsets] retcheck verification window label={} no near refs/branches logged", label);
  }
#else
  (void)module_base;
  (void)module_end;
  (void)window_rva;
  (void)window_size;
  (void)label;
#endif
}

void LogRetcheckVerificationFunctionFingerprint(std::uintptr_t module_base,
                                                 std::uintptr_t module_end,
                                                 std::uint32_t verification_rva) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  if (verification_rva == 0) {
    return;
  }

  if (verification_rva >= 0x10) {
    LogRetcheckVerificationWindow(module_base, module_end, verification_rva - 0x10, 0x60, "prelude-minus-0x10");
  }
  LogRetcheckVerificationWindow(module_base, module_end, verification_rva, 0x80, "call-target");
  LogRetcheckVerificationWindow(module_base, module_end, verification_rva + 0x10, 0x70, "helper-plus-0x10");
  LogRetcheckVerificationWindow(module_base, module_end, verification_rva + 0x20, 0x60, "helper-plus-0x20");
  LogRetcheckVerificationWindow(module_base, module_end, verification_rva + 0x40, 0x180, "expanded-plus-0x40");
#else
  (void)module_base;
  (void)module_end;
  (void)verification_rva;
#endif
}

void ResolveRetcheckV2RequestFunctionsFromUnwind(
    std::uintptr_t module_base,
    const IMAGE_NT_HEADERS* nt,
    std::uint32_t protected_code_rva) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  if (nt == nullptr || protected_code_rva == 0) {
    return;
  }

  const auto& exception_directory =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  if (exception_directory.VirtualAddress == 0 ||
      exception_directory.Size < sizeof(RUNTIME_FUNCTION)) {
    return;
  }

  const auto* functions = reinterpret_cast<const RUNTIME_FUNCTION*>(
      module_base + exception_directory.VirtualAddress);
  const auto function_count =
      exception_directory.Size / sizeof(RUNTIME_FUNCTION);
  if (!IsReadableRange(functions,
                       function_count * sizeof(RUNTIME_FUNCTION))) {
    return;
  }

  struct RootFunction {
    std::uint32_t begin;
    std::uint32_t end;
    std::uint8_t flags;
    std::uint8_t prologue_size;
  };
  std::vector<RootFunction> roots;
  const auto lower_bound =
      protected_code_rva > 0x5000 ? protected_code_rva - 0x5000 : 0;
  for (std::size_t index = 0; index < function_count; ++index) {
    const auto& function = functions[index];
    if (function.BeginAddress < lower_bound ||
        function.BeginAddress >= protected_code_rva ||
        function.EndAddress <= function.BeginAddress) {
      continue;
    }

    const auto unwind_rva = function.UnwindData & ~std::uint32_t{3};
    const auto* unwind =
        reinterpret_cast<const std::uint8_t*>(module_base + unwind_rva);
    if (!IsReadableRange(unwind, 3)) {
      continue;
    }
    const auto flags = static_cast<std::uint8_t>(unwind[0] >> 3);
    if ((flags & UNW_FLAG_CHAININFO) != 0) {
      continue;
    }
    roots.push_back(
        {function.BeginAddress, function.EndAddress, flags, unwind[1]});
  }

  std::size_t pair_count = 0;
  RootFunction allocator{};
  RootFunction submit{};
  for (std::size_t index = 1; index < roots.size(); ++index) {
    const auto& first = roots[index - 1];
    const auto& second = roots[index];
    const auto first_size = first.end - first.begin;
    const auto second_size = second.end - second.begin;
    const auto gap =
        second.begin >= first.end ? second.begin - first.end : UINT32_MAX;
    const bool allocator_shape =
        first.flags == 0 && first.prologue_size >= 0x60 &&
        first_size >= 0x200 && first_size <= 0x800;
    const bool submit_shape =
        (second.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) ==
            (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) &&
        second.prologue_size >= 0x60 && second_size >= 0x400 &&
        second_size <= 0xC00;
    if (!allocator_shape || !submit_shape || gap > 0x20) {
      continue;
    }

    allocator = first;
    submit = second;
    ++pair_count;
    PIPE_LOG_WARN(
        "[Offsets] retcheck V2 unwind pair candidate allocator=0x{:08X}..0x{:08X} prologue=0x{:X} submit=0x{:08X}..0x{:08X} prologue=0x{:X} gap=0x{:X}",
        first.begin,
        first.end,
        first.prologue_size,
        second.begin,
        second.end,
        second.prologue_size,
        gap);
  }

  if (pair_count == 1) {
    kCheckRuntimeV2.request_allocator =
        reinterpret_cast<void*>(module_base + allocator.begin);
    kCheckRuntimeV2.request_submit =
        reinterpret_cast<void*>(module_base + submit.begin);
    PIPE_LOG_WARN(
        "[Offsets] retcheck V2 request functions derived dynamically from unique unwind topology allocator=0x{:08X} submit=0x{:08X}",
        allocator.begin,
        submit.begin);
    LogMemoryRegionProbe("RetcheckV2Unwind",
                         0,
                         "request-allocator-at-derivation",
                         kCheckRuntimeV2.request_allocator,
                         1);
    LogMemoryRegionProbe("RetcheckV2Unwind",
                         0,
                         "request-submit-at-derivation",
                         kCheckRuntimeV2.request_submit,
                         1);
  } else {
    PIPE_LOG_WARN(
        "[Offsets] retcheck V2 unwind topology did not produce a unique request-function pair candidates={}",
        pair_count);
  }
#else
  (void)module_base;
  (void)nt;
  (void)protected_code_rva;
#endif
}

void ResolveRetcheckV2DispatcherFromAutomapTopology(
    std::uintptr_t module_base,
    const IMAGE_NT_HEADERS* nt,
    std::uint32_t add_cell_rva = 0,
    bool force_broad_topology = false) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  if (nt == nullptr) {
    return;
  }

  if (!force_broad_topology && add_cell_rva == 0 &&
      AUTOMAP_AddAutomapCell != nullptr) {
    add_cell_rva = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(AUTOMAP_AddAutomapCell) -
        module_base);
  }
  if (force_broad_topology) {
    add_cell_rva = 0;
  }
  const auto& exception_directory =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  const auto* functions = reinterpret_cast<const RUNTIME_FUNCTION*>(
      module_base + exception_directory.VirtualAddress);
  const auto function_count =
      exception_directory.Size / sizeof(RUNTIME_FUNCTION);
  if (exception_directory.VirtualAddress == 0 ||
      !IsReadableRange(functions,
                       function_count * sizeof(RUNTIME_FUNCTION))) {
    return;
  }

  struct DispatcherGap {
    std::uint32_t begin;
    std::uint32_t end;
    std::uint32_t next_function;
  };
  std::vector<DispatcherGap> dispatcher_gaps;
  if (add_cell_rva != 0) {
    std::uint32_t previous_function_end = 0;
    for (std::size_t index = 0; index < function_count; ++index) {
      const auto& function = functions[index];
      if (function.BeginAddress >= add_cell_rva) {
        break;
      }
      if (function.EndAddress <= add_cell_rva &&
          function.EndAddress > previous_function_end) {
        previous_function_end = function.EndAddress;
      }
    }
    if (previous_function_end == 0 ||
        previous_function_end >= add_cell_rva ||
        add_cell_rva - previous_function_end > 0x400) {
      PIPE_LOG_WARN(
          "[Offsets] retcheck V2 dispatcher topology rejected automap predecessor gap start=0x{:08X} end=0x{:08X}",
          previous_function_end,
          add_cell_rva);
      return;
    }
    dispatcher_gaps.push_back(
        {previous_function_end, add_cell_rva, add_cell_rva});
  } else {
    std::uint32_t previous_function_end = 0;
    for (std::size_t index = 0; index < function_count; ++index) {
      const auto& function = functions[index];
      if (function.EndAddress <= function.BeginAddress) {
        continue;
      }
      const auto unwind_rva =
          function.UnwindData & ~std::uint32_t{3};
      const auto* unwind =
          reinterpret_cast<const std::uint8_t*>(module_base + unwind_rva);
      if (!IsReadableRange(unwind, 3)) {
        previous_function_end =
            std::max(previous_function_end,
                     static_cast<std::uint32_t>(function.EndAddress));
        continue;
      }
      const auto flags = static_cast<std::uint8_t>(unwind[0] >> 3);
      const auto prologue_size = unwind[1];
      const auto unwind_code_count = unwind[2];
      const auto function_size =
          function.EndAddress - function.BeginAddress;
      const auto gap =
          function.BeginAddress >= previous_function_end
              ? function.BeginAddress - previous_function_end
              : UINT32_MAX;
      const bool add_function_shape =
          flags == 0 && prologue_size == 4 &&
          unwind_code_count == 1 && function_size >= 0x50 &&
          function_size <= 0x90 && gap >= 0x20 && gap <= 0x400;
      if (add_function_shape) {
        dispatcher_gaps.push_back(
            {previous_function_end,
             function.BeginAddress,
             function.BeginAddress});
      }
      previous_function_end =
          std::max(previous_function_end,
                   static_cast<std::uint32_t>(function.EndAddress));
    }
    PIPE_LOG_WARN(
        "[Offsets] retcheck V2 dispatcher broad unwind topology candidates={} (diagnostic-only until independently selected)",
        dispatcher_gaps.size());
  }
  if (dispatcher_gaps.empty()) {
    return;
  }

  auto is_executable = [](const void* address) {
    MEMORY_BASIC_INFORMATION info{};
    if (address == nullptr ||
        VirtualQuery(address, &info, sizeof(info)) == 0 ||
        info.State != MEM_COMMIT ||
        (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
      return false;
    }
    constexpr DWORD kExecutable =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY;
    return (info.Protect & kExecutable) != 0;
  };

  std::vector<void**> vtable_candidates;
  const auto* section = IMAGE_FIRST_SECTION(nt);
  for (WORD section_index = 0;
       section_index < nt->FileHeader.NumberOfSections;
       ++section_index, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_READ) == 0 ||
        (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
      continue;
    }
    const auto* begin = reinterpret_cast<const std::uint8_t*>(
        module_base + section->VirtualAddress);
    const auto size = static_cast<std::size_t>(section->Misc.VirtualSize);
    if (!IsReadableRange(begin, size)) {
      continue;
    }
    for (std::size_t offset = 0; offset + sizeof(void*) <= size;
         offset += sizeof(void*)) {
      std::uintptr_t value = 0;
      std::memcpy(&value, begin + offset, sizeof(value));
      const auto method_rva =
          value >= module_base ? value - module_base : UINTPTR_MAX;
      const auto gap_it = std::find_if(
          dispatcher_gaps.begin(),
          dispatcher_gaps.end(),
          [method_rva](const DispatcherGap& gap) {
            return method_rva >= gap.begin && method_rva < gap.end;
          });
      if (gap_it == dispatcher_gaps.end() || offset < 0x10 ||
          !is_executable(reinterpret_cast<const void*>(value))) {
        continue;
      }
      auto** vtable = reinterpret_cast<void**>(
          const_cast<std::uint8_t*>(begin + offset - 0x10));
      void* entries[3]{};
      if (!IsReadableRange(vtable, sizeof(entries))) {
        continue;
      }
      std::memcpy(entries, vtable, sizeof(entries));
      if (reinterpret_cast<std::uintptr_t>(entries[2]) != value ||
          !is_executable(entries[0]) || !is_executable(entries[1])) {
        continue;
      }
      if (std::find(vtable_candidates.begin(),
                    vtable_candidates.end(),
                    vtable) == vtable_candidates.end()) {
        vtable_candidates.push_back(vtable);
      }
    }
  }

  struct DispatcherCandidate {
    void** slot;
    void* object;
    void** vtable;
    void* method;
    std::size_t readable_xrefs;
  };
  std::vector<DispatcherCandidate> dispatcher_candidates;
  section = IMAGE_FIRST_SECTION(nt);
  for (WORD section_index = 0;
       section_index < nt->FileHeader.NumberOfSections;
       ++section_index, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) == 0 ||
        (section->Characteristics & IMAGE_SCN_MEM_READ) == 0) {
      continue;
    }
    const auto* begin = reinterpret_cast<const std::uint8_t*>(
        module_base + section->VirtualAddress);
    const auto size = static_cast<std::size_t>(section->Misc.VirtualSize);
    const auto section_begin = reinterpret_cast<std::uintptr_t>(begin);
    const auto section_end = section_begin + size;
    auto cursor = section_begin;
    while (cursor < section_end) {
      MEMORY_BASIC_INFORMATION info{};
      if (VirtualQuery(reinterpret_cast<const void*>(cursor),
                       &info,
                       sizeof(info)) == 0) {
        break;
      }
      const auto region_end = std::min(
          section_end,
          reinterpret_cast<std::uintptr_t>(info.BaseAddress) +
              info.RegionSize);
      const bool readable_region =
          info.State == MEM_COMMIT &&
          (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
      if (!readable_region || region_end <= cursor) {
        cursor = region_end > cursor ? region_end : section_end;
        continue;
      }

      auto aligned_cursor =
          (cursor + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
      for (; aligned_cursor + sizeof(void*) <= region_end;
           aligned_cursor += sizeof(void*)) {
        void* object = nullptr;
        std::memcpy(&object,
                    reinterpret_cast<const void*>(aligned_cursor),
                    sizeof(object));
        const auto object_address =
            reinterpret_cast<std::uintptr_t>(object);
        if (object_address < 0x10000 ||
            object_address > 0x00007FFFFFFFFFFFULL ||
            !IsReadableRange(object, sizeof(void*))) {
          continue;
        }
        void** object_vtable = nullptr;
        std::memcpy(&object_vtable, object, sizeof(object_vtable));
        if (std::find(vtable_candidates.begin(),
                      vtable_candidates.end(),
                      object_vtable) == vtable_candidates.end()) {
          continue;
        }
        void* method = nullptr;
        std::memcpy(&method,
                    reinterpret_cast<const std::uint8_t*>(object_vtable) +
                        0x10,
                    sizeof(method));
        dispatcher_candidates.push_back(
            {reinterpret_cast<void**>(aligned_cursor),
             object,
             object_vtable,
             method,
             0});
      }
      cursor = region_end;
    }
  }

  section = IMAGE_FIRST_SECTION(nt);
  for (WORD section_index = 0;
       section_index < nt->FileHeader.NumberOfSections;
       ++section_index, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
        (section->Characteristics & IMAGE_SCN_MEM_READ) == 0) {
      continue;
    }
    const auto section_begin =
        module_base + section->VirtualAddress;
    const auto section_end =
        section_begin + section->Misc.VirtualSize;
    auto cursor = section_begin;
    while (cursor < section_end) {
      MEMORY_BASIC_INFORMATION info{};
      if (VirtualQuery(reinterpret_cast<const void*>(cursor),
                       &info,
                       sizeof(info)) == 0) {
        break;
      }
      const auto region_end = std::min(
          section_end,
          reinterpret_cast<std::uintptr_t>(info.BaseAddress) +
              info.RegionSize);
      const bool readable_region =
          info.State == MEM_COMMIT &&
          (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
      if (!readable_region || region_end <= cursor) {
        cursor = region_end > cursor ? region_end : section_end;
        continue;
      }

      const auto* p = reinterpret_cast<const std::uint8_t*>(cursor);
      const auto* end = reinterpret_cast<const std::uint8_t*>(region_end);
      while (p + 16 <= end) {
        hde64s instruction{};
        const auto length = hde64_disasm(p, &instruction);
        if (length == 0 || (instruction.flags & F_ERROR) != 0) {
          ++p;
          continue;
        }
        const bool rip_relative =
            (instruction.flags & F_DISP32) != 0 &&
            instruction.modrm_mod == 0 && instruction.modrm_rm == 5 &&
            instruction.p_67 == 0 &&
            (instruction.opcode == 0x8B ||
             instruction.opcode == 0x8D ||
             instruction.opcode == 0x89);
        if (rip_relative) {
          const auto displacement =
              static_cast<std::int32_t>(instruction.disp.disp32);
          const auto target =
              reinterpret_cast<std::uintptr_t>(p + length) +
              displacement;
          for (auto& candidate : dispatcher_candidates) {
            if (target ==
                reinterpret_cast<std::uintptr_t>(candidate.slot)) {
              ++candidate.readable_xrefs;
            }
          }
        }
        p += length;
      }
      cursor = region_end;
    }
  }

  PIPE_LOG_WARN(
      "[Offsets] retcheck V2 dispatcher topology mode={} unwind_gaps={} vtables={} global_slots={}",
      add_cell_rva != 0 ? "anchored-automap" : "broad-unwind",
      dispatcher_gaps.size(),
      vtable_candidates.size(),
      dispatcher_candidates.size());
  for (std::size_t index = 0;
       index < dispatcher_candidates.size() && index < 8;
       ++index) {
    const auto& candidate = dispatcher_candidates[index];
    PIPE_LOG_WARN(
        "[Offsets] retcheck V2 dispatcher topology candidate slot=0x{:08X} object={:p} vtable={:p} method=0x{:08X} readable_xrefs={}",
        RvaFromAddress(
            module_base,
            reinterpret_cast<const std::uint8_t*>(candidate.slot)),
        candidate.object,
        static_cast<void*>(candidate.vtable),
        RvaFromAddress(
            module_base,
            reinterpret_cast<const std::uint8_t*>(candidate.method)),
        candidate.readable_xrefs);
  }
  if (dispatcher_candidates.empty() && !force_broad_topology) {
    static bool broad_fallback_attempted = false;
    if (!broad_fallback_attempted) {
      broad_fallback_attempted = true;
      PIPE_LOG_WARN(
          "[Offsets] retcheck V2 anchored dispatcher topology has no live global object slot; trying broad unwind topology once");
      ResolveRetcheckV2DispatcherFromAutomapTopology(
          module_base, nt, 0, true);
    }
    return;
  }
  const DispatcherCandidate* selected = nullptr;
  const char* selection_reason = nullptr;
  if (dispatcher_candidates.size() == 1) {
    selected = &dispatcher_candidates.front();
    selection_reason = "unique-global-slot";
  } else if (dispatcher_candidates.size() > 1) {
    std::size_t minimum_xrefs = SIZE_MAX;
    std::size_t minimum_xref_count = 0;
    std::uintptr_t minimum_v2_distance = UINTPTR_MAX;
    std::size_t minimum_distance_count = 0;
    const DispatcherCandidate* minimum_xref_candidate = nullptr;
    const DispatcherCandidate* nearest_v2_candidate = nullptr;
    const auto v2_slot_address =
        module_base + g_retcheck_v2_slot_rva;
    for (const auto& candidate : dispatcher_candidates) {
      if (candidate.readable_xrefs < minimum_xrefs) {
        minimum_xrefs = candidate.readable_xrefs;
        minimum_xref_count = 1;
        minimum_xref_candidate = &candidate;
      } else if (candidate.readable_xrefs == minimum_xrefs) {
        ++minimum_xref_count;
      }
      const auto slot_address =
          reinterpret_cast<std::uintptr_t>(candidate.slot);
      const auto distance =
          slot_address >= v2_slot_address
              ? slot_address - v2_slot_address
              : v2_slot_address - slot_address;
      if (distance < minimum_v2_distance) {
        minimum_v2_distance = distance;
        minimum_distance_count = 1;
        nearest_v2_candidate = &candidate;
      } else if (distance == minimum_v2_distance) {
        ++minimum_distance_count;
      }
    }
    if (minimum_xref_count == 1 && minimum_distance_count == 1 &&
        minimum_xref_candidate == nearest_v2_candidate) {
      selected = minimum_xref_candidate;
      selection_reason =
          "fewest-readable-xrefs-and-nearest-v2-slot";
    }
  }
  if (selected != nullptr) {
    const auto& candidate = *selected;
    const auto method_rva = RvaFromAddress(
        module_base,
        reinterpret_cast<const std::uint8_t*>(candidate.method));
    const auto gap_it = std::find_if(
        dispatcher_gaps.begin(),
        dispatcher_gaps.end(),
        [method_rva](const DispatcherGap& gap) {
          return method_rva >= gap.begin && method_rva < gap.end;
        });
    kCheckRuntimeV2.dispatcher_slot = candidate.slot;
    kCheckRuntimeV2.dispatcher_object = candidate.object;
    kCheckRuntimeV2.dispatcher_method = candidate.method;
    kCheckRuntimeV2.dispatcher_method_offset = 0x10;
    PIPE_LOG_WARN(
        "[Offsets] retcheck V2 dispatcher derived dynamically from automap/vtable topology slot=0x{:08X} method=0x{:08X} reason={}",
        RvaFromAddress(
            module_base,
            reinterpret_cast<const std::uint8_t*>(candidate.slot)),
        method_rva,
        selection_reason);
    if (gap_it != dispatcher_gaps.end() && add_cell_rva == 0) {
      PIPE_LOG_WARN(
          "[Offsets] retcheck V2 dispatcher broad topology independently selected adjacent function candidate=0x{:08X}; diagnostic-only, no automap offset assigned",
          gap_it->next_function);
    }
  }
#else
  (void)module_base;
  (void)nt;
  (void)add_cell_rva;
  (void)force_broad_topology;
#endif
}

void LogRetcheckV2FieldReferences(std::uintptr_t module_base,
                                  std::uintptr_t module_end,
                                  std::uint32_t slot_rva,
                                  bool snapshot_only = false) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  if (slot_rva == 0 || module_base + slot_rva >= module_end) {
    return;
  }

  struct FieldDef {
    std::uint32_t offset;
    const char* name;
  };
  static constexpr FieldDef kFields[] = {
      {0x00, "constants"},
      {0x08, "unknown1"},
      {0x10, "unknown2"},
      {0x18, "table_begin"},
      {0x20, "table_end"},
      {0x28, "image_range"},
      {0x30, "unknown6"},
      {0x38, "state"},
  };

  auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
  auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
  std::size_t total_logged = 0;
  std::size_t field_counts[std::size(kFields)]{};
  std::uint32_t derived_table_begin = 0;
  std::uint32_t derived_table_end = 0;
  std::uintptr_t slot_words[8]{};
  const auto* slot_object = reinterpret_cast<const void*>(module_base + slot_rva);
  if (IsReadableRange(slot_object, sizeof(slot_words))) {
    std::memcpy(slot_words, slot_object, sizeof(slot_words));
    const auto table_begin_value = slot_words[3];
    const auto table_end_value = slot_words[4];
    const auto byte_count =
        table_end_value > table_begin_value ? table_end_value - table_begin_value : 0;
    const bool table_shape_ok =
        table_begin_value >= module_base && table_begin_value < module_end &&
        table_end_value > table_begin_value && table_end_value <= module_end &&
        byte_count % sizeof(std::uint32_t) == 0 && byte_count / sizeof(std::uint32_t) <= 0x10000;
    if (table_shape_ok) {
      derived_table_begin =
          static_cast<std::uint32_t>(table_begin_value - module_base);
      derived_table_end =
          static_cast<std::uint32_t>(table_end_value - module_base);
      const auto* new_protected_code_begin =
          reinterpret_cast<const std::uint8_t*>(table_begin_value);
      const auto* new_protected_code_end =
          reinterpret_cast<const std::uint8_t*>(table_end_value);
      if (kCheckRuntimeV2.protected_code_begin != nullptr &&
          (kCheckRuntimeV2.protected_code_begin != new_protected_code_begin ||
           kCheckRuntimeV2.protected_code_end != new_protected_code_end)) {
        PIPE_LOG_WARN(
            "[Offsets] retcheck V2 verifier range changed; clearing accumulated runtime metadata");
        kCheckRuntimeV2 = {};
      }
      kCheckRuntimeV2.protected_code_begin =
          new_protected_code_begin;
      kCheckRuntimeV2.protected_code_end =
          new_protected_code_end;
      kCheckRuntimeV2.protected_code_size =
          static_cast<std::uint32_t>(byte_count);
      if (kCheckRuntimeV2.request_allocator == nullptr ||
          kCheckRuntimeV2.request_submit == nullptr) {
        ResolveRetcheckV2RequestFunctionsFromUnwind(
            module_base, nt, derived_table_begin);
      }
      if (kCheckRuntimeV2.dispatcher_slot == nullptr) {
        ResolveRetcheckV2DispatcherFromAutomapTopology(module_base, nt);
      }
      PIPE_LOG_WARN(
          "[Offsets] retcheck V2 verifier code range derived from slot values begin=0x{:08X} end=0x{:08X} bytes=0x{:X} dwords={}",
          derived_table_begin,
          derived_table_end,
          byte_count,
          byte_count / sizeof(std::uint32_t));
      const auto* verifier_code =
          reinterpret_cast<const std::uint8_t*>(module_base + derived_table_begin);
      std::vector<std::uint8_t> verifier_snapshot(byte_count);
      MEMORY_BASIC_INFORMATION snapshot_info{};
      auto query_natural_readability = [&]() {
        snapshot_info = {};
        return VirtualQuery(verifier_code, &snapshot_info, sizeof(snapshot_info)) != 0 &&
               snapshot_info.State == MEM_COMMIT &&
               (snapshot_info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
      };
      bool naturally_readable = query_natural_readability();
      static bool s_waited_for_verifier_window = false;
      if (!naturally_readable && !s_waited_for_verifier_window) {
        s_waited_for_verifier_window = true;
        PIPE_LOG_WARN(
            "[Offsets] retcheck V2 verifier is sealed; waiting up to 30 seconds for a natural readable window (no protection changes)");
        constexpr std::size_t kWindowPollAttempts = 1200;
        constexpr DWORD kWindowPollDelayMs = 25;
        for (std::size_t attempt = 0; attempt < kWindowPollAttempts; ++attempt) {
          Sleep(kWindowPollDelayMs);
          if (query_natural_readability()) {
            naturally_readable = true;
            PIPE_LOG_WARN(
                "[Offsets] retcheck V2 natural readable window observed after {} ms protect=0x{:X}",
                (attempt + 1) * kWindowPollDelayMs,
                snapshot_info.Protect);
            break;
          }
        }
      }
      if (!naturally_readable) {
        PIPE_LOG_WARN(
            "[Offsets] retcheck V2 verifier contract snapshot unavailable: protected range is not naturally readable protect=0x{:X}; page protection was not changed",
            snapshot_info.Protect);
        return;
      }

      std::memcpy(verifier_snapshot.data(), verifier_code, byte_count);
      PIPE_LOG_WARN(
          "[Offsets] retcheck V2 verifier snapshot captured source=natural-readable-window bytes=0x{:X} protect=0x{:X}",
          byte_count,
          snapshot_info.Protect);
      static constexpr std::uint8_t kRequestAllocatorPrefix[] = {
          0x48, 0x8D, 0x44, 0x24, 0x68, 0xB1, 0x22, 0x48, 0x89, 0x44, 0x24, 0x20, 0xE8};
      static constexpr std::uint8_t kRequestSubmitPrefix[] = {
          0x41, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0xE8};
      static constexpr std::uint8_t kEntryContract[] = {
          0x49, 0x8B, 0xF8, 0x8B, 0xF2, 0x8B, 0xE9};
      static constexpr std::uint8_t kRequestWriteContract[] = {
          0x48, 0x8B, 0x44, 0x24, 0x30, 0x89, 0x70, 0x04,
          0x89, 0x28, 0x48, 0x89, 0x78, 0x08};
      static constexpr std::uint8_t kDispatcherSuffix[] = {
          0x48, 0x8B, 0xD3, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x10};
      for (std::size_t code_offset = 0; code_offset + 16 <= byte_count; ++code_offset) {
        const auto* p = verifier_snapshot.data() + code_offset;
        const auto* live_p = verifier_code + code_offset;
        if (code_offset + sizeof(kEntryContract) <= byte_count &&
            std::memcmp(p, kEntryContract, sizeof(kEntryContract)) == 0) {
          kCheckRuntimeV2.entry_contract_ok = true;
        }
        if (code_offset + sizeof(kRequestWriteContract) <= byte_count &&
            std::memcmp(p, kRequestWriteContract, sizeof(kRequestWriteContract)) == 0) {
          kCheckRuntimeV2.request_contract_ok = true;
        }
        if (code_offset + sizeof(kRequestAllocatorPrefix) + sizeof(std::int32_t) <= byte_count &&
            std::memcmp(p, kRequestAllocatorPrefix, sizeof(kRequestAllocatorPrefix)) == 0) {
          const auto* snapshot_call = p + sizeof(kRequestAllocatorPrefix) - 1;
          const auto* call = live_p + sizeof(kRequestAllocatorPrefix) - 1;
          const auto target =
              reinterpret_cast<std::uintptr_t>(call + 5) + ReadI32Unaligned(snapshot_call + 1);
          kCheckRuntimeV2.request_allocator = reinterpret_cast<void*>(target);
          PIPE_LOG_WARN(
              "[Offsets] retcheck V2 request allocator derived callsite=0x{:08X} target=0x{:08X}",
              RvaFromAddress(module_base, call),
              RvaFromAddress(module_base, reinterpret_cast<const std::uint8_t*>(target)));
          LogMemoryRegionProbe("RetcheckV2VerifierCallsite",
                               slot_rva,
                               "request-allocator-at-callsite-snapshot",
                               kCheckRuntimeV2.request_allocator,
                               1);
        }
        if (code_offset + sizeof(kRequestSubmitPrefix) + sizeof(std::int32_t) <= byte_count &&
            std::memcmp(p, kRequestSubmitPrefix, sizeof(kRequestSubmitPrefix)) == 0) {
          const auto* snapshot_call = p + sizeof(kRequestSubmitPrefix) - 1;
          const auto* call = live_p + sizeof(kRequestSubmitPrefix) - 1;
          const auto target =
              reinterpret_cast<std::uintptr_t>(call + 5) + ReadI32Unaligned(snapshot_call + 1);
          kCheckRuntimeV2.request_submit = reinterpret_cast<void*>(target);
          PIPE_LOG_WARN(
              "[Offsets] retcheck V2 request submit derived callsite=0x{:08X} target=0x{:08X}",
              RvaFromAddress(module_base, call),
              RvaFromAddress(module_base, reinterpret_cast<const std::uint8_t*>(target)));
          LogMemoryRegionProbe("RetcheckV2VerifierCallsite",
                               slot_rva,
                               "request-submit-at-callsite-snapshot",
                               kCheckRuntimeV2.request_submit,
                               1);
        }
        if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x0D &&
            std::memcmp(p + 7, kDispatcherSuffix, sizeof(kDispatcherSuffix)) == 0) {
          const auto dispatcher_slot =
              reinterpret_cast<std::uintptr_t>(live_p + 7) + ReadI32Unaligned(p + 3);
          kCheckRuntimeV2.dispatcher_slot = reinterpret_cast<void**>(dispatcher_slot);
          kCheckRuntimeV2.dispatcher_method_offset = 0x10;
          kCheckRuntimeV2.dispatcher_contract_ok = true;
          void* dispatcher_object = nullptr;
          void** dispatcher_vtable = nullptr;
          void* dispatcher_method = nullptr;
          if (IsReadableRange(kCheckRuntimeV2.dispatcher_slot, sizeof(dispatcher_object))) {
            std::memcpy(&dispatcher_object,
                        kCheckRuntimeV2.dispatcher_slot,
                        sizeof(dispatcher_object));
          }
          if (IsReadableRange(dispatcher_object, sizeof(dispatcher_vtable))) {
            std::memcpy(&dispatcher_vtable, dispatcher_object, sizeof(dispatcher_vtable));
          }
          const auto* method_slot = dispatcher_vtable == nullptr
                                        ? nullptr
                                        : reinterpret_cast<void* const*>(
                                              reinterpret_cast<const std::uint8_t*>(dispatcher_vtable) + 0x10);
          if (IsReadableRange(method_slot, sizeof(dispatcher_method))) {
            std::memcpy(&dispatcher_method, method_slot, sizeof(dispatcher_method));
          }
          kCheckRuntimeV2.dispatcher_object = dispatcher_object;
          kCheckRuntimeV2.dispatcher_method = dispatcher_method;
          PIPE_LOG_WARN(
              "[Offsets] retcheck V2 dispatcher derived callsite=0x{:08X} slot=0x{:08X} object={:p} vtable={:p} virtual_method_offset=0x10 method={:p}",
              RvaFromAddress(module_base, p),
              RvaFromAddress(module_base,
                             reinterpret_cast<const std::uint8_t*>(dispatcher_slot)),
              dispatcher_object,
              static_cast<void*>(dispatcher_vtable),
              dispatcher_method);
        }
      }
      PIPE_LOG_WARN(
          "[Offsets] retcheck V2 runtime compatibility metadata resolved={} contracts={}/{}/{} allocator={:p} submit={:p} dispatcher_slot={:p} dispatcher_object={:p} dispatcher_method={:p} virtual_method_offset=0x{:X}",
          IsRetcheckV2RuntimeResolvedDiagnostic() ? "yes" : "no",
          kCheckRuntimeV2.entry_contract_ok ? "entry-ok" : "entry-missing",
          kCheckRuntimeV2.request_contract_ok ? "request-ok" : "request-missing",
          kCheckRuntimeV2.dispatcher_contract_ok ? "dispatcher-ok" : "dispatcher-missing",
          kCheckRuntimeV2.request_allocator,
          kCheckRuntimeV2.request_submit,
          static_cast<void*>(kCheckRuntimeV2.dispatcher_slot),
          kCheckRuntimeV2.dispatcher_object,
          kCheckRuntimeV2.dispatcher_method,
          kCheckRuntimeV2.dispatcher_method_offset);
      constexpr std::uint32_t kVerifierChunkSize = 0xA0;
      for (std::uint32_t chunk_offset = 0; chunk_offset < byte_count;
           chunk_offset += kVerifierChunkSize) {
        const auto chunk_size =
            std::min<std::uint32_t>(kVerifierChunkSize, static_cast<std::uint32_t>(byte_count - chunk_offset));
        std::string label = "v2-verifier-code-" + std::to_string(chunk_offset / kVerifierChunkSize);
        LogRetcheckVerificationWindow(module_base,
                                      module_end,
                                      derived_table_begin + chunk_offset,
                                      chunk_size,
                                      label.c_str());
      }
    } else {
      PIPE_LOG_WARN(
          "[Offsets] retcheck V2 table pointers rejected from slot values begin={:p} end={:p} bytes=0x{:X}",
          reinterpret_cast<void*>(table_begin_value),
          reinterpret_cast<void*>(table_end_value),
          byte_count);
    }
  }
  if (snapshot_only) {
    return;
  }
  bool scan_complete = false;
  const auto* section = IMAGE_FIRST_SECTION(nt);
  for (WORD section_index = 0;
       section_index < nt->FileHeader.NumberOfSections && !scan_complete;
       ++section_index, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }

    const auto* start = reinterpret_cast<const std::uint8_t*>(module_base + section->VirtualAddress);
    const auto* end = start + section->Misc.VirtualSize;
    for (const std::uint8_t* p = start; p + 8 <= end && !scan_complete; ++p) {
      const bool has_rex = p[0] >= 0x40 && p[0] <= 0x4F;
      if (!has_rex && p > start && p[-1] >= 0x40 && p[-1] <= 0x4F) {
        continue;
      }
      const std::size_t opcode_index = has_rex ? 1 : 0;
      const std::uint8_t opcode = p[opcode_index];
      std::size_t modrm_index = 0;
      if (opcode == 0x8B || opcode == 0x8D || opcode == 0x89) {
        modrm_index = opcode_index + 1;
      } else if (opcode == 0x0F && p[opcode_index + 1] >= 0xB6 && p[opcode_index + 1] <= 0xB7) {
        modrm_index = opcode_index + 2;
      } else {
        continue;
      }

      const std::uint8_t modrm = p[modrm_index];
      if ((modrm & 0xC7) != 0x05) {
        continue;
      }

      const auto* displacement = p + modrm_index + 1;
      const auto* next = displacement + sizeof(std::int32_t);
      if (next > end) {
        continue;
      }
      const auto target = reinterpret_cast<std::uintptr_t>(next) + ReadI32Unaligned(displacement);
      if (target < module_base || target >= module_end) {
        continue;
      }

      for (std::size_t field_index = 0; field_index < std::size(kFields); ++field_index) {
        const auto& field = kFields[field_index];
        if (target != module_base + slot_rva + field.offset) {
          continue;
        }

        const auto instruction_rva = RvaFromAddress(module_base, p);
        ++field_counts[field_index];
        if (field_counts[field_index] <= 12) {
          PIPE_LOG_WARN(
              "[Offsets] retcheck V2 field ref field={} field_offset=0x{:02X} instr=0x{:08X} opcode=0x{:02X} modrm=0x{:02X}",
              field.name,
              field.offset,
              instruction_rva,
              opcode,
              modrm);
        }
        if (field_counts[field_index] <= 3) {
          const auto window_rva = instruction_rva >= 0x40 ? instruction_rva - 0x40 : 0;
          std::string label = std::string("v2-field-") + field.name;
          LogRetcheckVerificationWindow(module_base, module_end, window_rva, 0xC0, label.c_str());
        }

        if (opcode == 0x89 && (field.offset == 0x18 || field.offset == 0x20)) {
          const auto store_register =
              static_cast<std::uint8_t>(((modrm >> 3) & 0x07) | (has_rex && (p[0] & 0x04) ? 0x08 : 0));
          const auto* search_begin = p >= start + 0x20 ? p - 0x20 : start;
          for (const auto* candidate = p; candidate-- > search_begin;) {
            if (candidate + 7 > p || candidate[0] < 0x40 || candidate[0] > 0x4F ||
                candidate[1] != 0x8D || (candidate[2] & 0xC7) != 0x05) {
              continue;
            }
            const auto lea_register = static_cast<std::uint8_t>(
                ((candidate[2] >> 3) & 0x07) | ((candidate[0] & 0x04) ? 0x08 : 0));
            if (lea_register != store_register) {
              continue;
            }
            const auto lea_target =
                reinterpret_cast<std::uintptr_t>(candidate + 7) + ReadI32Unaligned(candidate + 3);
            if (lea_target < module_base || lea_target >= module_end) {
              continue;
            }
            const auto derived_rva =
                RvaFromAddress(module_base, reinterpret_cast<const std::uint8_t*>(lea_target));
            if (field.offset == 0x18) {
              derived_table_begin = derived_rva;
            } else {
              derived_table_end = derived_rva;
            }
            PIPE_LOG_WARN(
                "[Offsets] retcheck V2 table initializer field={} store=0x{:08X} source_lea=0x{:08X} derived=0x{:08X}",
                field.name,
                instruction_rva,
                RvaFromAddress(module_base, candidate),
                derived_rva);
            break;
          }
        }
        ++total_logged;
        scan_complete = derived_table_begin != 0 && derived_table_end > derived_table_begin;
        for (std::size_t required_index = 0; required_index < std::size(kFields); ++required_index) {
          if (required_index == 3 || required_index == 4) {
            continue;
          }
          if (field_counts[required_index] == 0) {
            scan_complete = false;
            break;
          }
        }
        break;
      }
    }
  }

  PIPE_LOG_WARN("[Offsets] retcheck V2 field ref summary slot=0x{:08X} refs_logged={}",
                 slot_rva,
                 total_logged);
  for (std::size_t field_index = 0; field_index < std::size(kFields); ++field_index) {
    PIPE_LOG_WARN("[Offsets] retcheck V2 field ref count field={} count={}",
                  kFields[field_index].name,
                  field_counts[field_index]);
  }
  if (derived_table_begin != 0 && derived_table_end > derived_table_begin) {
    const auto byte_count = derived_table_end - derived_table_begin;
    PIPE_LOG_WARN(
        "[Offsets] retcheck V2 verifier code initializer resolved begin=0x{:08X} end=0x{:08X} bytes=0x{:X} dwords={}",
        derived_table_begin,
        derived_table_end,
        byte_count,
        byte_count / sizeof(std::uint32_t));
  } else {
    PIPE_LOG_WARN(
        "[Offsets] retcheck V2 table initializer unresolved begin=0x{:08X} end=0x{:08X}",
        derived_table_begin,
        derived_table_end);
  }
#else
  (void)module_base;
  (void)module_end;
  (void)slot_rva;
#endif
}

const char* Register64NameFromRexModrm(std::uint8_t rex, std::uint8_t modrm) {
  static constexpr const char* kNames[] = {
      "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  };
  const auto index = static_cast<std::uint8_t>(((modrm >> 3) & 0x07) | ((rex & 0x04) != 0 ? 0x08 : 0x00));
  return index < 16 ? kNames[index] : "unknown";
}

std::uint8_t Rol8(std::uint8_t value, unsigned int shift);
std::uint8_t Ror8(std::uint8_t value, unsigned int shift);
std::uint8_t RetcheckHelper64640(std::uint8_t value);
std::uint8_t FindRetcheckHelperInputForOutput(std::uint8_t expected_output);

int Register64NameToIndex(const char* name) {
  static constexpr const char* kNames[] = {
      "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  };
  for (int i = 0; i < 16; ++i) {
    if (std::strcmp(name, kNames[i]) == 0) {
      return i;
    }
  }
  return -1;
}

struct RetcheckTrapMemoryByte {
  bool found = false;
  std::uint32_t instruction_rva = 0;
  std::uint32_t byte_offset = 0;
  std::uint8_t actual_byte = 0;
  bool actual_readable = false;
  bool known_transform = false;
  std::uint8_t pre_ror_imm = 0;
  std::uint8_t xor_imm = 0;
  std::uint8_t post_ror_imm = 0;
  std::string transform_window;
};

struct RetcheckTrapFirstTransform {
  bool found = false;
  std::uint8_t seed = 0;
  std::uint8_t xor1 = 0;
  std::uint8_t rol1 = 0;
  std::uint8_t xor2 = 0;
  std::uint8_t rol2 = 0;
};

bool TryReadRetcheckV2ConstantsPointer(std::uintptr_t module_base,
                                       std::uint32_t slot_rva,
                                       const std::uint8_t** constants) {
  if (constants == nullptr) {
    return false;
  }
  *constants = nullptr;
  if (slot_rva == 0) {
    return false;
  }

  const auto* slot = reinterpret_cast<const std::uint8_t*>(module_base + slot_rva);
  std::uintptr_t constants_value = 0;
  if (!IsReadableRange(slot, sizeof(constants_value)) || !TryReadValue(slot, &constants_value) ||
      constants_value == 0) {
    return false;
  }

  *constants = reinterpret_cast<const std::uint8_t*>(constants_value);
  return true;
}

RetcheckTrapFirstTransform FindRetcheckFirstTransform(const std::uint8_t* window_begin,
                                                      const std::uint8_t* xor_mem) {
  RetcheckTrapFirstTransform transform{};
  const auto* search_begin = xor_mem >= window_begin + 96 ? xor_mem - 96 : window_begin;
  for (const std::uint8_t* p = search_begin; p + 24 <= xor_mem; ++p) {
    if (p[0] == 0xC6 && p[1] == 0x45 && p[4] == 0xE8 && p[9] == 0x0F && p[10] == 0xB6 &&
        p[11] == 0x45 && p[12] == p[2] && p[13] == 0x34 && p[15] == 0xD0 && p[16] == 0xC0 &&
        p[17] == 0x34 && p[19] == 0xC0 && p[20] == 0xC0) {
      transform.found = true;
      transform.seed = p[3];
      transform.xor1 = p[14];
      transform.rol1 = 1;
      transform.xor2 = p[18];
      transform.rol2 = p[21];
    }
    if (p[0] == 0xC6 && p[1] == 0x44 && p[2] == 0x24 && p[5] == 0xE8 && p[10] == 0x0F &&
        p[11] == 0xB6 && p[12] == 0x44 && p[13] == 0x24 && p[14] == p[3] && p[15] == 0x34 &&
        p[17] == 0xD0 && p[18] == 0xC0 && p[19] == 0x34 && p[21] == 0xC0 && p[22] == 0xC0) {
      transform.found = true;
      transform.seed = p[4];
      transform.xor1 = p[16];
      transform.rol1 = 1;
      transform.xor2 = p[20];
      transform.rol2 = p[23];
    }
    if (p + 28 <= xor_mem && p[0] == 0xC6 && p[1] == 0x85 && p[6] == 0x17 && p[7] == 0xE8 &&
        p[12] == 0x0F && p[13] == 0xB6 && p[14] == 0x85 && p[19] == 0x34 && p[21] == 0xD0 &&
        p[22] == 0xC0 && p[23] == 0x34 && p[25] == 0xC0 && p[26] == 0xC0) {
      const std::uint32_t init_disp = ReadU32Unaligned(p + 2);
      const std::uint32_t load_disp = ReadU32Unaligned(p + 15);
      if (init_disp == load_disp) {
        transform.found = true;
        transform.seed = p[6];
        transform.xor1 = p[20];
        transform.rol1 = 1;
        transform.xor2 = p[24];
        transform.rol2 = p[27];
      }
    }
  }
  return transform;
}

RetcheckTrapMemoryByte FindRetcheckTrapMemoryByte(const std::uint8_t* window_begin,
                                                  const std::uint8_t* callsite,
                                                  std::uintptr_t module_base,
                                                  const char* load_register,
                                                  const std::uint8_t* constants) {
  RetcheckTrapMemoryByte result{};
  const int expected_base = Register64NameToIndex(load_register);
  if (expected_base < 0 || constants == nullptr) {
    return result;
  }

  for (const std::uint8_t* q = window_begin; q + 6 <= callsite; ++q) {
    const bool has_rex = q[0] >= 0x40 && q[0] <= 0x4F;
    const std::uint8_t rex = has_rex ? q[0] : 0;
    const std::uint8_t opcode = has_rex ? q[1] : q[0];
    if (opcode != 0x32) {
      continue;
    }

    const auto* modrm_ptr = has_rex ? q + 2 : q + 1;
    const std::uint8_t modrm = *modrm_ptr;
    const int reg_index = static_cast<int>(((modrm >> 3) & 0x07) | ((rex & 0x04) != 0 ? 0x08 : 0x00));
    const int base_index = static_cast<int>((modrm & 0x07) | ((rex & 0x01) != 0 ? 0x08 : 0x00));
    const bool disp32_mem = (modrm & 0xC0) == 0x80;
    const bool sib_encoded = (modrm & 0x07) == 0x04;
    if (reg_index != 0 || !disp32_mem || sib_encoded || base_index != expected_base) {
      continue;
    }

    const auto* disp_ptr = modrm_ptr + 1;
    const auto* next = disp_ptr + sizeof(std::uint32_t);
    if (next > callsite) {
      continue;
    }

    const auto offset = ReadU32Unaligned(disp_ptr);
    result.found = true;
    result.instruction_rva = RvaFromAddress(module_base, q);
    result.byte_offset = offset;
    result.actual_readable =
        offset < 0x1000000 && IsReadableRange(constants + offset, sizeof(result.actual_byte)) &&
        TryReadValue(constants + offset, &result.actual_byte);
    if (q >= window_begin + 7 && q[-7] == 0xC0 && q[-6] == 0xC8 && q[-4] == 0x34 && q[-2] == 0xD0 &&
        q[-1] == 0xC8) {
      result.known_transform = true;
      result.pre_ror_imm = q[-5];
      result.xor_imm = q[-3];
      result.post_ror_imm = 1;
    }
    const auto* transform_begin = q >= window_begin + 16 ? q - 16 : window_begin;
    const auto* transform_end = q + 6 <= callsite ? q + 6 : callsite;
    result.transform_window = HexBytes(transform_begin, transform_end);
  }

  return result;
}

const char* ClassifyRetcheckTrapAction(const std::uint8_t* cmp, const std::uint8_t* window_end) {
  if (cmp + 8 > window_end || cmp[0] != 0x80 || cmp[1] != 0xF9 || cmp[2] != 0x3B) {
    return "unknown";
  }

  const std::uint8_t* trap = nullptr;
  if (cmp[3] == 0x75 && cmp + 5 <= window_end) {
    trap = cmp + 5;
  } else if (cmp[3] == 0x0F && cmp[4] == 0x85 && cmp + 9 <= window_end) {
    trap = cmp + 9;
  } else {
    return "unknown-branch";
  }

  if (trap + 4 <= window_end && trap[0] == 0x33 && trap[1] == 0xC0 && trap[2] == 0x0F && trap[3] == 0xB6) {
    return "null-deref-rax";
  }
  if (trap + 4 <= window_end && trap[0] == 0x0F && trap[1] == 0xB6 && trap[2] == 0x00) {
    return "read-rax";
  }
  if (trap + 4 <= window_end && trap[0] == 0x0F && trap[1] == 0xB6 && trap[2] == 0x06) {
    return "read-rsi";
  }
  if (trap + 4 <= window_end && trap[0] == 0x0F && trap[1] == 0xB6 && trap[2] == 0x0E) {
    return "read-rsi";
  }
  if (trap + 4 <= window_end && trap[0] == 0x41 && trap[1] == 0x0F && trap[2] == 0xB6 && trap[3] == 0x06) {
    return "read-r14";
  }
  return "unknown";
}

struct RetcheckTrapCallsiteShape {
  std::uint32_t callsite_rva = 0;
  std::uint32_t slot_load_rva = 0;
  std::uint32_t slot_rva = 0;
  const char* load_register = "none";
  bool stack_byte_found = false;
  std::uint8_t stack_disp = 0;
  const char* trap_action = "unknown";
  bool v2_layout = false;
  bool equation_found = false;
  bool equation_would_trap = false;
  std::uint32_t equation_byte_offset = 0;
  std::uint8_t equation_actual_byte = 0;
  std::uint8_t equation_trap_byte = 0;
  std::uint8_t equation_cmp = 0;
};

bool IsRetcheckV2LayoutSlot(std::uintptr_t module_base, std::uint32_t slot_rva) {
  if (slot_rva == 0) {
    return false;
  }

  const auto* slot_as_struct = reinterpret_cast<const std::uint8_t*>(module_base + slot_rva);
  std::uintptr_t words[6]{};
  if (!IsReadableRange(slot_as_struct, sizeof(words))) {
    return false;
  }
  std::memcpy(words, slot_as_struct, sizeof(words));

  const auto* constants = reinterpret_cast<const std::uint8_t*>(words[0]);
  const auto* table_begin = reinterpret_cast<const std::uint32_t*>(words[3]);
  const auto* table_end = reinterpret_cast<const std::uint32_t*>(words[4]);
  const auto* image_range = reinterpret_cast<const RetCheckData::ImageData*>(words[5]);
  const auto table_begin_value = reinterpret_cast<std::uintptr_t>(table_begin);
  const auto table_end_value = reinterpret_cast<std::uintptr_t>(table_end);
  const bool constants_ok = IsReadableRange(constants, kConstantOffset + sizeof(std::uint32_t));
  const bool table_shape_ok = table_end_value > table_begin_value &&
                              ((table_end_value - table_begin_value) % sizeof(std::uint32_t)) == 0 &&
                              (table_begin_value % sizeof(std::uint32_t)) == 0 &&
                              (table_end_value % sizeof(std::uint32_t)) == 0;
  std::uint8_t screenshot_context_byte = 0;
  const bool screenshot_context_ok =
      constants_ok && TryReadValue(constants + 0x5C, &screenshot_context_byte) && screenshot_context_byte == 0x3A;

  void* image_base = nullptr;
  std::uint64_t image_size = 0;
  const bool range_readable = IsReadableRange(image_range, sizeof(RetCheckData::ImageData));
  if (range_readable) {
    TryReadValue(&image_range->base, &image_base);
    TryReadValue(&image_range->size, &image_size);
  }
  const bool range_ok = range_readable && image_base != nullptr && image_size >= 0x100000 && image_size <= 0x80000000;
  return constants_ok && table_shape_ok && range_ok && screenshot_context_ok;
}

RetcheckTrapCallsiteShape LogRetcheckTrapCallsiteShape(const std::uint8_t* callsite,
                                                       const std::uint8_t* window_begin,
                                                       const std::uint8_t* window_end,
                                                       std::uintptr_t module_base,
                                                       std::uintptr_t module_end) {
  RetcheckTrapCallsiteShape shape{};
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  std::uint32_t slot_rva = 0;
  std::uint32_t load_rva = 0;
  const char* load_register = "none";
  for (const std::uint8_t* q = window_begin; q + 7 <= callsite; ++q) {
    if (q > window_begin && q[-1] >= 0x40 && q[-1] <= 0x4F) {
      continue;
    }

    const bool has_rex = q[0] >= 0x40 && q[0] <= 0x4F;
    const std::uint8_t opcode = has_rex ? q[1] : q[0];
    const std::uint8_t modrm = has_rex ? q[2] : q[1];
    const bool rip_relative_mov = has_rex && opcode == 0x8B && (modrm & 0xC7) == 0x05;
    if (!rip_relative_mov) {
      continue;
    }

    const auto* disp = q + 3;
    const auto* next = q + 7;
    const auto target = reinterpret_cast<std::uintptr_t>(next) + ReadI32Unaligned(disp);
    if (target >= module_base && target < module_end) {
      slot_rva = static_cast<std::uint32_t>(target - module_base);
      load_rva = RvaFromAddress(module_base, q);
      load_register = Register64NameFromRexModrm(q[0], modrm);
    }
  }

  std::uint8_t stack_disp = 0;
  bool stack_byte_load_found = false;
  const std::uint8_t* cmp = nullptr;
  for (const std::uint8_t* q = callsite + 5; q + 13 <= window_end; ++q) {
    const bool stack_load = q[0] == 0x0F && q[1] == 0xB6 && (q[2] == 0x4D || q[2] == 0x45);
    const bool transform_compare = q[4] == 0x80 && q[5] == 0xC1 && q[6] == 0x55 && q[7] == 0x80 &&
                                   q[8] == 0xF1 && q[9] == 0x57 && q[10] == 0x80 && q[11] == 0xF9 &&
                                   q[12] == 0x3B;
    if (stack_load && transform_compare) {
      stack_byte_load_found = true;
      stack_disp = q[3];
      cmp = q + 10;
      break;
    }
  }

  const char* trap_action = cmp == nullptr ? "unknown" : ClassifyRetcheckTrapAction(cmp, window_end);
  const auto* cmp_window_end = cmp != nullptr && cmp + 16 <= window_end ? cmp + 16 : window_end;
  const std::string cmp_bytes = cmp == nullptr ? "" : HexBytes(cmp, cmp_window_end);
  shape.callsite_rva = RvaFromAddress(module_base, callsite);
  shape.slot_load_rva = load_rva;
  shape.slot_rva = slot_rva;
  shape.load_register = load_register;
  shape.stack_byte_found = stack_byte_load_found;
  shape.stack_disp = stack_disp;
  shape.trap_action = trap_action;
  shape.v2_layout = IsRetcheckV2LayoutSlot(module_base, slot_rva);
  const std::uint8_t* constants = nullptr;
  const bool constants_found = TryReadRetcheckV2ConstantsPointer(module_base, slot_rva, &constants);
  const RetcheckTrapMemoryByte memory_byte =
      constants_found ? FindRetcheckTrapMemoryByte(window_begin, callsite, module_base, load_register, constants)
                      : RetcheckTrapMemoryByte{};
  const auto* xor_mem_address = memory_byte.found
                                    ? reinterpret_cast<const std::uint8_t*>(module_base + memory_byte.instruction_rva)
                                    : nullptr;
  const RetcheckTrapFirstTransform first_transform =
      xor_mem_address != nullptr ? FindRetcheckFirstTransform(window_begin, xor_mem_address)
                                 : RetcheckTrapFirstTransform{};
  PIPE_LOG_WARN(
      "[Offsets] retcheck trap callsite shape callsite=0x{:08X} slot_load=0x{:08X} slot=0x{:08X} register={} stack_byte_found={} stack_disp=0x{:02X} trap_action={} v2_layout={} cmp_window={}",
      shape.callsite_rva,
      load_rva,
      slot_rva,
      load_register,
      stack_byte_load_found ? "yes" : "no",
      stack_disp,
      trap_action,
      shape.v2_layout ? "yes" : "no",
      cmp_bytes);
  PIPE_LOG_WARN(
      "[Offsets] retcheck trap memory byte callsite=0x{:08X} slot=0x{:08X} constants_found={} constants={:p} xor_mem_found={} xor_mem=0x{:08X} register={} byte_offset=0x{:X} readable={} actual=0x{:02X} known_transform={} pre_ror={} xor_imm=0x{:02X} post_ror={} transform_window={}",
      shape.callsite_rva,
      slot_rva,
      constants_found ? "yes" : "no",
      static_cast<const void*>(constants),
      memory_byte.found ? "yes" : "no",
      memory_byte.instruction_rva,
      load_register,
      memory_byte.byte_offset,
      memory_byte.actual_readable ? "yes" : "no",
      memory_byte.actual_byte,
      memory_byte.known_transform ? "yes" : "no",
      static_cast<unsigned>(memory_byte.pre_ror_imm),
      static_cast<unsigned>(memory_byte.xor_imm),
      static_cast<unsigned>(memory_byte.post_ror_imm),
      memory_byte.transform_window);
  if (memory_byte.found) {
    const auto* prewindow_begin = callsite >= window_begin + 64 ? callsite - 64 : window_begin;
    const auto* prewindow_end = callsite + 5 <= window_end ? callsite + 5 : window_end;
    PIPE_LOG_WARN(
        "[Offsets] retcheck trap prewindow callsite=0x{:08X} stack_disp=0x{:02X} xor_mem=0x{:08X} bytes={}",
        shape.callsite_rva,
        stack_disp,
        memory_byte.instruction_rva,
        HexBytes(prewindow_begin, prewindow_end));
  }
  if (first_transform.found && memory_byte.known_transform && memory_byte.actual_readable) {
    std::uint8_t rolling = RetcheckHelper64640(first_transform.seed);
    rolling ^= first_transform.xor1;
    rolling = Rol8(rolling, first_transform.rol1);
    rolling ^= first_transform.xor2;
    rolling = Rol8(rolling, first_transform.rol2);

    std::uint8_t before_mem_xor = Ror8(rolling, memory_byte.pre_ror_imm);
    before_mem_xor ^= memory_byte.xor_imm;
    before_mem_xor = Ror8(before_mem_xor, memory_byte.post_ror_imm);

    const std::uint8_t trap_helper_output = static_cast<std::uint8_t>((0x3B ^ 0x57) - 0x55);
    const std::uint8_t trap_helper_input = FindRetcheckHelperInputForOutput(trap_helper_output);
    const std::uint8_t trap_mem_byte = static_cast<std::uint8_t>(before_mem_xor ^ trap_helper_input);
    const std::uint8_t actual_helper_input = static_cast<std::uint8_t>(before_mem_xor ^ memory_byte.actual_byte);
    const std::uint8_t actual_helper_output = RetcheckHelper64640(actual_helper_input);
    const std::uint8_t actual_cmp = static_cast<std::uint8_t>((actual_helper_output + 0x55) ^ 0x57);
    const bool would_trap = actual_cmp == 0x3B;
    shape.equation_found = true;
    shape.equation_would_trap = would_trap;
    shape.equation_byte_offset = memory_byte.byte_offset;
    shape.equation_actual_byte = memory_byte.actual_byte;
    shape.equation_trap_byte = trap_mem_byte;
    shape.equation_cmp = actual_cmp;
    PIPE_LOG_WARN(
        "[Offsets] retcheck trap equation callsite=0x{:08X} slot=0x{:08X} seed=0x{:02X} first_xor=0x{:02X} first_rol={} second_xor=0x{:02X} second_rol={} byte_offset=0x{:X} actual=0x{:02X} before_mem_xor=0x{:02X} trap_byte=0x{:02X} actual_helper_input=0x{:02X} actual_helper_output=0x{:02X} actual_cmp=0x{:02X} predicted_path={} helper=0x00064640",
        shape.callsite_rva,
        slot_rva,
        first_transform.seed,
        first_transform.xor1,
        static_cast<unsigned>(first_transform.rol1),
        first_transform.xor2,
        static_cast<unsigned>(first_transform.rol2),
        memory_byte.byte_offset,
        memory_byte.actual_byte,
        before_mem_xor,
        trap_mem_byte,
        actual_helper_input,
        actual_helper_output,
        actual_cmp,
        would_trap ? "trap" : "clean-skip");
  } else {
    PIPE_LOG_WARN(
        "[Offsets] retcheck trap equation skipped callsite=0x{:08X} first_transform={} known_transform={} actual_readable={}",
        shape.callsite_rva,
        first_transform.found ? "yes" : "no",
        memory_byte.known_transform ? "yes" : "no",
        memory_byte.actual_readable ? "yes" : "no");
  }

  if (slot_rva != 0) {
    static std::vector<std::uint32_t> validated_callsite_slots;
    if (std::find(validated_callsite_slots.begin(), validated_callsite_slots.end(), slot_rva) ==
        validated_callsite_slots.end()) {
      validated_callsite_slots.push_back(slot_rva);
      ValidateRetcheckDataSlot("Diagnostic_RetcheckDataSlot_CallsiteShape", slot_rva);
    }
  }
#else
  (void)callsite;
  (void)window_begin;
  (void)window_end;
  (void)module_base;
  (void)module_end;
#endif
  return shape;
}

void LogRetcheckVerificationCallsiteDiagnostics(const std::vector<SignatureDef>& signatures) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  HMODULE module = GetModuleHandle(NULL);
  if (module == nullptr) {
    return;
  }

  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
  auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
  const auto module_end = module_base + nt->OptionalHeader.SizeOfImage;

  std::uint32_t verification_rva = 0;
  const SignatureDef* verification = FindSignature(signatures, "Diagnostic_RetcheckTrap_VerificationCall");
  if (verification != nullptr) {
    if (verification->target != nullptr && *verification->target != nullptr) {
      verification_rva =
          static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(*verification->target) - module_base);
    }
    if (verification_rva == 0) {
      for (const auto& diagnostic : verification->diagnostics) {
        if (diagnostic.in_image && diagnostic.resolved_offset != 0) {
          verification_rva = static_cast<std::uint32_t>(diagnostic.resolved_offset);
          break;
        }
      }
    }
  }

  if (verification_rva == 0) {
    verification_rva = 0x00064640;
    PIPE_LOG_WARN(
        "[Offsets] retcheck verification callsite scan using diagnostic fallback target=0x{:08X}; no runtime assignment",
        verification_rva);
  }
  if (verification_rva == 0) {
    PIPE_LOG_WARN("[Offsets] retcheck verification callsite scan skipped: verification target unresolved");
    (void)signatures;
    return;
  }

  PIPE_LOG_WARN("[Offsets] retcheck verification callsite scan: target=0x{:08X}", verification_rva);
  LogRetcheckVerificationFunctionFingerprint(module_base, module_end, verification_rva);
  std::size_t logged = 0;
  std::vector<RetcheckTrapCallsiteShape> trap_shapes;
  const auto* section = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections && logged < 16; ++i, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }

    const auto* start = reinterpret_cast<const std::uint8_t*>(module_base + section->VirtualAddress);
    const auto* end = start + section->Misc.VirtualSize;
    for (const std::uint8_t* p = start; p + 5 <= end && logged < 16; ++p) {
      if (p[0] != 0xE8) {
        continue;
      }

      const auto rel = ReadI32Unaligned(p + 1);
      const auto target = reinterpret_cast<std::uintptr_t>(p + 5) + rel;
      if (target < module_base || target >= module_end ||
          static_cast<std::uint32_t>(target - module_base) != verification_rva) {
        continue;
      }

      const auto* window_begin = p > start + 80 ? p - 80 : start;
      const auto* window_end = p + 64 < end ? p + 64 : end;
      bool has_null_trap_epilogue = false;
      bool matches_supplied_pfn_automap_trap = false;
      for (const std::uint8_t* q = p + 5; q + 9 <= window_end; ++q) {
        if (q[0] == 0x80 && q[1] == 0xF9 && q[2] == 0x3B && q[3] == 0x0F && q[4] == 0x85) {
          has_null_trap_epilogue = true;
          break;
        }
        if (q + 8 <= window_end && q[0] == 0x80 && q[1] == 0xF9 && q[2] == 0x3B && q[3] == 0x75) {
          has_null_trap_epilogue = true;
          if (q[4] == 0x04 && q[5] == 0x41 && q[6] == 0x0F && q[7] == 0xB6) {
            matches_supplied_pfn_automap_trap = true;
          }
          break;
        }
      }

      PIPE_LOG_WARN(
          "[Offsets] retcheck verification callsite rva=0x{:08X} trap_epilogue={} supplied_pfn_automap_trap={} delta_to_screenshot=0x{:X}",
          RvaFromAddress(module_base, p),
          has_null_trap_epilogue ? "yes" : "no",
          matches_supplied_pfn_automap_trap ? "yes" : "no",
          RvaFromAddress(module_base, p) > 0x000B805D ? RvaFromAddress(module_base, p) - 0x000B805D
                                                     : 0x000B805D - RvaFromAddress(module_base, p));
      trap_shapes.push_back(LogRetcheckTrapCallsiteShape(p, window_begin, window_end, module_base, module_end));
      LogNearbyPlayerIdDecodeReferences(window_begin, window_end, p, module_base, module_end, verification_rva);
      if (matches_supplied_pfn_automap_trap) {
        std::uint32_t slot_rva = 0;
        std::uint32_t load_rva = 0;
        for (const std::uint8_t* q = window_begin; q + 7 <= p; ++q) {
          if (q > window_begin && q[-1] >= 0x40 && q[-1] <= 0x4F) {
            continue;
          }

          const bool has_rex = q[0] >= 0x40 && q[0] <= 0x4F;
          const std::uint8_t opcode = has_rex ? q[1] : q[0];
          const std::uint8_t modrm = has_rex ? q[2] : q[1];
          const bool has_full_instruction = has_rex ? (q + 7 <= p) : (q + 6 <= p);
          if (!has_full_instruction || !has_rex || opcode != 0x8B || (modrm & 0xC7) != 0x05) {
            continue;
          }

          const std::uint8_t* disp = has_rex ? q + 3 : q + 2;
          const std::uint8_t* next = has_rex ? q + 7 : q + 6;
          const auto target = reinterpret_cast<std::uintptr_t>(next) + ReadI32Unaligned(disp);
          if (target >= module_base && target < module_end) {
            slot_rva = static_cast<std::uint32_t>(target - module_base);
            load_rva = RvaFromAddress(module_base, q);
          }
        }

        if (slot_rva != 0) {
          PIPE_LOG_WARN(
              "[Offsets] retcheck supplied pfnAutomap discriminator load=0x{:08X} slot=0x{:08X} source_callsite=0x{:08X}",
              load_rva,
              slot_rva,
              RvaFromAddress(module_base, p));
          ValidateRetcheckDataSlot("Diagnostic_RetcheckDataSlot_PfnAutomapTrap_Discriminated", slot_rva);
        }
      }
      if (matches_supplied_pfn_automap_trap) {
        LogCodeWindow("retcheck supplied pfnAutomap trap bytes", window_begin, window_end, p, module_base);
      }
      ++logged;
    }
  }

  if (logged == 0) {
    PIPE_LOG_WARN("[Offsets] retcheck verification callsite scan: no direct callsites found");
  } else {
    std::uint32_t dominant_slot = 0;
    std::size_t dominant_slot_count = 0;
    std::size_t v2_layout_count = 0;
    std::size_t stack_found_count = 0;
    std::size_t null_deref_count = 0;
    std::size_t read_r14_count = 0;
    std::size_t read_rsi_count = 0;
    std::size_t unknown_action_count = 0;
    std::size_t equation_found_count = 0;
    std::size_t equation_clean_count = 0;
    std::size_t equation_trap_count = 0;
    std::size_t dominant_actual_count = 0;
    std::size_t dominant_trap_byte_count = 0;
    std::uint8_t dominant_actual_byte = 0;
    std::uint8_t dominant_trap_byte = 0;
    for (const auto& shape : trap_shapes) {
      if (shape.v2_layout) {
        ++v2_layout_count;
      }
      if (shape.stack_byte_found) {
        ++stack_found_count;
      }
      if (std::strcmp(shape.trap_action, "null-deref-rax") == 0) {
        ++null_deref_count;
      } else if (std::strcmp(shape.trap_action, "read-r14") == 0) {
        ++read_r14_count;
      } else if (std::strcmp(shape.trap_action, "read-rsi") == 0) {
        ++read_rsi_count;
      } else {
        ++unknown_action_count;
      }

      std::size_t slot_count = 0;
      for (const auto& other : trap_shapes) {
        if (other.slot_rva != 0 && other.slot_rva == shape.slot_rva) {
          ++slot_count;
        }
      }
      if (shape.slot_rva != 0 && slot_count > dominant_slot_count) {
        dominant_slot = shape.slot_rva;
        dominant_slot_count = slot_count;
      }

      if (shape.equation_found) {
        ++equation_found_count;
        if (shape.equation_would_trap) {
          ++equation_trap_count;
        } else {
          ++equation_clean_count;
        }

        std::size_t actual_count = 0;
        std::size_t trap_byte_count = 0;
        for (const auto& other : trap_shapes) {
          if (!other.equation_found) {
            continue;
          }
          if (other.equation_actual_byte == shape.equation_actual_byte) {
            ++actual_count;
          }
          if (other.equation_trap_byte == shape.equation_trap_byte) {
            ++trap_byte_count;
          }
        }
        if (actual_count > dominant_actual_count) {
          dominant_actual_byte = shape.equation_actual_byte;
          dominant_actual_count = actual_count;
        }
        if (trap_byte_count > dominant_trap_byte_count) {
          dominant_trap_byte = shape.equation_trap_byte;
          dominant_trap_byte_count = trap_byte_count;
        }
      }
    }

    PIPE_LOG_WARN(
        "[Offsets] retcheck trap callsite summary total={} dominant_slot=0x{:08X} dominant_slot_count={} protected_v2_count={} v2_layout_count={} stack_byte_found_count={} actions=null-deref-rax:{} read-r14:{} read-rsi:{} unknown:{}",
        trap_shapes.size(),
        dominant_slot,
        dominant_slot_count,
        v2_layout_count,
        v2_layout_count,
        stack_found_count,
        null_deref_count,
        read_r14_count,
        read_rsi_count,
        unknown_action_count);
    PIPE_LOG_WARN(
        "[Offsets] retcheck trap equation summary total={} found={} clean={} trap={} skipped={} dominant_actual=0x{:02X} dominant_actual_count={} dominant_trap_byte=0x{:02X} dominant_trap_byte_count={} verdict={}",
        trap_shapes.size(),
        equation_found_count,
        equation_clean_count,
        equation_trap_count,
        trap_shapes.size() - equation_found_count,
        dominant_actual_byte,
        dominant_actual_count,
        dominant_trap_byte,
        dominant_trap_byte_count,
        equation_found_count == trap_shapes.size() && equation_trap_count == 0 ? "clean-diagnostic-only"
                                                                         : "needs-more-diagnostics");
    if (dominant_slot != 0 && dominant_slot_count >= 8 && v2_layout_count >= 8) {
      g_retcheck_v2_slot_rva = dominant_slot;
      g_retcheck_v2_evidence_callsites = dominant_slot_count;
      g_retcheck_v2_protected_layout_votes = v2_layout_count;
      g_retcheck_v2_equation_total = trap_shapes.size();
      g_retcheck_v2_equation_clean = equation_clean_count;
      g_retcheck_v2_equation_trap = equation_trap_count;
      g_retcheck_v2_equation_skipped = trap_shapes.size() - equation_found_count;
      kCheckDataV2 = reinterpret_cast<RetCheckDataV2*>(module_base + dominant_slot);
      PIPE_LOG_WARN(
          "[Offsets] retcheck V2 layout resolved diagnostically: slot=0x{:08X} evidence_callsites={} protected_layout_votes={} v2_layout_votes={} equation_clean={}/{} equation_trap={} equation_skipped={} v2_ptr={:p}; old kCheckData/RetcheckBypass remains blocked",
          dominant_slot,
          dominant_slot_count,
          v2_layout_count,
          v2_layout_count,
          g_retcheck_v2_equation_clean,
          g_retcheck_v2_equation_total,
          g_retcheck_v2_equation_trap,
          g_retcheck_v2_equation_skipped,
          static_cast<void*>(kCheckDataV2));
      LogRetcheckV2FieldReferences(module_base, module_end, dominant_slot);
    }
  }
#else
  (void)signatures;
#endif
}

bool IsPlausibleRangeSize(std::uint64_t size) {
  return size >= 0x100000 && size <= 0x80000000;
}

bool IsPlausibleCount(std::uint32_t count) {
  return count > 0 && count <= 0x100000;
}

bool IsAlignedPointer(std::uintptr_t value, std::uintptr_t alignment) {
  return value != 0 && (value % alignment) == 0;
}

std::uint8_t Rol8(std::uint8_t value, unsigned int shift) {
  shift &= 7;
  return static_cast<std::uint8_t>((value << shift) | (value >> (8 - shift)));
}

std::uint8_t Ror8(std::uint8_t value, unsigned int shift) {
  shift &= 7;
  return static_cast<std::uint8_t>((value >> shift) | (value << (8 - shift)));
}

std::uint8_t RetcheckHelper64640(std::uint8_t value) {
  return Rol8(static_cast<std::uint8_t>(Ror8(value, 1) + 0x63), 3);
}

std::uint8_t FindRetcheckHelperInputForOutput(std::uint8_t expected_output) {
  for (unsigned int candidate = 0; candidate <= 0xFF; ++candidate) {
    if (RetcheckHelper64640(static_cast<std::uint8_t>(candidate)) == expected_output) {
      return static_cast<std::uint8_t>(candidate);
    }
  }
  return 0;
}

void LogRetcheckPfnAutomapByteEquation(const char* source_name,
                                       std::uint32_t slot_rva,
                                       const char* mode,
                                       const std::uint8_t* constants) {
  static constexpr std::size_t kPfnAutomapTrapByteOffset = 0x5C5;

  std::uint8_t actual_byte = 0;
  const bool actual_readable = IsReadableRange(constants + kPfnAutomapTrapByteOffset, sizeof(actual_byte)) &&
                               TryReadValue(constants + kPfnAutomapTrapByteOffset, &actual_byte);

  const std::uint8_t trap_helper_output = static_cast<std::uint8_t>((0x3B ^ 0x57) - 0x55);
  const std::uint8_t trap_helper_input = FindRetcheckHelperInputForOutput(trap_helper_output);

  std::uint8_t rolling = RetcheckHelper64640(0x17);
  rolling ^= 0x44;
  rolling = Rol8(rolling, 1);
  rolling ^= 0x8B;
  rolling = Rol8(rolling, 2);

  std::uint8_t before_mem_xor = Ror8(rolling, 2);
  before_mem_xor ^= 0x8B;
  before_mem_xor = Ror8(before_mem_xor, 1);

  const std::uint8_t trap_mem_byte = static_cast<std::uint8_t>(before_mem_xor ^ trap_helper_input);
  const std::uint8_t actual_helper_input = static_cast<std::uint8_t>(before_mem_xor ^ actual_byte);
  const std::uint8_t actual_helper_output = RetcheckHelper64640(actual_helper_input);
  const std::uint8_t actual_cmp = static_cast<std::uint8_t>((actual_helper_output + 0x55) ^ 0x57);
  const bool would_trap = actual_readable && actual_cmp == 0x3B;
  PIPE_LOG_WARN(
      "[Offsets] retcheck pfnAutomap byte equation {} slot=0x{:08X} mode={} constants={:p} byte_offset=0x{:X} readable={} actual=0x{:02X} trap_byte=0x{:02X} before_mem_xor=0x{:02X} actual_helper_input=0x{:02X} actual_helper_output=0x{:02X} actual_cmp=0x{:02X} trap_helper_input=0x{:02X} trap_helper_output=0x{:02X} predicted_path={} helper=0x00064640",
      source_name,
      slot_rva,
      mode,
      static_cast<const void*>(constants),
      static_cast<unsigned int>(kPfnAutomapTrapByteOffset),
      actual_readable ? "yes" : "no",
      actual_byte,
      trap_mem_byte,
      before_mem_xor,
      actual_helper_input,
      actual_helper_output,
      actual_cmp,
      trap_helper_input,
      trap_helper_output,
      would_trap ? "trap" : "clean-skip");
}

void LogRetcheckConstantsProbe(const char* source_name,
                               std::uint32_t slot_rva,
                               const char* mode,
                               const std::uint8_t* constants) {
  if (!IsReadableRange(constants, kConstantOffset + sizeof(std::uint32_t))) {
    return;
  }

  std::uint8_t trap_byte = 0;
  std::uint32_t legacy_constant = 0;
  std::uint32_t byte_5c_dword = 0;
  TryReadValue(constants + 0x5C, &trap_byte);
  TryReadValue(constants + 0x5C, &byte_5c_dword);
  TryReadValue(constants + kConstantOffset, &legacy_constant);
  PIPE_LOG_WARN(
      "[Offsets] retcheck constants probe {} slot=0x{:08X} mode={} constants={:p} byte_5c=0x{:02X} dword_5c=0x{:08X} legacy_c6=0x{:08X}",
      source_name,
      slot_rva,
      mode,
      static_cast<const void*>(constants),
      trap_byte,
      byte_5c_dword,
      legacy_constant);

  LogRetcheckPfnAutomapByteEquation(source_name, slot_rva, mode, constants);
}

void LogRetcheckDirectTableProbe(const char* source_name,
                                 std::uint32_t slot_rva,
                                 const char* mode,
                                 const std::uint32_t* begin,
                                 const std::uint32_t* end) {
  const auto begin_value = reinterpret_cast<std::uintptr_t>(begin);
  const auto end_value = reinterpret_cast<std::uintptr_t>(end);
  if (begin == nullptr || end == nullptr || end_value <= begin_value) {
    return;
  }

  const std::uintptr_t byte_count = end_value - begin_value;
  if ((byte_count % sizeof(std::uint32_t)) != 0 || byte_count > 0x1000000) {
    return;
  }

  const auto entry_count = static_cast<std::uint32_t>(byte_count / sizeof(std::uint32_t));
  const bool table_readable = IsPlausibleCount(entry_count) && IsReadableRange(begin, byte_count);
  LogMemoryRegionProbe(source_name, slot_rva, "direct-table-begin", begin, byte_count);
  LogMemoryRegionProbe(source_name, slot_rva, "direct-table-end-minus-4", end - 1, sizeof(std::uint32_t));
  std::uint32_t first = 0;
  std::uint32_t second = 0;
  std::uint32_t last = 0;
  if (table_readable) {
    TryReadValue(begin, &first);
    if (entry_count > 1) {
      TryReadValue(begin + 1, &second);
    }
    TryReadValue(end - 1, &last);
  }

  PIPE_LOG_WARN(
      "[Offsets] retcheck direct table probe {} slot=0x{:08X} mode={} begin={:p} end={:p} entries={} readable={} first=0x{:08X} second=0x{:08X} last=0x{:08X}",
      source_name,
      slot_rva,
      mode,
      static_cast<const void*>(begin),
      static_cast<const void*>(end),
      entry_count,
      table_readable ? "yes" : "no",
      first,
      second,
      last);
}

void LogRetcheckProtectedTableReadProbe(const char* source_name,
                                        std::uint32_t slot_rva,
                                        const char* mode,
                                        const std::uint32_t* begin,
                                        const std::uint32_t* end) {
#if defined(NYX_D2R_SAFE_DIAGNOSTIC_MODE) && defined(NYX_D2R_SAFE_RETCHECK_PROBE)
  const auto begin_value = reinterpret_cast<std::uintptr_t>(begin);
  const auto end_value = reinterpret_cast<std::uintptr_t>(end);
  if (begin == nullptr || end == nullptr || end_value <= begin_value) {
    return;
  }

  const std::uintptr_t byte_count = end_value - begin_value;
  if ((byte_count % sizeof(std::uint32_t)) != 0 || byte_count > 0x1000000) {
    return;
  }

  MEMORY_BASIC_INFORMATION before{};
  if (VirtualQuery(begin, &before, sizeof(before)) == 0) {
    PIPE_LOG_WARN("[Offsets] retcheck protected table probe {} slot=0x{:08X} mode={} skipped: VirtualQuery failed",
                  source_name,
                  slot_rva,
                  mode);
    return;
  }

  const bool naturally_readable =
      before.State == MEM_COMMIT &&
      (before.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
      IsReadableRange(begin, byte_count);
  if (!naturally_readable) {
    PIPE_LOG_WARN(
        "[Offsets] retcheck protected table probe {} slot=0x{:08X} mode={} skipped: range is not naturally readable begin={:p} bytes=0x{:X} protect=0x{:X}; page protection was not changed",
        source_name,
        slot_rva,
        mode,
        static_cast<const void*>(begin),
        static_cast<unsigned int>(byte_count),
        before.Protect);
    return;
  }

  const auto entry_count = static_cast<std::uint32_t>(byte_count / sizeof(std::uint32_t));
  std::uint32_t first = 0;
  std::uint32_t second = 0;
  std::uint32_t last = 0;
  const bool first_ok = TryReadValue(begin, &first);
  const bool second_ok = entry_count > 1 && TryReadValue(begin + 1, &second);
  const bool last_ok = TryReadValue(end - 1, &last);

  PIPE_LOG_WARN(
      "[Offsets] retcheck protected table probe {} slot=0x{:08X} mode={} natural_read=ok entries={} first_ok={} first=0x{:08X} second_ok={} second=0x{:08X} last_ok={} last=0x{:08X} protect=0x{:X}",
      source_name,
      slot_rva,
      mode,
      entry_count,
      first_ok ? "yes" : "no",
      first,
      second_ok ? "yes" : "no",
      second,
      last_ok ? "yes" : "no",
      last,
      before.Protect);
#else
  (void)source_name;
  (void)slot_rva;
  (void)mode;
  (void)begin;
  (void)end;
#endif
}

void LogRetcheckV2ReadinessProbe(const char* source_name,
                                 std::uint32_t slot_rva,
                                 const char* mode,
                                 const std::uint8_t* constants,
                                 const std::uint32_t* table_begin,
                                 const std::uint32_t* table_end,
                                 const RetCheckData::ImageData* image_range,
                                 bool constants_ok,
                                 bool table_shape_ok,
                                 bool table_readable,
                                 bool range_ok) {
  const auto begin_value = reinterpret_cast<std::uintptr_t>(table_begin);
  const auto end_value = reinterpret_cast<std::uintptr_t>(table_end);
  const auto byte_count = table_shape_ok ? end_value - begin_value : 0;
  const auto entry_count = table_shape_ok ? static_cast<std::uint32_t>(byte_count / sizeof(std::uint32_t)) : 0;

  std::uint8_t trap_byte = 0;
  const bool trap_byte_ok = constants_ok && TryReadValue(constants + 0x5C, &trap_byte);
  std::uint32_t legacy_constant = 0;
  const bool legacy_constant_ok = constants_ok && TryReadValue(constants + kConstantOffset, &legacy_constant);

  MEMORY_BASIC_INFORMATION table_info{};
  const bool table_query_ok = table_begin != nullptr && VirtualQuery(table_begin, &table_info, sizeof(table_info)) != 0;
  const bool table_noaccess = table_query_ok && (table_info.Protect & PAGE_NOACCESS) != 0;
  const bool screenshot_context_ok = trap_byte_ok && trap_byte == 0x3A;
  const bool v2_layout_ready = constants_ok && table_shape_ok && range_ok && screenshot_context_ok && table_query_ok;

  PIPE_LOG_WARN(
      "[Offsets] retcheck V2 readiness {} slot=0x{:08X} mode={} object_layout=qword0/constants qword3/table_begin qword4/table_end qword5/image_range screenshot_byte_5c={} trap_byte=0x{:02X} entries={} table_readable={} table_protect=0x{:X} table_state=0x{:X} byte_count=0x{:X} image_range={:p}/{} legacy_constant_ok={} legacy_constant=0x{:08X} verdict={} activation=blocked",
      source_name,
      slot_rva,
      mode,
      screenshot_context_ok ? "match" : "mismatch",
      trap_byte,
      entry_count,
      table_readable ? "yes" : "no",
      table_query_ok ? table_info.Protect : 0,
      table_query_ok ? table_info.State : 0,
      static_cast<unsigned int>(byte_count),
      static_cast<const void*>(image_range),
      range_ok ? "valid" : "bad",
      legacy_constant_ok ? "yes" : "no",
      legacy_constant,
      v2_layout_ready ? (table_noaccess ? "v2-layout-ready-protected-diagnostic-only"
                                        : "v2-layout-ready-readable-diagnostic-only")
                      : "not-ready");
}

void LogRetcheckGlobalBlockProbe(const char* source_name,
                                 std::uint32_t slot_rva,
                                 const char* mode,
                                 const void* object,
                                 const std::uintptr_t* words,
                                 std::size_t word_count) {
  if (word_count < 6) {
    return;
  }

  const auto* constants = reinterpret_cast<const std::uint8_t*>(words[0]);
  auto* table_begin = reinterpret_cast<const std::uint32_t*>(words[3]);
  auto* table_end = reinterpret_cast<const std::uint32_t*>(words[4]);
  auto* image_range = reinterpret_cast<const RetCheckData::ImageData*>(words[5]);

  LogRetcheckConstantsProbe(source_name, slot_rva, mode, constants);
  LogRetcheckDirectTableProbe(source_name, slot_rva, mode, table_begin, table_end);

  std::uint64_t image_size = 0;
  void* image_base = nullptr;
  bool range_readable = IsReadableRange(image_range, sizeof(RetCheckData::ImageData));
  if (range_readable) {
    TryReadValue(&image_range->size, &image_size);
    TryReadValue(&image_range->base, &image_base);
  }

  const bool constants_ok = IsReadableRange(constants, kConstantOffset + sizeof(std::uint32_t));
  const auto table_begin_value = reinterpret_cast<std::uintptr_t>(table_begin);
  const auto table_end_value = reinterpret_cast<std::uintptr_t>(table_end);
  const bool table_shape_ok = table_end_value > table_begin_value &&
                              ((table_end_value - table_begin_value) % sizeof(std::uint32_t)) == 0 &&
                              IsAlignedPointer(table_begin_value, sizeof(std::uint32_t)) &&
                              IsAlignedPointer(table_end_value, sizeof(std::uint32_t));
  const bool table_readable = table_shape_ok && IsReadableRange(table_begin, table_end_value - table_begin_value);
  const bool range_ok = range_readable && image_base != nullptr && IsPlausibleRangeSize(image_size);
  const bool protected_direct_range_layout = constants_ok && table_shape_ok && range_ok && !table_readable;
  const bool v2_plausible = constants_ok && table_readable && range_ok;

  PIPE_LOG_WARN(
      "[Offsets] retcheck global block probe {} slot=0x{:08X} mode={} object={:p} constants_ok={} table_shape={} table_readable={} protected_direct_range_layout={} range={:p}/{} image_base={:p} image_size=0x{:X} v2_plausible={}",
      source_name,
      slot_rva,
      mode,
      object,
      constants_ok ? "yes" : "no",
      table_shape_ok ? "yes" : "no",
      table_readable ? "yes" : "no",
      protected_direct_range_layout ? "yes" : "no",
      static_cast<const void*>(image_range),
      range_readable ? "readable" : "bad",
      image_base,
      image_size,
      v2_plausible ? "yes" : "no");

  if (v2_plausible || protected_direct_range_layout) {
    LogRetcheckV2ReadinessProbe(source_name,
                                slot_rva,
                                mode,
                                constants,
                                table_begin,
                                table_end,
                                image_range,
                                constants_ok,
                                table_shape_ok,
                                table_readable,
                                range_ok);
  }

  if (v2_plausible) {
    PIPE_LOG_WARN(
        "[Offsets] retcheck global block probe {} slot=0x{:08X} suggests patched layout: constants=qword0 direct_table=qword3..qword4 image_range=qword5; not assigned in safe diagnostic mode",
        source_name,
        slot_rva);
#if defined(NYX_D2R_SAFE_DIAGNOSTIC_MODE) && defined(NYX_D2R_SAFE_RETCHECK_PROBE)
    if (!g_retcheck_protected_layout_dry_run_done) {
      g_retcheck_protected_layout_dry_run_done = true;
      RetcheckBypass::ProbeProtectedLayout(const_cast<void*>(object));
    }
#endif
  } else if (protected_direct_range_layout) {
    PIPE_LOG_WARN(
        "[Offsets] retcheck global block probe {} slot=0x{:08X} suggests protected patched layout: constants=qword0 direct_table=qword3..qword4 image_range=qword5, but direct table is unreadable/protected; keep retcheck blocked",
        source_name,
        slot_rva);
    LogRetcheckProtectedTableReadProbe(source_name, slot_rva, mode, table_begin, table_end);
#if defined(NYX_D2R_SAFE_DIAGNOSTIC_MODE) && defined(NYX_D2R_SAFE_RETCHECK_PROBE)
    if (!g_retcheck_protected_layout_dry_run_done) {
      g_retcheck_protected_layout_dry_run_done = true;
      RetcheckBypass::ProbeProtectedLayout(const_cast<void*>(object));
    }
#endif
  }
}

void LogRetcheckObjectWords(const char* source_name, std::uint32_t slot_rva, const char* mode, const void* object) {
  std::uintptr_t words[8]{};
  if (!IsReadableRange(object, sizeof(words))) {
    PIPE_LOG_WARN("[Offsets] retcheck object probe {} slot=0x{:08X} mode={} object={:p} rejected: first qwords unreadable",
                  source_name,
                  slot_rva,
                  mode,
                  object);
    return;
  }

  std::memcpy(words, object, sizeof(words));
  PIPE_LOG_WARN(
      "[Offsets] retcheck object probe {} slot=0x{:08X} mode={} object={:p} qwords=[0]=0x{:016X} [1]=0x{:016X} [2]=0x{:016X} [3]=0x{:016X} [4]=0x{:016X} [5]=0x{:016X} [6]=0x{:016X} [7]=0x{:016X}",
      source_name,
      slot_rva,
      mode,
      object,
      words[0],
      words[1],
      words[2],
      words[3],
      words[4],
      words[5],
      words[6],
      words[7]);
  LogRetcheckGlobalBlockProbe(source_name, slot_rva, mode, object, words, 8);
}

bool ProbeRetcheckLayoutAt(const char* source_name,
                           std::uint32_t slot_rva,
                           const char* mode,
                           const std::uint8_t* object,
                           std::size_t object_shift) {
  const std::uint8_t* view = object + object_shift;
  if (!IsReadableRange(view, sizeof(RetCheckData))) {
    return false;
  }

  std::uint8_t* constants = nullptr;
  RetCheckData::ReturnAddresses* addresses = nullptr;
  RetCheckData::ImageData* range = nullptr;
  TryReadValue(view + 0x00, &constants);
  TryReadValue(view + 0x08, &addresses);
  TryReadValue(view + 0x18, &range);

  const bool constants_readable = IsReadableRange(constants, kConstantOffset + sizeof(std::uint32_t));
  const bool addresses_readable = IsReadableRange(addresses, sizeof(RetCheckData::ReturnAddresses));
  const bool range_readable = IsReadableRange(range, sizeof(RetCheckData::ImageData));

  std::uint32_t table_count = 0;
  std::uint32_t* table_ptr = nullptr;
  bool table_ptr_readable = false;
  if (addresses_readable && addresses != nullptr) {
    TryReadValue(&addresses->count, &table_count);
    TryReadValue(&addresses->ptr, &table_ptr);
    const std::size_t probe_count = std::min<std::size_t>(table_count, 16);
    table_ptr_readable = IsPlausibleCount(table_count) && IsReadableRange(table_ptr, probe_count * sizeof(std::uint32_t));
  }

  void* range_base = nullptr;
  std::uint64_t range_size = 0;
  bool range_base_first_readable = false;
  void* alt_range_base = nullptr;
  std::uint64_t alt_range_size = 0;
  if (range_readable && range != nullptr) {
    TryReadValue(&range->base, &range_base);
    TryReadValue(&range->size, &range_size);
    TryReadValue(reinterpret_cast<std::uint8_t*>(range) + 0x00, &alt_range_base);
    TryReadValue(reinterpret_cast<std::uint8_t*>(range) + 0x08, &alt_range_size);
    range_base_first_readable = alt_range_base != nullptr && IsPlausibleRangeSize(alt_range_size);
  }

  const bool range_plausible = range_readable && range_base != nullptr && IsPlausibleRangeSize(range_size);
  const bool plausible =
      constants_readable && addresses_readable && range_readable && table_ptr_readable && range_plausible;

  if (object_shift == 0 || constants_readable || addresses_readable || range_readable || plausible ||
      range_base_first_readable) {
    PIPE_LOG_WARN(
        "[Offsets] retcheck layout probe {} slot=0x{:08X} mode={} shift=0x{:02X} view={:p} constants={:p}/{} addresses={:p}/{} table_count={} table_ptr={:p}/{} range={:p}/{} image_base={:p} image_size=0x{:X} alt_range_base={:p} alt_range_size=0x{:X} plausible={}",
        source_name,
        slot_rva,
        mode,
        object_shift,
        static_cast<const void*>(view),
        static_cast<void*>(constants),
        constants_readable ? "readable" : "bad",
        static_cast<void*>(addresses),
        addresses_readable ? "readable" : "bad",
        table_count,
        static_cast<void*>(table_ptr),
        table_ptr_readable ? "readable" : "bad",
        static_cast<void*>(range),
        range_readable ? "readable" : "bad",
        range_base,
        range_size,
        alt_range_base,
        alt_range_size,
        plausible ? "yes" : "no");
  }

  if (plausible) {
    PIPE_LOG_WARN(
        "[Offsets] retcheck layout probe {} slot=0x{:08X} mode={} shift=0x{:02X} is structurally plausible; still not assigned in safe diagnostic mode",
        source_name,
        slot_rva,
        mode,
        object_shift);
  }

  return plausible;
}

void ProbeRetcheckDataObject(const char* source_name, std::uint32_t slot_rva, const char* mode, const void* object) {
  if (!IsReadableRange(object, sizeof(RetCheckData))) {
    PIPE_LOG_WARN("[Offsets] retcheck object probe {} slot=0x{:08X} mode={} object={:p} rejected: object is not readable",
                  source_name,
                  slot_rva,
                  mode,
                  object);
    return;
  }

  LogRetcheckObjectWords(source_name, slot_rva, mode, object);

  static constexpr std::size_t kShifts[] = {0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40};
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(object);
  for (std::size_t shift : kShifts) {
    ProbeRetcheckLayoutAt(source_name, slot_rva, mode, bytes, shift);
  }

  void* first_pointer = nullptr;
  if (TryReadValue(object, &first_pointer) && first_pointer != nullptr && first_pointer != object &&
      IsReadableRange(first_pointer, sizeof(RetCheckData))) {
    LogRetcheckObjectWords(source_name, slot_rva, "slot->first-pointer", first_pointer);
    ProbeRetcheckLayoutAt(source_name,
                          slot_rva,
                          "slot->first-pointer",
                          reinterpret_cast<const std::uint8_t*>(first_pointer),
                          0);
  }
}

void ValidateRetcheckDataSlot(const char* source_name, std::uint32_t slot_rva) {
  HMODULE module = GetModuleHandle(NULL);
  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  auto* slot = reinterpret_cast<RetCheckData**>(module_base + slot_rva);

  if (!IsReadableRange(slot, sizeof(RetCheckData*))) {
    PIPE_LOG_WARN("[Offsets] retcheck slot candidate {} slot=0x{:08X} rejected: slot is not readable",
                  source_name,
                  slot_rva);
    return;
  }

  RetCheckData* data = *slot;
  PIPE_LOG_WARN("[Offsets] retcheck slot candidate {} slot=0x{:08X} slot_value={:p}",
                source_name,
                slot_rva,
                static_cast<void*>(data));

  ProbeRetcheckDataObject(source_name, slot_rva, "slot-pointee", data);
  ProbeRetcheckDataObject(source_name, slot_rva, "slot-as-struct", slot);
}

void LogRetcheckDataSlotDiagnostics(const std::vector<SignatureDef>& signatures) {
  static constexpr const char* kSlotSources[] = {
      "Diagnostic_RetcheckDataSlot_LoadRCX_FromTrap",
      "Diagnostic_RetcheckDataSlot_LoadRDX_FromTrap",
      "Diagnostic_RetcheckDataSlot_PfnAutomapTrap",
  };

  for (const char* source : kSlotSources) {
    const SignatureDef* sig = FindSignature(signatures, source);
    if (sig == nullptr) {
      continue;
    }

    std::vector<std::uint32_t> slot_rvas;
    if (sig->target != nullptr && *sig->target != nullptr) {
      HMODULE module = GetModuleHandle(NULL);
      const auto module_base = reinterpret_cast<std::uintptr_t>(module);
      slot_rvas.push_back(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(*sig->target) - module_base));
    }

    for (const auto& diagnostic : sig->diagnostics) {
      if (diagnostic.in_image) {
        slot_rvas.push_back(static_cast<std::uint32_t>(diagnostic.resolved_offset));
      }
    }

    std::sort(slot_rvas.begin(), slot_rvas.end());
    slot_rvas.erase(std::unique(slot_rvas.begin(), slot_rvas.end()), slot_rvas.end());
    for (std::uint32_t slot_rva : slot_rvas) {
      ValidateRetcheckDataSlot(source, slot_rva);
    }
  }
}

bool IsFocusedDiagnosticOffset(const char* name) {
  static constexpr const char* kFocusedNames[] = {
      "kCheckData",
      "s_automapLayerLink",
      "s_currentAutomapLayer",
      "s_panelManager",
      "AutoMapPanel_GetMode",
      "AutoMapPanel_CreateAutoMapData",
      "AutoMapPanel_PrecisionToAutomap",
      "DATATBLS_GetAutomapCellId",
      "sgptClientSideUnitHashTable",
      "GetClientSideUnitHashTableByType",
      "GetServerSideUnitHashTableByType",
  };

  for (const char* focused : kFocusedNames) {
    if (std::strcmp(name, focused) == 0) {
      return true;
    }
  }
  return false;
}

bool IsSensitiveDiagnosticOffset(const char* name) {
  static constexpr const char* kSensitiveNames[] = {
      "kCheckData",
      "sgptClientSideUnitHashTable",
      "GetClientSideUnitHashTableByType",
      "Diagnostic_RetcheckDataSlot_LoadRCX_FromTrap",
      "Diagnostic_RetcheckDataSlot_LoadRDX_FromTrap",
      "Diagnostic_RetcheckDataSlot_PfnAutomapTrap",
      "Diagnostic_RetcheckTrap_ContextByteBase",
      "Diagnostic_RetcheckTrap_VerificationCall",
  };

  for (const char* sensitive : kSensitiveNames) {
    if (std::strcmp(name, sensitive) == 0) {
      return true;
    }
  }
  return false;
}

bool IsPromotionEligibleDiagnosticOffset(const char* name) {
  if (IsSensitiveDiagnosticOffset(name)) {
    return false;
  }

  static constexpr const char* kNeedsStructuralValidationPrefixes[] = {
      "Diagnostic_PlayerIndex_",
      "Diagnostic_TableRange_",
  };
  for (const char* prefix : kNeedsStructuralValidationPrefixes) {
    const std::size_t prefix_len = std::strlen(prefix);
    if (std::strncmp(name, prefix, prefix_len) == 0) {
      return false;
    }
  }

  return true;
}

void RetryUnresolvedNonSensitiveOffsets(std::vector<SignatureDef>& signatures) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
#ifdef NYX_D2R_FAST_DIAGNOSTIC
  PIPE_LOG_WARN("[Offsets] Fast diagnostic mode: skipping timed late retries");
  (void)signatures;
  return;
#endif
  static constexpr DWORD kRetryDelaysMs[] = {
      10000,
      10000,
  };

  for (std::size_t pass = 0; pass < std::size(kRetryDelaysMs); ++pass) {
    std::vector<SignatureDef> retry_signatures;
    for (const auto& sig : signatures) {
      if (sig.target != nullptr && *sig.target == nullptr && !IsSensitiveDiagnosticOffset(sig.name)) {
        retry_signatures.push_back(sig);
      }
    }

    if (retry_signatures.empty()) {
      return;
    }

    PIPE_LOG_WARN("[Offsets] Safe diagnostic late retry pass {}: {} unresolved non-sensitive offset(s), waiting {} ms",
                  pass + 1,
                  retry_signatures.size(),
                  kRetryDelaysMs[pass]);
    Sleep(kRetryDelaysMs[pass]);

    PatternScanner retry_scanner;
    if (!retry_scanner.Initialize()) {
      PIPE_LOG_ERROR("[Offsets] Late retry pass {} failed to initialize pattern scanner", pass + 1);
      continue;
    }

    retry_scanner.ScanAll(retry_signatures);

    HMODULE module = GetModuleHandle(NULL);
    const auto module_base = reinterpret_cast<std::uintptr_t>(module);
    for (const auto& sig : retry_signatures) {
      const bool retry_resolved = sig.target != nullptr && *sig.target != nullptr;
      if (SignatureDef* original = FindMutableSignature(signatures, sig.name); original != nullptr) {
        if (retry_resolved) {
          original->offset = sig.offset;
          original->parsed = sig.parsed;
          original->diagnostics = sig.diagnostics;
        } else if (!sig.diagnostics.empty()) {
          original->diagnostics = sig.diagnostics;
        }
      }
      if (retry_resolved) {
        const auto rva = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(*sig.target) - module_base);
        PIPE_LOG_WARN("[Offsets] Late retry pass {} resolved {:<36} RVA=0x{:08X}", pass + 1, sig.name, rva);
      } else {
        PIPE_LOG_WARN("[Offsets] Late retry pass {} still missing {:<36}", pass + 1, sig.name);
      }
    }
  }
#else
  (void)signatures;
#endif
}

std::vector<SignatureDef> BuildFocusedDiagnosticSignatureList() {
  auto signatures = BuildSignatureList();
  signatures.erase(std::remove_if(signatures.begin(),
                                  signatures.end(),
                                  [](const SignatureDef& sig) { return !IsFocusedDiagnosticOffset(sig.name); }),
                   signatures.end());
  signatures.push_back({
      "Diagnostic_AutoMapPanel_CreateAutoMapData_Strict",
      "4C 89 44 24 ? 53 55 56 57 41 54 41 56 41 57 48 83 EC ? 0F 28 02 33 C0",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_AUTOMAP_AddAutomapCell_FromNewCellCaller",
      "E8 ? ? ? ? 48 8B 75 ? 48 85 F6 0F 84 ? ? ? ? E8 ^ ? ? ? 8D 57 30",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_ClearLinkedList_AfterListAnchor",
      "48 8D 3D ? ? ? ? 48 89 9C 24 ? ? ? ? 48 8B CF 48 89 B4 24 ? ? ? ? 48 8D 15 ? ? ? ? E8 ^ ? ? ?",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_Widget_GetScaledPosition_CallNearAnchor",
      "48 8D 54 24 ? 48 8B CE E8 ^ ? ? ? 48 8B 5C 24 ? 48 8B 74 24 ? 48 8B 7C 24 ? 8B 10 8B 48",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_Widget_GetScaledSize_CallA",
      "8B D7 48 8D 4C 24 ? E8 ^ ? ? ? 85 C0 0F 85 ? ? ? ? 41 8B D6",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_Widget_GetScaledSize_CallB",
      "49 8B CD C1 E2 ? E8 ^ ? ? ? E9 ? ? ? ? 8B 73 ? 41 03 F0 41 3B F3",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_EncTransformValue_CallA",
      "44 8B C6 8B D3 49 8B CE E8 ^ ? ? ? 48 8B E8 48 85 C0 0F 84",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_EncTransformValue_CallB",
      "48 8B CB 4C 8B 70 10 E8 ^ ? ? ? 41 B8 ? ? ? ? 44 39 45",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_BcAllocator_NearD2Allocator_CallA",
      "48 8D 4C 24 ? 4C 8B C0 48 8B F0 E8 ^ ? ? ? 48 8B 5C 24 ? 48 85 DB",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_BcAllocator_NearD2Allocator_CallB",
      "8B 4C 24 ? 48 8B D3 E8 ^ ? ? ? 48 8B 0D ? ? ? ? 8B F8 48 85 C9",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_DRLG_AllocLevel_NearInitContext",
      "44 8B 82 ? ? ? ? 48 8B 92 ? ? ? ? E8 ^ ? ? ? 48 83 7F ? ? 46 8B 0C A0",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_GetLevelDef_NearRoomContext",
      "48 8B 42 20 44 0F B6 90 C8 00 00 00 41 80 FA 04 75 EE 48 81 C2 10 03 00 00 48 89 74 24 ? 44 8B CD 4C 8B C7 E8 ^ ? ? ? 80 7B 38",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_EncEncryptionKeys_InitLoad",
      "48 8D 05 ? ? ? ? 48 89 05 ? ? ? ? 48 8B 05 ^ ? ? ? 48 85 C0 74 1E 66 0F 1F 44 00 00",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_TableRange_StartupAccumulator",
      "33 C9 48 8D 05 ? ? ? ? 48 8D 15 ^ ? ? ? 48 03 08 48 83 C0 08 48 3B C2 75 F4",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_TableRange_AutomapMessageA",
      "48 8B CB 89 54 24 ? 48 8D 15 ^ ? ? ? 44 89 54 24 ? E8 ? ? ? ? 8B 45 77",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_TableRange_AutomapMessageB",
      "8B 45 77 48 8D 15 ^ ? ? ? 48 89 7C 24 ? 45 8B CC 89 44 24 ? 4C 8B C6",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_PlayerIndex_LegacyEncryptedTable",
      "48 8D 15 ^ ? ? ? 8B DF",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_PlayerIndex_TableCandidate_CallA",
      "41 B8 22 00 00 00 48 8D 15 ^ ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 0F 57 C0 48 89 1D",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_PlayerIndex_TableCandidate_CallB",
      "48 89 05 ? ? ? ? 48 8D 15 ^ ? ? ? 33 C0 48 8D 0D ? ? ? ? 0F 11 05",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_PlayerIndex_TableCandidate_CallC",
      "41 B8 1B 00 00 00 48 8D 15 ^ ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 0F 57 C0",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_RetcheckTrap_ContextByteBase",
      "48 8B 0D ^ ? ? ? 32 41 5C E8 ? ? ? ? 0F B6 4D ? 80 C1 55 80 F1 57 80 F9 3B",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_RetcheckTrap_VerificationCall",
      "48 8B 0D ? ? ? ? 32 41 5C E8 ^ ? ? ? 0F B6 4D ? 80 C1 55 80 F1 57 80 F9 3B",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_RetcheckDataSlot_LoadRCX_FromTrap",
      "48 8B 0D ^ ? ? ? C0 C8 ? 34 8B D0 C8 32 81 C5 05 00 00 48 8D 4D ? 88 45 ? E8 ? ? ? ? 0F B6 4D ? 80 C1 55 80 F1 57 80 F9 3B",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_RetcheckDataSlot_LoadRDX_FromTrap",
      "48 8B 15 ^ ? ? ? 48 8D 4D ? C0 C8 ? 34 8B D0 C8 32 82 C5 05 00 00 88 45 ? E8 ? ? ? ? 0F B6 4D ? 80 C1 55 80 F1 57 80 F9 3B",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  signatures.push_back({
      "Diagnostic_RetcheckDataSlot_PfnAutomapTrap",
      "48 8B 0D ^ ? ? ? C0 C8 ? 34 8B D0 C8 32 81 C5 05 00 00 48 8D 4D ? 88 45 ? E8 ? ? ? ? 0F B6 4D ? 80 C1 55 80 F1 57 80 F9 3B 75 04 41 0F B6 06 48 83 C4 30 41 5E 5F",
      OffsetType::Relative32Add,
      &g_diagnostic_only_target,
      0,
      std::nullopt,
  });
  return signatures;
}

void LogFocusedRescanDiagnostics(std::vector<SignatureDef>& baseline_signatures) {
  static constexpr int kPassCount = 2;
  static constexpr DWORD kDelayMs = 10000;

  HMODULE module = GetModuleHandle(NULL);
  std::uintptr_t module_base = reinterpret_cast<std::uintptr_t>(module);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
  const auto* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
  const auto module_end = module_base + nt->OptionalHeader.SizeOfImage;
  auto focused_template = BuildFocusedDiagnosticSignatureList();

  std::vector<std::uint32_t> baseline_rvas(focused_template.size(), 0);
  std::vector<std::vector<std::uint32_t>> pass_rvas(kPassCount, std::vector<std::uint32_t>(focused_template.size(), 0));
  std::vector<std::uint32_t> baseline_hints(focused_template.size(), 0);
  std::vector<std::vector<std::uint32_t>> pass_hints(kPassCount, std::vector<std::uint32_t>(focused_template.size(), 0));

  auto baseline_scan_signatures = BuildFocusedDiagnosticSignatureList();
  std::vector<void*> baseline_targets(baseline_scan_signatures.size(), nullptr);
  for (std::size_t i = 0; i < baseline_scan_signatures.size(); ++i) {
    baseline_scan_signatures[i].target = &baseline_targets[i];
  }

  PatternScanner baseline_scanner;
  if (baseline_scanner.Initialize()) {
    PIPE_LOG_WARN("[Offsets] Safe diagnostic focused baseline rescan");
    baseline_scanner.ScanAll(baseline_scan_signatures);
    const auto* diagnostic_add_cell = FindSignature(
        baseline_scan_signatures,
        "Diagnostic_AUTOMAP_AddAutomapCell_FromNewCellCaller");
    if (diagnostic_add_cell != nullptr &&
        diagnostic_add_cell->target != nullptr &&
        *diagnostic_add_cell->target != nullptr &&
        kCheckRuntimeV2.dispatcher_slot == nullptr) {
      const auto add_cell_rva = static_cast<std::uint32_t>(
          reinterpret_cast<std::uintptr_t>(*diagnostic_add_cell->target) -
          module_base);
      ResolveRetcheckV2DispatcherFromAutomapTopology(
          module_base, nt, add_cell_rva);
    }
    LogPlayerIdOffsetCandidateDiagnostics(baseline_scan_signatures);
    LogRetcheckDataSlotDiagnostics(baseline_scan_signatures);
    LogRetcheckVerificationCallsiteDiagnostics(baseline_scan_signatures);
  } else {
    PIPE_LOG_ERROR("[Offsets] Focused baseline rescan failed to initialize pattern scanner");
  }

  for (std::size_t i = 0; i < focused_template.size(); ++i) {
    void* target = i < baseline_targets.size() ? baseline_targets[i] : nullptr;
    if (target == nullptr) {
      const SignatureDef* baseline_sig = FindSignature(baseline_signatures, focused_template[i].name);
      if (baseline_sig != nullptr && baseline_sig->target != nullptr && *baseline_sig->target != nullptr) {
        target = *baseline_sig->target;
      }
    }
    if (target != nullptr) {
      const auto address = reinterpret_cast<std::uintptr_t>(target);
      baseline_rvas[i] = static_cast<std::uint32_t>(address - module_base);
    }
    if (std::strcmp(focused_template[i].name, "sgptClientSideUnitHashTable") == 0) {
      baseline_hints[i] = GetNearestBeforeServerUnitTableHint(baseline_scan_signatures);
    } else if (std::strcmp(focused_template[i].name, "AutoMapPanel_CreateAutoMapData") == 0) {
      baseline_hints[i] = GetAutomapCreateDataClusterHint(baseline_scan_signatures);
    }
  }

  for (std::size_t i = 0; i < focused_template.size(); ++i) {
    void* late_target = i < baseline_targets.size() ? baseline_targets[i] : nullptr;
    SignatureDef* runtime_sig = FindMutableSignature(baseline_signatures, focused_template[i].name);
    if (late_target == nullptr || runtime_sig == nullptr || runtime_sig->target == nullptr ||
        *runtime_sig->target != nullptr) {
      continue;
    }
    runtime_sig->offset = reinterpret_cast<std::uintptr_t>(late_target) - module_base;
    *runtime_sig->target = late_target;
    PIPE_LOG_WARN(
        "[Offsets] promoted unique focused-rescan result: name={} RVA=0x{:08X}",
        runtime_sig->name,
        static_cast<std::uint32_t>(runtime_sig->offset));
  }

#ifdef NYX_D2R_FAST_DIAGNOSTIC
  PIPE_LOG_WARN(
      "[Offsets] Fast diagnostic mode: focused baseline complete; skipping two timed stability passes");
  return;
#endif

  for (int pass = 1; pass <= kPassCount; ++pass) {
    static constexpr DWORD kMonitorIntervalMs = 500;
    for (DWORD elapsed = 0; elapsed < kDelayMs;
         elapsed += kMonitorIntervalMs) {
      Sleep(kMonitorIntervalMs);
      if (elapsed % 5000 == 0 &&
          g_retcheck_v2_slot_rva != 0 &&
          !IsRetcheckV2RuntimeResolvedDiagnostic()) {
        LogRetcheckV2FieldReferences(module_base,
                                     module_end,
                                     g_retcheck_v2_slot_rva,
                                     true);
      }
    }
    PIPE_LOG_WARN("[Offsets] Safe diagnostic focused rescan pass {}/{} after {} ms",
                  pass,
                  kPassCount,
                  kDelayMs * pass);

    auto pass_signatures = BuildFocusedDiagnosticSignatureList();
    std::vector<void*> local_targets(pass_signatures.size(), nullptr);
    for (std::size_t i = 0; i < pass_signatures.size(); ++i) {
      pass_signatures[i].target = &local_targets[i];
    }

    PatternScanner scanner;
    if (!scanner.Initialize()) {
      PIPE_LOG_ERROR("[Offsets] Focused rescan pass {} failed to initialize pattern scanner", pass);
      continue;
    }

    scanner.ScanAll(pass_signatures);
    const auto* diagnostic_add_cell = FindSignature(
        pass_signatures,
        "Diagnostic_AUTOMAP_AddAutomapCell_FromNewCellCaller");
    if (diagnostic_add_cell != nullptr &&
        diagnostic_add_cell->target != nullptr &&
        *diagnostic_add_cell->target != nullptr &&
        kCheckRuntimeV2.dispatcher_slot == nullptr) {
      const auto add_cell_rva = static_cast<std::uint32_t>(
          reinterpret_cast<std::uintptr_t>(*diagnostic_add_cell->target) -
          module_base);
      ResolveRetcheckV2DispatcherFromAutomapTopology(
          module_base, nt, add_cell_rva);
    }

    PIPE_LOG_INFO("[Offsets] Focused rescan inventory pass {}:", pass);
    for (std::size_t i = 0; i < pass_signatures.size(); ++i) {
      void* target = local_targets[i];
      if (target != nullptr) {
        std::uintptr_t address = reinterpret_cast<std::uintptr_t>(target);
        pass_rvas[pass - 1][i] = static_cast<std::uint32_t>(address - module_base);
        PIPE_LOG_INFO("[Offsets]   PASS{} FOUND   {:<36} RVA=0x{:08X}",
                      pass,
                      pass_signatures[i].name,
                      pass_rvas[pass - 1][i]);
      } else {
        PIPE_LOG_WARN("[Offsets]   PASS{} MISSING {:<36}", pass, pass_signatures[i].name);
      }
      if (std::strcmp(pass_signatures[i].name, "sgptClientSideUnitHashTable") == 0) {
        pass_hints[pass - 1][i] = GetNearestBeforeServerUnitTableHint(pass_signatures);
      } else if (std::strcmp(pass_signatures[i].name, "AutoMapPanel_CreateAutoMapData") == 0) {
        pass_hints[pass - 1][i] = GetAutomapCreateDataClusterHint(pass_signatures);
      }
    }

    LogUnitHashTableCandidateDiagnostics(pass_signatures);
    LogPlayerIdOffsetCandidateDiagnostics(pass_signatures);
    LogRetcheckSafetyDiagnostics(pass_signatures);
    LogRetcheckDataSlotDiagnostics(pass_signatures);
  }

  PIPE_LOG_WARN("[Offsets] Focused rescan stability summary:");
  std::vector<std::pair<const char*, std::uint32_t>> stable_candidates;
  for (std::size_t i = 0; i < focused_template.size(); ++i) {
    const std::uint32_t baseline = baseline_rvas[i];
    const std::uint32_t pass1 = pass_rvas[0][i];
    const std::uint32_t pass2 = pass_rvas[1][i];
    const std::uint32_t baseline_hint = baseline_hints[i];
    const std::uint32_t pass1_hint = pass_hints[0][i];
    const std::uint32_t pass2_hint = pass_hints[1][i];

    const bool any_found = baseline != 0 || pass1 != 0 || pass2 != 0;
    const bool all_found = baseline != 0 && pass1 != 0 && pass2 != 0;
    const bool passes_match = pass1 != 0 && pass1 == pass2;
    const bool all_match = all_found && baseline == pass1 && pass1 == pass2;
    const bool all_hints_match = baseline_hint != 0 && baseline_hint == pass1_hint && pass1_hint == pass2_hint;
    SignatureDef* runtime_sig = FindMutableSignature(baseline_signatures, focused_template[i].name);
    const bool runtime_assigned = runtime_sig != nullptr && runtime_sig->target != nullptr && *runtime_sig->target != nullptr;

    const char* state = "missing";
    if (runtime_assigned && std::strcmp(focused_template[i].name, "sgptClientSideUnitHashTable") == 0) {
      state = "runtime-assigned";
    } else if (all_hints_match && std::strcmp(focused_template[i].name, "sgptClientSideUnitHashTable") == 0) {
      state = "ambiguous-stable";
    } else if (all_hints_match && std::strcmp(focused_template[i].name, "AutoMapPanel_CreateAutoMapData") == 0) {
      state = "ambiguous-favored-stable";
    } else if (all_match) {
      state = "stable";
    } else if (baseline == 0 && passes_match) {
      state = "late-stable";
    } else if (any_found && (pass1 == 0 || pass2 == 0 || baseline == 0)) {
      state = "intermittent";
    } else if (any_found) {
      state = "changed";
    }

    PIPE_LOG_WARN("[Offsets]   {:<36} state={:<12} baseline=0x{:08X} pass1=0x{:08X} pass2=0x{:08X}",
                  focused_template[i].name,
                  state,
                  baseline,
                  pass1,
                  pass2);
    if (std::strcmp(focused_template[i].name, "sgptClientSideUnitHashTable") == 0) {
      if (runtime_assigned) {
        PIPE_LOG_WARN("[Offsets]   {:<36} runtime=0x{:08X} reason=server-neighbor-discriminator assigned before focused rescan",
                      focused_template[i].name,
                      baseline);
      } else if (all_hints_match) {
        PIPE_LOG_WARN("[Offsets]   {:<36} hint=0x{:08X} reason=nearest-before-server-accessor, not assigned",
                      focused_template[i].name,
                      baseline_hint);
      }
    }
    if (all_hints_match && std::strcmp(focused_template[i].name, "AutoMapPanel_CreateAutoMapData") == 0) {
      PIPE_LOG_WARN("[Offsets]   {:<36} hint=0x{:08X} reason=nearest-automap-cluster-candidate, not assigned",
                    focused_template[i].name,
                    baseline_hint);
      stable_candidates.push_back({focused_template[i].name, baseline_hint});
    }
    const bool stable_or_late_stable = all_match || (baseline == 0 && passes_match);
    if (stable_or_late_stable && IsPromotionEligibleDiagnosticOffset(focused_template[i].name)) {
      const auto promoted_rva = all_match ? baseline : pass1;
      stable_candidates.push_back({focused_template[i].name, promoted_rva});
      if (runtime_sig != nullptr && runtime_sig->target != nullptr && *runtime_sig->target == nullptr &&
          IsRuntimeRequiredOffset(runtime_sig->name)) {
        runtime_sig->offset = promoted_rva;
        *runtime_sig->target = reinterpret_cast<void*>(module_base + promoted_rva);
        PIPE_LOG_WARN("[Offsets]   {:<36} runtime=0x{:08X} reason=focused-rescan-stable-promotion",
                      focused_template[i].name,
                      promoted_rva);
      }
    } else if (all_match && !IsPromotionEligibleDiagnosticOffset(focused_template[i].name)) {
      PIPE_LOG_WARN("[Offsets]   {:<36} promotion=blocked reason=needs-structural-validation",
                    focused_template[i].name);
    }
  }
  if (!stable_candidates.empty()) {
    PIPE_LOG_WARN("[Offsets] Stable non-sensitive diagnostic candidates:");
    for (const auto& candidate : stable_candidates) {
      PIPE_LOG_WARN("[Offsets]   candidate {:<36} RVA=0x{:08X} status=eligible-for-pattern-hardening",
                    candidate.first,
                    candidate.second);
    }
  }
  PIPE_LOG_WARN("[Offsets] Focused rescan is diagnostic only; no late/intermittent result was assigned to runtime offsets");
}

constexpr std::uint32_t kPlayerIdCacheMagic = 0x43444950;  // "PIDC"
constexpr std::uint32_t kPlayerIdCacheVersion = 2;

struct PlayerIdConstantsCacheFile {
  std::uint32_t magic;
  std::uint32_t version;
  std::uint64_t exe_hash;
  std::uint32_t xor_const;
  std::uint32_t add_const;
};

std::string GetPlayerIdConstantsCachePath(OffsetCacheManager& cache_mgr, std::uint64_t exe_hash) {
  std::string path = cache_mgr.GetCachePath(exe_hash);
  if (path.size() > 4 && path.substr(path.size() - 4) == ".bin") {
    path = path.substr(0, path.size() - 4) + ".playerid.bin";
  } else {
    path += ".playerid.bin";
  }
  return path;
}

bool LoadPlayerIdConstantsFromCache(OffsetCacheManager& cache_mgr, std::uint64_t exe_hash) {
  const std::string cache_path = GetPlayerIdConstantsCachePath(cache_mgr, exe_hash);
  std::ifstream file(cache_path, std::ios::binary);
  if (!file) {
    return false;
  }

  PlayerIdConstantsCacheFile data{};
  file.read(reinterpret_cast<char*>(&data), sizeof(data));
  if (!file) {
    PIPE_LOG_WARN("[PlayerIdConstants] Failed reading cache file {}", cache_path);
    return false;
  }

  if (data.magic != kPlayerIdCacheMagic || data.version != kPlayerIdCacheVersion || data.exe_hash != exe_hash) {
    return false;
  }

  PlayerIdXorConst = data.xor_const;
  PlayerIdAddConst = data.add_const;
  PIPE_LOG_INFO("[PlayerIdConstants] Loaded cached XOR=0x{:08X} ADD=0x{:08X}", PlayerIdXorConst, PlayerIdAddConst);
  return true;
}

bool SavePlayerIdConstantsToCacheInternal(OffsetCacheManager& cache_mgr,
                                          std::uint64_t exe_hash,
                                          std::uint32_t xor_const,
                                          std::uint32_t add_const) {
  if (exe_hash == 0) {
    return false;
  }
  if (!cache_mgr.EnsureCacheDirectory()) {
    return false;
  }

  const std::string cache_path = GetPlayerIdConstantsCachePath(cache_mgr, exe_hash);
  std::ofstream file(cache_path, std::ios::binary | std::ios::trunc);
  if (!file) {
    PIPE_LOG_WARN("[PlayerIdConstants] Failed creating cache file {}", cache_path);
    return false;
  }

  PlayerIdConstantsCacheFile data{
      kPlayerIdCacheMagic,
      kPlayerIdCacheVersion,
      exe_hash,
      xor_const,
      add_const,
  };

  file.write(reinterpret_cast<const char*>(&data), sizeof(data));
  if (!file) {
    PIPE_LOG_WARN("[PlayerIdConstants] Failed writing cache file {}", cache_path);
    return false;
  }

  PIPE_LOG_DEBUG("[PlayerIdConstants] Cached XOR=0x{:08X} ADD=0x{:08X}", xor_const, add_const);
  return true;
}

}  // namespace

bool InitializeOffsets() {
  PIPE_LOG_INFO("[Offsets] Initializing...");

  auto signatures = BuildSignatureList();
  const bool patch_diagnostic_requested = IsPatchDiagnosticRequested();
  PIPE_LOG_INFO("[Offsets] startup profile={}",
                patch_diagnostic_requested ? "full-patch-diagnostic" : "fast-runtime");

  if (signatures.empty()) {
    PIPE_LOG_WARN("[Offsets] No offsets defined in D2R_OFFSET_LIST");
    return true;  // Not an error, just nothing to do
  }

  PIPE_LOG_DEBUG("[Offsets] {} offsets to resolve", signatures.size());

  OffsetCacheManager cache_mgr;
  std::uint64_t exe_hash = cache_mgr.ComputeExecutableHash();
  std::uint32_t sig_hash = cache_mgr.ComputeSignatureHash(signatures);
  PIPE_LOG_INFO("[Offsets] Executable hash: 0x{:016X}", exe_hash);
  PIPE_LOG_INFO("[Offsets] Signature hash: 0x{:08X}", sig_hash);

  if (exe_hash == 0) {
    PIPE_LOG_WARN("[Offsets] Failed to compute executable hash, caching disabled");
  }

  if (exe_hash != 0) {
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
#ifdef NYX_D2R_FAST_DIAGNOSTIC
    if (!patch_diagnostic_requested) {
      auto cached = cache_mgr.LoadCache(exe_hash, sig_hash);
      if (cached.has_value()) {
        PIPE_LOG_INFO("[Offsets] Fast startup: validating executable-hash-bound offset cache");
        ApplyCachedOffsets(*cached, signatures);
        if (ValidateOffsets()) {
          PIPE_LOG_INFO("[Offsets] Fast startup: validated offset cache accepted");
          RegisterOffsetsWithDolos();
          return true;
        }
        PIPE_LOG_WARN("[Offsets] Fast startup: cached offsets failed validation; rescanning");
      }
    } else {
      PIPE_LOG_WARN("[Offsets] Full patch diagnostic requested: bypassing offset cache");
    }
#else
    PIPE_LOG_WARN("[Offsets] Safe diagnostic mode: ignoring offset cache and forcing full scan");
#endif
#else
    auto cached = cache_mgr.LoadCache(exe_hash, sig_hash);
    if (cached.has_value()) {
      PIPE_LOG_DEBUG("[Offsets] Applying cached offsets...");
      ApplyCachedOffsets(*cached, signatures);

      if (ValidateOffsets()) {
        PIPE_LOG_INFO("[Offsets] Loaded {} offsets from cache", signatures.size());
        RegisterOffsetsWithDolos();
        return true;
      }

      PIPE_LOG_DEBUG("[Offsets] Cache validation failed, rescanning...");
    }
#endif
  }

  PIPE_LOG_DEBUG("[Offsets] Performing full pattern scan...");

  PatternScanner scanner;
  if (!scanner.Initialize()) {
    PIPE_LOG_ERROR("[Offsets] Failed to initialize pattern scanner");
    return false;
  }

  if (!scanner.ScanAll(signatures)) {
    PIPE_LOG_WARN("[Offsets] Not all patterns were found");
  }

  RetryUnresolvedNonSensitiveOffsets(signatures);
  ResolveClientSideUnitTableFromServerNeighbor(signatures);
  ResolveCurrentAutomapLayerFromLayerLink(signatures);
  ResolveAutomapOffsetsFromCreateDataCluster(signatures);
  ResolveReferenceUiOffsetFromDataLayout(signatures);

#ifdef NYX_D2R_PE_DUMP
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  PIPE_LOG_WARN("[Offsets] Safe diagnostic mode: PE dump disabled");
#else
  if (exe_hash != 0) {
    std::string dump_path = cache_mgr.GetCachePath(exe_hash);
    if (dump_path.size() > 4 && dump_path.substr(dump_path.size() - 4) == ".bin") {
      dump_path = dump_path.substr(0, dump_path.size() - 4) + ".exe";
    } else {
      dump_path += ".exe";
    }

    PEBuilder builder(scanner.module_base(), scanner.module_size());
    for (const auto& sec : scanner.sections()) {
      builder.AddSection(sec);
    }
    if (!builder.WriteExecutable(scanner.buffer(), dump_path)) {
      PIPE_LOG_WARN("[Offsets] Failed to write PE dump");
    }
  }
#endif
#endif  // NYX_D2R_PE_DUMP

  auto count_found_offsets = [&signatures]() {
    std::size_t count = 0;
    for (const auto& sig : signatures) {
      if (*sig.target != nullptr) {
        ++count;
      }
    }
    return count;
  };

  auto count_missing_required_offsets = [&signatures]() {
    std::size_t count = 0;
    for (const auto& sig : signatures) {
      if (*sig.target == nullptr && IsRuntimeRequiredOffset(sig.name)) {
        ++count;
      }
    }
    return count;
  };

  std::size_t found_count = count_found_offsets();
  std::size_t missing_required_count = count_missing_required_offsets();

  PIPE_LOG_INFO("[Offsets] Resolved {}/{} offsets", found_count, signatures.size());
  PIPE_LOG_INFO("[Offsets] Runtime-required missing offsets: {}", missing_required_count);
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  HMODULE module = GetModuleHandle(NULL);
  std::uintptr_t module_base = reinterpret_cast<std::uintptr_t>(module);
  PIPE_LOG_INFO("[Offsets] Diagnostic offset inventory:");
  PIPE_LOG_WARN("[Offsets] Diagnostic build marker: player-index transform-xref probe enabled; retcheck remains read-only/blocked");
  for (const auto& sig : signatures) {
    if (*sig.target != nullptr) {
      std::uintptr_t address = reinterpret_cast<std::uintptr_t>(*sig.target);
      PIPE_LOG_INFO("[Offsets]   FOUND   {:<36} RVA=0x{:08X} VA={:p}",
                    sig.name,
                    static_cast<std::uint32_t>(address - module_base),
                    *sig.target);
    } else {
      PIPE_LOG_WARN("[Offsets]   MISSING {:<36} pattern={}", sig.name, sig.pattern);
    }
  }
#ifdef NYX_D2R_FAST_DIAGNOSTIC
  if (!patch_diagnostic_requested) {
    PIPE_LOG_WARN(
        "[Offsets] Fast startup: skipping extended patch/Retcheck diagnostics; "
        "use START_PATCH_DIAGNOSE_UND_CACHE.bat when investigating a game patch");
  } else {
    PIPE_LOG_WARN("[Offsets] Running requested extended patch/Retcheck diagnostics");
    LogUnitHashTableCandidateDiagnostics(signatures);
    LogRetcheckSafetyDiagnostics(signatures);
    LogPlayerIdOffsetCandidateDiagnostics(signatures);
    LogPlayerIdTransformXrefDiagnostics(signatures);
    LogClientPlayerUnitTableDiagnostics();
    LogFocusedRescanDiagnostics(signatures);
    ResolveAutomapOffsetsFromCreateDataCluster(signatures);
    LogPlayerIdDecodeSiteDiagnostics(signatures);
    PIPE_LOG_WARN("[Offsets] Requested extended patch diagnostics complete");
  }
#else
  LogUnitHashTableCandidateDiagnostics(signatures);
  LogRetcheckSafetyDiagnostics(signatures);
  LogPlayerIdOffsetCandidateDiagnostics(signatures);
  LogPlayerIdTransformXrefDiagnostics(signatures);
  LogClientPlayerUnitTableDiagnostics();
  LogFocusedRescanDiagnostics(signatures);
  ResolveAutomapOffsetsFromCreateDataCluster(signatures);
  LogPlayerIdDecodeSiteDiagnostics(signatures);
  PIPE_LOG_WARN("[Offsets] Safe diagnostic extended diagnostics complete; skipping extra late retry");
#endif
  found_count = count_found_offsets();
  missing_required_count = count_missing_required_offsets();
  PIPE_LOG_INFO("[Offsets] Post-diagnostic resolved {}/{} offsets", found_count, signatures.size());
  const std::size_t effective_found_count =
      found_count + (IsRetcheckV2RuntimeResolvedDiagnostic() && kCheckData == nullptr ? 1 : 0);
  PIPE_LOG_INFO(
      "[Offsets] Post-diagnostic effective compatibility resolved {}/{} offsets (Retcheck V2 supersedes legacy kCheckData={})",
      effective_found_count,
      signatures.size(),
      effective_found_count != found_count ? "yes" : "no");
  PIPE_LOG_INFO("[Offsets] Post-diagnostic runtime-required missing offsets: {}", missing_required_count);
#endif
  if (found_count != signatures.size()) {
    LogMissingOffsets(signatures);
  }

#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
#ifndef NYX_D2R_FAST_DIAGNOSTIC
  if (exe_hash != 0 && missing_required_count == 0) {
    auto cache = BuildCache(exe_hash, sig_hash, signatures);
    if (cache_mgr.SaveCache(cache)) {
      PIPE_LOG_INFO(
          "[Offsets] Full patch diagnostic cached validated runtime offsets for future fast starts");
    }
  } else {
    PIPE_LOG_WARN("[Offsets] Full patch diagnostic did not cache incomplete runtime offsets");
  }
#else
  if (patch_diagnostic_requested && exe_hash != 0 && missing_required_count == 0) {
    auto cache = BuildCache(exe_hash, sig_hash, signatures);
    if (cache_mgr.SaveCache(cache)) {
      PIPE_LOG_INFO(
          "[Offsets] Patch diagnostic cached validated runtime offsets for future fast starts");
    }
  } else {
    PIPE_LOG_WARN("[Offsets] Fast startup: incomplete scan results are not cached");
  }
#endif
#else
  if (exe_hash != 0 && found_count == signatures.size()) {
    auto cache = BuildCache(exe_hash, sig_hash, signatures);
    if (cache_mgr.SaveCache(cache)) {
      PIPE_LOG_DEBUG("[Offsets] Offsets cached for future use");
    }
  } else if (found_count > 0) {
    PIPE_LOG_WARN("[Offsets] Incomplete scan result not cached");
  }
#endif

  RegisterOffsetsWithDolos();
#ifdef NYX_D2R_SAFE_DIAGNOSTIC_MODE
  if (missing_required_count == 0 && found_count != signatures.size()) {
    PIPE_LOG_WARN(
        "[Offsets] Safe diagnostic readiness: runtime-required offsets resolved; remaining missing offsets are gated/legacy");
  }
  return missing_required_count == 0;
#else
  return found_count == signatures.size();
#endif
}

bool ValidateOffsets() {
#define VALIDATE_OFFSET(...)                                                                                           \
  if (D2R_GET_VAR(__VA_ARGS__) == nullptr && IsRuntimeRequiredOffset(D2R_GET_NAME(__VA_ARGS__))) return false;
  D2R_OFFSET_LIST(VALIDATE_OFFSET)
#undef VALIDATE_OFFSET

  return true;
}

bool InitializePlayerIdConstants() {
  // Prefer validated cached constants by exe hash.
  //
  // We intentionally avoid trusting an initialization-time pattern scan result
  // here because false positives can select invalid immediates and destabilize
  // later calls. Runtime code validates candidates against real unit lookups
  // and persists only validated values.

  OffsetCacheManager cache_mgr;
  std::uint64_t exe_hash = cache_mgr.ComputeExecutableHash();
  if (exe_hash != 0 && LoadPlayerIdConstantsFromCache(cache_mgr, exe_hash)) {
    return true;
  }

  // Bootstrap constants: runtime validation/recovery may replace these and
  // cache validated values for future launches.
  PlayerIdXorConst = 0x8633C320;
  PlayerIdAddConst = 0x53D5CDD3;
  PIPE_LOG_WARN("[PlayerIdConstants] No validated cache found, using bootstrap constants");
  return true;
}

bool SavePlayerIdConstantsToCache(uint32_t xor_const, uint32_t add_const) {
  OffsetCacheManager cache_mgr;
  std::uint64_t exe_hash = cache_mgr.ComputeExecutableHash();
  return SavePlayerIdConstantsToCacheInternal(cache_mgr, exe_hash, xor_const, add_const);
}

void GetOffsetInfo(OffsetInfo* out, std::size_t count) {
  if (count == 0 || out == nullptr) {
    return;
  }

  std::size_t i = 0;

#define FILL_INFO(...)                                                                                                 \
  if (i < count) {                                                                                                     \
    out[i].name = D2R_GET_NAME(__VA_ARGS__);                                                                           \
    out[i].pattern = D2R_GET_PATTERN(__VA_ARGS__);                                                                     \
    out[i].type = D2R_GET_TYPE(__VA_ARGS__);                                                                           \
    out[i].value = D2R_GET_VAR(__VA_ARGS__);                                                                           \
    out[i].found = D2R_GET_VAR(__VA_ARGS__) != nullptr;                                                                \
    ++i;                                                                                                               \
  }
  D2R_OFFSET_LIST(FILL_INFO)
#undef FILL_INFO
}

}  // namespace d2r
