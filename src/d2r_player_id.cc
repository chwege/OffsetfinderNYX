#include "d2r_player_id.h"

#include <dolos/pipe_log.h>
#include "d2r_safety.h"
#include "d2r_structs.h"
#include "offsets.h"

#include <Windows.h>
#include <bit>
#include <unordered_set>

namespace d2r {

// Forward declaration — GetUnit is defined in d2r_methods.cc.
D2UnitStrc* GetUnit(uint32_t id, uint32_t type);

namespace {

constexpr uint32_t  kLegacyPlayerIdXorConst        = 0x8633C320u;
constexpr uint32_t  kLegacyPlayerIdAddConst         = 0x53D5CDD3u;
constexpr std::size_t kMaxUnitChainTraversal        = 8192;
constexpr ULONGLONG kPlayerIdCacheHitWindowMs       = 3000;
constexpr uint32_t  kPlayerIdCacheCommitHits        = 3;
constexpr ULONGLONG kDirectLocalPlayerScanIntervalMs = 250;

PlayerIdCandidateState  s_player_id_candidate{};
LocalPlayerIdentityState s_local_player_identity{};

// -------------------------------------------------------------------------
// TryGetUnitNoThrow — SEH-wrapped GetUnit
// -------------------------------------------------------------------------
D2UnitStrc* TryGetUnitNoThrow(uint32_t id, uint32_t type) {
#if defined(_MSC_VER)
  __try {
    return GetUnit(id, type);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return nullptr;
  }
#else
  return GetUnit(id, type);
#endif
}

bool IsReadableRange(const void* address, std::size_t size) {
  if (address == nullptr || size == 0) {
    return false;
  }

  MEMORY_BASIC_INFORMATION info{};
  if (VirtualQuery(address, &info, sizeof(info)) == 0) {
    return false;
  }

  if (info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD) != 0 || (info.Protect & PAGE_NOACCESS) != 0) {
    return false;
  }

  const auto start        = reinterpret_cast<std::uintptr_t>(address);
  const auto region_start = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
  const auto region_end   = region_start + info.RegionSize;
  return start >= region_start && size <= region_end - start;
}

bool IsPlausibleLocalPlayerUnit(D2UnitStrc* unit) {
  if (!IsReadableRange(unit, sizeof(D2UnitStrc))) {
    return false;
  }

  if (unit->dwUnitType != 0 || unit->dwId == 0 || unit->dwId == 0xFFFFFFFFu) {
    return false;
  }

  if (unit->wPosX == 0 || unit->wPosY == 0 || unit->pDrlgAct == nullptr || unit->pDynamicPath == nullptr) {
    return false;
  }

  if (!IsReadableRange(unit->pDrlgAct, sizeof(D2DrlgActStrc)) ||
      !IsReadableRange(unit->pDynamicPath, sizeof(D2DynamicPathStrc))) {
    return false;
  }

  if (unit->pDrlgAct->ptDrlg == nullptr || !IsReadableRange(unit->pDrlgAct->ptDrlg, sizeof(D2DrlgStrc))) {
    return false;
  }

  return true;
}

// -------------------------------------------------------------------------
// Decode helpers
// -------------------------------------------------------------------------
bool TryDecodePlayerIdWithConstants(uint32_t index, uint32_t xor_const, uint32_t add_const, uint32_t* out_id) {
  if (out_id == nullptr) {
    return false;
  }

#if defined(_MSC_VER)
  __try {
#endif
    // Current patches resolve player identity directly through the unit table.
    // Keep this decoder dormant unless every legacy component is independently
    // available; treating the pre-transform value as an ID creates false hits.
    if (EncTransformValue == nullptr || EncEncryptionKeys == nullptr ||
        PlayerIndexToIDEncryptedTable == nullptr) {
      return false;
    }

    uintptr_t keys_base = *EncEncryptionKeys;
    if (keys_base == 0) {
      return false;
    }

    uint32_t key       = *(uint32_t*)(keys_base + 0x146);
    uint32_t encrypted = PlayerIndexToIDEncryptedTable[index];
    uint32_t temp      = (encrypted ^ key ^ xor_const) + add_const;
    uint32_t v         = std::rotl(std::rotl(temp, 9), 7);
    uint32_t id = EncTransformValue(&v);
    if (id == 0xFFFFFFFFu) {
      id = 0;
    }
    *out_id = id;
    return true;
#if defined(_MSC_VER)
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
#endif
}

inline uint32_t DecodePlayerIdWithConstants(uint32_t index, uint32_t xor_const, uint32_t add_const) {
  uint32_t id = 0;
  if (!TryDecodePlayerIdWithConstants(index, xor_const, add_const, &id)) {
    return 0;
  }
  return id;
}

// -------------------------------------------------------------------------
// Cache helpers
// -------------------------------------------------------------------------
void RememberLocalPlayerId(uint32_t id) {
  if (id == 0) {
    return;
  }
  s_local_player_identity.cached_id = id;
}

// Scans the client hash table and returns true (+ sets *out_id) when exactly
// one player unit looks like the active local player.
bool TryResolveLocalPlayerIdFromUnitTable(uint32_t* out_id) {
  if (out_id == nullptr || sgptClientSideUnitHashTable == nullptr) {
    return false;
  }
#if defined(_MSC_VER)
  __try {
#endif
    EntityHashTable* client_units = sgptClientSideUnitHashTable;
    uint32_t plausible_id    = 0;
    uint32_t plausible_count = 0;

    for (size_t i = 0; i < kUnitHashTableCount; ++i) {
      if (!IsReadableRange(&client_units[0][i], sizeof(D2UnitStrc*))) {
        continue;
      }

      std::size_t traversed = 0;
      D2UnitStrc* last_node = nullptr;
      for (D2UnitStrc* current = client_units[0][i]; current; current = current->pUnitNext) {
        if (++traversed > kMaxUnitChainTraversal) {
          break;
        }
        if (current == last_node) {
          break;
        }
        last_node = current;

        if (!IsPlausibleLocalPlayerUnit(current)) {
          continue;
        }

        ++plausible_count;
        if (plausible_id == 0) {
          plausible_id = current->dwId;
        }
        if (plausible_count > 1 || current->dwId != plausible_id) {
          return false;
        }
      }
    }

    if (plausible_count != 1 || plausible_id == 0) {
      return false;
    }
    *out_id = plausible_id;
    return true;
#if defined(_MSC_VER)
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
#endif
}

// Tries the fast direct-identity path: returns cached ID if still valid,
// or re-runs the single-player-ID scan if the scan interval has elapsed.
bool TryGetDirectLocalPlayerId(uint32_t* out_id) {
  if (out_id == nullptr) {
    return false;
  }

  if (s_local_player_identity.cached_id != 0) {
    if (TryGetUnitNoThrow(s_local_player_identity.cached_id, 0) != nullptr) {
      *out_id = s_local_player_identity.cached_id;
      return true;
    }
    s_local_player_identity.cached_id = 0;
  }

  ULONGLONG now = GetTickCount64();
  if (now - s_local_player_identity.last_scan_ms < kDirectLocalPlayerScanIntervalMs) {
    return false;
  }
  s_local_player_identity.last_scan_ms = now;

  uint32_t direct_id = 0;
  if (!TryResolveLocalPlayerIdFromUnitTable(&direct_id)) {
    return false;
  }
  if (TryGetUnitNoThrow(direct_id, 0) == nullptr) {
    return false;
  }

  s_local_player_identity.cached_id = direct_id;
  *out_id = direct_id;
  if (!s_local_player_identity.logged_direct_path) {
    s_local_player_identity.logged_direct_path = true;
    PIPE_LOG_INFO("[LocalPlayerIdentity] Using direct local-player unit identity path (id=0x{:08X})", direct_id);
  }
  return true;
}

// Records a validated (xor, add) pair; commits it to the on-disk cache
// after kPlayerIdCacheCommitHits consecutive confirmations.
void ObservePlayerIdCandidateForCache(uint32_t xor_val, uint32_t add_val) {
  ULONGLONG now         = GetTickCount64();
  bool      same_candidate = (s_player_id_candidate.xor_const == xor_val &&
                               s_player_id_candidate.add_const == add_val &&
                               now - s_player_id_candidate.last_hit_ms <= kPlayerIdCacheHitWindowMs);
  if (same_candidate) {
    ++s_player_id_candidate.hits;
  } else {
    s_player_id_candidate.xor_const  = xor_val;
    s_player_id_candidate.add_const  = add_val;
    s_player_id_candidate.hits       = 1;
    s_player_id_candidate.committed  = false;
  }
  s_player_id_candidate.last_hit_ms = now;

  if (!s_player_id_candidate.committed && s_player_id_candidate.hits >= kPlayerIdCacheCommitHits) {
    s_player_id_candidate.committed = true;
    if (SavePlayerIdConstantsToCache(xor_val, add_val)) {
      PIPE_LOG_INFO("[PlayerIdConstants] Cached validated runtime constants after {} confirmations",
                    kPlayerIdCacheCommitHits);
    }
  }
}

// Two-pass binary scan of executable sections for the XOR+ADD instruction
// pattern used to decode player IDs.  Updates global PlayerIdXorConst /
// PlayerIdAddConst on success.
bool TryRecoverPlayerIdConstantsFromRuntime(uint32_t index, uint32_t* recovered_id) {
  HMODULE module = GetModuleHandle(NULL);
  if (!module) {
    return false;
  }

  auto dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
  auto nt   = reinterpret_cast<const IMAGE_NT_HEADERS*>(
      reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
  const uint8_t* base = reinterpret_cast<const uint8_t*>(module);

  std::unordered_set<uint64_t> seen_candidates;
  auto try_candidate = [&](uint32_t xor_val, uint32_t add_val, const char* source) -> bool {
    uint64_t key = (static_cast<uint64_t>(xor_val) << 32) | add_val;
    if (!seen_candidates.insert(key).second) {
      return false;
    }

    uint32_t candidate_id = 0;
    if (!TryDecodePlayerIdWithConstants(index, xor_val, add_val, &candidate_id)) {
      return false;
    }
    if (candidate_id == 0) {
      return false;
    }
    if (TryGetUnitNoThrow(candidate_id, 0) == nullptr) {
      return false;
    }

    PlayerIdXorConst = xor_val;
    PlayerIdAddConst = add_val;
    ObservePlayerIdCandidateForCache(xor_val, add_val);
    if (recovered_id != nullptr) {
      *recovered_id = candidate_id;
    }
    PIPE_LOG_INFO("[PlayerIdConstants] Recovered runtime constants from {} candidate (xor=0x{:08X} add=0x{:08X})",
                  source,
                  xor_val,
                  add_val);
    return true;
  };

  const auto* section = IMAGE_FIRST_SECTION(nt);
  // Pass 1: strict candidates.
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }
    const uint8_t* start = base + section->VirtualAddress;
    const uint8_t* end   = start + section->Misc.VirtualSize;
    for (const uint8_t* p = start; p + 16 <= end; ++p) {
      if (p[0]  != 0x35 || p[5]  != 0x05 || p[10] != 0xC1 || p[11] != 0xC0 ||
          p[12] != 0x09 || p[13] != 0xC1 || p[14] != 0xC0 || p[15] != 0x07) {
        continue;
      }
      if (try_candidate(*reinterpret_cast<const uint32_t*>(p + 1),
                        *reinterpret_cast<const uint32_t*>(p + 6),
                        "strict")) {
        return true;
      }
    }
  }

  // Pass 2: relaxed candidates.
  section = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }
    const uint8_t* start = base + section->VirtualAddress;
    const uint8_t* end   = start + section->Misc.VirtualSize;
    for (const uint8_t* p = start; p + 12 <= end; ++p) {
      if (p[0] != 0x35 || p[5] != 0x05 || p[10] != 0xC1 || p[11] != 0xC0) {
        continue;
      }
      if (try_candidate(*reinterpret_cast<const uint32_t*>(p + 1),
                        *reinterpret_cast<const uint32_t*>(p + 6),
                        "relaxed")) {
        return true;
      }
    }
  }

  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
uint32_t GetPlayerId(uint32_t index) {
  if (index < 0 || index >= 8) {
    return 0;
  };

  const bool is_local_slot = (s_PlayerUnitIndex != nullptr && index == *s_PlayerUnitIndex);
  if (!is_local_slot || sgptClientSideUnitHashTable == nullptr) {
    uint32_t id = DecodePlayerIdWithConstants(index, PlayerIdXorConst, PlayerIdAddConst);
    return id;
  }

  static bool s_local_player_observed = false;
  uint32_t direct_id = 0;
  if (TryGetDirectLocalPlayerId(&direct_id)) {
    s_local_player_observed = true;
    return direct_id;
  }

  uint32_t id = DecodePlayerIdWithConstants(index, PlayerIdXorConst, PlayerIdAddConst);

  if (id != 0 && TryGetUnitNoThrow(id, 0) != nullptr) {
    s_local_player_observed = true;
    RememberLocalPlayerId(id);
    return id;
  }

  uint32_t legacy_id = DecodePlayerIdWithConstants(index, kLegacyPlayerIdXorConst, kLegacyPlayerIdAddConst);
  if (legacy_id != 0 && TryGetUnitNoThrow(legacy_id, 0) != nullptr) {
    s_local_player_observed = true;
    RememberLocalPlayerId(legacy_id);
    if (PlayerIdXorConst != kLegacyPlayerIdXorConst || PlayerIdAddConst != kLegacyPlayerIdAddConst) {
      PIPE_LOG_WARN(
          "[PlayerIdConstants] Runtime validation failed for current constants "
          "(xor=0x{:08X} add=0x{:08X}), reverting to bootstrap constants",
          PlayerIdXorConst,
          PlayerIdAddConst);
      PlayerIdXorConst = kLegacyPlayerIdXorConst;
      PlayerIdAddConst = kLegacyPlayerIdAddConst;
    }
    return legacy_id;
  }

  // During teardown/loading, player units can be transiently absent.
  // Avoid expensive recovery scans in these states and after we have already
  // observed a valid local player once for this session.
  const bool has_any_player_units = HasAnyPlayerUnits();
  if (s_local_player_observed || !has_any_player_units) {
    if (!has_any_player_units) {
      s_local_player_identity.cached_id = 0;
    }
    return 0;
  }

  // For local slot, try runtime recovery whenever current constants fail to
  // produce a resolvable player unit. This also handles id==0 cases.
  static ULONGLONG s_last_recovery_attempt_ms = 0;
  ULONGLONG now = GetTickCount64();
  if (now - s_last_recovery_attempt_ms >= 1000) {
    s_last_recovery_attempt_ms = now;

    uint32_t recovered_id = 0;
    if (TryRecoverPlayerIdConstantsFromRuntime(index, &recovered_id)) {
      RememberLocalPlayerId(recovered_id);
      return recovered_id;
    }
  }

  return 0;
}

D2UnitStrc* GetPlayerUnit(uint32_t index) {
  uint32_t id = GetPlayerId(index);
  if (id == 0) {
    return nullptr;
  }
  return TryGetUnitNoThrow(id, 0);
}

void LogLocalPlayerIdentityDiagnostic() {
  uint32_t id = 0;
  if (TryGetDirectLocalPlayerId(&id)) {
    PIPE_LOG_WARN("[LocalPlayerIdentity] Diagnostic direct local-player unit identity resolved id=0x{:08X}", id);
    return;
  }

  PIPE_LOG_WARN("[LocalPlayerIdentity] Diagnostic direct local-player unit identity not resolved");
}

}  // namespace d2r
