#include "unit_table_diagnostics.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include <dolos/pipe_log.h>

#include "d2r_methods.h"
#include "d2r_structs.h"

namespace d2r {
namespace {

constexpr size_t kUnitTableBytes = sizeof(EntityHashTable);
constexpr size_t kUnitTableBlockBytes = kUnitTypeCount * kUnitTableBytes;
constexpr size_t kMaxNodesPerChain = 4096;

static_assert(kUnitTableBytes == 0x400);
static_assert(kUnitTableBlockBytes == 0x1800);

struct TableStats {
  size_t nonempty_buckets = 0;
  size_t nodes = 0;
  size_t matching_types = 0;
  size_t mismatching_types = 0;
  size_t invalid_nodes = 0;
  size_t truncated_chains = 0;
  std::array<size_t, kUnitTypeCount> observed_types{};
  size_t other_types = 0;
  uint32_t first_id = 0;
  uint32_t first_class_id = 0;
  D2UnitStrc* first_unit = nullptr;
  bool has_first = false;
};

bool IsReadableRange(const void* address, size_t size) {
  if (address == nullptr || size == 0) {
    return false;
  }

  MEMORY_BASIC_INFORMATION info{};
  if (VirtualQuery(address, &info, sizeof(info)) == 0 ||
      info.State != MEM_COMMIT ||
      (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
    return false;
  }

  const uintptr_t begin = reinterpret_cast<uintptr_t>(address);
  const uintptr_t region_end = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
  return begin <= region_end && size <= region_end - begin;
}

TableStats AnalyzeTable(EntityHashTable* block, uint32_t expected_type) {
  TableStats stats{};
  EntityHashTable* table = block + expected_type;
  if (!IsReadableRange(table, sizeof(*table))) {
    stats.invalid_nodes = 1;
    return stats;
  }

  __try {
    for (size_t bucket = 0; bucket < kUnitHashTableCount; ++bucket) {
      D2UnitStrc* current = (*table)[bucket];
      if (current != nullptr) {
        ++stats.nonempty_buckets;
      }

      size_t chain_nodes = 0;
      while (current != nullptr && chain_nodes < kMaxNodesPerChain) {
        if (!IsReadableRange(current, offsetof(D2UnitStrc, pUnitNext) + sizeof(current->pUnitNext))) {
          ++stats.invalid_nodes;
          break;
        }

        const uint32_t observed_type = current->dwUnitType;
        if (!stats.has_first) {
          stats.first_id = current->dwId;
          stats.first_class_id = current->dwClassId;
          stats.first_unit = current;
          stats.has_first = true;
        }

        ++stats.nodes;
        ++chain_nodes;
        if (observed_type == expected_type) {
          ++stats.matching_types;
        } else {
          ++stats.mismatching_types;
        }
        if (observed_type < stats.observed_types.size()) {
          ++stats.observed_types[observed_type];
        } else {
          ++stats.other_types;
        }

        D2UnitStrc* next = current->pUnitNext;
        if (next == current) {
          ++stats.truncated_chains;
          break;
        }
        current = next;
      }

      if (current != nullptr && chain_nodes == kMaxNodesPerChain) {
        ++stats.truncated_chains;
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    ++stats.invalid_nodes;
  }

  return stats;
}

struct BlockStats {
  size_t nodes = 0;
  size_t matching_types = 0;
  size_t mismatching_types = 0;
  size_t invalid_nodes = 0;
};

BlockStats AnalyzeBlock(const char* label,
                        EntityHashTable* block,
                        uintptr_t image_base,
                        bool verify_client_lookup) {
  BlockStats totals{};
  const uintptr_t block_address = reinterpret_cast<uintptr_t>(block);
  const uintptr_t block_rva = block_address >= image_base ? block_address - image_base : 0;

  PIPE_LOG_INFO("[UnitTableModel] block={} base_rva=0x{:08X} table_bytes=0x{:X} type_count={}",
                label, static_cast<uint32_t>(block_rva), kUnitTableBytes, kUnitTypeCount);

  for (uint32_t type = 0; type < kUnitTypeCount; ++type) {
    const TableStats stats = AnalyzeTable(block, type);
    totals.nodes += stats.nodes;
    totals.matching_types += stats.matching_types;
    totals.mismatching_types += stats.mismatching_types;
    totals.invalid_nodes += stats.invalid_nodes;

    const D2UnitStrc* lookup =
        verify_client_lookup && stats.has_first ? GetUnit(stats.first_id, type) : nullptr;
    const char* lookup_result =
        !verify_client_lookup ? "not-client-block"
                              : (!stats.has_first ? "no-sample"
                                                  : (lookup == stats.first_unit ? "match" : "mismatch"));

    const uintptr_t table_rva = block_rva + type * kUnitTableBytes;
    PIPE_LOG_INFO(
        "[UnitTableModel] block={} table_type={} table_rva=0x{:08X} buckets={} nodes={} "
        "type_matches={} mismatches={} invalid={} truncated={} first_id=0x{:08X} "
        "first_class=0x{:08X} lookup={} histogram=[{},{},{},{},{},{}] other={}",
        label, type, static_cast<uint32_t>(table_rva), stats.nonempty_buckets, stats.nodes,
        stats.matching_types, stats.mismatching_types, stats.invalid_nodes,
        stats.truncated_chains, stats.first_id, stats.first_class_id, lookup_result,
        stats.observed_types[0], stats.observed_types[1], stats.observed_types[2],
        stats.observed_types[3], stats.observed_types[4], stats.observed_types[5],
        stats.other_types);
  }

  const bool six_type_layout = totals.nodes != 0 && totals.mismatching_types == 0 &&
                               totals.invalid_nodes == 0;
  PIPE_LOG_INFO(
      "[UnitTableModel] block={} summary nodes={} matches={} mismatches={} invalid={} layout={}",
      label, totals.nodes, totals.matching_types, totals.mismatching_types,
      totals.invalid_nodes, six_type_layout ? "six-type-consistent" : "not-yet-confirmed");
  return totals;
}

}  // namespace

void LogUnitTableBlockDiagnostics() {
  PIPE_LOG_INFO("[UnitTableModel] Starting read-only adjacent unit-table validation");
  if (sgptClientSideUnitHashTable == nullptr) {
    PIPE_LOG_WARN("[UnitTableModel] Primary unit-table pointer is unresolved");
    return;
  }

  const uintptr_t image_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
  EntityHashTable* const primary = sgptClientSideUnitHashTable;
  EntityHashTable* const adjacent = reinterpret_cast<EntityHashTable*>(
      reinterpret_cast<uint8_t*>(primary) + kUnitTableBlockBytes);

  const BlockStats primary_stats =
      AnalyzeBlock("resolved-primary", primary, image_base, true);
  const BlockStats adjacent_stats =
      AnalyzeBlock("adjacent-plus-0x1800", adjacent, image_base, false);
  const bool pair_consistent = primary_stats.nodes != 0 && adjacent_stats.nodes != 0 &&
                               primary_stats.mismatching_types == 0 &&
                               adjacent_stats.mismatching_types == 0 &&
                               primary_stats.invalid_nodes == 0 &&
                               adjacent_stats.invalid_nodes == 0;

  PIPE_LOG_INFO(
      "[UnitTableModel] pair delta=0x{:X} primary_nodes={} adjacent_nodes={} result={}",
      kUnitTableBlockBytes, primary_stats.nodes, adjacent_stats.nodes,
      pair_consistent ? "two-adjacent-six-type-blocks-consistent" : "needs-more-evidence");
  PIPE_LOG_INFO("[UnitTableModel] Validation is read-only; client/server roles remain unassigned");
}

}  // namespace d2r
