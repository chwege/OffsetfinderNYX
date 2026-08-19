#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <hde/hde64.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <dolos/pipe_log.h>

#include "reference_offset_diagnostics.h"

namespace d2r {
namespace {

struct ReferenceTarget {
  const char* name;
  std::uint32_t expected_rva;
  std::size_t xref_count = 0;
  std::size_t immediate_count = 0;
  std::size_t immediate_plus_one_count = 0;
  std::size_t image_rva_count = 0;
  std::size_t image_rva_plus_one_count = 0;
  std::size_t image_pointer_count = 0;
  std::size_t external_exec_immediate_count = 0;
  std::size_t external_exec_plus_one_count = 0;
  struct NearbyCandidate {
    std::uint32_t instruction_rva = 0;
    std::uint32_t resolved_rva = 0;
    std::int64_t delta = 0;
    std::string bytes;
    std::string context;
  };
  std::array<NearbyCandidate, 8> nearby{};
  std::size_t nearby_count = 0;
};

enum class PatternAddressMode {
  RipRelative,
  DirectDisplacement,
  MatchRva,
};

struct DynamicReferencePattern {
  const char* name;
  std::vector<int> bytes;
  std::int32_t displacement_offset;
  std::int32_t adjustment;
  PatternAddressMode mode;
  bool require_match_xref = false;
};

std::string FormatBytes(const std::uint8_t* bytes, std::size_t size) {
  std::string result;
  result.reserve(size * 3);
  char value[4]{};
  for (std::size_t i = 0; i < size; ++i) {
    std::snprintf(value, sizeof(value), "%02X", bytes[i]);
    if (!result.empty()) {
      result.push_back(' ');
    }
    result.append(value);
  }
  return result;
}

bool IsReadableRegion(const MEMORY_BASIC_INFORMATION& info) {
  return info.State == MEM_COMMIT &&
         (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
}

bool IsReadableExecutableRegion(const MEMORY_BASIC_INFORMATION& info) {
  if (!IsReadableRegion(info)) {
    return false;
  }
  const auto protection = info.Protect & 0xFF;
  return protection == PAGE_EXECUTE_READ ||
         protection == PAGE_EXECUTE_READWRITE ||
         protection == PAGE_EXECUTE_WRITECOPY;
}

void AddNearbyCandidate(ReferenceTarget* target,
                        ReferenceTarget::NearbyCandidate candidate) {
  if (target == nullptr) {
    return;
  }
  for (std::size_t i = 0; i < target->nearby_count; ++i) {
    if (target->nearby[i].instruction_rva == candidate.instruction_rva) {
      return;
    }
  }
  if (target->nearby_count < target->nearby.size()) {
    target->nearby[target->nearby_count++] = std::move(candidate);
    return;
  }

  auto distance = [](std::int64_t value) {
    return value < 0 ? -value : value;
  };
  std::size_t worst = 0;
  for (std::size_t i = 1; i < target->nearby.size(); ++i) {
    if (distance(target->nearby[i].delta) >
        distance(target->nearby[worst].delta)) {
      worst = i;
    }
  }
  if (distance(candidate.delta) < distance(target->nearby[worst].delta)) {
    target->nearby[worst] = std::move(candidate);
  }
}

bool MatchesPattern(const std::uint8_t* bytes,
                    const DynamicReferencePattern& pattern) {
  for (std::size_t i = 0; i < pattern.bytes.size(); ++i) {
    if (pattern.bytes[i] >= 0 &&
        bytes[i] != static_cast<std::uint8_t>(pattern.bytes[i])) {
      return false;
    }
  }
  return true;
}

std::size_t CountExecutableRipReferences(const std::uint8_t* module,
                                         const IMAGE_NT_HEADERS64* nt,
                                         std::uint32_t target_rva) {
  std::size_t count = 0;
  const auto image_size = nt->OptionalHeader.SizeOfImage;
  const auto* sections = IMAGE_FIRST_SECTION(nt);
  for (std::uint16_t section_index = 0;
       section_index < nt->FileHeader.NumberOfSections; ++section_index) {
    const auto& section = sections[section_index];
    if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
        section.VirtualAddress >= image_size) {
      continue;
    }

    const auto section_size = std::min<std::size_t>(
        section.Misc.VirtualSize, image_size - section.VirtualAddress);
    const auto* p = module + section.VirtualAddress;
    const auto* end = p + section_size;
    while (p + 16 <= end) {
      hde64s instruction{};
      const auto length = hde64_disasm(p, &instruction);
      if (length == 0 || (instruction.flags & F_ERROR) != 0 ||
          p + length > end) {
        ++p;
        continue;
      }

      const bool rip_relative =
          (instruction.flags & F_DISP32) != 0 && instruction.modrm_mod == 0 &&
          instruction.modrm_rm == 5 && instruction.p_67 == 0;
      if (rip_relative) {
        const auto displacement =
            static_cast<std::int32_t>(instruction.disp.disp32);
        const auto resolved_rva = static_cast<std::uint32_t>(
            p + length + displacement - module);
        if (resolved_rva == target_rva) {
          ++count;
        }
      }
      p += length;
    }
  }
  return count;
}

void LogDynamicReferencePatternScan(const std::uint8_t* module,
                                    const IMAGE_NT_HEADERS64* nt) {
  const std::array<DynamicReferencePattern, 7> patterns{{
      {"unit_table", {0x48, 0x03, 0xC7, 0x49, 0x8B, 0x8C, 0xC6}, 7, 0,
       PatternAddressMode::DirectDisplacement},
      {"ui_offset",
       {0x22, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
       0, 0x10, PatternAddressMode::MatchRva},
      {"expansion",
       {0x48, 0x8B, 0x05, -1, -1, -1, -1, 0x48, 0x85, 0xC0, 0x74, -1,
        0x80, 0x78, 0x5C, 0x01, 0x0F, 0x94, 0xC0, 0xC3},
       3, 0, PatternAddressMode::RipRelative},
      {"hover",
       {0xC6, 0x84, 0xC2, -1, -1, -1, -1, -1, 0x48, 0x8B, 0x74, 0x24,
        -1},
       3, -1, PatternAddressMode::DirectDisplacement},
      {"roster",
       {0x4C, 0x8B, 0x15, -1, -1, -1, -1, 0x49, 0x8B, 0xD2, 0x83,
        0xF9, 0xFF, 0x74, -1, 0x48, 0x85, 0xD2, 0x74, -1, 0x0F, 0x1F,
        0x40, 0x00, 0x39, 0x4A, 0x48},
       3, 0,
       PatternAddressMode::RipRelative},
      {"panels",
       {0x48, 0x89, 0x05, -1, -1, -1, -1, 0x48, 0x85, 0xDB, 0x74, 0x1E},
       3, 0, PatternAddressMode::RipRelative},
      {"keybindings",
       {-1, -1, -1, -1, -1, -1, -1, -1, 0x09, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x47, 0x61, 0x6D, 0x65, 0x20, 0x43, 0x68, 0x61, 0x74, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
       0, 0x14, PatternAddressMode::MatchRva, true},
  }};

  struct Result {
    std::uint32_t match_rva;
    std::uint32_t resolved_rva;
    std::size_t code_xrefs = 0;
  };
  const auto image_size = nt->OptionalHeader.SizeOfImage;
  const auto* sections = IMAGE_FIRST_SECTION(nt);
  PIPE_LOG_WARN(
      "[DynamicReferenceScan] begin source=semantic-patterns runtime_assignment=no");

  for (const auto& pattern : patterns) {
    std::vector<Result> results;
    for (std::uint16_t section_index = 0;
         section_index < nt->FileHeader.NumberOfSections; ++section_index) {
      const auto& section = sections[section_index];
      if ((pattern.mode != PatternAddressMode::MatchRva &&
           (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) ||
          section.VirtualAddress >= image_size) {
        continue;
      }

      const auto section_size = std::min<std::size_t>(
          section.Misc.VirtualSize, image_size - section.VirtualAddress);
      const auto* section_begin = module + section.VirtualAddress;
      const auto* section_end = section_begin + section_size;
      auto cursor = reinterpret_cast<std::uintptr_t>(section_begin);
      while (cursor < reinterpret_cast<std::uintptr_t>(section_end)) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info,
                         sizeof(info)) == 0) {
          break;
        }
        const auto region_begin = std::max(
            cursor, reinterpret_cast<std::uintptr_t>(info.BaseAddress));
        const auto region_end = std::min(
            reinterpret_cast<std::uintptr_t>(section_end),
            reinterpret_cast<std::uintptr_t>(info.BaseAddress) +
                info.RegionSize);
        if (!IsReadableRegion(info) || region_end <= region_begin) {
          cursor = region_end > cursor ? region_end
                                       : reinterpret_cast<std::uintptr_t>(section_end);
          continue;
        }

        const auto* begin = reinterpret_cast<const std::uint8_t*>(region_begin);
        const auto* end = reinterpret_cast<const std::uint8_t*>(region_end);
        for (const auto* candidate = begin;
             candidate + pattern.bytes.size() <= end; ++candidate) {
          if (!MatchesPattern(candidate, pattern)) {
            continue;
          }

          if (pattern.displacement_offset < 0 &&
              candidate - begin < -pattern.displacement_offset) {
            continue;
          }
          const auto displacement_address = candidate +
              static_cast<std::ptrdiff_t>(pattern.displacement_offset);
          if (displacement_address < begin || displacement_address + 4 > end) {
            continue;
          }
          std::int32_t displacement = 0;
          std::memcpy(&displacement, displacement_address,
                      sizeof(displacement));
          const auto match_rva = static_cast<std::uint32_t>(candidate - module);
          std::int64_t resolved = 0;
          switch (pattern.mode) {
            case PatternAddressMode::RipRelative:
              resolved = static_cast<std::int64_t>(match_rva) +
                         pattern.displacement_offset + 4 + displacement +
                         pattern.adjustment;
              break;
            case PatternAddressMode::DirectDisplacement:
              resolved = static_cast<std::int64_t>(displacement) +
                         pattern.adjustment;
              break;
            case PatternAddressMode::MatchRva:
              resolved = static_cast<std::int64_t>(match_rva) +
                         pattern.adjustment;
              break;
          }
          if (resolved < 0 || resolved > UINT32_MAX) {
            continue;
          }
          results.push_back(
              {match_rva, static_cast<std::uint32_t>(resolved), 0});
        }
        cursor = region_end;
      }
    }

    std::sort(results.begin(), results.end(), [](const Result& left,
                                                  const Result& right) {
      return left.match_rva < right.match_rva;
    });
    results.erase(std::unique(results.begin(), results.end(),
                              [](const Result& left, const Result& right) {
                                return left.match_rva == right.match_rva &&
                                       left.resolved_rva == right.resolved_rva;
                              }),
                  results.end());
    if (pattern.require_match_xref) {
      for (auto& result : results) {
        result.code_xrefs =
            CountExecutableRipReferences(module, nt, result.match_rva);
      }
      results.erase(
          std::remove_if(results.begin(), results.end(),
                         [](const Result& result) {
                           return result.code_xrefs == 0;
                         }),
          results.end());
    }
    for (const auto& result : results) {
      PIPE_LOG_WARN(
          "[DynamicReferenceScan] candidate name={} match=0x{:08X} resolved=0x{:08X} in_image={} code_xrefs={}",
          pattern.name, result.match_rva, result.resolved_rva,
          result.resolved_rva < image_size ? "yes" : "no",
          result.code_xrefs);
    }
    if (results.size() == 1) {
      PIPE_LOG_WARN(
          "[DynamicReferenceScan] summary name={} matches=1 status=UNIQUE resolved=0x{:08X}",
          pattern.name, results.front().resolved_rva);
    } else {
      PIPE_LOG_WARN(
          "[DynamicReferenceScan] summary name={} matches={} status={} resolved=n/a",
          pattern.name, results.size(),
          results.empty() ? "NOT_FOUND" : "AMBIGUOUS");
    }
  }
  PIPE_LOG_WARN("[DynamicReferenceScan] end action=none");
}

}  // namespace

void MonitorCurrentPatchReferenceTargets() {
  struct MonitorTarget {
    const char* name;
    std::uint32_t rva;
    std::vector<std::uint8_t> previous;
    std::size_t changes = 0;
    std::size_t logged = 0;
  };

  std::array<MonitorTarget, 4> targets{{
      {"ui_control", 0x01EC9120},
      {"hover", 0x01DFB080},
      {"panels", 0x01E11E40},
      {"keybindings", 0x019D2420},
  }};
  constexpr std::size_t kBefore = 0x100;
  constexpr std::size_t kWindowSize = 0x400;
  constexpr int kSeconds = 30;
  constexpr std::size_t kMaxLoggedChanges = 96;

  const auto module_base = reinterpret_cast<std::uintptr_t>(
      GetModuleHandleW(nullptr));
  if (module_base == 0) {
    PIPE_LOG_WARN("[ReferenceMonitor] skipped: module base unavailable");
    return;
  }

  PIPE_LOG_WARN(
      "[ReferenceMonitor] begin duration={}s window_before=0x{:X} "
      "window_size=0x{:X} mode=read-only-bootstrap",
      kSeconds, kBefore, kWindowSize);
  for (auto& target : targets) {
    target.previous.resize(kWindowSize);
    const auto start = module_base + target.rva - kBefore;
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(start), &info,
                     sizeof(info)) == 0 || !IsReadableRegion(info) ||
        start + kWindowSize >
            reinterpret_cast<std::uintptr_t>(info.BaseAddress) +
                info.RegionSize) {
      target.previous.clear();
      PIPE_LOG_WARN(
          "[ReferenceMonitor] baseline name={} rva=0x{:08X} readable=no",
          target.name, target.rva);
      continue;
    }
    std::memcpy(target.previous.data(), reinterpret_cast<const void*>(start),
                kWindowSize);
    PIPE_LOG_WARN(
        "[ReferenceMonitor] baseline name={} rva=0x{:08X} readable=yes "
        "protect=0x{:X}",
        target.name, target.rva, info.Protect);
  }

  for (int second = 1; second <= kSeconds; ++second) {
    Sleep(1000);
    for (auto& target : targets) {
      if (target.previous.empty()) {
        continue;
      }
      const auto start = module_base + target.rva - kBefore;
      MEMORY_BASIC_INFORMATION info{};
      if (VirtualQuery(reinterpret_cast<const void*>(start), &info,
                       sizeof(info)) == 0 || !IsReadableRegion(info) ||
          start + kWindowSize >
              reinterpret_cast<std::uintptr_t>(info.BaseAddress) +
                  info.RegionSize) {
        continue;
      }
      const auto* current = reinterpret_cast<const std::uint8_t*>(start);
      for (std::size_t i = 0; i < kWindowSize; ++i) {
        if (current[i] == target.previous[i]) {
          continue;
        }
        ++target.changes;
        if (target.logged < kMaxLoggedChanges) {
          PIPE_LOG_WARN(
              "[ReferenceMonitor] change second={} name={} "
              "location=0x{:08X} relative={:+#x} old=0x{:02X} new=0x{:02X}",
              second, target.name,
              static_cast<std::uint32_t>(target.rva - kBefore + i),
              static_cast<std::int64_t>(i) -
                  static_cast<std::int64_t>(kBefore),
              target.previous[i], current[i]);
          ++target.logged;
        }
        target.previous[i] = current[i];
      }
    }
  }

  for (const auto& target : targets) {
    PIPE_LOG_WARN(
        "[ReferenceMonitor] summary name={} rva=0x{:08X} changes={} "
        "logged={} result={}",
        target.name, target.rva, target.changes, target.logged,
        target.changes != 0 ? "changed" : "stable");
  }
  PIPE_LOG_WARN("[ReferenceMonitor] end action=none");
}

void LogCurrentPatchReferenceDiagnostics() {
  std::array<ReferenceTarget, 7> targets{{
      {"unit_table", 0x01EB9430},
      {"ui_offset", 0x01EC9120},
      {"expansion", 0x01E0C508},
      {"hover", 0x01DFB080},
      {"roster", 0x01ECF748},
      {"panels", 0x01E11E40},
      {"keybindings", 0x019D2420},
  }};

  const auto module = reinterpret_cast<const std::uint8_t*>(
      GetModuleHandleW(nullptr));
  if (module == nullptr) {
    PIPE_LOG_WARN(
        "[ReferenceOffsets] skipped: main module base is unavailable");
    return;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    PIPE_LOG_WARN("[ReferenceOffsets] skipped: invalid DOS header");
    return;
  }
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
      module + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    PIPE_LOG_WARN("[ReferenceOffsets] skipped: invalid NT header");
    return;
  }

  PIPE_LOG_WARN(
      "[ReferenceOffsets] begin mode=current-patch-bootstrap-only "
      "runtime_assignment=no image_size=0x{:08X}",
      nt->OptionalHeader.SizeOfImage);

  LogDynamicReferencePatternScan(module, nt);

  const auto* sections = IMAGE_FIRST_SECTION(nt);
  for (std::uint16_t section_index = 0;
       section_index < nt->FileHeader.NumberOfSections; ++section_index) {
    const auto& section = sections[section_index];
    if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }

    const auto section_begin = reinterpret_cast<std::uintptr_t>(module) +
                               section.VirtualAddress;
    const auto section_end =
        section_begin + std::min<std::size_t>(
                            section.Misc.VirtualSize,
                            nt->OptionalHeader.SizeOfImage -
                                section.VirtualAddress);
    auto cursor = section_begin;
    while (cursor < section_end) {
      MEMORY_BASIC_INFORMATION info{};
      if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info,
                       sizeof(info)) == 0) {
        break;
      }
      const auto region_begin = std::max(
          cursor, reinterpret_cast<std::uintptr_t>(info.BaseAddress));
      const auto region_end = std::min(
          section_end, reinterpret_cast<std::uintptr_t>(info.BaseAddress) +
                           info.RegionSize);
      if (!IsReadableRegion(info) || region_end <= region_begin) {
        cursor = region_end > cursor ? region_end : section_end;
        continue;
      }

      const auto* p = reinterpret_cast<const std::uint8_t*>(region_begin);
      const auto* end = reinterpret_cast<const std::uint8_t*>(region_end);
      while (p + 16 <= end) {
        hde64s instruction{};
        const auto length = hde64_disasm(p, &instruction);
        if (length == 0 || (instruction.flags & F_ERROR) != 0 ||
            p + length > end) {
          ++p;
          continue;
        }

        const bool rip_relative =
            (instruction.flags & F_DISP32) != 0 &&
            instruction.modrm_mod == 0 && instruction.modrm_rm == 5 &&
            instruction.p_67 == 0;
        if (rip_relative) {
          const auto displacement =
              static_cast<std::int32_t>(instruction.disp.disp32);
          const auto target_address =
              reinterpret_cast<std::uintptr_t>(p + length) + displacement;
          const auto target_rva = static_cast<std::uint32_t>(
              target_address - reinterpret_cast<std::uintptr_t>(module));
          for (auto& target : targets) {
            const auto delta =
                static_cast<std::int64_t>(target_rva) -
                static_cast<std::int64_t>(target.expected_rva);
            const auto distance = delta < 0 ? -delta : delta;
            if (delta != 0 && distance <= 0x4000) {
              const auto* context_begin =
                  p >= reinterpret_cast<const std::uint8_t*>(region_begin) + 12
                      ? p - 12
                      : p;
              const auto* context_end = std::min(end, p + length + 20);
              AddNearbyCandidate(
                  &target,
                  {static_cast<std::uint32_t>(p - module), target_rva, delta,
                   FormatBytes(p, length),
                   FormatBytes(
                       context_begin,
                       static_cast<std::size_t>(context_end - context_begin))});
            }
            if (target_rva != target.expected_rva) {
              continue;
            }

            ++target.xref_count;
            const auto* context_begin =
                p >= reinterpret_cast<const std::uint8_t*>(region_begin) + 12
                    ? p - 12
                    : p;
            const auto* context_end =
                std::min(end, p + length + 20);
            PIPE_LOG_WARN(
                "[ReferenceOffsets] xref name={} target=0x{:08X} "
                "instruction=0x{:08X} length={} opcode=0x{:02X} "
                "modrm=0x{:02X} bytes={} context={}",
                target.name, target.expected_rva,
                static_cast<std::uint32_t>(
                    p - module),
                length, instruction.opcode, instruction.modrm,
                FormatBytes(p, length),
                FormatBytes(context_begin,
                            static_cast<std::size_t>(context_end -
                                                     context_begin)));
          }
        }

        for (std::size_t byte_offset = 0; byte_offset + 4 <= length;
             ++byte_offset) {
          std::uint32_t value = 0;
          std::memcpy(&value, p + byte_offset, sizeof(value));
          for (auto& target : targets) {
            const bool exact = value == target.expected_rva;
            const bool plus_one =
                value != 0 && value - 1 == target.expected_rva;
            if (!exact && !plus_one) {
              continue;
            }

            auto& count = exact ? target.immediate_count
                                : target.immediate_plus_one_count;
            ++count;
            if (count > 8) {
              continue;
            }
            const auto* context_begin =
                p >= reinterpret_cast<const std::uint8_t*>(region_begin) + 12
                    ? p - 12
                    : p;
            const auto* context_end = std::min(end, p + length + 20);
            PIPE_LOG_WARN(
                "[ReferenceOffsets] immediate name={} expected=0x{:08X} "
                "encoded=0x{:08X} adjustment={} instruction=0x{:08X} "
                "byte_offset={} bytes={} context={}",
                target.name, target.expected_rva, value,
                exact ? "none" : "minus-one",
                static_cast<std::uint32_t>(p - module), byte_offset,
                FormatBytes(p, length),
                FormatBytes(context_begin,
                            static_cast<std::size_t>(context_end -
                                                     context_begin)));
          }
        }
        p += length;
      }
      cursor = region_end;
    }
  }

  const auto module_base = reinterpret_cast<std::uintptr_t>(module);
  const auto image_end = module_base + nt->OptionalHeader.SizeOfImage;
  auto cursor = module_base;
  while (cursor < image_end) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info,
                     sizeof(info)) == 0) {
      break;
    }
    const auto region_begin = std::max(
        cursor, reinterpret_cast<std::uintptr_t>(info.BaseAddress));
    const auto region_end = std::min(
        image_end, reinterpret_cast<std::uintptr_t>(info.BaseAddress) +
                       info.RegionSize);
    if (!IsReadableRegion(info) || region_end <= region_begin) {
      cursor = region_end > cursor ? region_end : image_end;
      continue;
    }

    const auto* bytes = reinterpret_cast<const std::uint8_t*>(region_begin);
    const auto size = static_cast<std::size_t>(region_end - region_begin);
    for (std::size_t offset = 0; offset + 4 <= size; ++offset) {
      std::uint32_t value32 = 0;
      std::memcpy(&value32, bytes + offset, sizeof(value32));
      std::uint64_t value64 = 0;
      if (offset + 8 <= size) {
        std::memcpy(&value64, bytes + offset, sizeof(value64));
      }

      for (auto& target : targets) {
        const bool exact_rva = value32 == target.expected_rva;
        const bool plus_one =
            value32 != 0 && value32 - 1 == target.expected_rva;
        const bool pointer =
            value64 == module_base + target.expected_rva;
        if (!exact_rva && !plus_one && !pointer) {
          continue;
        }

        auto* count = pointer
                          ? &target.image_pointer_count
                          : (exact_rva ? &target.image_rva_count
                                       : &target.image_rva_plus_one_count);
        ++*count;
        if (*count > 8) {
          continue;
        }
        const auto context_begin = offset > 12 ? offset - 12 : 0;
        const auto context_end = std::min(size, offset + 20);
        PIPE_LOG_WARN(
            "[ReferenceOffsets] image-value name={} kind={} "
            "location=0x{:08X} value=0x{:X} context={}",
            target.name,
            pointer ? "absolute-pointer"
                    : (exact_rva ? "rva" : "rva-plus-one"),
            static_cast<std::uint32_t>(region_begin + offset - module_base),
            pointer ? value64 : value32,
            FormatBytes(bytes + context_begin, context_end - context_begin));
      }
    }
    cursor = region_end;
  }

  SYSTEM_INFO system_info{};
  GetSystemInfo(&system_info);
  auto process_cursor = reinterpret_cast<std::uintptr_t>(
      system_info.lpMinimumApplicationAddress);
  const auto process_end = reinterpret_cast<std::uintptr_t>(
      system_info.lpMaximumApplicationAddress);
  while (process_cursor < process_end) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(process_cursor), &info,
                     sizeof(info)) == 0) {
      break;
    }
    const auto region_begin =
        reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    const auto region_end = region_begin + info.RegionSize;
    const bool inside_main_image =
        region_begin < image_end && region_end > module_base;
    if (!inside_main_image && IsReadableExecutableRegion(info) &&
        info.Type == MEM_PRIVATE && info.RegionSize <= 0x20000000) {
      const auto* bytes = reinterpret_cast<const std::uint8_t*>(region_begin);
      const auto size = static_cast<std::size_t>(info.RegionSize);
      for (std::size_t offset = 0; offset + 4 <= size; ++offset) {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes + offset, sizeof(value));
        for (auto& target : targets) {
          const bool exact = value == target.expected_rva;
          const bool plus_one =
              value != 0 && value - 1 == target.expected_rva;
          if (!exact && !plus_one) {
            continue;
          }
          auto& count = exact ? target.external_exec_immediate_count
                              : target.external_exec_plus_one_count;
          ++count;
          if (count > 8) {
            continue;
          }
          const auto context_begin = offset > 16 ? offset - 16 : 0;
          const auto context_end = std::min(size, offset + 24);
          PIPE_LOG_WARN(
              "[ReferenceOffsets] external-exec-immediate name={} "
              "expected=0x{:08X} encoded=0x{:08X} adjustment={} "
              "address={:p} allocation_base={:p} region_offset=0x{:X} "
              "protect=0x{:X} context={}",
              target.name, target.expected_rva, value,
              exact ? "none" : "minus-one",
              reinterpret_cast<const void*>(region_begin + offset),
              info.AllocationBase, offset, info.Protect,
              FormatBytes(bytes + context_begin,
                          context_end - context_begin));
        }
      }
    }
    if (region_end <= process_cursor) {
      break;
    }
    process_cursor = region_end;
  }

  for (const auto& target : targets) {
    const auto target_address = module_base + target.expected_rva;
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<const void*>(target_address), &info,
                     sizeof(info)) == 0 || !IsReadableRegion(info)) {
      PIPE_LOG_WARN(
          "[ReferenceOffsets] target-memory name={} rva=0x{:08X} "
          "readable=no",
          target.name, target.expected_rva);
      continue;
    }
    const auto readable_end =
        reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
    const auto snapshot_size = static_cast<std::size_t>(
        std::min<std::uintptr_t>(64, readable_end - target_address));
    PIPE_LOG_WARN(
        "[ReferenceOffsets] target-memory name={} rva=0x{:08X} "
        "readable=yes protect=0x{:X} bytes={}",
        target.name, target.expected_rva, info.Protect,
        FormatBytes(reinterpret_cast<const std::uint8_t*>(target_address),
                    snapshot_size));
  }

  for (const auto& target : targets) {
    PIPE_LOG_WARN(
        "[ReferenceOffsets] summary name={} expected=0x{:08X} "
        "executable_xrefs={} immediates={} immediates_plus_one={} "
        "image_rvas={} image_rvas_plus_one={} image_pointers={} "
        "external_exec_immediates={} external_exec_plus_one={} "
        "result={} runtime_assignment=no",
        target.name, target.expected_rva, target.xref_count,
        target.immediate_count, target.immediate_plus_one_count,
        target.image_rva_count, target.image_rva_plus_one_count,
        target.image_pointer_count,
        target.external_exec_immediate_count,
        target.external_exec_plus_one_count,
        target.xref_count != 0 ? "xref-found" : "no-readable-xref");
    if (target.xref_count == 0) {
      auto nearby = target.nearby;
      auto distance = [](std::int64_t value) {
        return value < 0 ? -value : value;
      };
      std::sort(
          nearby.begin(), nearby.begin() + target.nearby_count,
          [&](const ReferenceTarget::NearbyCandidate& left,
              const ReferenceTarget::NearbyCandidate& right) {
            return distance(left.delta) < distance(right.delta);
          });
      for (std::size_t i = 0; i < target.nearby_count; ++i) {
        const auto& candidate = nearby[i];
        PIPE_LOG_WARN(
            "[ReferenceOffsets] nearby name={} expected=0x{:08X} "
            "resolved=0x{:08X} delta={:+#x} instruction=0x{:08X} "
            "bytes={} context={}",
            target.name, target.expected_rva, candidate.resolved_rva,
            candidate.delta, candidate.instruction_rva, candidate.bytes,
            candidate.context);
      }
    }
  }
  PIPE_LOG_WARN("[ReferenceOffsets] end action=none");
}

}  // namespace d2r
