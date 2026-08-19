#include "retcheck_bypass.h"

#include "offsets.h"

#include <Windows.h>
#include <dolos/pipe_log.h>
#include <nyx/util.h>
#include <algorithm>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <vector>

namespace d2r {

static std::vector<uint32_t> s_patched_array;
static RetCheckData::ReturnAddresses s_replacement_table;

static uintptr_t s_original_address_table_ptr = 0;
static uint64_t s_original_image_base = 0;
static uint64_t s_original_image_size = 0;
static std::atomic<DWORD> s_swap_owner_thread_id{0};
static thread_local uint32_t s_thread_swap_depth = 0;

struct RetCheckProtectedLayout {
  uint8_t* constants;
  void* unknown1;
  void* unknown2;
  uint8_t* protected_code_begin;
  uint8_t* protected_code_end;
  RetCheckData::ImageData* range;
  void* unknown6;
  uint64_t unknown7;
};

static const uint8_t sbox_30[16] = {
    0x05, 0x01, 0x0D, 0x09, 0x04, 0x02, 0x0B, 0x03, 0x0A, 0x07, 0x0C, 0x0E, 0x00, 0x06, 0x08, 0x0F};

static const uint8_t sbox_10[16] = {
    0x0C, 0x01, 0x05, 0x07, 0x04, 0x00, 0x0D, 0x09, 0x0E, 0x03, 0x08, 0x06, 0x0A, 0x02, 0x0B, 0x0F};

static uint32_t apply_sbox(uint32_t val, const uint8_t* sbox) {
  uint32_t result = 0;
  for (int i = 0; i < 4; i++) {
    uint8_t byte_val = (val >> (i * 8)) & 0xFF;
    uint8_t low_nibble = byte_val & 0xF;
    uint8_t high_nibble = (byte_val >> 4) & 0xF;
    uint8_t new_low = sbox[low_nibble];
    uint8_t new_high = sbox[high_nibble];
    uint8_t new_byte = new_low | (new_high << 4);
    result |= (new_byte << (i * 8));
  }
  return result;
}

static uint32_t obfuscate_return_address(uintptr_t retaddr, uintptr_t image_base, uint32_t constant) {
  uint32_t offset = static_cast<uint32_t>(retaddr - image_base);
  uint32_t v21 = offset ^ 0x95BE951C;
  uint32_t transformed = apply_sbox(v21, sbox_30);
  v21 = (0x23CC70 + transformed) ^ 0x7F8AA577;
  v21 = std::rotl(v21, 7);
  uint32_t v20 = std::rotr(v21, 7);
  uint32_t v8 = (v20 ^ constant) - 0x23CC70;
  v20 = apply_sbox(v8, sbox_10);
  uint32_t v9 = v20 ^ 0x95BE951C;
  return v9;
}

static uint32_t deobfuscate_return_address(uint32_t obfuscated, uint32_t constant) {
  uint32_t v20 = obfuscated ^ 0x95BE951C;
  uint32_t v8 = apply_sbox(v20, sbox_30);  // inv(sbox_10) = sbox_30
  uint32_t v21 = (v8 + 0x23CC70) ^ constant;
  uint32_t transformed = (v21 ^ 0x7F8AA577) - 0x23CC70;
  uint32_t original_v21 = apply_sbox(transformed, sbox_10);  // inv(sbox_30) = sbox_10
  return original_v21 ^ 0x95BE951C;
}

static uint32_t get_constant_at_index(uint8_t* constants, size_t index) {
  return *reinterpret_cast<uint32_t*>(&constants[index]);
}

static int32_t ReadI32Unaligned(const uint8_t* address) {
  int32_t value = 0;
  std::memcpy(&value, address, sizeof(value));
  return value;
}

static std::vector<uint32_t> CollectDirectCallReturnOffsets(uintptr_t image_base, uint32_t image_size, uint32_t target_rva) {
  std::vector<uint32_t> result;
  if (image_base == 0 || image_size < sizeof(IMAGE_DOS_HEADER)) {
    return result;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
      static_cast<uint32_t>(dos->e_lfanew) > image_size - sizeof(IMAGE_NT_HEADERS)) {
    return result;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.NumberOfSections == 0) {
    return result;
  }

  const uint32_t image_limit = std::min<uint32_t>(image_size, nt->OptionalHeader.SizeOfImage);
  const uintptr_t target_va = image_base + target_rva;
  const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
  for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
      continue;
    }

    const uint32_t section_rva = section[i].VirtualAddress;
    const uint32_t section_size = std::max(section[i].Misc.VirtualSize, section[i].SizeOfRawData);
    if (section_size < 5 || section_rva >= image_limit) {
      continue;
    }

    const uint32_t bounded_size = std::min<uint32_t>(section_size, image_limit - section_rva);
    const auto* begin = reinterpret_cast<const uint8_t*>(image_base + section_rva);
    const auto* end = begin + bounded_size - 5;
    for (const uint8_t* cursor = begin; cursor <= end; ++cursor) {
      if (*cursor != 0xE8) {
        continue;
      }

      const uintptr_t next = reinterpret_cast<uintptr_t>(cursor + 5);
      const uintptr_t target = static_cast<uintptr_t>(static_cast<intptr_t>(next) + ReadI32Unaligned(cursor + 1));
      if (target == target_va) {
        result.push_back(static_cast<uint32_t>(next - image_base));
      }
    }
  }

  std::sort(result.begin(), result.end());
  result.erase(std::unique(result.begin(), result.end()), result.end());
  return result;
}

static std::string FormatHexSample(const std::vector<uint32_t>& values, size_t limit) {
  std::ostringstream stream;
  stream << std::uppercase << std::hex << std::setfill('0');
  const size_t count = std::min(values.size(), limit);
  for (size_t i = 0; i < count; ++i) {
    if (i != 0) {
      stream << ' ';
    }
    stream << "0x" << std::setw(8) << values[i];
  }
  return stream.str();
}

static bool IsReadableRangeLocal(const void* address, size_t size) {
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

  const auto start = reinterpret_cast<uintptr_t>(address);
  const auto region_start = reinterpret_cast<uintptr_t>(info.BaseAddress);
  const auto region_end = region_start + info.RegionSize;
  return start >= region_start && size <= region_end - start;
}

bool RetcheckBypass::ProbeProtectedLayout(void* layout_block) {
#if defined(NYX_D2R_SAFE_DIAGNOSTIC_MODE) && defined(NYX_D2R_SAFE_RETCHECK_PROBE)
  if (layout_block == nullptr || !IsReadableRangeLocal(layout_block, sizeof(RetCheckProtectedLayout))) {
    PIPE_LOG_WARN("RetcheckBypass: protected-layout dry-run skipped: layout block is not readable ({:p})", layout_block);
    return false;
  }

  RetCheckProtectedLayout layout{};
  std::memcpy(&layout, layout_block, sizeof(layout));

  const auto begin_value = reinterpret_cast<uintptr_t>(layout.protected_code_begin);
  const auto end_value = reinterpret_cast<uintptr_t>(layout.protected_code_end);
  const bool constants_ok = IsReadableRangeLocal(layout.constants, kConstantOffset + sizeof(uint32_t));
  const bool range_ok = IsReadableRangeLocal(layout.range, sizeof(RetCheckData::ImageData)) &&
                        layout.range->base != nullptr && layout.range->size >= 0x100000 &&
                        layout.range->size <= 0x80000000;
  const bool table_shape_ok = layout.protected_code_begin != nullptr && layout.protected_code_end != nullptr &&
                              end_value > begin_value &&
                              ((end_value - begin_value) % sizeof(uint32_t)) == 0 &&
                              ((begin_value % sizeof(uint32_t)) == 0) && ((end_value % sizeof(uint32_t)) == 0);

  if (!constants_ok || !range_ok || !table_shape_ok) {
    PIPE_LOG_WARN(
        "RetcheckBypass: protected-layout dry-run rejected constants_ok={} range_ok={} table_shape_ok={} constants={:p} table_begin={:p} table_end={:p} range={:p}",
        constants_ok ? "yes" : "no",
        range_ok ? "yes" : "no",
        table_shape_ok ? "yes" : "no",
        static_cast<void*>(layout.constants),
        static_cast<void*>(layout.protected_code_begin),
        static_cast<void*>(layout.protected_code_end),
        static_cast<void*>(layout.range));
    return false;
  }

  const auto byte_count = end_value - begin_value;
  const auto entry_count = static_cast<uint32_t>(byte_count / sizeof(uint32_t));
  if (entry_count == 0 || entry_count > 0x100000) {
    PIPE_LOG_WARN("RetcheckBypass: protected-layout dry-run rejected invalid entry count {}", entry_count);
    return false;
  }

  MEMORY_BASIC_INFORMATION before{};
  if (VirtualQuery(layout.protected_code_begin, &before, sizeof(before)) == 0) {
    PIPE_LOG_WARN("RetcheckBypass: protected-layout dry-run skipped: table VirtualQuery failed gle={}", GetLastError());
    return false;
  }

  const bool table_was_readable = IsReadableRangeLocal(layout.protected_code_begin, byte_count);
  DWORD old_protect = 0;
  bool changed_protection = false;
  if (!table_was_readable &&
      !VirtualProtect(layout.protected_code_begin, byte_count, PAGE_READONLY, &old_protect)) {
    PIPE_LOG_WARN("RetcheckBypass: protected-layout dry-run skipped: table VirtualProtect failed gle={} begin={:p} bytes=0x{:X}",
                  GetLastError(),
                  static_cast<void*>(layout.protected_code_begin),
                  static_cast<unsigned int>(byte_count));
    return false;
  }
  if (!table_was_readable) {
    changed_protection = true;
  } else {
    old_protect = before.Protect;
  }

  std::vector<uint32_t> copied(entry_count);
  std::memcpy(copied.data(), layout.protected_code_begin, byte_count);

  if (changed_protection) {
    DWORD ignored = 0;
    const bool restored =
        VirtualProtect(layout.protected_code_begin, byte_count, old_protect, &ignored) != FALSE;
    if (!restored) {
      PIPE_LOG_ERROR("RetcheckBypass: protected-layout dry-run restore_failed gle={}", GetLastError());
      return false;
    }
  }

  constexpr DWORD kExecutableProtection =
      PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
  if ((before.Protect & kExecutableProtection) != 0) {
    PIPE_LOG_WARN(
        "RetcheckBypass: V2 qword3..qword4 is executable verifier code, not a legacy return-address table; begin={:p} end={:p} bytes=0x{:X} protect=0x{:X} dword_sample={}",
        static_cast<void*>(layout.protected_code_begin),
        static_cast<void*>(layout.protected_code_end),
        static_cast<unsigned int>(byte_count),
        before.Protect,
        FormatHexSample(copied, 16));
    PIPE_LOG_WARN(
        "RetcheckBypass: legacy decoder and table rewrite are not applicable to the V2 verifier code range; activation remains disabled");
    return false;
  }

  const uint32_t constant = get_constant_at_index(layout.constants, kConstantOffset);
  const auto image_base = reinterpret_cast<uintptr_t>(layout.range->base);
  const auto image_size = static_cast<uint64_t>(layout.range->size);
  constexpr uint32_t kRetcheckHelperRva = 0x00064640;
  const auto known_return_offsets =
      CollectDirectCallReturnOffsets(image_base, static_cast<uint32_t>(std::min<uint64_t>(image_size, 0xFFFFFFFFull)), kRetcheckHelperRva);
  std::vector<uint32_t> sorted_raw = copied;
  std::sort(sorted_raw.begin(), sorted_raw.end());
  const uint32_t raw_first = copied.empty() ? 0 : copied.front();
  const uint32_t raw_second = copied.size() > 1 ? copied[1] : 0;
  const uint32_t raw_last = copied.empty() ? 0 : copied.back();
  size_t int3_like_entries = 0;
  for (uint32_t value : copied) {
    if (value == 0xCCCCCCCCu) {
      ++int3_like_entries;
    }
  }

  struct ConstantEvaluation {
    size_t index = 0;
    uint32_t constant = 0;
    size_t decoded_in_range = 0;
    size_t nonzero_offsets = 0;
    uint32_t min_offset = std::numeric_limits<uint32_t>::max();
    uint32_t max_offset = 0;
    uint32_t first_offset = 0;
    uint32_t second_offset = 0;
    uint32_t last_offset = 0;
    size_t known_return_decoded_matches = 0;
    size_t known_return_encoded_matches_image_base = 0;
    size_t known_return_encoded_matches_zero_base = 0;
    bool replacement_preview_ok = false;
  };

  const auto evaluate_constant = [&](size_t index) {
    ConstantEvaluation result{};
    result.index = index;
    result.constant = get_constant_at_index(layout.constants, index);
    std::vector<uint32_t> replacement_preview;
    replacement_preview.reserve(copied.size());

    for (size_t i = 0; i < copied.size(); ++i) {
      const uint32_t offset = deobfuscate_return_address(copied[i], result.constant);
      if (i == 0) {
        result.first_offset = offset;
      } else if (i == 1) {
        result.second_offset = offset;
      }
      if (i == copied.size() - 1) {
        result.last_offset = offset;
      }
      if (offset != 0) {
        ++result.nonzero_offsets;
      }
      if (offset < image_size) {
        ++result.decoded_in_range;
        result.min_offset = std::min(result.min_offset, offset);
        result.max_offset = std::max(result.max_offset, offset);
        if (std::binary_search(known_return_offsets.begin(), known_return_offsets.end(), offset)) {
          ++result.known_return_decoded_matches;
        }
        replacement_preview.push_back(obfuscate_return_address(image_base + offset, 0, result.constant));
      }
    }

    for (uint32_t known_offset : known_return_offsets) {
      const uint32_t encoded_with_image_base =
          obfuscate_return_address(image_base + known_offset, image_base, result.constant);
      const uint32_t encoded_with_zero_base = obfuscate_return_address(image_base + known_offset, 0, result.constant);
      if (std::binary_search(sorted_raw.begin(), sorted_raw.end(), encoded_with_image_base)) {
        ++result.known_return_encoded_matches_image_base;
      }
      if (std::binary_search(sorted_raw.begin(), sorted_raw.end(), encoded_with_zero_base)) {
        ++result.known_return_encoded_matches_zero_base;
      }
    }

    std::sort(replacement_preview.begin(), replacement_preview.end());
    result.replacement_preview_ok = replacement_preview.size() == copied.size();
    return result;
  };

  const ConstantEvaluation legacy_evaluation = evaluate_constant(kConstantOffset);

  MEMORY_BASIC_INFORMATION constants_region{};
  size_t constants_readable_bytes = 0;
  if (VirtualQuery(layout.constants, &constants_region, sizeof(constants_region)) != 0 &&
      constants_region.State == MEM_COMMIT && (constants_region.Protect & PAGE_GUARD) == 0 &&
      (constants_region.Protect & PAGE_NOACCESS) == 0) {
    const auto constants_start = reinterpret_cast<uintptr_t>(layout.constants);
    const auto region_start = reinterpret_cast<uintptr_t>(constants_region.BaseAddress);
    const auto region_end = region_start + constants_region.RegionSize;
    if (constants_start >= region_start && constants_start < region_end) {
      constants_readable_bytes = std::min<size_t>(region_end - constants_start, 0x400);
    }
  }

  std::vector<ConstantEvaluation> best_constants;
  if (constants_readable_bytes >= sizeof(uint32_t)) {
    for (size_t index = 0; index + sizeof(uint32_t) <= constants_readable_bytes; ++index) {
      ConstantEvaluation candidate = evaluate_constant(index);
      best_constants.push_back(candidate);
      std::sort(best_constants.begin(), best_constants.end(), [](const auto& a, const auto& b) {
        if (a.known_return_decoded_matches != b.known_return_decoded_matches) {
          return a.known_return_decoded_matches > b.known_return_decoded_matches;
        }
        if (a.known_return_encoded_matches_image_base != b.known_return_encoded_matches_image_base) {
          return a.known_return_encoded_matches_image_base > b.known_return_encoded_matches_image_base;
        }
        if (a.known_return_encoded_matches_zero_base != b.known_return_encoded_matches_zero_base) {
          return a.known_return_encoded_matches_zero_base > b.known_return_encoded_matches_zero_base;
        }
        if (a.decoded_in_range != b.decoded_in_range) {
          return a.decoded_in_range > b.decoded_in_range;
        }
        if (a.replacement_preview_ok != b.replacement_preview_ok) {
          return a.replacement_preview_ok && !b.replacement_preview_ok;
        }
        return a.index < b.index;
      });
      if (best_constants.size() > 5) {
        best_constants.pop_back();
      }
    }
  }

  PIPE_LOG_WARN(
      "RetcheckBypass: protected-layout dry-run entries={} table_was_readable={} changed_protection={} raw_first=0x{:08X} raw_second=0x{:08X} raw_last=0x{:08X} int3_like_entries={} legacy_constant_index=0x{:X} legacy_constant=0x{:08X} image_base={:p} image_size=0x{:X} decoded_in_range={}/{} nonzero_offsets={} min_offset=0x{:08X} max_offset=0x{:08X} first_offset=0x{:08X} second_offset=0x{:08X} last_offset=0x{:08X} replacement_preview_ok={} old_protect=0x{:X} restored={} constants_sweep_bytes=0x{:X}",
      entry_count,
      table_was_readable ? "yes" : "no",
      changed_protection ? "yes" : "no",
      raw_first,
      raw_second,
      raw_last,
      int3_like_entries,
      kConstantOffset,
      legacy_evaluation.constant,
      reinterpret_cast<void*>(image_base),
      image_size,
      legacy_evaluation.decoded_in_range,
      copied.size(),
      legacy_evaluation.nonzero_offsets,
      legacy_evaluation.min_offset == std::numeric_limits<uint32_t>::max() ? 0 : legacy_evaluation.min_offset,
      legacy_evaluation.max_offset,
      legacy_evaluation.first_offset,
      legacy_evaluation.second_offset,
      legacy_evaluation.last_offset,
      legacy_evaluation.replacement_preview_ok ? "yes" : "no",
      old_protect,
      changed_protection ? "yes" : "not-needed",
      constants_readable_bytes);
  PIPE_LOG_WARN("RetcheckBypass: protected-layout table raw-sample count={} values={}",
                std::min<size_t>(copied.size(), 16),
                FormatHexSample(copied, 16));
  PIPE_LOG_WARN("RetcheckBypass: protected-layout known-helper-calls helper=0x{:06X} returns={} sample={}",
                kRetcheckHelperRva,
                known_return_offsets.size(),
                FormatHexSample(known_return_offsets, 16));
  for (size_t i = 0; i < best_constants.size(); ++i) {
    const auto& candidate = best_constants[i];
    PIPE_LOG_WARN(
        "RetcheckBypass: protected-layout constant-sweep rank={} index=0x{:X} constant=0x{:08X} decoded_in_range={}/{} known_return_decoded_matches={} known_return_encoded_matches_image_base={} known_return_encoded_matches_zero_base={} nonzero_offsets={} min_offset=0x{:08X} max_offset=0x{:08X} first_offset=0x{:08X} second_offset=0x{:08X} last_offset=0x{:08X} replacement_preview_ok={}",
        i + 1,
        candidate.index,
        candidate.constant,
        candidate.decoded_in_range,
        copied.size(),
        candidate.known_return_decoded_matches,
        candidate.known_return_encoded_matches_image_base,
        candidate.known_return_encoded_matches_zero_base,
        candidate.nonzero_offsets,
        candidate.min_offset == std::numeric_limits<uint32_t>::max() ? 0 : candidate.min_offset,
        candidate.max_offset,
        candidate.first_offset,
        candidate.second_offset,
        candidate.last_offset,
        candidate.replacement_preview_ok ? "yes" : "no");
  }
  const bool best_preview_ok = !best_constants.empty() && best_constants.front().replacement_preview_ok;
  const size_t best_decoded_in_range =
      best_constants.empty() ? legacy_evaluation.decoded_in_range : best_constants.front().decoded_in_range;
  const uint32_t best_constant = best_constants.empty() ? legacy_evaluation.constant : best_constants.front().constant;
  const size_t best_constant_index = best_constants.empty() ? kConstantOffset : best_constants.front().index;
  if (!legacy_evaluation.replacement_preview_ok && !best_preview_ok) {
    PIPE_LOG_WARN(
        "RetcheckBypass: V2 activation blocker: legacy return-table decoder mismatch best_index=0x{:X} best_constant=0x{:08X} best_decoded_in_range={}/{} legacy_decoded_in_range={}/{} best_known_decoded_matches={} best_known_encoded_image_base={} best_known_encoded_zero_base={}; old table rewrite remains disabled",
        best_constant_index,
        best_constant,
        best_decoded_in_range,
        copied.size(),
        legacy_evaluation.decoded_in_range,
        copied.size(),
        best_constants.empty() ? legacy_evaluation.known_return_decoded_matches
                               : best_constants.front().known_return_decoded_matches,
        best_constants.empty() ? legacy_evaluation.known_return_encoded_matches_image_base
                               : best_constants.front().known_return_encoded_matches_image_base,
        best_constants.empty() ? legacy_evaluation.known_return_encoded_matches_zero_base
                               : best_constants.front().known_return_encoded_matches_zero_base);
  } else {
    PIPE_LOG_WARN(
        "RetcheckBypass: V2 dry-run replacement preview is structurally plausible; activation still requires explicit V2-safe swap implementation");
  }
  return legacy_evaluation.replacement_preview_ok || (!best_constants.empty() && best_constants.front().replacement_preview_ok);
#else
  (void)layout_block;
  return false;
#endif
}

static bool RestoreOriginalRetcheckState() {
  RetCheckData* data_ptr = kCheckData;
  if (data_ptr == nullptr || data_ptr->range == nullptr || s_original_address_table_ptr == 0) {
    return false;
  }
  data_ptr->addresses = reinterpret_cast<RetCheckData::ReturnAddresses*>(s_original_address_table_ptr);
  data_ptr->range->base = reinterpret_cast<void*>(s_original_image_base);
  data_ptr->range->size = s_original_image_size;
  return true;
}

static void ForceRestoreRetcheckState(const char* reason) {
  if (!RestoreOriginalRetcheckState()) {
    PIPE_LOG_ERROR("RetcheckBypass: force-restore failed ({})", reason);
  } else {
    PIPE_LOG_WARN("RetcheckBypass: force-restored original state ({})", reason);
  }
  s_thread_swap_depth = 0;
  s_swap_owner_thread_id.store(0, std::memory_order_release);
}

bool RetcheckBypass::Initialize() {
  if (!s_patched_array.empty()) {
    return true;
  }

  if (kCheckDataV2 != nullptr || kCheckRuntimeV2.protected_code_begin != nullptr) {
    PIPE_LOG_WARN(
        "RetcheckBypass: legacy initialization blocked because Retcheck V2 runtime metadata is present; use the separately gated V2 adapter");
    return false;
  }

  RetCheckData* data_ptr = kCheckData;
  if (data_ptr == nullptr) {
    PIPE_LOG_ERROR("RetcheckBypass: kCheckData is unavailable; retcheck bypass disabled");
    return false;
  }
  if (data_ptr->addresses == nullptr) {
    PIPE_LOG_ERROR("Original address table pointer is NULL!");
    return false;
  }
  if (data_ptr->range == nullptr) {
    PIPE_LOG_ERROR("Original image range pointer is NULL!");
    return false;
  }

  // Back up original state.
  s_original_address_table_ptr = reinterpret_cast<uintptr_t>(data_ptr->addresses);
  s_original_image_base = reinterpret_cast<uintptr_t>(data_ptr->range->base);
  s_original_image_size = data_ptr->range->size;

  if (s_original_address_table_ptr == 0) {
    PIPE_LOG_ERROR("Backed-up address table pointer is invalid!");
    return false;
  }

  RetCheckData::ReturnAddresses* address_table = data_ptr->addresses;
  uint32_t constant = get_constant_at_index(data_ptr->constants, kConstantOffset);
  uintptr_t real_image_base = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

  s_patched_array.reserve(address_table->count);
  for (uint32_t i = 0; i < address_table->count; ++i) {
    uint32_t offset = deobfuscate_return_address(address_table->ptr[i], constant);
    uintptr_t retaddr = real_image_base + offset;
    s_patched_array.push_back(obfuscate_return_address(retaddr, 0, constant));
  }
  std::sort(s_patched_array.begin(), s_patched_array.end());

  s_replacement_table.ptr = s_patched_array.data();
  s_replacement_table.count = static_cast<uint32_t>(s_patched_array.size());

  PIPE_LOG_TRACE("RetcheckBypass: table built ({} entries)", s_patched_array.size());
  return true;
}

bool RetcheckBypass::IsOperational() {
  return !s_patched_array.empty() && s_original_address_table_ptr != 0 &&
         s_original_image_size != 0;
}

bool RetcheckBypass::Shutdown() {
  if (s_patched_array.empty()) {
    PIPE_LOG("RetcheckBypass: nothing to restore");
    return false;
  }

  if (s_thread_swap_depth != 0 || s_swap_owner_thread_id.load(std::memory_order_acquire) != 0) {
    ForceRestoreRetcheckState("shutdown");
  } else if (!RestoreOriginalRetcheckState()) {
    PIPE_LOG_ERROR("RetcheckBypass: failed to restore original table during shutdown");
    return false;
  }

  s_patched_array.clear();
  s_original_address_table_ptr = 0;
  s_original_image_base = 0;
  s_original_image_size = 0;

  PIPE_LOG_TRACE("RetcheckBypass: table restored");
  return true;
}

bool RetcheckBypass::SwapIn() {
  if (s_patched_array.empty() || s_original_address_table_ptr == 0 || s_original_image_size == 0) {
    PIPE_LOG_ERROR("RetcheckBypass: SwapIn called before initialization");
    return false;
  }

  DWORD tid = GetCurrentThreadId();
  if (s_thread_swap_depth == 0) {
    DWORD expected = 0;
    if (!s_swap_owner_thread_id.compare_exchange_strong(expected, tid, std::memory_order_acq_rel)) {
      if (expected != tid) {
        PIPE_LOG_ERROR("RetcheckBypass: SwapIn denied, active on another thread (owner={}, current={})", expected, tid);
        return false;
      }
    }
  }
  ++s_thread_swap_depth;
  if (s_thread_swap_depth > 1) {
    return true;
  }

  RetCheckData* data_ptr = kCheckData;
  if (data_ptr == nullptr || data_ptr->range == nullptr) {
    ForceRestoreRetcheckState("SwapIn invalid check data");
    return false;
  }
  data_ptr->range->base = 0;
  data_ptr->range->size = std::numeric_limits<int64_t>::max();
  data_ptr->addresses = &s_replacement_table;
  return true;
}

bool RetcheckBypass::SwapOut() {
  if (s_thread_swap_depth == 0) {
    ForceRestoreRetcheckState("SwapOut underflow");
    return false;
  }

  --s_thread_swap_depth;
  if (s_thread_swap_depth > 0) {
    return true;
  }

  bool ok = RestoreOriginalRetcheckState();
  if (!ok) {
    ForceRestoreRetcheckState("SwapOut restore failure");
    return false;
  }

  s_swap_owner_thread_id.store(0, std::memory_order_release);
  return true;
}

bool RetcheckBypass::AddAddress(uintptr_t return_address) {
  if (s_patched_array.empty()) {
    PIPE_LOG_ERROR("AddAddress called before Initialize");
    return false;
  }

  RetCheckData* data_ptr = kCheckData;
  if (data_ptr == nullptr) {
    PIPE_LOG_ERROR("RetcheckBypass: AddAddress denied because kCheckData is unavailable");
    return false;
  }
  uint32_t constant = get_constant_at_index(data_ptr->constants, kConstantOffset);
  uint32_t obfuscated = obfuscate_return_address(return_address, 0, constant);

  auto it = std::lower_bound(s_patched_array.begin(), s_patched_array.end(), obfuscated);
  if (it == s_patched_array.end() || *it != obfuscated) {
    PIPE_LOG_TRACE("RetcheckBypass: adding return address 0x{:016X}", return_address);
    s_patched_array.insert(it, obfuscated);
    // Update pointer/count in case the vector reallocated.
    s_replacement_table.ptr = s_patched_array.data();
    s_replacement_table.count = static_cast<uint32_t>(s_patched_array.size());
  }

  return true;
}

#ifdef NYX_D2R_DEBUG_RETCHECK
void RetcheckBypass::ValidateReturnAddressValid(uintptr_t retaddr) {
  RetCheckData* data = kCheckData;
  if (data == nullptr || data->range == nullptr || data->addresses == nullptr) {
    PIPE_LOG_TRACE("RetcheckBypass: validation skipped because kCheckData is unavailable");
    return;
  }
  const uintptr_t image_base = reinterpret_cast<uintptr_t>(data->range->base);
  const uint32_t constant = get_constant_at_index(data->constants, kConstantOffset);
  uint32_t calculated = obfuscate_return_address(retaddr, image_base, constant);

  PIPE_LOG_TRACE("Data");
  PIPE_LOG_TRACE("  Return Address: {:p}", (void*)retaddr);
  PIPE_LOG_TRACE("  Image Base: {:p}", (void*)image_base);
  PIPE_LOG_TRACE("  Constant: {}", constant);
  PIPE_LOG_TRACE("  Offset: 0x{:08X}", static_cast<uint32_t>(retaddr - image_base));
  PIPE_LOG_TRACE("  Obfuscated Value: 0x{:08X}", calculated);
  PIPE_LOG_TRACE("");

  uint32_t* array_ptr = data->addresses->ptr;
  uint32_t array_size = data->addresses->count;

  PIPE_LOG_TRACE("Integrity Check Table:");
  PIPE_LOG_TRACE("  Array Pointer: 0x{:p}", (void*)array_ptr);
  PIPE_LOG_TRACE("  Array Size: {} entries", array_size);
  PIPE_LOG_TRACE("");

  if (array_ptr == 0 || array_size == 0) {
    PIPE_LOG_TRACE("ERROR: Invalid table configuration!");
    return;
  }

  PIPE_LOG_TRACE("Performing Linear Scan");
  bool found_linear = false;
  int linear_index = -1;

  for (uint32_t i = 0; i < array_size; i++) {
    if (array_ptr[i] == calculated) {
      found_linear = true;
      linear_index = i;
      break;
    }
  }

  if (found_linear) {
    PIPE_LOG_TRACE("  FOUND at index {}", linear_index);
  } else {
    PIPE_LOG_TRACE("  NOT FOUND");
  }

  PIPE_LOG_TRACE("Performing Binary Search");
  bool found_binary = false;
  int binary_index = -1;

  if (array_size > 0) {
    int v10 = array_size - 1;
    int v11 = 0;

    if (array_size - 1 > 1) {
      while (v10 - v11 > 1) {
        int v12 = (v10 + v11) / 2;

        if (array_ptr[v12] >= calculated) {
          v10 = v12;
        }

        int v14 = v12 + 1;
        if (array_ptr[v12] >= calculated) {
          v14 = v11;
        }
        v11 = v14;
      }
    }

    if (array_ptr[v11] == calculated) {
      found_binary = true;
      binary_index = v11;
    } else if (array_ptr[v10] == calculated) {
      found_binary = true;
      binary_index = v10;
    }

    if (found_binary) {
      PIPE_LOG_TRACE("  FOUND at index {}", binary_index);
    } else {
      PIPE_LOG_TRACE("  NOT FOUND");
      PIPE_LOG_TRACE("  indices: v11={} (0x{:08X}), v10={} (0x{:08X})", v11, array_ptr[v11], v10, array_ptr[v10]);
    }
  }
  PIPE_LOG_TRACE("");

  PIPE_LOG_TRACE("\nSample:");
  for (uint32_t i = 0; i < array_size && i < 10; i++) {
    PIPE_LOG_TRACE("  [{}] 0x{:08X}{}", i, array_ptr[i], (array_ptr[i] == calculated) ? " <-- TARGET" : "");
  }

  if (array_size > 10) {
    PIPE_LOG_TRACE("  ... ({} more entries)", array_size - 10);
  }

  PIPE_LOG_TRACE("Results");
  if (found_linear && found_binary) {
    PIPE_LOG_TRACE("SUCCESS: Algorithm is CORRECT!");
    PIPE_LOG_TRACE("The obfuscated value was found using both methods.");
  } else if (found_linear && !found_binary) {
    PIPE_LOG_TRACE("WARNING: Found via linear scan but NOT binary search.");
    PIPE_LOG_TRACE("This suggests the array may not be properly sorted.");
  } else {
    PIPE_LOG_TRACE("FAILURE: Value not found in table.");
    PIPE_LOG_TRACE("Possible causes:");
    PIPE_LOG_TRACE("  1. Obfuscation algorithm is incorrect");
    PIPE_LOG_TRACE("  2. Wrong constant[c6] value");
    PIPE_LOG_TRACE("  3. Wrong image_base value");
    PIPE_LOG_TRACE("  4. Return address is invalid");
  }
}
#endif  // NYX_D2R_DEBUG_RETCHECK

}  // namespace d2r
