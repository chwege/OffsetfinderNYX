#define NOMINMAX
#include <Windows.h>

#include <hde/hde64.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

struct ReferenceTarget {
  const char* name;
  std::uint32_t rva;
};

constexpr std::array<ReferenceTarget, 7> kCurrentPatchReferences{{
    {"unit_table", 0x01EB9430},
    {"ui_offset", 0x01EC9120},
    {"expansion", 0x01E0C508},
    {"hover", 0x01DFB080},
    {"roster", 0x01ECF748},
    {"panels", 0x01E11E40},
    {"keybindings", 0x019D2420},
}};

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary | std::ios::ate);
  if (!stream) {
    return {};
  }
  const auto size = stream.tellg();
  if (size <= 0) {
    return {};
  }
  std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
  stream.seekg(0);
  stream.read(reinterpret_cast<char*>(data.data()), size);
  return stream ? data : std::vector<std::uint8_t>{};
}

void PrintBytes(const std::uint8_t* bytes, std::size_t size) {
  for (std::size_t i = 0; i < size; ++i) {
    std::printf("%02X%s", bytes[i], i + 1 == size ? "" : " ");
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "Usage: offset_xref_analyzer.exe <path-to-D2R.exe>\n");
    return 2;
  }
  const std::filesystem::path exe_path =
      std::filesystem::absolute(argv[1]);
  const auto file = ReadFile(exe_path);
  if (file.size() < sizeof(IMAGE_DOS_HEADER)) {
    std::fprintf(stderr, "Could not read PE file: %s\n",
                 exe_path.string().c_str());
    return 1;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
      static_cast<std::size_t>(dos->e_lfanew) +
              sizeof(IMAGE_NT_HEADERS64) >
          file.size()) {
    std::fprintf(stderr, "Invalid DOS/NT headers\n");
    return 1;
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
      file.data() + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    std::fprintf(stderr, "Not a valid 64-bit PE image\n");
    return 1;
  }

  std::vector<std::uint8_t> image(nt->OptionalHeader.SizeOfImage);
  const auto header_size =
      std::min<std::size_t>(nt->OptionalHeader.SizeOfHeaders, file.size());
  std::copy_n(file.data(), header_size, image.data());

  const auto* sections = IMAGE_FIRST_SECTION(nt);
  for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    const auto& section = sections[i];
    if (section.PointerToRawData >= file.size() ||
        section.VirtualAddress >= image.size()) {
      continue;
    }
    const auto copy_size = std::min<std::size_t>(
        {section.SizeOfRawData,
         file.size() - section.PointerToRawData,
         image.size() - section.VirtualAddress});
    std::copy_n(file.data() + section.PointerToRawData, copy_size,
                image.data() + section.VirtualAddress);
  }

  std::array<std::size_t, kCurrentPatchReferences.size()> match_counts{};
  std::printf("PE: %s\n", exe_path.string().c_str());
  std::printf("ImageSize: 0x%08X Timestamp: 0x%08X\n",
              nt->OptionalHeader.SizeOfImage, nt->FileHeader.TimeDateStamp);

  for (std::uint16_t section_index = 0;
       section_index < nt->FileHeader.NumberOfSections; ++section_index) {
    const auto& section = sections[section_index];
    if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
        section.VirtualAddress >= image.size()) {
      continue;
    }

    const auto section_size = std::min<std::size_t>(
        std::max(section.Misc.VirtualSize, section.SizeOfRawData),
        image.size() - section.VirtualAddress);
    std::size_t offset = 0;
    while (offset + 16 <= section_size) {
      const auto instruction_rva =
          static_cast<std::uint32_t>(section.VirtualAddress + offset);
      const auto* instruction = image.data() + instruction_rva;
      hde64s decoded{};
      const auto length = hde64_disasm(instruction, &decoded);
      if (length == 0 || (decoded.flags & F_ERROR) != 0 ||
          offset + length > section_size) {
        ++offset;
        continue;
      }

      const bool rip_relative =
          (decoded.flags & F_DISP32) != 0 && decoded.modrm_mod == 0 &&
          decoded.modrm_rm == 5 && decoded.p_67 == 0;
      if (rip_relative) {
        const auto displacement =
            static_cast<std::int32_t>(decoded.disp.disp32);
        const auto target_rva = static_cast<std::uint32_t>(
            static_cast<std::int64_t>(instruction_rva) + length +
            displacement);
        for (std::size_t target_index = 0;
             target_index < kCurrentPatchReferences.size(); ++target_index) {
          const auto& target = kCurrentPatchReferences[target_index];
          if (target_rva != target.rva) {
            continue;
          }
          ++match_counts[target_index];
          const auto context_begin =
              instruction_rva >= 12 ? instruction_rva - 12 : 0;
          const auto context_end = std::min<std::size_t>(
              image.size(), instruction_rva + length + 20);
          std::printf(
              "\nXREF name=%s target=0x%08X instruction=0x%08X "
              "length=%u opcode=0x%02X modrm=0x%02X\n",
              target.name, target.rva, instruction_rva, length,
              decoded.opcode, decoded.modrm);
          std::printf("  instruction: ");
          PrintBytes(instruction, length);
          std::printf("\n  context[0x%08X..0x%08zX]: ", context_begin,
                      context_end);
          PrintBytes(image.data() + context_begin,
                     context_end - context_begin);
          std::printf("\n");
        }
      }

      offset += length;
    }
  }

  std::printf("\nSUMMARY\n");
  for (std::size_t i = 0; i < kCurrentPatchReferences.size(); ++i) {
    std::printf("  %-12s target=0x%08X executable_xrefs=%zu\n",
                kCurrentPatchReferences[i].name,
                kCurrentPatchReferences[i].rva, match_counts[i]);
  }
  std::printf(
      "Reference RVAs are bootstrap checks only; no runtime fallback is "
      "generated.\n");
  return 0;
}
