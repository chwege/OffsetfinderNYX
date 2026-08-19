#pragma once

#include "d2r_structs.h"

#include <dolos/offset_types.h>

#include <cstddef>
#include <cstdint>

namespace d2r {

using dolos::OffsetType;

#define D2R_EXPAND(x) x

#define D2R_GET_NAME_2(name, pattern) #name
#define D2R_GET_NAME_3(name, pattern, type) #name
#define D2R_GET_NAME_SELECT(_1, _2, _3, MACRO, ...) MACRO
#define D2R_GET_NAME(...) D2R_EXPAND(D2R_GET_NAME_SELECT(__VA_ARGS__, D2R_GET_NAME_3, D2R_GET_NAME_2)(__VA_ARGS__))

#define D2R_GET_VAR_2(name, pattern) name
#define D2R_GET_VAR_3(name, pattern, type) name
#define D2R_GET_VAR_SELECT(_1, _2, _3, MACRO, ...) MACRO
#define D2R_GET_VAR(...) D2R_EXPAND(D2R_GET_VAR_SELECT(__VA_ARGS__, D2R_GET_VAR_3, D2R_GET_VAR_2)(__VA_ARGS__))

#define D2R_GET_PATTERN_2(name, pattern) pattern
#define D2R_GET_PATTERN_3(name, pattern, type) pattern
#define D2R_GET_PATTERN_SELECT(_1, _2, _3, MACRO, ...) MACRO
#define D2R_GET_PATTERN(...)                                                                                           \
  D2R_EXPAND(D2R_GET_PATTERN_SELECT(__VA_ARGS__, D2R_GET_PATTERN_3, D2R_GET_PATTERN_2)(__VA_ARGS__))

#define D2R_GET_TYPE_2(name, pattern) OffsetType::Relative32Add
#define D2R_GET_TYPE_3(name, pattern, type) type
#define D2R_GET_TYPE_SELECT(_1, _2, _3, MACRO, ...) MACRO
#define D2R_GET_TYPE(...) D2R_EXPAND(D2R_GET_TYPE_SELECT(__VA_ARGS__, D2R_GET_TYPE_3, D2R_GET_TYPE_2)(__VA_ARGS__))

// Pattern format:
//   - Hex bytes: "8B 1D" (space-separated)
//   - Wildcard:  "?" (matches any single byte)
//   - Offset:    "^" (marks where to extract the offset value, counts as a wildcard)
//
// Examples:
//   "48 8B 0D ^ ? ? ?" - LEA/MOV with RIP-relative offset
//   "E8 ^ ? ? ?" - CALL with relative offset
//   "48 89 5C 24 ? 48 89 74 24 ?" - Function prologue (no ^)
#define D2R_OFFSET_LIST(V)                                                                                             \
  /* Advanced offsets */                                                                                               \
  V(D2Allocator, "48 8B 0D ^ ? ? ? 8B F8 48 85 C9")                                                                    \
  V(kCheckData, "48 8B 05 ^ ? ? ? 41 80 F0")                                                                           \
                                                                                                                       \
  /* Maphack offsets */                                                                                                \
  V(DRLG_AllocLevel, "44 8B 82 ? ? ? ? 48 8B 92 ? ? ? ? E8 ^ ? ? ? 48 83 7F ? ? 46 8B 0C A0")                         \
  V(DRLG_InitLevel, "E8 ^ ? ? ? 44 8B 8C 24 ? ? ? ? 41 83 F9")                                                         \
  V(ROOMS_AddRoomData, "E8 ^ ? ? ? 49 BB ? ? ? ? ? ? ? ? FF C6")                                                       \
  V(GetLevelDef, "48 8B 42 20 44 0F B6 90 C8 00 00 00 41 80 FA 04 75 EE 48 81 C2 10 03 00 00 48 89 74 24 ? 44 8B CD 4C 8B C7 E8 ^ ? ? ? 80 7B 38") \
  V(s_automapLayerLink, "48 8B 05 ^ ? ? ? 49 89 86")                                                                   \
  V(s_currentAutomapLayer, "48 8B CE FF 15 ? ? ? ? 41 8B FF 8B C7 48 03 D8 48 8B 05 ^ ? ? ? 8B 08 39 4C 24 ? 0F 85")  \
  V(ClearLinkedList, "48 8D 3D ? ? ? ? 48 89 9C 24 ? ? ? ? 48 8B CF 48 89 B4 24 ? ? ? ? 48 8D 15 ? ? ? ? E8 ^ ? ? ?")  \
  V(AUTOMAP_NewAutomapCell, "E8 ^ ? ? ? 48 8B 75 ? 48 85 F6 0F 84 ? ? ? ? E8 ? ? ? ? 8D 57")                           \
  V(AUTOMAP_AddAutomapCell, "E8 ? ? ? ? 48 8B 75 ? 48 85 F6 0F 84 ? ? ? ? E8 ^ ? ? ? 8D 57 30")                       \
                                                                                                                       \
  /* Widget offsets */                                                                                                 \
  V(Widget::GetScaledPosition, "48 8D 54 24 ? 48 8B CE E8 ^ ? ? ? 48 8B 5C 24 ? 48 8B 74 24 ? 48 8B 7C 24 ? 8B 10 8B 48") \
  V(Widget::GetScaledSize, "49 8B CD C1 E2 ? E8 ^ ? ? ? E9 ? ? ? ? 8B 73 ? 41 03 F0 41 3B F3")                         \
  V(PanelManager::GetScreenSizeX, "E8 ^ ? ? ? 0F 57 C0 0F 57 FF")                                                       \
  V(s_panelManager, "0F 84 ? ? ? ? 48 8B 05 ^ ? ? ? 0F 57 C9")                                                         \
  V(AutoMapPanel_GetMode, "E8 ^ ? ? ? 83 F8 ? 75 ? 33 D2 48 8B CF")                                                    \
  V(AutoMapPanel_CreateAutoMapData, "4C 89 44 24 ? 53 55 56 57 41 54 41 56 41 57 48 83 EC ? 0F 28 02 33 C0")           \
  V(AutoMapPanel_PrecisionToAutomap, "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 56 48 8B EC 48 83 EC ? 49 8B D8 48 8B FA 48 8B F1") \
  V(AutoMapPanel_spdwShift, "8B 0D ^ ? ? ? 8B 35")                                                                     \
                                                                                                                       \
  /* Data table offsets*/                                                                                              \
  V(sgptDataTbls, "0F B6 A9 BD 01 00 00 8D 45 FF 3C 02 0F 87 ? ? ? ? 49 8B 9E 88 00 00 00 48 8D 15 ^ ? ? ? 8B C5 41 8B FC 48 03 C0 48 8B 14 C2") \
  V(DATATBLS_GetAutomapCellId, "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 63 D9 45 8B D9")                          \
                                                                                                                       \
  /* Unit offsets */                                                                                                   \
  V(s_PlayerUnitIndex, "8B 0D ^ ? ? ? 48 8B 58 18")                                                                    \
  V(sgptClientSideUnitHashTable, "48 63 C1 48 8D 0D ^ ? ? ? 48 C1 E0")                                                 \
  V(GetClientSideUnitHashTableByType, "E8 ^ ? ? ? 8B D5 41 B9")                                                        \
  V(GetServerSideUnitHashTableByType, "E8 ^ ? ? ? 45 8B C1 41 83 E0")                                                  \
  V(EncEncryptionKeys, "48 03 08 48 83 C0 08 48 3B C2 75 F4 48 B8 ? ? ? ? ? ? ? ? 48 F7 E9 48 C1 FA ? 48 8B C2 48 C1 E8 ? 48 03 D0 48 89 15 ? ? ? ? C3 CC 48 8D 05 ? ? ? ? 48 89 05 ? ? ? ? 48 8B 05 ^ ? ? ? 48 85 C0") \
                                                                                                                       \
  /* Optional patch-reference offsets; dynamically resolved, never hardcoded. */                                       \
  V(Reference_UIOffset, "48 63 C1 48 8D 0D ^ ? ? ? 0F B6 04 08 C3")                                                    \
  V(Reference_Expansion, "48 8B 05 ^ ? ? ? 48 85 C0 74 ? 80 78 5C 01 0F 94 C0 C3")                                   \
  V(Reference_Roster, "4C 8B 15 ^ ? ? ? 49 8B D2 83 F9 FF 74 ? 48 85 D2 74 ? 0F 1F 40 00 39 4A 48")

constexpr std::size_t kOffsetCount = 0
#define COUNT_OFFSET(...) +1
    D2R_OFFSET_LIST(COUNT_OFFSET)
#undef COUNT_OFFSET
    ;

bool InitializeOffsets();
bool InitializePlayerIdConstants();
bool SavePlayerIdConstantsToCache(uint32_t xor_const, uint32_t add_const);
bool ValidateOffsets();

struct OffsetInfo {
  const char* name;
  const char* pattern;
  OffsetType type;
  void* value;
  bool found;
};

void GetOffsetInfo(OffsetInfo* out, std::size_t count);

}  // namespace d2r
