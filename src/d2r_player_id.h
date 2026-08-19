#pragma once

#include "d2r_structs.h"

namespace d2r {

uint32_t    GetPlayerId(uint32_t index);
D2UnitStrc* GetPlayerUnit(uint32_t index);
void        LogLocalPlayerIdentityDiagnostic();

}  // namespace d2r
