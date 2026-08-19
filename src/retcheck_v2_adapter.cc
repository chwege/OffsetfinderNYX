#include "retcheck_v2_adapter.h"

#include <Windows.h>

#include <cstdint>
#include <cstring>

#include <dolos/pipe_log.h>

#include "d2r_structs.h"

namespace d2r {
namespace {

struct RetcheckV2Request {
  std::uint32_t argument0;
  std::uint32_t argument1;
  void* context;
};
static_assert(sizeof(RetcheckV2Request) == 0x10);

bool IsReadable(const void* address, std::size_t size) {
  if (address == nullptr || size == 0) {
    return false;
  }

  MEMORY_BASIC_INFORMATION info{};
  if (VirtualQuery(address, &info, sizeof(info)) == 0 || info.State != MEM_COMMIT ||
      (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
    return false;
  }

  const auto start = reinterpret_cast<std::uintptr_t>(address);
  const auto region_start = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
  const auto region_end = region_start + info.RegionSize;
  return start >= region_start && size <= region_end - start;
}

bool IsCommittedRange(const void* address, std::size_t size) {
  if (address == nullptr || size == 0) {
    return false;
  }

  MEMORY_BASIC_INFORMATION info{};
  if (VirtualQuery(address, &info, sizeof(info)) == 0 ||
      info.State != MEM_COMMIT) {
    return false;
  }

  const auto start = reinterpret_cast<std::uintptr_t>(address);
  const auto region_start = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
  const auto region_end = region_start + info.RegionSize;
  return start >= region_start && size <= region_end - start;
}

bool IsExecutable(const void* address) {
  if (address == nullptr) {
    return false;
  }

  MEMORY_BASIC_INFORMATION info{};
  if (VirtualQuery(address, &info, sizeof(info)) == 0 || info.State != MEM_COMMIT ||
      (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
    return false;
  }

  constexpr DWORD kExecutable =
      PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
  return (info.Protect & kExecutable) != 0;
}

void LogMemoryRegion(const char* label, const void* address) {
  MEMORY_BASIC_INFORMATION info{};
  const bool query_ok = address != nullptr && VirtualQuery(address, &info, sizeof(info)) != 0;
  PIPE_LOG_WARN(
      "[RetcheckV2Adapter] region={} address={:p} query={} base={:p} size=0x{:X} state=0x{:X} protect=0x{:X} allocation_protect=0x{:X} type=0x{:X}",
      label,
      address,
      query_ok ? "ok" : "failed",
      query_ok ? info.BaseAddress : nullptr,
      query_ok ? info.RegionSize : 0,
      query_ok ? info.State : 0,
      query_ok ? info.Protect : 0,
      query_ok ? info.AllocationProtect : 0,
      query_ok ? info.Type : 0);
}

}  // namespace

bool RetcheckV2Adapter::HasResolvedMetadata() {
  const auto& runtime = kCheckRuntimeV2;
  return runtime.protected_code_begin != nullptr &&
         runtime.protected_code_end > runtime.protected_code_begin &&
         runtime.entry_contract_ok && runtime.request_contract_ok &&
         runtime.dispatcher_contract_ok && runtime.request_allocator != nullptr &&
         runtime.request_submit != nullptr && runtime.dispatcher_slot != nullptr &&
         runtime.dispatcher_object != nullptr && runtime.dispatcher_method != nullptr &&
         runtime.dispatcher_method_offset == 0x10;
}

bool RetcheckV2Adapter::ValidateReadOnly() {
  const auto& runtime = kCheckRuntimeV2;
  const auto code_size =
      runtime.protected_code_begin != nullptr &&
              runtime.protected_code_end > runtime.protected_code_begin
          ? static_cast<std::size_t>(runtime.protected_code_end -
                                     runtime.protected_code_begin)
          : 0;
  const bool code_range_ok =
      code_size != 0 && code_size == runtime.protected_code_size &&
      IsCommittedRange(runtime.protected_code_begin, code_size);
  const bool code_readable =
      code_range_ok && IsReadable(runtime.protected_code_begin, code_size);
  const bool allocator_ok = IsExecutable(runtime.request_allocator);
  const bool submit_ok = IsExecutable(runtime.request_submit);
  const bool method_ok = IsExecutable(runtime.dispatcher_method);
  const bool entry_contract_ok =
      code_range_ok && runtime.entry_contract_ok;
  const bool request_contract_ok =
      code_range_ok && runtime.request_contract_ok;
  const bool dispatcher_contract_ok =
      code_range_ok && runtime.dispatcher_contract_ok;
  const bool signature_contract_ok =
      entry_contract_ok && request_contract_ok && dispatcher_contract_ok;

  void* current_object = nullptr;
  void** current_vtable = nullptr;
  void* current_method = nullptr;
  if (IsReadable(runtime.dispatcher_slot, sizeof(current_object))) {
    std::memcpy(&current_object, runtime.dispatcher_slot, sizeof(current_object));
  }
  if (IsReadable(current_object, sizeof(current_vtable))) {
    std::memcpy(&current_vtable, current_object, sizeof(current_vtable));
  }
  const auto* method_slot =
      current_vtable == nullptr
          ? nullptr
          : reinterpret_cast<void* const*>(
                reinterpret_cast<const std::uint8_t*>(current_vtable) +
                runtime.dispatcher_method_offset);
  if (IsReadable(method_slot, sizeof(current_method))) {
    std::memcpy(&current_method, method_slot, sizeof(current_method));
  }

  const bool dispatcher_ok =
      current_object != nullptr && current_object == runtime.dispatcher_object &&
      current_method != nullptr && current_method == runtime.dispatcher_method &&
      runtime.dispatcher_method_offset == 0x10;
  const bool topology_ready =
      code_range_ok && runtime.request_allocator != nullptr &&
      runtime.request_submit != nullptr && runtime.dispatcher_slot != nullptr &&
      runtime.dispatcher_object != nullptr && runtime.dispatcher_method != nullptr &&
      runtime.dispatcher_method_offset == 0x10 && dispatcher_ok;
  const bool ready =
      code_range_ok && signature_contract_ok && allocator_ok && submit_ok &&
      method_ok && dispatcher_ok;

  LogMemoryRegion("verifier-begin", runtime.protected_code_begin);
  LogMemoryRegion("request-allocator", runtime.request_allocator);
  LogMemoryRegion("request-submit", runtime.request_submit);
  LogMemoryRegion("dispatcher-slot", runtime.dispatcher_slot);
  LogMemoryRegion("dispatcher-method", runtime.dispatcher_method);

  PIPE_LOG_WARN(
      "[RetcheckV2Adapter] read-only validation ready={} topology={} code_range={} code_access={} code_size=0x{:X} entry_contract={} request_contract={} dispatcher_contract={} request_size=0x{:X} allocator_metadata={} allocator_live={} submit_metadata={} submit_live={} dispatcher={} method={} action=none",
      ready ? "yes" : "no",
      topology_ready ? "ready" : "incomplete",
      code_range_ok ? "ok" : "invalid",
      code_readable ? "naturally-readable" : "protected-or-inaccessible",
      code_size,
      entry_contract_ok ? "ok" : (code_readable ? "mismatch" : "not-observed"),
      request_contract_ok ? "ok" : (code_readable ? "mismatch" : "not-observed"),
      dispatcher_contract_ok ? "ok" : (code_readable ? "mismatch" : "not-observed"),
      sizeof(RetcheckV2Request),
      runtime.request_allocator != nullptr ? "present" : "missing",
      allocator_ok ? "ok" : "invalid",
      runtime.request_submit != nullptr ? "present" : "missing",
      submit_ok ? "ok" : "invalid",
      dispatcher_ok ? "stable" : "changed",
      method_ok ? "executable" : "invalid");
  PIPE_LOG_WARN(
      "[RetcheckV2Adapter] dry-run only; no allocator, submit, dispatcher, hook, swap, or protected function was invoked");
  return ready;
}

}  // namespace d2r
