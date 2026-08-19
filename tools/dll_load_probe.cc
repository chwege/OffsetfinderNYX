#include <Windows.h>

#include <cstdio>
#include <filesystem>
#include <string>

static std::string FormatWindowsError(DWORD error) {
  char* message = nullptr;
  const DWORD length = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      error,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<char*>(&message),
      0,
      nullptr);
  std::string result = length != 0 && message != nullptr ? message : "No system message available";
  if (message != nullptr) {
    LocalFree(message);
  }
  while (!result.empty() && (result.back() == '\r' || result.back() == '\n')) {
    result.pop_back();
  }
  return result;
}

int main(int argc, char** argv) {
  const std::filesystem::path dll_path =
      argc > 1 ? std::filesystem::absolute(argv[1])
               : std::filesystem::absolute(std::filesystem::path("nyx.d2r.dll"));

  std::printf("DLL load probe: %s\n", dll_path.string().c_str());
  SetLastError(ERROR_SUCCESS);
  HMODULE module = LoadLibraryExA(dll_path.string().c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
  if (module == nullptr) {
    const DWORD error = GetLastError();
    std::fprintf(stderr, "LoadLibraryEx failed: error=%lu (0x%08lX): %s\n",
                 error,
                 error,
                 FormatWindowsError(error).c_str());
    return 1;
  }

  std::printf("LoadLibraryEx succeeded: module=%p\n", static_cast<void*>(module));
  std::printf("Waiting briefly for the safe diagnostic worker...\n");
  Sleep(5000);
  std::printf("Probe finished.\n");
  return 0;
}
