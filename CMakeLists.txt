cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set runtime linking to /MT
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
message(STATUS "Link against static runtime")

project(nyx_d2r LANGUAGES C CXX ASM_MASM)

add_subdirectory(tools)

# Local override for Nyx source. This keeps vendored Nyx as default, but allows
# building nyx-d2r against a local Nyx checkout for rapid iteration.
set(NYX_SOURCE_OVERRIDE "" CACHE PATH "Path to a local Nyx source tree (must contain CMakeLists.txt)")

if(NYX_SOURCE_OVERRIDE)
  if(NOT IS_DIRECTORY "${NYX_SOURCE_OVERRIDE}")
    message(FATAL_ERROR "NYX_SOURCE_OVERRIDE does not exist: ${NYX_SOURCE_OVERRIDE}")
  endif()

  if(NOT EXISTS "${NYX_SOURCE_OVERRIDE}/CMakeLists.txt")
    message(FATAL_ERROR "NYX_SOURCE_OVERRIDE must point to Nyx source root (missing CMakeLists.txt): ${NYX_SOURCE_OVERRIDE}")
  endif()

  message(STATUS "Using local Nyx source override: ${NYX_SOURCE_OVERRIDE}")
  add_subdirectory("${NYX_SOURCE_OVERRIDE}" "${CMAKE_BINARY_DIR}/_deps/nyx-local")
else()
  add_subdirectory(vendor)
endif()

# Security/hardening profile toggles.
option(NYX_D2R_ENABLE_PE_DUMP "Enable writing PE dump during offset scan" OFF)
option(NYX_D2R_ENABLE_RETCHECK_DEBUG "Enable verbose retcheck diagnostics" OFF)
option(NYX_D2R_SAFE_DIAGNOSTIC_MODE "Load diagnostics and a guarded runtime without protected calls" ON)
option(NYX_D2R_SAFE_SKIP_OFFSET_SCAN "In safe diagnostic mode, skip offset scanning entirely" OFF)
option(NYX_D2R_SAFE_NO_THREAD_SUSPEND "In safe diagnostic mode, scan without suspending game threads" ON)
option(NYX_D2R_SAFE_NO_DECRYPT_TOUCH "In safe diagnostic mode, scan readable memory without invoking decrypt gadgets" ON)
option(NYX_D2R_SAFE_RETCHECK_PROBE "In safe diagnostic mode, temporarily read-probe the protected retcheck table and restore protection" OFF)
option(NYX_D2R_SAFE_READ_ONLY_RUNTIME "In safe diagnostic mode, register only guarded read-only runtime bindings" ON)
option(NYX_D2R_FAST_DIAGNOSTIC "Skip already-confirmed timed diagnostic retries and monitoring" ON)
set(NYX_D2R_SIGN_PFX "" CACHE FILEPATH "Optional PFX used to sign nyx.d2r after linking")
set(NYX_D2R_SIGN_PASSWORD "" CACHE STRING "Password for NYX_D2R_SIGN_PFX")

set(NYX_D2R_SOURCES
  src/d2r_binding.cc
  src/d2r_feature_check.cc
  src/d2r_game.cc
  src/d2r_methods.cc
  src/d2r_player_id.cc
  src/d2r_reveal.cc
  src/d2r_safety.cc
  src/decryption_stub.asm
  src/main.cc
  src/offsets.cc
  src/reference_offset_diagnostics.cc
  src/retcheck_bypass.cc
  src/retcheck_v2_adapter.cc
  src/unit_table_diagnostics.cc
)

add_library(nyx.d2r SHARED ${NYX_D2R_SOURCES})

# Enable ImGui <-> V8 helpers defined in vendor/nyx/vendor/imgui/imconfig.h
target_compile_definitions(nyx.d2r PRIVATE
  NYX_IMGUI_V8_INTEGRATION
  $<$<BOOL:${NYX_D2R_ENABLE_PE_DUMP}>:NYX_D2R_PE_DUMP>
  $<$<BOOL:${NYX_D2R_ENABLE_RETCHECK_DEBUG}>:NYX_D2R_DEBUG_RETCHECK>
  $<$<BOOL:${NYX_D2R_SAFE_DIAGNOSTIC_MODE}>:NYX_D2R_SAFE_DIAGNOSTIC_MODE>
  $<$<BOOL:${NYX_D2R_SAFE_SKIP_OFFSET_SCAN}>:NYX_D2R_SAFE_SKIP_OFFSET_SCAN>
  $<$<BOOL:${NYX_D2R_SAFE_RETCHECK_PROBE}>:NYX_D2R_SAFE_RETCHECK_PROBE>
  $<$<BOOL:${NYX_D2R_SAFE_READ_ONLY_RUNTIME}>:NYX_D2R_SAFE_READ_ONLY_RUNTIME>
  $<$<BOOL:${NYX_D2R_FAST_DIAGNOSTIC}>:NYX_D2R_FAST_DIAGNOSTIC>
  $<$<CONFIG:Debug>:NYX_D2R_DEV_BUILD=1>
  $<$<NOT:$<CONFIG:Debug>>:NYX_D2R_HARDENED_BUILD=1>
)

message(STATUS "NYX_D2R_ENABLE_PE_DUMP=${NYX_D2R_ENABLE_PE_DUMP}")
message(STATUS "NYX_D2R_ENABLE_RETCHECK_DEBUG=${NYX_D2R_ENABLE_RETCHECK_DEBUG}")
message(STATUS "NYX_D2R_SAFE_DIAGNOSTIC_MODE=${NYX_D2R_SAFE_DIAGNOSTIC_MODE}")
message(STATUS "NYX_D2R_SAFE_SKIP_OFFSET_SCAN=${NYX_D2R_SAFE_SKIP_OFFSET_SCAN}")
message(STATUS "NYX_D2R_SAFE_NO_THREAD_SUSPEND=${NYX_D2R_SAFE_NO_THREAD_SUSPEND}")
message(STATUS "NYX_D2R_SAFE_NO_DECRYPT_TOUCH=${NYX_D2R_SAFE_NO_DECRYPT_TOUCH}")
message(STATUS "NYX_D2R_SAFE_RETCHECK_PROBE=${NYX_D2R_SAFE_RETCHECK_PROBE}")
message(STATUS "NYX_D2R_SAFE_READ_ONLY_RUNTIME=${NYX_D2R_SAFE_READ_ONLY_RUNTIME}")
message(STATUS "NYX_D2R_FAST_DIAGNOSTIC=${NYX_D2R_FAST_DIAGNOSTIC}")

if(TARGET dolos)
  target_compile_definitions(dolos PUBLIC
    $<$<BOOL:${NYX_D2R_SAFE_DIAGNOSTIC_MODE}>:NYX_D2R_SAFE_DIAGNOSTIC_MODE>
    $<$<BOOL:${NYX_D2R_SAFE_NO_THREAD_SUSPEND}>:NYX_D2R_SAFE_NO_THREAD_SUSPEND>
    $<$<BOOL:${NYX_D2R_SAFE_NO_DECRYPT_TOUCH}>:NYX_D2R_SAFE_NO_DECRYPT_TOUCH>
    $<$<BOOL:${NYX_D2R_SAFE_READ_ONLY_RUNTIME}>:NYX_D2R_SAFE_READ_ONLY_RUNTIME>
  )
endif()

target_external_js_sources(nyx.d2r lib ${CMAKE_CURRENT_BINARY_DIR}/d2r_builtins.cc d2r_builtins)

target_link_libraries(nyx.d2r PRIVATE nyx::dolos)
target_include_directories(
  nyx.d2r
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/nyx/dolos/vendor/minhook/src)

add_custom_command(
  TARGET nyx.d2r POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_INSTALL_PREFIX}/bin/scripts
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          ${CMAKE_CURRENT_SOURCE_DIR}/scripts
          ${CMAKE_INSTALL_PREFIX}/bin/scripts
)

if(NYX_D2R_SIGN_PFX)
  if(NOT EXISTS "${NYX_D2R_SIGN_PFX}")
    message(FATAL_ERROR "NYX_D2R_SIGN_PFX does not exist: ${NYX_D2R_SIGN_PFX}")
  endif()
  add_custom_command(
    TARGET nyx.d2r POST_BUILD
    COMMAND signtool sign /fd SHA256 /f "${NYX_D2R_SIGN_PFX}" /p "${NYX_D2R_SIGN_PASSWORD}" $<TARGET_FILE:nyx.d2r>
  )
else()
  message(STATUS "DLL signing disabled; set NYX_D2R_SIGN_PFX to enable it")
endif()

install(TARGETS nyx.d2r RUNTIME DESTINATION bin)

install(
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/tools/start_local_automap_test.bat
  DESTINATION bin
  RENAME START_LOCAL_AUTOMAP_TEST.bat)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/typings
  DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
  FILES_MATCHING PATTERN "*.d.ts")

# Nyx loads runtime packages from a "scripts" directory next to the module.
install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/scripts
  DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
  PATTERN "node_modules" EXCLUDE
  PATTERN ".git" EXCLUDE
  PATTERN "*.tsbuildinfo" EXCLUDE)
