add_executable(simple_injector simple_injector.cc)
install(TARGETS simple_injector RUNTIME DESTINATION bin)

add_executable(
  offset_xref_analyzer
  offset_xref_analyzer.cc
  ${CMAKE_SOURCE_DIR}/vendor/nyx/dolos/vendor/minhook/src/hde/hde64.c)
target_include_directories(
  offset_xref_analyzer
  PRIVATE ${CMAKE_SOURCE_DIR}/vendor/nyx/dolos/vendor/minhook/src)
