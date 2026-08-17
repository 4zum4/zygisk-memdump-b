cmake_minimum_required(VERSION 3.18.1)

if (NOT DEFINED TOOL_NAME)
    message(FATAL_ERROR "TOOL_NAME is not set")
else ()
    project(${TOOL_NAME})
endif ()

# Generate the config-path header in the build tree instead of editing a
# tracked source file with platform-specific `sed -i` syntax. This works on
# Linux/macOS/Windows hosts and avoids races when multiple ABIs are built.
set(GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_INCLUDE_DIR}")
file(WRITE "${GENERATED_INCLUDE_DIR}/logcat.h"
"#ifndef ZYGISK_MEMDUMP_LOGCAT_H\n"
"#define ZYGISK_MEMDUMP_LOGCAT_H\n\n"
"#include <string>\n\n"
"const std::string config_file_path = \"/data/adb/modules/${MODULE_DIR}/config\";\n\n"
"void logcat();\n\n"
"#endif // ZYGISK_MEMDUMP_LOGCAT_H\n")

message("Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 20)

set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")
set(C_FLAGS "-fdata-sections -ffunction-sections")
set(CXX_FLAGS "${CXX_FLAGS} -fno-exceptions -fno-rtti")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(C_FLAGS "${C_FLAGS} -O2 -fvisibility=hidden -fvisibility-inlines-hidden")
    set(LINKER_FLAGS "${LINKER_FLAGS} -Wl,-exclude-libs,ALL -Wl,--gc-sections -Wl,--strip-all")
else ()
    set(C_FLAGS "${C_FLAGS} -O0")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")

add_executable(${TOOL_NAME} main.cpp logcat.cpp)
target_include_directories(${TOOL_NAME} BEFORE PRIVATE "${GENERATED_INCLUDE_DIR}")
target_link_libraries(${TOOL_NAME} log)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${TOOL_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${TOOL_NAME}")
endif ()
