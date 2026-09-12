cmake_minimum_required(VERSION 3.25)

# Accept both SDK archive layouts, without depending on a moved SDK tree.
set(UNSLOP_SDK_ROOT "$ENV{IDASDK}" CACHE PATH "IDA SDK root or src directory")
if(NOT UNSLOP_SDK_ROOT)
    set(UNSLOP_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/idasdk/ida-sdk")
endif()
set(_unslop_sdk_init "")
foreach(_suffix IN ITEMS cmake src/cmake)
    if(EXISTS "${UNSLOP_SDK_ROOT}/${_suffix}/idasdk_init.cmake")
        set(_unslop_sdk_init "${UNSLOP_SDK_ROOT}/${_suffix}/idasdk_init.cmake")
        break()
    endif()
endforeach()
if(NOT _unslop_sdk_init)
    message(FATAL_ERROR "Set IDASDK or -DUNSLOP_SDK_ROOT to an IDA SDK with CMake support")
endif()
set(ENV{IDASDK} "${UNSLOP_SDK_ROOT}")
include("${_unslop_sdk_init}")

project(unslopper CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(idasdk REQUIRED)

# ── Unslopper plugin ─────────────────────────────────────────────────────────
#   src/            plugin entry, shared types, logging
#   src/core/       CFF recovery engine (dispatcher, state, CFG rewrite)
#   src/passes/     microcode transformation passes (MBA, opaque, svc, VM)
#   src/profiles/   per-protector detection + configuration
ida_add_plugin(unslopper
    SOURCES
        # entry + shared
        src/plugin.cpp
        src/unslop_log.cpp
        # core CFF engine
        src/core/microcode_utils.cpp
        src/core/dispatcher.cpp
        src/core/state_resolver.cpp
        src/core/history_tracker.cpp
        src/core/block_dup.cpp
        src/core/cfg_rewriter.cpp
        src/core/stack_jtbl.cpp
        # transformation passes
        src/passes/mba_simplify.cpp
        src/passes/ixguard_mba.cpp
        src/passes/hash_predicates.cpp
        src/passes/svc_flags.cpp
        src/passes/opaque_mba.cpp
        src/passes/anti_decompiler.cpp
        src/passes/semantic_diffusion.cpp
        src/passes/virtual_call.cpp
        src/passes/arxan_patterns.cpp
        src/passes/arxan_branches.cpp
        src/passes/verified_jump.cpp
        src/passes/svc_resolver.cpp
        src/passes/fairplay_dispatch.cpp
        # protector profiles
        src/profiles/ollvm.cpp
        src/profiles/promon.cpp
        src/profiles/dexprotector.cpp
        src/profiles/mvg.cpp
)

# Keep the installable artifact with this build rather than inside the SDK.
set_target_properties(unslopper PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# Flat includes ("foo.h") resolve regardless of which subdirectory a header
# lives in, so translation units never need "../" path prefixes.
target_include_directories(unslopper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/passes
    ${CMAKE_CURRENT_SOURCE_DIR}/src/profiles
)
