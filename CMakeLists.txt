cmake_minimum_required(VERSION 3.25)

# Standalone build: pull in the IDA SDK cmake helpers before project().
include(${CMAKE_CURRENT_SOURCE_DIR}/../../tools/idasdk/ida-sdk/src/cmake/idasdk_init.cmake OPTIONAL)
if(NOT COMMAND find_package OR NOT DEFINED idasdk_DIR)
    # Fall back to $ENV{IDASDK}
    if(DEFINED ENV{IDASDK})
        include($ENV{IDASDK}/cmake/idasdk_init.cmake)
    endif()
endif()

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
        # transformation passes
        src/passes/mba_simplify.cpp
        src/passes/opaque_mba.cpp
        src/passes/anti_decompiler.cpp
        src/passes/semantic_diffusion.cpp
        src/passes/virtual_call.cpp
        src/passes/svc_resolver.cpp
        src/passes/fairplay_dispatch.cpp
        # protector profiles
        src/profiles/ollvm.cpp
        src/profiles/promon.cpp
        src/profiles/dexprotector.cpp
        src/profiles/mvg.cpp
)

# Flat includes ("foo.h") resolve regardless of which subdirectory a header
# lives in, so translation units never need "../" path prefixes.
target_include_directories(unslopper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/passes
    ${CMAKE_CURRENT_SOURCE_DIR}/src/profiles
)
