# ares-bridge — generic N64Recomp Ares oracle integration
#
# Build modes:
#   * Placeholder (default).  WITH_ARES_BRIDGE=OFF.  Compiles only
#     src/ares_bridge.cpp; every functional API call abort()s with a
#     diagnostic. Header-stable for consumer compilation.
#   * Real (WITH_ARES_BRIDGE=ON).  Pulls in Ares from
#     third_party/ares/, compiles src/ares_core_glue.cpp, links a
#     working oracle.
#
# Real-mode build assumes Ares has been pre-built into
# ${ARES_BUILD_DIR} (default: ${CMAKE_CURRENT_SOURCE_DIR}/build/ares).
# To prep Ares (one-time per checkout):
#
#   cmake -S ares-bridge/third_party/ares \
#         -B ares-bridge/build/ares \
#         -G "Visual Studio 17 2022" -A x64 \
#         -DARES_CORES=n64\;gb \
#         -DARES_BUILD_OPTIONAL_TARGETS=OFF \
#         -DARES_PRECOMPILE_HEADERS=OFF \
#         -DARES_UNITY_CORES=OFF
#   cmake --build ares-bridge/build/ares --target ares --config Release
#
# Doing it externally (rather than add_subdirectory) keeps Ares' large
# CMake state from leaking into N64Recomp's build.

option(WITH_ARES_BRIDGE
    "Compile the Ares oracle bridge against a real Ares checkout. \
Default OFF — the placeholder library is always built."
    OFF)

# ---- Always-built placeholder library --------------------------------------

add_library(ares_bridge STATIC
    src/ares_bridge.cpp
)

target_include_directories(ares_bridge PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_features(ares_bridge PUBLIC cxx_std_17)

# ---- Real-mode build (opt-in) ----------------------------------------------

if(WITH_ARES_BRIDGE)
    set(ARES_SUBMODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/third_party/ares")
    set(ARES_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build/ares"
        CACHE PATH "Directory containing a built Ares (ares.lib, nall.lib, ...)")

    if(NOT EXISTS "${ARES_SUBMODULE_PATH}/ares/ares/ares.hpp")
        message(FATAL_ERROR
            "WITH_ARES_BRIDGE=ON but Ares submodule not present at\n"
            "  ${ARES_SUBMODULE_PATH}\n"
            "Add the submodule (one-time):\n"
            "  git submodule update --init --recursive\n"
            "or initially:\n"
            "  git submodule add https://github.com/ares-emulator/ares.git \\\n"
            "    ares-bridge/third_party/ares")
    endif()

    # Apply local patches to the vendored Ares submodule. These are
    # additive hooks ares-bridge depends on (per-instruction RSP
    # trace, etc) — they're vendored as patch files so a re-clone
    # plus a fresh `git submodule update` followed by cmake configure
    # automatically re-applies them. If Ares upstream changes
    # conflict with a patch, the configure fails with a clear
    # diagnostic instead of producing a silently-broken build.
    set(_ares_patch_dir "${CMAKE_CURRENT_SOURCE_DIR}/patches")
    file(GLOB _ares_patches "${_ares_patch_dir}/*.patch")
    list(SORT _ares_patches)
    find_program(_git_exe git REQUIRED)
    foreach(_patch IN LISTS _ares_patches)
        get_filename_component(_patch_name "${_patch}" NAME)
        # Idempotency: check if patch is already applied. `git apply
        # --reverse --check` succeeds if the patch's "after" state is
        # currently in the tree (i.e., it's been applied), in which
        # case we skip re-applying.
        execute_process(
            COMMAND "${_git_exe}" apply --reverse --check "${_patch}"
            WORKING_DIRECTORY "${ARES_SUBMODULE_PATH}"
            RESULT_VARIABLE _already_applied
            OUTPUT_QUIET ERROR_QUIET)
        if(_already_applied EQUAL 0)
            message(STATUS
                "ares-bridge: patch already applied: ${_patch_name}")
        else()
            execute_process(
                COMMAND "${_git_exe}" apply --check "${_patch}"
                WORKING_DIRECTORY "${ARES_SUBMODULE_PATH}"
                RESULT_VARIABLE _patch_check
                ERROR_VARIABLE _patch_err)
            if(NOT _patch_check EQUAL 0)
                message(FATAL_ERROR
                    "ares-bridge: cannot apply patch '${_patch_name}' "
                    "to vendored Ares — upstream may have changed in a "
                    "way that conflicts. Update the patch file. "
                    "git apply --check output:\n${_patch_err}")
            endif()
            execute_process(
                COMMAND "${_git_exe}" apply "${_patch}"
                WORKING_DIRECTORY "${ARES_SUBMODULE_PATH}"
                RESULT_VARIABLE _patch_apply
                ERROR_VARIABLE _patch_err)
            if(NOT _patch_apply EQUAL 0)
                message(FATAL_ERROR
                    "ares-bridge: patch '${_patch_name}' check passed "
                    "but apply failed:\n${_patch_err}")
            endif()
            message(STATUS
                "ares-bridge: applied patch ${_patch_name}")
        endif()
    endforeach()

    set(_ares_lib       "${ARES_BUILD_DIR}/ares/Release/ares.lib")
    set(_nall_lib       "${ARES_BUILD_DIR}/nall/nall/nall.dir/Release/nall.lib")
    set(_libco_lib      "${ARES_BUILD_DIR}/libco/Release/libco.lib")
    set(_chdr_lib       "${ARES_BUILD_DIR}/thirdparty/Release/chdr-static.lib")
    set(_sljit_lib      "${ARES_BUILD_DIR}/thirdparty/Release/sljit.lib")
    set(_lzma_lib       "${ARES_BUILD_DIR}/thirdparty/libchdr/deps/lzma-24.05/Release/lzma.lib")
    set(_zlib_lib       "${ARES_BUILD_DIR}/thirdparty/libchdr/deps/zlib-1.3.1/Release/zlibstatic.lib")
    set(_zstd_lib       "${ARES_BUILD_DIR}/thirdparty/libchdr/deps/zstd-1.5.6/build/cmake/lib/Release/zstd_static.lib")

    foreach(_lib IN ITEMS
        "${_ares_lib}" "${_nall_lib}" "${_libco_lib}"
        "${_chdr_lib}" "${_sljit_lib}"
        "${_lzma_lib}" "${_zlib_lib}" "${_zstd_lib}")
        if(NOT EXISTS "${_lib}")
            message(FATAL_ERROR
                "WITH_ARES_BRIDGE=ON but Ares lib not built: ${_lib}\n"
                "Build Ares first — see the comment at the top of "
                "ares-bridge/CMakeLists.txt for the cmake invocations.")
        endif()
    endforeach()

    target_compile_definitions(ares_bridge PUBLIC
        N64RECOMP_ARES_BRIDGE_REAL=1
    )

    # Bake firmware paths from the vendored ares tree into a generated
    # header. Reading at runtime (vs embedding bytes) avoids needing a
    # custom sourcery-style binary-to-array tool.
    set(ARES_FIRMWARE_PIF_NTSC
        "${ARES_SUBMODULE_PATH}/ares/System/Nintendo 64/pif.ntsc.rom")
    set(ARES_FIRMWARE_PIF_PAL
        "${ARES_SUBMODULE_PATH}/ares/System/Nintendo 64/pif.pal.rom")
    set(ARES_FIRMWARE_PIF_SM5
        "${ARES_SUBMODULE_PATH}/mia/Firmware/Nintendo 64/pif.sm5.rom")
    foreach(_fw IN ITEMS
            "${ARES_FIRMWARE_PIF_NTSC}"
            "${ARES_FIRMWARE_PIF_PAL}"
            "${ARES_FIRMWARE_PIF_SM5}")
        if(NOT EXISTS "${_fw}")
            message(FATAL_ERROR
                "ares-bridge: PIF firmware missing at ${_fw}\n"
                "Did the vendored ares tree get partially deleted?")
        endif()
    endforeach()
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/ares_firmware_paths.hpp.in"
        "${CMAKE_CURRENT_BINARY_DIR}/ares_firmware_paths.hpp"
        @ONLY)
    target_include_directories(ares_bridge PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}")

    # Ares uses many compile definitions in its own build; when our
    # glue includes ares headers we must supply matching ones. We
    # explicitly do NOT define ARES_ENABLE_CHD because the oracle has
    # no use for CD-ROM image support and including <libchdr/chd.h>
    # would require pulling that header tree onto our include path.
    target_compile_definitions(ares_bridge PRIVATE
        PROFILE_PERFORMANCE
        BUILD_LOCAL
        CORE_GB
    )

    # Ares header search paths. Order matters: more-specific first.
    # Ares uses #include <ares/ares.hpp>, <nall/...>, <n64/...>, etc.
    # Those map to subdirs under ares/, nall/, ares/n64/ — but with the
    # repo's "ares" appearing twice (third_party/ares/ares/ares/ares.hpp).
    target_include_directories(ares_bridge SYSTEM PRIVATE
        "${ARES_SUBMODULE_PATH}"
        "${ARES_SUBMODULE_PATH}/ares"
        "${ARES_SUBMODULE_PATH}/nall"
        "${ARES_SUBMODULE_PATH}/ares/ares"
        "${ARES_SUBMODULE_PATH}/ares/n64"
        "${ARES_SUBMODULE_PATH}/libco"
        "${ARES_SUBMODULE_PATH}/thirdparty"
    )

    # The real glue.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/ares_core_glue.cpp")
        target_sources(ares_bridge PRIVATE
            src/ares_core_glue.cpp
        )
    else()
        message(WARNING
            "WITH_ARES_BRIDGE=ON but src/ares_core_glue.cpp does not "
            "exist yet. Bridge will link with placeholder bodies only. "
            "See DESIGN.md.")
    endif()

    # Phase 2 / Stage B: always-on RSP per-instruction trace ring.
    # Implementation depends on the matching extern "C" hook in the
    # vendored ares/n64/rsp/rsp.cpp (a 4-line modification — see the
    # comment in that file). If the hook is missing, the linker will
    # complain about an undefined reference to
    # `ares_rsp_external_instruction_hook`.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/ares_rsp_ring.cpp")
        target_sources(ares_bridge PRIVATE
            src/ares_rsp_ring.cpp
        )
    endif()

    # Link the pre-built Ares stack. Order: ares first (consumer), then
    # the libs ares depends on.
    target_link_libraries(ares_bridge PRIVATE
        "${_ares_lib}"
        "${_nall_lib}"
        "${_libco_lib}"
        "${_chdr_lib}"
        "${_sljit_lib}"
        "${_lzma_lib}"
        "${_zlib_lib}"
        "${_zstd_lib}"
    )

    # Ares pulls in winmm + Threads + WinSock + Shell via its own
    # CMake; replicate. PUBLIC because consumer executables linking
    # ares_bridge inherit the same dependencies — nall's GDB server
    # uses winsock unconditionally and is reachable from any code
    # that includes <ares/ares.hpp>.
    if(WIN32)
        target_link_libraries(ares_bridge PUBLIC
            winmm     # multimedia (timeBeginPeriod etc)
            Ws2_32    # WinSock 2 (nall::GDB server)
            Shlwapi   # registry helpers (SHDeleteKey/Value)
        )
    endif()
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads)
    if(TARGET Threads::Threads)
        target_link_libraries(ares_bridge PRIVATE Threads::Threads)
    endif()

    target_compile_features(ares_bridge PRIVATE cxx_std_20)

    message(STATUS "ares-bridge: REAL mode enabled")
    message(STATUS "  Ares submodule: ${ARES_SUBMODULE_PATH}")
    message(STATUS "  Ares build:     ${ARES_BUILD_DIR}")

    # Stage A smoke-test executable. Validates that ares_bridge.lib
    # links cleanly against ares.lib + dependencies and that the
    # System construction + frame-step lifecycle runs end-to-end.
    # Lives under smoke/ rather than tests/ because the top-level
    # .gitignore reserves tests/ for local scratch directories.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/smoke/smoke_oracle_boot.cpp")
        add_executable(ares_bridge_smoke_oracle_boot
            smoke/smoke_oracle_boot.cpp
        )
        target_link_libraries(ares_bridge_smoke_oracle_boot PRIVATE
            ares_bridge
        )
        target_compile_features(ares_bridge_smoke_oracle_boot PRIVATE
            cxx_std_20
        )
        set_target_properties(ares_bridge_smoke_oracle_boot PROPERTIES
            FOLDER "ares-bridge/smoke"
        )
    endif()

    # Standalone TCP-driven oracle server. Lives in its own process so
    # it doesn't share libco / sljit / threading state with the
    # consumer (which empirically breaks Ares — see the comment at
    # the top of server/ares_oracle_server.cpp). Diff harnesses
    # connect to this server on TCP 4372 by default.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/server/ares_oracle_server.cpp")
        add_executable(ares_oracle_server
            server/ares_oracle_server.cpp
        )
        target_link_libraries(ares_oracle_server PRIVATE
            ares_bridge
        )
        target_compile_features(ares_oracle_server PRIVATE
            cxx_std_20
        )
        set_target_properties(ares_oracle_server PROPERTIES
            FOLDER "ares-bridge/server"
        )
    endif()

    # Single-task aspMain replay oracle (diffs recompiled-RSP audio vs ares).
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/server/ares_replay.cpp")
        add_executable(ares_replay
            server/ares_replay.cpp
        )
        target_link_libraries(ares_replay PRIVATE
            ares_bridge
        )
        target_compile_features(ares_replay PRIVATE
            cxx_std_20
        )
        set_target_properties(ares_replay PROPERTIES
            FOLDER "ares-bridge/server"
        )
    endif()
else()
    message(STATUS "ares-bridge: placeholder mode (set -DWITH_ARES_BRIDGE=ON to "
                   "enable real Ares integration)")
endif()
