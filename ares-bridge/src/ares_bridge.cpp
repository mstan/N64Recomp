// Part of N64Recomp's ares-bridge subsystem (added by Matthew Stanley
// in mstan fork; not present upstream). Distributed under the project's
// MIT License (see ../../LICENSE).
//
// Copyright (c) 2026 Matthew Stanley
//
// ---------------------------------------------------------------------

/*
 * ares_bridge.cpp — placeholder build (real Ares core not linked).
 *
 * This file exists only so the linker resolves the bridge symbols
 * when N64Recomp is built without -DWITH_ARES_BRIDGE=ON. Every
 * functional entry point logs the call site and abort()s — there
 * is no silent NOT_IMPLEMENTED return path. Consumers MUST gate
 * calls behind ares_bridge_is_real(), which is the only function
 * here that returns without aborting.
 *
 * The real implementation lives behind WITH_ARES_BRIDGE=ON and
 * pulls in ares-bridge/third_party/ares + ares_core_glue.cpp.
 * See DESIGN.md.
 */

#include "ares_bridge.h"

/* When the real bridge is linked, ares_core_glue.cpp owns every
 * symbol declared in ares_bridge.h. This translation unit becomes
 * empty so the linker doesn't see duplicate definitions. */
#ifndef N64RECOMP_ARES_BRIDGE_REAL

#include <cstdio>
#include <cstdlib>

namespace {

[[noreturn]] void bridge_abort(const char *fn) {
    std::fprintf(stderr,
        "\nares-bridge: %s called but bridge was built as a "
        "placeholder.\n"
        "             Reconfigure with -DWITH_ARES_BRIDGE=ON and "
        "rebuild,\n"
        "             or gate the call behind ares_bridge_is_real() "
        "== 1.\n",
        fn);
    std::fflush(stderr);
    std::abort();
}

} // namespace

extern "C" {

ares_status_t ares_init(const char *) {
    bridge_abort("ares_init");
}

void ares_shutdown(void) {
    bridge_abort("ares_shutdown");
}

ares_status_t ares_reset(void) {
    bridge_abort("ares_reset");
}

ares_status_t ares_step_frame(void) {
    bridge_abort("ares_step_frame");
}

ares_status_t ares_step_instruction(void) {
    bridge_abort("ares_step_instruction");
}

ares_status_t ares_read_cpu_register(int, uint64_t *) {
    bridge_abort("ares_read_cpu_register");
}

ares_status_t ares_read_cp0_register(int, uint64_t *) {
    bridge_abort("ares_read_cp0_register");
}

ares_status_t ares_read_fpr(int, uint64_t *) {
    bridge_abort("ares_read_fpr");
}

ares_status_t ares_read_fpu_control(int, uint32_t *) {
    bridge_abort("ares_read_fpu_control");
}

ares_status_t ares_read_pc(uint32_t *) {
    bridge_abort("ares_read_pc");
}

ares_status_t ares_read_hi_lo(uint64_t *, uint64_t *) {
    bridge_abort("ares_read_hi_lo");
}

ares_status_t ares_read_memory(uint32_t, void *, size_t) {
    bridge_abort("ares_read_memory");
}

ares_status_t ares_set_controller(int, const ares_input_t *) {
    bridge_abort("ares_set_controller");
}

ares_status_t ares_save_state(void *, size_t, size_t *) {
    bridge_abort("ares_save_state");
}

ares_status_t ares_load_state(const void *, size_t) {
    bridge_abort("ares_load_state");
}

/* Capability probes — these are the ONLY functions that may return
 * without aborting. Their entire purpose is letting consumers ask
 * "is this build wired up?" before calling anything else. */

int ares_bridge_is_real(void) {
#ifdef N64RECOMP_ARES_BRIDGE_REAL
    return 1;
#else
    return 0;
#endif
}

const char *ares_bridge_version(void) {
#ifdef N64RECOMP_ARES_BRIDGE_REAL
    /* Real builds replace this string with the linked Ares git
     * SHA via a CMake-generated header. */
    return "ares-bridge: real build, ares_core_glue.cpp pending";
#else
    return "placeholder (build with -DWITH_ARES_BRIDGE=ON)";
#endif
}

} /* extern "C" */

#endif /* !N64RECOMP_ARES_BRIDGE_REAL */
