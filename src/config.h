#ifndef __RECOMP_CONFIG_H__
#define __RECOMP_CONFIG_H__

#include <cstdint>
#include <filesystem>
#include <vector>

namespace N64Recomp {
    struct InstructionPatch {
        std::string func_name;
        int32_t vram;
        uint32_t value;
    };

    struct FunctionTextHook {
        std::string func_name;
        int32_t before_vram;
        std::string text;
    };

    struct FunctionSize {
        std::string func_name;
        uint32_t size_bytes;

        FunctionSize(const std::string& func_name, uint32_t size_bytes) : func_name(std::move(func_name)), size_bytes(size_bytes) {}
    };

    struct ManualFunction {
        std::string func_name;
        std::string section_name;
        uint32_t vram;
        uint32_t size;

        ManualFunction(const std::string& func_name, std::string section_name, uint32_t vram, uint32_t size) : func_name(std::move(func_name)), section_name(std::move(section_name)), vram(vram), size(size) {}
    };

    // [[input.decompressed_section]] — describes a runtime-decompressed
    // section. The recompiler decompresses it at build time so it can
    // emit MIPS-to-C for the bytes the runtime will produce. See
    // decompressed.h for the synthesis pipeline.
    struct DecompressedSection {
        std::string name;
        uint32_t vram = 0;
        uint32_t rom_wrapper = 0;
        std::string wrapper_format;
        bool relocatable = true;
    };

    // [[input.decompressed_section_pattern]] — describes a SLOT that
    // multiple decompressed fragments share at runtime. Stadium's
    // dynamic asset slots (e.g. vram 0x8FF00000) have hundreds of
    // wrappers that all link at the same vram and get swapped in/out.
    // For these, instead of declaring each wrapper individually, the
    // user describes the slot and the engine auto-discovers every
    // wrapper in the ROM that decompresses to a fragment at this
    // vram + format.
    //
    // Synthesized section names are: <base_name>__rom_<rom_wrapper>
    // where rom_wrapper is the ROM offset of each wrapper's magic.
    // Wrappers whose decompressed bytes hash-equal another wrapper's
    // are deduplicated (only one section emitted per distinct content;
    // the runtime-side dispatch handles which wrapper-offset is in
    // play at a given moment).
    struct DecompressedSectionPattern {
        // Base name for emitted sections; suffix __rom_<offset>
        // appends per wrapper. Defaults to "frag_<vram>" if empty.
        std::string base_name;
        uint32_t vram = 0;
        std::string wrapper_format;
        bool relocatable = true;
    };

    // [[input.decompressed_section_patch]] -- build-time patches applied to
    // decompressed fragment bytes before CFG discovery, reloc parsing, and
    // content hashing. These model game loader fixups that happen after
    // decompression but before the fragment is executed/registered.
    struct DecompressedSectionPatch {
        bool has_rom_wrapper = false;
        uint32_t rom_wrapper = 0;
        bool has_original_pattern_id = false;
        uint32_t original_pattern_id = 0;
        uint32_t offset = 0;
        uint32_t value = 0;
    };

    // [output] collision_policy — what to do when two emitted symbols
    // would share a name. "error" (default) aborts the build with a
    // message naming both colliders. "suffix" auto-disambiguates by
    // appending __rom_<rom_addr> to each colliding symbol.
    enum class CollisionPolicy {
        Error,   // default
        Suffix,
    };

    struct Config {
        int32_t entrypoint;
        int32_t functions_per_output_file;
        bool has_entrypoint;
        bool uses_mips3_float_mode;
        bool single_file_output;
        bool use_absolute_symbols;
        bool unpaired_lo16_warnings;
        bool trace_mode;
        bool allow_exports;
        bool strict_patch_mode;
        std::filesystem::path elf_path;
        std::filesystem::path symbols_file_path;
        std::filesystem::path func_reference_syms_file_path;
        std::vector<std::filesystem::path> data_reference_syms_file_paths;
        std::filesystem::path rom_file_path;
        std::filesystem::path output_func_path;
        std::filesystem::path relocatable_sections_path;
        std::filesystem::path output_binary_path;
        std::vector<std::string> stubbed_funcs;
        std::vector<std::string> ignored_funcs;
        std::vector<std::string> renamed_funcs;
        std::vector<InstructionPatch> instruction_patches;
        std::vector<FunctionTextHook> function_hooks;
        std::vector<FunctionSize> manual_func_sizes;
        std::vector<ManualFunction> manual_functions;
        std::vector<DecompressedSection> decompressed_sections;
        std::vector<DecompressedSectionPattern> decompressed_section_patterns;
        std::vector<DecompressedSectionPatch> decompressed_section_patches;
        // Authoritative function-entry seeds for decompressed sections,
        // expressed as absolute (bytes-encoded) link VRAMs. The engine's
        // CFG discovery cannot resolve indirect (jalr) / data-table function
        // pointers, so an entry only reached that way is never seeded and a
        // runtime call to it misses get_function. Each VRAM here that falls
        // inside a decompressed section's code region is force-seeded: if it
        // lands inside an already-emitted function it becomes a dispatch
        // alias (no parent split); otherwise a standalone function. This is
        // the manifest sink that the runtime capture loop folds back into
        // (see the runtime-overlay-discovery design). A VRAM matching no
        // section, or already covered, is a harmless no-op.
        std::vector<uint32_t> decompressed_force_function_vrams;
        CollisionPolicy collision_policy = CollisionPolicy::Error;
        std::string bss_section_suffix;
        std::string recomp_include;

        Config(const char* path);
        bool good() { return !bad; }
    private:
        bool bad;
    };
}

#endif
