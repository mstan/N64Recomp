# Vendored TinyCC (libtcc) 0.9.27 — x86_64 Windows

Used as the in-process recompilation backend for runtime overlay/fragment shards
(see `LiveRecomp/tcc_generator.cpp`). libtcc.dll is loaded dynamically at
runtime; `lib/` (libtcc1-64.a) and `include/` are the bundled toolchain pointed
at via `tcc_set_lib_path`, shipped beside the host executable.

Source: official `tcc-0.9.27-win64-bin` distribution (https://bellard.org/tcc/).
TinyCC is distributed under the GNU Lesser General Public License (LGPL) v2.1.
For binary releases, ship the corresponding libtcc source + the LGPL text
alongside, per the project's GPL/LGPL release-compliance policy.
