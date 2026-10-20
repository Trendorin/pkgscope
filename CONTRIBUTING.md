# Contributing to PkgScope

Thanks for helping. Bug reports, new rules, formats, documentation and code are all welcome.
For anything larger than a small fix, open an issue first so we can agree on the approach.

## Build and test

```sh
cmake -S . -B build -G Ninja -DPKGSCOPE_WERROR=ON -DPKGSCOPE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure

# parsers: libFuzzer with ASan and UBSan (clang)
CC=clang CXX=clang++ cmake -S . -B fuzz -DPKGSCOPE_FUZZ=ON -DPKGSCOPE_BUILD_GUI=OFF
cmake --build fuzz --target pkgscope-fuzz && fuzz/pkgscope-fuzz -max_total_time=300 corpus/
```

## Guidelines

- `src/core` has no Qt Widgets; everything that reads input is bounds-checked and never
  executes it. A new parser gets a line in `tests/fuzz/fuzz_parsers.cpp`.
- Files from a package are opened beneath their root without following symlinks
  (`securefs::openBeneath`, `readBeneath`).
- A rule needs a severity, a plain explanation of why it matters and the evidence it found.
- `pkgscope-sandbox` stays small, Qt-free and not setuid.
- Note user-visible changes in `CHANGELOG.md` and both READMEs.

By contributing you agree that your work is licensed under the MIT license.
