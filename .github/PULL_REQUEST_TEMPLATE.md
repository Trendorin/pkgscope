## What and why

<!-- What does this change, and why? Link related issues. -->

## Checklist

- [ ] Builds with `-DPKGSCOPE_WERROR=ON`; `ctest` passes
- [ ] Parser changes: the fuzzer (`-DPKGSCOPE_FUZZ=ON`) ran for a few minutes without findings
- [ ] Sandbox changes: checked with a real package, and the host stayed untouched
- [ ] User-visible changes noted in `CHANGELOG.md` and both READMEs (EN and RU)
