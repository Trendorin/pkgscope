# Command line

```
pkgscope-cli [options] FILE
```

| option | |
|---|---|
| `--trace` | also run the file in the sandbox and record its behaviour |
| `--allow-network` | let the traced program reach the network (isolated by default) |
| `--timeout SEC` | seconds per sandbox stage (default from the settings) |
| `--keep` | keep the sandbox directory for manual inspection |
| `-j, --json PATH` | write a JSON report |
| `--html PATH` | write an HTML report |
| `--md PATH` | write a Markdown report |
| `-q, --quiet` | print only the verdict line |
| `--fail-on SEVERITY` | exit with status 3 if a finding of this severity or higher exists (`low`, `medium`, `high`, `critical`) |

## Exit codes

| code | meaning |
|---|---|
| 0 | done |
| 1 | the file could not be analysed |
| 2 | wrong arguments |
| 3 | `--fail-on` matched a finding |
| 4 | `--trace` was requested but the sandbox run did not complete (the static result is still printed) |
| 1 | also: a requested report file could not be written |

## In CI

```sh
pkgscope-cli --trace --fail-on high --json pkgscope.json ./dist/myapp.deb
```

The AppImage runs the same command line with `--cli`:
`./PkgScope-*.AppImage --cli FILE`.
