# Security policy

PkgScope opens hostile files on purpose and can run untrusted installers in its sandbox, so
security problems matter. Please report them privately.

## Reporting

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/Trendorin/pkgscope/security/advisories/new).
Please don't open a public issue for a security problem. Include the file that triggers it (or
how to build one), the version, your distribution and kernel. You will get an answer within a week.

## What counts

- a crafted file that crashes a parser, makes it read or write out of bounds, or hangs it;
- extraction that writes outside its directory, follows a symlink or hardlink out of it, or
  leaves setuid files or device nodes behind;
- static inspection executing anything from the input;
- a traced program that changes the real system, reads your home directory, reaches the host's
  abstract Unix sockets or signals processes outside the sandbox, or survives the end of a run;
- `pkgscope-sandbox` granting more than it should to an unprivileged caller.

Out of scope: malware that PkgScope does not detect (please open a normal issue with a sample
description), and network access during a trace you started with **Allow network**.

## Supported versions

Security fixes go into the latest release.
