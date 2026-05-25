# ARM64EC Callback Behavior Probe

This scratch repository runs tiny x64 and ARM64EC programs on GitHub's
Windows-on-Arm runner and records which xTAJIT notification callbacks fire for
executable memory-protection and section-map operations.

The output is observational. It is intended to inform Wine/FEX integration work,
not to assert pass/fail behavior.
