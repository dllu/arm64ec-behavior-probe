# ARM64EC Callback Behavior Probe

This scratch repository runs a tiny x64 program on GitHub's Windows-on-Arm
runner and records which `xtajit64.dll` notification callbacks fire for
executable memory-protection and section-map operations.

The output is observational. It is intended to inform Wine/FEX integration work,
not to assert pass/fail behavior.
