# Patch archive provenance

**Deferred:** Further patch 445 analysis and compatibility work is postponed
until base-game work is complete. The observations below are preserved as
historical provenance and do not make patch research an active priority.

**Date:** 2026-10-17. The separately supplied `drakan_patch445_eng.zip` has
SHA-256 `40e219a0cda8593be3c3489033fbf045f5c53e4cfba610b95e0836bd52458ec1`.
The existing separate `drakan_patch445_eng/data1.cab` was inspected with
Unshield 1.6.2; its derivation from that ZIP was not checked. The cabinet lists 42 files, including `Drakan.exe` and
`Readme_Patch.txt`. Only those two were extracted to the separate, ignored
`research/installed/patch445-probe/` directory; no retail files were replaced.

## Observed

- The extracted README has SHA-256
  `74e0b283fd952b7ce28b357c2b37983147a106068745ee16707a9c10a1b382b1`
  and identifies itself as the Patch 445 README. This supports identifying the
  cabinet as a patch 445 distribution; it does not prove what was installed.
- The extracted PE32 i386 executable has SHA-256
  `d635997c70df4f476adb5f7a7c11183840ebb073c28320c67f5620daa896ec27`,
  different from the retail executable. Its UTF-16 version-resource strings
  report FileVersion and ProductVersion `1, 0, 0, 1`, not a `445` build
  identifier. An exact executable-specific patch/build number is therefore
  **unknown**; the README and cabinet association are not independent proof
  of the executable's internal build number.

## Reproduction

From the repository root, choose a new private output directory and run:

```sh
unshield -V
unshield l drakan_patch445_eng/data1.cab
unshield -d research/installed/patch445-probe x drakan_patch445_eng/data1.cab Drakan.exe Readme_Patch.txt
sha256sum research/installed/patch445-probe/Drakan_Patch_Files/{Drakan.exe,Readme_Patch.txt}
file research/installed/patch445-probe/Drakan_Patch_Files/Drakan.exe
strings -el research/installed/patch445-probe/Drakan_Patch_Files/Drakan.exe
```

Keep this patch reference separate from retail research fixtures. No extracted
patch files or original archives belong in Git.
