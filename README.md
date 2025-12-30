# WinDumper

**WinDumper** is a Windows research and reverse-engineering utility focused on discovering, cataloging, and resolving **unexported `ntdll.dll` functions** across multiple Windows builds using **AOB (Array-Of-Bytes) signatures**.

The primary goal of the project is to provide a practical replacement for `GetProcAddress` when working with **internal / non-exported `ntdll` routines**, exposed through a helper called:

`GetProcAddressAOB()`

This allows code to dynamically locate internal functions at runtime without relying on exports, hard-coded offsets, or fragile symbol loading.

---

## What WinDumper Does

- Loads one or more `ntdll.dll` binaries (`*.bin`) **without executing their entrypoints**
- Downloads and loads the matching PDB for each binary
- Enumerates all symbols
- Filters to **non-exported, real code symbols inside `.text`**
- Generates **portable AOB signatures** using Capstone disassembly
- Uses **wildcards (`??`)** to tolerate changes between builds
- Validates every AOB using a pattern scanner
- Merges AOBs across **multiple Windows versions**
- Outputs a **copy-pasteable C table** for runtime lookup
- Exposes a simple runtime resolver:
  `GetProcAddressAOB("ntdll.dll", "FunctionName")`

---

## Why Some Functions Show as “Not Found”

When testing the generated AOB table using the example runtime loop, you may see output similar to:

`[ERROR] RtlpSomeInternalRoutine -> NOT FOUND`

This is **expected behavior** and not a bug.

### Why this happens

- The function **does not exist** in the `ntdll.dll` version currently running
- The function existed in *older* or *newer* Windows builds, but not this one
- The function was removed, inlined, or renamed by Microsoft
- The internal implementation changed enough that the AOB no longer matches

WinDumper intentionally aggregates AOBs from **multiple different `ntdll` builds**.  
As a result, some AOBs will naturally fail on systems that don’t contain that function.

---

## AOB Portability & Wildcards

AOBs are generated using **instruction-aware disassembly** and include wildcards for:

- Relative call/jump targets
- RIP-relative displacements (x64)
- PC-relative instructions (ARM64)
- Other build-specific immediates

Example AOB:

`48 8B ?? ?? ?? ?? 48 85 C0 74 ??`

Wildcards allow the signature to remain valid across:

- Minor compiler changes
- Small Windows updates

That said:

**No AOB can be guaranteed to survive all Windows versions forever.**

As Microsoft updates `ntdll.dll`, some AOBs will eventually need to be refreshed.

---

## Long-Term Maintenance

WinDumper is intentionally **data-driven**.

Over time:
- New Windows builds introduce new internal functions
- Old internal functions may disappear
- Existing AOBs may become stale

Updating WinDumper generally means:
1. Collecting newer `ntdll.dll` binaries
2. Re-running the generator
3. Replacing the generated AOB table

Older systems may also require **older AOB sets** if backward compatibility is required.

---

## Intended Use Cases

- Reverse engineering & research
- Internal Windows API exploration
- Loader / debugger tooling
- Educational projects
- Experimentation with undocumented behavior

This project is **not** intended to provide ABI stability guarantees or production-safe APIs.

---

## Core Feature: GetProcAddressAOB

The main reason this project exists.

`void* GetProcAddressAOB(const char* moduleName, const char* functionName);`

This function:
- Looks up the function name in the generated AOB table
- Tries all known AOBs for that function
- Scans the module at runtime
- Returns the resolved address or `NULL`

It enables calling internal `ntdll` routines as if they were exported.

---

## Disclaimer

This project relies on:
- Undocumented Windows internals
- Binary pattern matching
- Behavior that may change at any time

Use at your own risk.

WinDumper is intended for **research and learning purposes only**.

---
