# spoofer

Kernel-mode hardware spoofer. Runs entirely in ring 0 via a mapped driver — no user-mode hooks, no filter drivers, no persistent services. Maps once, spoofs everything, exits clean.

## What it actually touches

SMBIOS tables (Type 0, 1, 2, 3, 4, 11, 17, 41) rewritten in memory. EFI variables — SecureBoot, SetupMode, PK/KEK/db/dbx — patched at runtime. Boot identifiers in BCD and bootmgr. Disk serials in two places: the cached registry copy under `HARDWARE\DEVICEMAP\Scsi` and the live storage stack via a `\Driver\Disk` IRP hook so WMI queries match what the registry says. NIC MAC addresses on Ethernet and Wi-Fi adapters. UUID cache, ARP neighbor table, monitor EDID (including `EDID_OVERRIDE` subkeys, checksum recalculated), USB storage serials, volume GUIDs in `MountedDevices`, Windows ProductId (slight digit drift, activation blobs left alone), trace IDs across ETW/WMI/DiagTrack, MachineGuid, HardwareConfig\LastConfig with subkey carry, Cryptography keys, USN journal deleted and recreated, file timestamps on prefetch/recent/shellbags, artifacts cleanup (Prefetch, Event Logs, ETW) with credential preservation, Bluetooth radio addresses, TPM EK certs and owner auth, WMI CIMOM repository cache, hostname (NetBIOS + DNS), ACPI tables in memory (DSDT/SSDT), GPU identity in PCI config space and driver registry, PnP enum tree device instance paths, WiFi driver MAC via vendor NDIS OIDs.

Twenty-four stages total. Each one idempotent — same salt + boot nonce means same output. Run it twice in the same boot and nothing changes. Fresh boot, fresh mapper load, fresh nonce, new identity.

## How it works

The user-mode GUI (ImGui + DX11) launches a mapper that installs a vulnerable driver service (randomized name, `SeLoadDriverPrivilege`), opens its device, and uses its physical memory read/write primitives to allocate a large-page cave inside ntoskrnl.exe's address range. The spoof driver image gets relocated, imports resolved against kernel exports, sections copied, then written page-by-page to that cave. Entry point invoked through a hijacked `NtWriteVirtualMemory` SSDT slot — verified before and after, restored on exit. No shellcode, no persistent kernel component. The mapped driver runs, hits all stages, returns status, mapper tears down everything.

Preflight runs first: validates PDB symbols, paging setup, SSDT slot integrity, ntoskrnl range. Aborts clean if anything's off.

## Requirements

- Windows 10 1903 through 24H2/25H2
- Vulnerable driver with physical memory R/W (defaults to `EBIoDispatch`, IOCTLs `0x22E008` / `0x22E00C`)
- PDBs for your ntoskrnl.exe build
- Admin rights
- Secure Boot off (EFI variables need it)

## Building

Open `spoofer.sln` in VS2022. Three projects in the solution: `spoofer` (GUI), `mapper` (kernel loader), `driver` (the mapped image). x64 Release. Dependencies in `third_party/` — imgui, oxorany, ia32.

## Running

Run `spoofer.exe` as Administrator. Two buttons:

**SPOOF HARDWARE** — full run, all stages. Checkboxes let you disable network spoof (NIC/WiFi MAC) and artifact cleanup (Prefetch/Logs/ETW) independently.

**CLEAN TRACES ONLY** — just the artifact cleanup stage, standalone.

Logs to `spoofer.log` in the working directory. GUI shows a live log with color-coded output.

## Repository name

`spoofer`

## Description

Kernel-mode hardware spoofer — SMBIOS, disk, NIC, EDID, GPU, TPM, ACPI, EFI, boot IDs, USB, volumes, ProductId, traces, Bluetooth, hostname, WMI, ARP, UUID cache, enum tree, WiFi driver MAC. Mapped via SSDT hijack, runs once per boot, idempotent transforms.