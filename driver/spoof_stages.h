#pragma once

// ============================================================================
// spoof_stages.h -- per-stage result bitmask for op 17 (spoof_hardware).
//
// ONE header, included by BOTH sides of the transport so the bit layout can
// never drift:
//   driver:  driver\shared.h includes "spoof_stages.h" (same directory)
//   loader:  cheatlabs\comm\wnf_client.hpp includes its own copy
//
// transport: control_data_t.m_mode (uint32). verified spare on both sides --
// no dispatcher op reads it as an input (verify/query_caps/get_cr3/swap/
// read_virtual/write_virtual/read_scatter all use m_size/m_count/m_address/
// m_process_id/m_address1), and the loader never set it before op 17 existed.
// control_data_t stays 176 bytes (static_asserts on both sides unchanged).
// the kernel dispatcher zeroes m_mode before spoof::install() and copies
// spoof::g_stage_mask into it after, so stale caller bytes can never leak
// into a report.
//
// encoding: 2 bits per stage.
//   bit 2i+0 = RAN     -- the stage's code path actually executed
//   bit 2i+1 = CHANGED -- the stage found something and mutated it
// reader interpretation (the loader's log line):
//   ran + changed      -> ok
//   ran + not changed  -> miss for a scan stage (no copy found), FAIL for an
//                         install-type stage (hook could not be installed)
//   not ran            -> skip (stage never executed)
//   no report at all   -> ? (op failed before any stage ran)
// ============================================================================

namespace spoof {
namespace stages {

enum stage_t : unsigned int {
	smbios_physical = 0,        // raw SMBIOS table patch in physical memory
	smbios_cache_scan = 1,      // kernel boot-cache pool copies (RSMB source)
	smbios_mssmbios_reg = 2,    // Services\mssmbios\Data SMBiosData cache
	bios_volatile_reg = 3,      // HARDWARE\DESCRIPTION\System\BIOS serial/GUID
	machineguid_productid = 4,  // Cryptography\MachineGuid + ProductId
	mac = 5,                    // NIC NetworkAddress overrides
	disk_devicemap_reg = 6,     // DEVICEMAP\Scsi SerialNumber copies
	disk_ioctl_hook_install = 7,// \Driver\Disk dispatch interception install
	edid = 8,                   // Enum\DISPLAY EDID blocks
	acpi_physical = 9,         // RSDP->XSDT/RSDT->FACP physical tables
	acpi_cache_scan = 10,       // FACP/XSDT/RSDT pool copies
};

constexpr unsigned int k_stage_count = 11;

// the stage bit the RAN flag lives at
constexpr unsigned int ran_bit( stage_t s ) {
	return 1u << ( 2u * static_cast< unsigned int >( s ) );
}

// the stage bit the CHANGED flag lives at
constexpr unsigned int changed_bit( stage_t s ) {
	return 1u << ( 2u * static_cast< unsigned int >( s ) + 1u );
}

// driver-side helper: record one stage's outcome into the mask
inline void mark( unsigned int& mask, stage_t s, bool changed ) {
	mask |= ran_bit( s );
	if ( changed )
		mask |= changed_bit( s );
}

// reader-side helpers
inline bool stage_ran( unsigned int mask, stage_t s ) {
	return ( mask & ran_bit( s ) ) != 0;
}

inline bool stage_changed( unsigned int mask, stage_t s ) {
	return ( mask & changed_bit( s ) ) != 0;
}

} // namespace stages
} // namespace spoof