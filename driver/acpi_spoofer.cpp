// ============================================================================
// acpi_spoofer.cpp -- ACPI table OEM ID patch (physical, like SMBIOS).
//
// Stage 1 -- physical tables:
//   RSDP discovery: "RSD PTR " signature, checksum-validated, scanned in the
//   legacy 0xE0000-0xFFFFF window (the ACPI spec scan region) with the same
//   read discipline as the SMBIOS entry-point scan (mm_lowest_page lowered
//   for the window and restored in __finally). from the RSDP: XSDT (64-bit,
//   rev 2+) preferred over RSDT, then every table-entry is checked for the
//   FACP (FADT).
//
// Stage 2 -- boot-cached copies:
//   a bounded physical-RAM scan (same walker as the SMBIOS boot-cache stage)
//   finds POOL COPIES of FACP/XSDT/RSDT tables -- the copies
//   GetSystemFirmwareTable('ACPI', ...) serves, same boot-cache reality as
//   SMBIOS -- and patches them with the same idempotent transform. the
//   physical tables sitting in real RAM ranges are re-encountered by that
//   scan too and left untouched (the transform is a no-op on its own
//   output), so physical + cached copies always agree.
//
// patched, slight-change style (2-3 chars per field, printable ASCII
// preserved, length preserved): the OEMID (6 bytes @10) and OEM Table ID
// (8 bytes @16) of the XSDT/RSDT and the FACP. every patched table's
// checksum byte (@9) is recomputed over the full table length -- a stale
// checksum is itself a spoofer tell.
//
// NOTE: windows parses these tables at BOOT; runtime patching is read-safe
// -- post-boot readers (usermode GetSystemFirmwareTable, driver queries)
// see the patched bytes, and nothing in nt re-parses them while running.
// validation at every step of the RSDP -> XSDT/RSDT -> FACP walk; any
// failure skips the stage cleanly. one-shot per install.
// ============================================================================

#include <impl/includes.h>

namespace spoof::acpi {

	namespace {

		constexpr std::uint32_t k_oemid_salt = 0xA0C1u;
		constexpr std::uint32_t k_oemtid_salt = 0xA0C2u;
		// ALL physical RAM, hard-capped (same rationale + worst-case budget
		// as the smbios boot-cache scan -- see smbios_spoofer.cpp). the
		// shipped 4 GB cap is why the 2026-09-06 pass patched the served
		// FACP copy but left the XSDT copy untouched: it lives above 4 GB on
		// this 32 GB box.
		constexpr std::uint64_t k_pool_scan_cap = 64ull << 30; // 64 GB hard cap
		constexpr std::uint32_t k_max_entries = 128;

		// checksum over [0, len): all bytes except @9 sum to 0 mod 256
		void fix_checksum( std::uint8_t* table, std::uint32_t len ) {
			if ( len <= 9 )
				return;
			std::uint32_t sum = 0;
			for ( std::uint32_t i = 0; i < len; ++i )
				sum += ( i == 9 ) ? 0u : table[ i ];
			table[ 9 ] = static_cast< std::uint8_t >( ( 0x100 - ( sum & 0xFF ) ) & 0xFF );
		}

		bool bytes_are( const std::uint8_t* p, const char* sig, std::uint32_t n ) {
			for ( std::uint32_t i = 0; i < n; ++i ) {
				if ( p[ i ] != static_cast< std::uint8_t >( sig[ i ] ) )
					return false;
			}
			return true;
		}

		// slight-change patch of the OEMID (@10, 6 bytes) + OEM Table ID
		// (@16, 8 bytes) + checksum of one ACPI table held in a buffer.
		// randomize_serial's is_default_string gate skips placeholder OEM
		// ids ("To Be Filled By Oem..."-style) -- they are not identity.
		bool patch_oem_fields( std::uint8_t* table, std::uint32_t len ) {
			if ( !table || len < 36 )
				return false;

			char oem[ 8 ]{ };
			char tid[ 9 ]{ };
			for ( std::uint32_t i = 0; i < 6; ++i )
				oem[ i ] = static_cast< char >( table[ 10 + i ] );
			for ( std::uint32_t i = 0; i < 8; ++i )
				tid[ i ] = static_cast< char >( table[ 16 + i ] );

			bool changed = false;
			if ( randomize_serial( oem, 6, k_oemid_salt ) ) {
				for ( std::uint32_t i = 0; i < 6; ++i )
					table[ 10 + i ] = static_cast< std::uint8_t >( oem[ i ] );
				changed = true;
			}
			if ( randomize_serial( tid, 8, k_oemtid_salt ) ) {
				for ( std::uint32_t i = 0; i < 8; ++i )
					table[ 16 + i ] = static_cast< std::uint8_t >( tid[ i ] );
				changed = true;
			}

			if ( changed )
				fix_checksum( table, len );
			return changed;
		}

		// read + validate + patch one ACPI table copy at a physical address.
		// `sig` is the expected 4-byte signature, `max_len` the sane length
		// ceiling for that table type. bounds: len is re-validated against
		// the full read; the whole window must be real RAM.
		bool patch_table_at( std::uint64_t pa, const char* sig,
			std::uint32_t min_len, std::uint32_t max_len ) {
			std::uint8_t hdr[ 8 ]{ };
			if ( !read_phys( pa, hdr, sizeof( hdr ) ) )
				return false;
			if ( !bytes_are( hdr, sig, 4 ) )
				return false;
			std::uint32_t len = 0;
			memcpy( &len, hdr + 4, sizeof( len ) );
			if ( len < min_len || len > max_len )
				return false;
			if ( !is_writable_ram( pa, len ) )
				return false;

			auto* table = static_cast< std::uint8_t* >(
				kernel::ex_allocate_pool_with_tag( len, 'pAcp' ) );
			if ( !table )
				return false;

			bool changed = false;
			if ( read_phys( pa, table, len ) && bytes_are( table, sig, 4 ) ) {
				std::uint32_t rlen = 0;
				memcpy( &rlen, table + 4, sizeof( rlen ) );
				if ( rlen == len ) {
					changed = patch_oem_fields( table, len );
					if ( changed )
						( void )write_phys( pa, table, len );
				}
			}
			kernel::ex_free_pool_with_tag( table, 'pAcp' );
			return changed;
		}

		// FADT is small and header-fixed: sane length window [0x84, 0x400]
		bool patch_fadt_at( std::uint64_t pa ) {
			return patch_table_at( pa, "FACP", 0x84, 0x400 );
		}

		// root table (XSDT or RSDT): patch its own OEM fields, then walk the
		// entry array (u64 for XSDT, u32 for RSDT, entries start at +36) and
		// patch every FACP found. entry count is hard-capped.
		bool patch_root_table( std::uint64_t pa, bool xsdt ) {
			const char* sig = xsdt ? "XSDT" : "RSDT";
			std::uint8_t hdr[ 8 ]{ };
			if ( !read_phys( pa, hdr, sizeof( hdr ) ) )
				return false;
			if ( !bytes_are( hdr, sig, 4 ) )
				return false;
			std::uint32_t len = 0;
			memcpy( &len, hdr + 4, sizeof( len ) );
			if ( len < 36 || len > 0x1000 )
				return false;
			if ( !is_writable_ram( pa, len ) )
				return false;

			auto* table = static_cast< std::uint8_t* >(
				kernel::ex_allocate_pool_with_tag( len, 'pAcp' ) );
			if ( !table )
				return false;

			bool any = false;
			if ( read_phys( pa, table, len ) && bytes_are( table, sig, 4 ) ) {
				std::uint32_t rlen = 0;
				memcpy( &rlen, table + 4, sizeof( rlen ) );
				if ( rlen == len ) {
					if ( patch_oem_fields( table, len ) )
						( void )write_phys( pa, table, len );
					any = true;

					const std::uint32_t esz = xsdt ? 8u : 4u;
					std::uint32_t count = ( len - 36 ) / esz;
					if ( count > k_max_entries )
						count = k_max_entries;
					for ( std::uint32_t n = 0; n < count; ++n ) {
						std::uint64_t entry_pa = 0;
						if ( esz == 8 )
							memcpy( &entry_pa, table + 36 + n * 8, sizeof( entry_pa ) );
						else {
							std::uint32_t v = 0;
							memcpy( &v, table + 36 + n * 4, sizeof( v ) );
							entry_pa = v;
						}
						if ( !entry_pa || entry_pa > 0xFFFFFFFFFFFFull )
							continue;
						std::uint8_t eh[ 8 ]{ };
						if ( !read_phys( entry_pa, eh, sizeof( eh ) ) )
							continue;
						if ( bytes_are( eh, "FACP", 4 ) )
							( void )patch_fadt_at( entry_pa );
					}
				}
			}
			kernel::ex_free_pool_with_tag( table, 'pAcp' );
			return any;
		}

		// RSDP scan of the legacy window. checksum-validated per ACPI spec:
		// v1: sum of bytes [0,20) == 0; rev >= 2: sum of [0,36) == 0 (the
		// v2 length field is at least 36 on every shipping rev-2 RSDP).
		bool find_rsdp( std::uint64_t* xsdt_pa, std::uint64_t* rsdt_pa ) {
			*xsdt_pa = 0;
			*rsdt_pa = 0;

			auto* page = static_cast< std::uint8_t* >(
				kernel::ex_allocate_pool_with_tag( 0x1000, 'pAcp' ) );
			if ( !page )
				return false;

			bool found = false;
			for ( std::uint64_t pa = k_legacy_base; pa < 0x100000ull; pa += 0x1000 ) {
				if ( !read_phys( pa, page, 0x1000 ) )
					continue;
				for ( std::uint32_t off = 0; off + 36 <= 0x1000; ++off ) {
					if ( !bytes_are( page + off, "RSD PTR ", 8 ) )
						continue;

					std::uint32_t sum20 = 0, sum36 = 0;
					for ( std::uint32_t i = 0; i < 36; ++i ) {
						if ( i < 20 )
							sum20 += page[ off + i ];
						sum36 += page[ off + i ];
					}
					const auto rev = page[ off + 15 ];
					if ( rev >= 2 ) {
						if ( ( sum20 & 0xFF ) || ( sum36 & 0xFF ) )
							continue;
						std::uint64_t xsdt = 0;
						memcpy( &xsdt, page + off + 24, sizeof( xsdt ) );
						std::uint32_t rsdt = 0;
						memcpy( &rsdt, page + off + 16, sizeof( rsdt ) );
						if ( xsdt > 0xFFFFFFFFFFFFull )
							xsdt = 0;
						*xsdt_pa = xsdt;
						*rsdt_pa = rsdt;
					} else {
						if ( sum20 & 0xFF )
							continue;
						std::uint32_t rsdt = 0;
						memcpy( &rsdt, page + off + 16, sizeof( rsdt ) );
						*rsdt_pa = rsdt;
					}
					found = true;
					break;
				}
				if ( found )
					break;
			}

			kernel::ex_free_pool_with_tag( page, 'pAcp' );
			return found;
		}

		// ---- boot-cache pool-copy scan --------------------------------------
		//
		// FACP/XSDT/RSDT copies in kernel pool: the in-window length field only
		// gates the cheap pre-check (per-type sanity window); patch_table_at
		// then re-reads + re-validates the FULL table through the same
		// read/verify/patch/write path the physical stage uses, so writes
		// only ever happen on a fully validated, RAM-backed, changed table.
		std::uint32_t g_pool_patched = 0;

		bool acpi_window( std::uint64_t window_pa, const std::uint8_t* window,
			std::uint32_t window_len ) {
			for ( std::uint32_t i = 0; i + 8 <= window_len; ++i ) {
				const char* want = nullptr;
				std::uint32_t max_len = 0;
				if ( window[ i ] == 'F' && window[ i + 1 ] == 'A'
					&& window[ i + 2 ] == 'C' && window[ i + 3 ] == 'P' ) {
					want = "FACP";
					max_len = 0x400;
				} else if ( window[ i ] == 'X' && window[ i + 1 ] == 'S'
					&& window[ i + 2 ] == 'D' && window[ i + 3 ] == 'T' ) {
					want = "XSDT";
					max_len = 0x1000;
				} else if ( window[ i ] == 'R' && window[ i + 1 ] == 'S'
					&& window[ i + 2 ] == 'D' && window[ i + 3 ] == 'T' ) {
					want = "RSDT";
					max_len = 0x1000;
				} else {
					continue;
				}

				std::uint32_t len = 0;
				memcpy( &len, window + i + 4, sizeof( len ) );
				if ( len < 36 || len > max_len )
					continue;

				if ( patch_table_at( window_pa + i, want, 36, max_len ) )
					++g_pool_patched;
			}
			return false; // never stop early: patch every copy in the cap
		}

	} // anonymous namespace

	bool install( ) {
		// one-shot per install: repeated op-17 is a no-op (the OEM transform
		// is idempotent anyway; the latch also skips the RAM scan)
		static bool s_done = false;
		static bool s_result = false;
		if ( s_done )
			return s_result;
		s_done = true;
		s_result = false;

		bool walked = false;

		// stage 1: physical tables. the RSDP lives in the reserved legacy
		// window below the lowest RAM PFN, so dpm's bound is lowered for the
		// walk and restored in __finally (an SEH fault inside dpm must never
		// leave it lowered for the rest of the driver's lifetime)
		const auto saved_low = phys::mm_lowest_page;
		if ( phys::mm_lowest_page > 0xE0ull )
			phys::mm_lowest_page = 0xE0ull;
		__try {
			std::uint64_t xsdt_pa = 0, rsdt_pa = 0;
			if ( find_rsdp( &xsdt_pa, &rsdt_pa ) ) {
				if ( xsdt_pa )
					walked = patch_root_table( xsdt_pa, true ) || walked;
				if ( rsdt_pa )
					walked = patch_root_table( rsdt_pa, false ) || walked;
			}
		}
		__finally {
			phys::mm_lowest_page = saved_low;
		}

		// stage 2: boot-cached pool copies (real RAM only -- no lowered bound
		// needed; the physical legacy-window tables are never in these ranges,
		// and physical tables in RAM ranges re-transform to themselves)
		g_pool_patched = 0;
		__try {
			( void )spoof::ramscan::walk( &acpi_window, k_pool_scan_cap );
		}
		__finally {
			// state lives in g_pool_patched; the frame keeps the raw-access
			// pattern uniform with stage 1
		}

		s_result = walked || g_pool_patched != 0;

		// per-stage report (bit layout in comm/spoof_stages.h): the physical
		// walk ran (attempted) and the pool scan ran; each reports what it
		// actually changed
		spoof::mark_stage( spoof::stages::acpi_physical, walked );
		spoof::mark_stage( spoof::stages::acpi_cache_scan, g_pool_patched != 0 );
		return s_result;
	}

} // namespace spoof::acpi