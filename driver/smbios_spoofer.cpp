// ============================================================================
// smbios_spoofer.cpp -- raw SMBIOS table spoof.
//
// Copies of the SMBIOS data, all patched with the SAME idempotent transform
// so every one of them converges to the same spoofed bytes:
//   1. the raw firmware table in PHYSICAL memory -- found by FOLLOWING
//      POINTERS (the KeLoaderBlock locator: loader parameter block ->
//      extension -> SMBiosEPSHeader -> StructureTableAddress, hint
//      offsets first, generic qword walk with structure validation
//      deciding -- see collect_loader_candidates) plus the secondary
//      legacy-window anchor sweep ("_SM_" 2.x / "_SM3_" 3.x, checksum
//      soft-checked) over frames the kernel itself reports as RAM plus
//      the legacy shadow window, and patched in place.
//      THIS is the copy GetSystemFirmwareTable('RSMB') serves (2026-09-06
//      second live test, by elimination: the RAM scan patched every
//      chain-validatable pool copy and RSMB still served the real uuid).
//      the DMI table sits in firmware-reserved DRAM -- not on the OS RAM
//      list -- so admission is by structure-chain validation of the exact
//      bytes about to be rewritten (see try_patch_table_at), not by the
//      RAM-range check. the EPS sweep itself reads ONLY provably-DRAM
//      frames (2026-09-06 boot-B post-mortem: the blind sub-16MB sweep of
//      the first cut PTE-remapped the VGA aperture -- device MMIO -- and
//      the box hard-froze with no dump ~2.5 min later; the RAM-listed-only
//      build before it was stable for 42 min; see collect_eps_candidates).
//      after every surface is patched, an in-kernel 'RSMB' query
//      (ZwQuerySystemInformation class 76, resolved at runtime) CONFIRMS
//      the served bytes carry the transform -- the stage reports ok only
//      when they do (see verify_served_spoofed).
//   2. the mssmbios service registry cache
//      (SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData) -- same
//      table bytes behind a small header, patched with ZwSetValueKey. THIS
//      is the copy the WMI path serves (Win32_ComputerSystemProduct.UUID
//      tracked it live).
//   3. the KERNEL BOOT CACHE -- pool copies of the table found by a bounded
//      physical-RAM scan for the table's own type-0 vendor string,
//      validated by a coherent structure-chain walk, patched with the same
//      transform. NOT the bytes RSMB is served from on this platform (the
//      physical table is -- see 1), but patched anyway: belt-and-suspenders
//      for pool-resident consumers and for OS revisions that do serve a
//      cached copy
//   4. the volatile HKLM\HARDWARE\DESCRIPTION\System\BIOS values windows
//      stamps at boot -- SystemSerialNumber / BaseBoardSerialNumber /
//      SystemGUID are restamped from the patched table so registry-first
//      readers (most identification kits) see the spoofed values too
//
// The patch set (serial strings of type 1/2/3/17 + the type-1 UUID) is
// deliberately narrow: manufacturer/product/model strings, the type-0 vendor
// + BIOS version strings and every other identity anchor (CPU brand, GPU
// names) are NEVER touched -- see shared.h. the transform family lives in
// shared.h (slight-change: shape/length/class preserved, ~30% of alnum
// positions drift, min 2 max 8, deterministic per install, idempotent).
// ============================================================================

#include <impl/includes.h>

// nt!KeLoaderBlock -- the LOADER_PARAMETER_BLOCK pointer, exported by
// ntoskrnl as a DATA symbol. the ONE permitted import addition to this
// driver: the mapper resolves exported data symbols exactly like
// function exports (import-by-name against the ntoskrnl export table),
// and the smbios physical stage dereferences it to follow the
// firmware-reported pointer chain to the SMBIOS entry point instead of
// sweeping for anchors in memory the OS does not own. declared here
// because no WDK header declares it; declared at file scope because an
// extern "C" import placed inside the anonymous namespace below would
// get internal linkage.
extern "C" __declspec( dllimport ) void* KeLoaderBlock;

namespace spoof::smbios {

	namespace {

		#pragma pack( push, 1 )
		struct smbios_header_t {
			std::uint8_t  m_type;
			std::uint8_t  m_length;
			std::uint16_t m_handle;
		};
		struct smbios_type1_t {
			smbios_header_t m_hdr;
			std::uint8_t m_manufacturer, m_product_name, m_version, m_serial_number;
			std::uint8_t m_uuid[ 16 ];
		};
		struct smbios_type2_t {
			smbios_header_t m_hdr;
			std::uint8_t m_manufacturer, m_product, m_version, m_serial_number;
		};
		struct smbios_type3_t {
			smbios_header_t m_hdr;
			std::uint8_t m_manufacturer, m_type, m_version, m_serial_number, m_asset_tag;
		};
		struct smbios_type17_t {
			smbios_header_t m_hdr;
			std::uint16_t m_phys_array_handle, m_mem_err_handle, m_total_width, m_data_width, m_size;
			std::uint8_t  m_form_factor, m_device_set, m_device_locator, m_bank_locator, m_mem_type;
			std::uint16_t m_type_detail, m_speed;
			std::uint8_t  m_manufacturer, m_serial_number, m_asset_tag, m_part_number;
		};
		#pragma pack( pop )

		char* get_string_at( smbios_header_t* hdr, std::uint8_t* table_end,
			int idx, std::uint32_t* out_len ) {
			if ( out_len )
				*out_len = 0;
			if ( idx == 0 || !hdr || !table_end )
				return nullptr;
			auto* cur = reinterpret_cast< char* >( hdr ) + hdr->m_length;
			auto* lim = reinterpret_cast< char* >( table_end );
			if ( cur >= lim )
				return nullptr;
			for ( int i = 0; i < idx - 1; ++i ) {
				while ( cur < lim && *cur )
					++cur;
				if ( ++cur >= lim )
					return nullptr;
			}
			auto* end = cur;
			while ( end < lim && *end )
				++end;
			if ( end >= lim || end == cur )
				return nullptr;
			if ( out_len )
				*out_len = static_cast< std::uint32_t >( end - cur );
			return cur;
		}

		// NOTE: the deterministic transform family (hash_bytes / shape_hash /
		// is_mutable / randomize_serial / randomize_chars) lives in shared.h
		// -- the smbios, disk and edid stages must run the SAME algorithm so
		// two copies of one identifier (firmware table + kernel boot cache +
		// registry cache + live IOCTL buffer) always patch to identical bytes.

		// uuid transform: a GUID has no realism anchor and no "shape" to
		// preserve, so the spoofed uuid is a per-install CONSTANT -- every
		// byte derives from (salt, s_boot_nonce) only, then the v4/variant
		// bits are forced. that makes it IDEMPOTENT like the string family:
		// an already-patched copy transforms to itself (changed=false), so
		// every copy of the table converges to the same uuid no matter what
		// order the surfaces are patched in. an all-FF placeholder is left
		// alone (not identity), but an all-ZERO uuid IS spoofed (2026-09-06:
		// this board's mssmbios registry cache carries an all-zero t1 uuid;
		// a zero uuid is a machine-distinct constant too -- and skipping it
		// is what made the mssmbios stage report miss with nothing mutable).
		bool randomize_uuid( std::uint8_t* uuid, std::uint32_t salt ) {
			bool all_ff = true;
			for ( int i = 0; i < 16; ++i ) {
				all_ff = all_ff && uuid[ i ] == 0xffu;
			}
			if ( all_ff )
				return false;
			auto seed = hash_bytes( nullptr, 0, salt ) ^ ( spoof::s_boot_nonce | 0x9E3779B9u );
			std::uint8_t out[ 16 ]{ };
			for ( int i = 0; i < 16; ++i ) {
				seed = seed * 0x343fdu + 0x269ec3u;
				out[ i ] = static_cast< std::uint8_t >( seed >> 16 );
			}
			out[ 6 ] = static_cast< std::uint8_t >( ( out[ 6 ] & 0x0Fu ) | 0x40u ); // v4
			out[ 8 ] = static_cast< std::uint8_t >( ( out[ 8 ] & 0x3Fu ) | 0x80u ); // variant
			for ( int i = 0; i < 16; ++i ) {
				if ( out[ i ] != uuid[ i ] ) {
					memcpy( uuid, out, 16 );
					return true;
				}
			}
			return false; // already this install's uuid -- no drift
		}

		// ---- BIOS volatile-key sync ------------------------------------------
		//
		// usermode identification kits resolve the system/baseboard serial
		// through BOTH the raw firmware tables and the volatile
		// HKLM\HARDWARE\DESCRIPTION\System\BIOS values windows stamps at
		// boot. the registry copy still holds the OLD serial after the table
		// patch, so any reader that goes to the registry first (most do -- no
		// firmware query needed) would see the pre-spoof identity. capture
		// the freshly written serials and restamp the volatile keys; that
		// hive is rebuilt from firmware at every boot, so it self-heals.

		constexpr int k_slot_system_serial = 0;
		constexpr int k_slot_baseboard_serial = 1;
		constexpr int k_slot_count = 2;

		struct bios_capture_t {
			bool m_set[ k_slot_count ];
			wchar_t m_val[ k_slot_count ][ 64 ];
			bool m_any;
			// freshly patched type-1 UUID (restamped into the volatile BIOS
			// key as SystemGUID so the registry mirror tracks the table)
			bool m_uuid_set;
			std::uint8_t m_uuid[ 16 ];
		};

		void reset_capture( bios_capture_t* cap ) {
			if ( !cap )
				return;
			for ( auto& s : cap->m_set )
				s = false;
			for ( auto& v : cap->m_val )
				v[ 0 ] = L'\0';
			cap->m_any = false;
			cap->m_uuid_set = false;
			for ( auto& b : cap->m_uuid )
				b = 0;
		}

		void capture_serial( bios_capture_t* cap, int slot, const char* s, std::uint32_t len ) {
			if ( !cap || !s || !len || slot < 0 || slot >= k_slot_count )
				return;
			if ( len > 62 )
				len = 62;
			auto* dst = cap->m_val[ slot ];
			for ( std::uint32_t i = 0; i < len; ++i )
				dst[ i ] = static_cast< wchar_t >( static_cast< unsigned char >( s[ i ] ) );
			dst[ len ] = L'\0';
			cap->m_set[ slot ] = true;
			cap->m_any = true;
		}

		void capture_uuid( bios_capture_t* cap, const std::uint8_t* uuid ) {
			if ( !cap || !uuid )
				return;
			memcpy( cap->m_uuid, uuid, 16 );
			cap->m_uuid_set = true;
			cap->m_any = true;
		}

		std::uint32_t modify_table( std::uint8_t* table, std::uint32_t length,
			bios_capture_t* capture = nullptr ) {
			std::uint32_t patched = 0;
			for ( auto* cur = table; cur < table + length; ) {
				auto* hdr = reinterpret_cast< smbios_header_t* >( cur );
				if ( hdr->m_length < sizeof( smbios_header_t )
					|| cur + hdr->m_length > table + length )
					break;
				if ( hdr->m_type == 127 )
					break;

				if ( hdr->m_type == 1
					&& hdr->m_length >= ( std::uint8_t )( offsetof( smbios_type1_t, m_serial_number ) + 1 ) ) {
					auto* t1 = reinterpret_cast< smbios_type1_t* >( hdr );
					std::uint32_t slen = 0;
					auto* sv = get_string_at( hdr, table + length, t1->m_serial_number, &slen );
					if ( sv ) {
						if ( randomize_serial( sv, slen, 0x1103u + hdr->m_handle ) ) {
							++patched;
							capture_serial( capture, k_slot_system_serial, sv, slen );
						}
					}
					if ( hdr->m_length >= ( std::uint8_t )( offsetof( smbios_type1_t, m_uuid ) + 16 ) ) {
						if ( randomize_uuid( t1->m_uuid, 0x1104u + hdr->m_handle ) ) {
							++patched;
							capture_uuid( capture, t1->m_uuid );
						}
					}
				} else if ( hdr->m_type == 2
					&& hdr->m_length >= ( std::uint8_t )( offsetof( smbios_type2_t, m_serial_number ) + 1 ) ) {
					auto* t2 = reinterpret_cast< smbios_type2_t* >( hdr );
					std::uint32_t slen = 0;
					auto* sv = get_string_at( hdr, table + length, t2->m_serial_number, &slen );
					if ( sv ) {
						if ( randomize_serial( sv, slen, 0x1203u + hdr->m_handle ) ) {
							++patched;
							capture_serial( capture, k_slot_baseboard_serial, sv, slen );
						}
					}
				} else if ( hdr->m_type == 3
					&& hdr->m_length >= ( std::uint8_t )( offsetof( smbios_type3_t, m_serial_number ) + 1 ) ) {
					auto* t3 = reinterpret_cast< smbios_type3_t* >( hdr );
					std::uint32_t slen = 0;
					auto* sv = get_string_at( hdr, table + length, t3->m_serial_number, &slen );
					if ( sv )
						patched += randomize_serial( sv, slen, 0x1302u + hdr->m_handle ) ? 1u : 0u;
					if ( hdr->m_length >= ( std::uint8_t )( offsetof( smbios_type3_t, m_asset_tag ) + 1 ) ) {
						std::uint32_t alen = 0;
						auto* av = get_string_at( hdr, table + length, t3->m_asset_tag, &alen );
						if ( av )
							patched += randomize_serial( av, alen, 0x1304u + hdr->m_handle ) ? 1u : 0u;
					}
				} else if ( hdr->m_type == 17
					&& hdr->m_length >= ( std::uint8_t )( offsetof( smbios_type17_t, m_serial_number ) + 1 ) ) {
					auto* t17 = reinterpret_cast< smbios_type17_t* >( hdr );
					std::uint32_t slen = 0;
					auto* sv = get_string_at( hdr, table + length, t17->m_serial_number, &slen );
					if ( sv )
						patched += randomize_serial( sv, slen, 0x1118u + hdr->m_handle ) ? 1u : 0u;
				}

				auto* eos = cur + hdr->m_length;
				while ( eos < table + length - 1 && ( *eos || *( eos + 1 ) ) )
					++eos;
				if ( eos >= table + length - 1 )
					break;
				cur = eos + 2;
			}
			return patched;
		}

		// ---- physical read/write helpers ------------------------------------
		//
		// read_phys / write_phys / is_writable_ram / k_legacy_* now live in
		// shared.h (spoof::) -- the acpi stage runs the same RAM-window
		// discipline against the same kernel RAM list.

		// boot-cache scan signature (defined here; the deriving function and
		// the scan stage below fill it in)
		constexpr std::uint32_t k_max_sig = 24;

		struct cache_sig_t {
			bool m_valid = false;
			std::uint32_t m_len = 0;
			std::uint8_t m_bytes[ k_max_sig ]{ };
		};

		// scan-pass context (single comms thread, one install). the boot-cache
		// scan uses g_scan_sig, so these live here, above every consumer
		cache_sig_t g_scan_sig;
		std::uint64_t g_phys_table_pa = 0;
		std::uint32_t g_phys_table_len = 0;
		std::uint32_t g_scan_patched = 0;

		// ---- hard per-stage pool budget (2026-09-06 crash audit) -----------
		//
		// the stage's allocations are all balanced pair-by-pair, but a
		// one-shot kernel stage that allocates must also be UNABLE to consume
		// unbounded pool if any path ever regresses. every smbios-stage
		// allocation goes through stage_alloc/stage_free; the running total is
		// hard-capped and reset once per install. a stage that hits the cap
		// reports a miss -- a spoof miss is always recoverable, pool
		// exhaustion is not.
		constexpr std::uint32_t k_stage_pool_budget = 2u * 1024u * 1024u;
		std::uint32_t g_stage_pool_bytes = 0;

		void* stage_alloc( std::uint32_t size, unsigned long tag ) {
			if ( !size || g_stage_pool_bytes + size > k_stage_pool_budget )
				return nullptr;
			auto* p = kernel::ex_allocate_pool_with_tag( size, tag );
			if ( p )
				g_stage_pool_bytes += size;
			return p;
		}

		void stage_free( void* p, std::uint32_t size, unsigned long tag ) {
			if ( p ) {
				kernel::ex_free_pool_with_tag( p, tag );
				g_stage_pool_bytes -= size;
			}
		}

		void derive_signature( const std::uint8_t* table, std::uint32_t table_len,
			cache_sig_t* sig );

		// ---- SMBIOS entry point discovery ------------------------------------
		//
		// generic spec discovery, board-agnostic by construction: nothing
		// here is derived from any one machine -- the anchors are the spec
		// signatures, the ranges are platform facts, and every candidate is
		// admitted only by a structure-chain walk of its own bytes.
		//
		//   - the SMBIOS spec's own scan region is the legacy 0xE0000-0xFFFFF
		//     window (2.x "_SM_" anchors); UEFI carries NO placement rule for
		//     the 3.x "_SM3_" anchor -- it lives wherever the firmware put it,
		//     commonly in conventional or firmware-reserved low memory.
		//   - the sweep therefore covers the sub-16MB physical space, but
		//     ONLY frames that are provably DRAM: every page is gated against
		//     the kernel's own RAM list, plus the legacy shadow window. the
		//     2026-09-06 first cut swept the whole sub-16MB space blindly --
		//     including 0xA0000-0xBFFFF, the VGA aperture, which is device
		//     MMIO, NOT DRAM: reading it through a repointed PTE is a bus
		//     read to whatever device owned legacy VGA decode at that moment
		//     (a possibly runtime-suspended GPU). that build hard-froze the
		//     live box ~2.5 minutes later with no dump; the RAM-listed-only
		//     build before it was stable for 42 minutes. the page gate is the
		//     fix: a page is read only when the kernel itself reports the
		//     frame as RAM or it lies in the shadow window.
		//   - no PFN-floor lowering: every gated page is at or above
		//     mm_lowest_page by construction (mm_lowest_page IS the lowest
		//     RAM-listed PFN), so dpm's phys::is_address_valid admits them
		//     without touching the bound. the first cut lowered the floor to
		//     admit non-RAM-listed low frames -- exactly the frames that are
		//     not provably DRAM. never again.
		//   - the EPS-less sub-1GB signature fallback sweep of the first cut
		//     is REMOVED for the same reason: it PTE-remapped 262K frames on
		//     the PFN span alone, frames the OS does not own. the pointer-
		//     following route (loader block -> extension -> SMBios EPS) is
		//     the safe successor -- pointer hops with structure validation at
		//     every step, no blind frame reads.
		//
		// the EPS checksum is evaluated but deliberately SOFT: real firmwares
		// ship broken EPS checksums (not verifiable from usermode -- there is
		// no physical read path), so a checksum failure DOWNRANKS a candidate
		// instead of discarding it; the pointed-to table's own structure-
		// chain validation (see try_patch_table_at) is the real admission
		// test. the 2026-09-06 hard-gate build was a lesson: with the
		// checksum enforced, a board with a bad EPS checksum loses the whole
		// physical stage.

		constexpr std::uint64_t k_eps_sweep_base = 0x40000ull;    // 256KB -- below this is the real-mode IVT/BDA, never a firmware anchor
		constexpr std::uint64_t k_eps_sweep_end = 0x1000000ull;  // 16MB -- superset of the spec legacy window
		constexpr int k_max_eps_candidates = 8;

		struct eps_candidate_t {
			std::uint64_t m_table_pa;
			std::uint32_t m_table_len;
			bool m_checksum_ok;
		};

		bool parse_entry_point( const std::uint8_t* page, std::uint32_t offset,
			eps_candidate_t* out ) {
			if ( !out || offset > 0x1000 - 0x20 )
				return false;
			const auto* ep = page + offset;

			// SMBIOS 2.x: "_SM_" @0, checksum @4, len @5 (0x1F), "_DMI_" @0x10,
			// table len u16 @0x16, table addr u32 @0x18. the spec checksum:
			// sum of bytes [0, len@5) == 0 mod 256
			if ( ep[ 0 ] == '_' && ep[ 1 ] == 'S' && ep[ 2 ] == 'M' && ep[ 3 ] == '_' ) {
				if ( ep[ 5 ] < 0x1E || ep[ 5 ] > 0x20 )
					return false;
				if ( ep[ 10 ] != '_' || ep[ 11 ] != 'D' || ep[ 12 ] != 'M'
					|| ep[ 13 ] != 'I' || ep[ 14 ] != '_' )
					return false;
				std::uint32_t sum = 0;
				for ( int i = 0; i < ep[ 5 ]; ++i )
					sum += ep[ i ];
				out->m_checksum_ok = !( sum & 0xFF );
				std::uint16_t len = 0;
				std::uint32_t addr = 0;
				std::memcpy( &len, ep + 0x16, sizeof( len ) );
				std::memcpy( &addr, ep + 0x18, sizeof( addr ) );
				if ( !len || len > 0x100000 || !addr )
					return false;
				out->m_table_pa = addr;
				out->m_table_len = len;
				return true;
			}

			// SMBIOS 3.x: "_SM3_" @0, len @6 (0x18), table size u24 @0x0C,
			// table addr u64 @0x10. spec checksum @5: sum of bytes [0, 0x18)
			// == 0 mod 256 (the checksum always covers the fixed 0x18-byte
			// structure)
			if ( ep[ 0 ] == '_' && ep[ 1 ] == 'S' && ep[ 2 ] == 'M'
				&& ep[ 3 ] == '3' && ep[ 4 ] == '_' ) {
				if ( ep[ 6 ] != 0x18 || ep[ 7 ] != 3 )
					return false;
				std::uint32_t sum = 0;
				for ( int i = 0; i < 0x18; ++i )
					sum += ep[ i ];
				out->m_checksum_ok = !( sum & 0xFF );
				const auto size24 = ( static_cast< std::uint32_t >( ep[ 0x0C ] ) )
					| ( static_cast< std::uint32_t >( ep[ 0x0D ] ) << 8 )
					| ( static_cast< std::uint32_t >( ep[ 0x0E ] ) << 16 );
				std::uint64_t addr = 0;
				std::memcpy( &addr, ep + 0x10, sizeof( addr ) );
				if ( !size24 || size24 > 0x100000 || !addr || addr > 0xFFFFFFFFull )
					return false;
				out->m_table_pa = addr;
				out->m_table_len = size24;
				return true;
			}
			return false;
		}

		// ---- KeLoaderBlock route: pointer-following EPS discovery ------
		//
		// the successor to the deleted sub-1GB fallback sweep. a pure-UEFI
		// placement keeps the EPS nowhere in the sweepable window at all --
		// on this class of board it exists only as the SMBiosEPSHeader
		// pointer inside the LOADER_PARAMETER_EXTENSION. the only safe way
		// to a physical frame the OS does not list as RAM is to FOLLOW a
		// firmware-reported pointer and validate the pointed-to bytes --
		// never to read blind frames.
		//
		// route: KeLoaderBlock -> LOADER_PARAMETER_BLOCK -> Extension ->
		// SMBiosEPSHeader -> the EPS structure -> StructureTableAddress
		// (PHYSICAL) -> the DMI table, patched by the same
		// chain-validation admission as every other target.
		//
		// VERSION-AGNOSTIC BY CONSTRUCTION (2026-09-06 directive): the
		// PDB-verified offsets on the 26200 family (Extension at +0x0f0,
		// SMBiosEPSHeader at +0x038) are tried FIRST as a hint, but
		// NOTHING depends on them. the generic pass walks every aligned
		// qword of a bounded loader-parameter-block window, offering each
		// value BOTH as a direct EPS pointer and as a pointer to a struct
		// whose own aligned qwords are then scanned two levels down. the
		// extension's own Size field (at +0, when present) bounds its
		// scan generically. STRUCTURE VALIDATION of the pointed-to bytes
		// -- the _SM_/_SM3_ entry-point parse, the checksum ranking, and
		// the chain-walk admission of the pointed-to table -- is what
		// picks the real EPS, so a moved field or a foreign layout still
		// works; a box whose loader block carries no SMBios pointer at
		// all finds no candidate and reports an honest miss. no offset,
		// range or string derived from any one machine is load-bearing.
		//
		// TRUST MODEL (reconciled with the is_page_readable sweep gate):
		//   - a candidate read as a KERNEL VA is gated page-by-page by
		//     MmIsAddressValid BEFORE the dereference -- the mapped image
		//     has no unwind metadata, so an ungated VA read is a potential
		//     bugcheck, never an acceptable risk
		//   - a candidate read as a PHYSICAL address passes the SAME
		//     is_page_readable gate as the sweep: kernel-RAM-listed or
		//     legacy shadow window only, never the VGA aperture, never
		//     an unlisted frame
		//   - the TABLE the validated EPS points to is admitted by chain
		//     validation (try_patch_table_at) even in firmware-reserved
		//     DRAM off the RAM list: pointer provenance + byte validation
		//     is its own trust class -- exactly how the OS itself reaches
		//     the table. the chain walk of the exact bytes about to be
		//     rewritten, not the RAM list, is the admission test
		constexpr std::uint32_t k_lpb_scan_bytes = 0x200;   // LPB window (struct is ~0x100-0x110 on every known family)
		constexpr std::uint32_t k_ext_scan_bytes = 0x400;   // pointed-struct window (SMBiosEPSHeader is +0x038 on 26200)

		// canonical upper-half VA -- every kernel-mode pointer the loader
		// block can legally hold lives in this range
		bool is_kernel_va( std::uint64_t v ) {
			return v >= 0xFFFF800000000000ull && v <= 0xFFFFFFFFFFFFF000ull;
		}

		// read up to len bytes at a kernel VA, page chunk by page chunk,
		// each page validated by MmIsAddressValid BEFORE a byte moves. no
		// __try anywhere in this image: validate first, then touch.
		bool read_kernel_va( std::uint64_t va, void* dst, std::uint32_t len ) {
			if ( !va || !dst || !len )
				return false;
			auto* out = static_cast< std::uint8_t* >( dst );
			std::uint64_t done = 0;
			while ( done < len ) {
				const auto cur = va + done;
				if ( !is_kernel_va( cur ) )
					return false;
				if ( !kernel::mm_is_address_valid( reinterpret_cast< void* >( cur ) ) )
					return false;
				const auto page_left = 0x1000 - ( cur & 0xFFF );
				auto take = len - done;
				if ( take > page_left )
					take = page_left;
				memcpy( out + done, reinterpret_cast< const void* >( cur ), take );
				done += take;
			}
			return true;
		}

		// dedupe-with-ranking store shared by the locator and the merge:
		// same table address updates in place (checksum-valid outranks a
		// broken-checksum anchor), a new address takes a free slot.
		void eps_store( eps_candidate_t* list, int* count, int cap, const eps_candidate_t& c ) {
			for ( int i = 0; i < *count; ++i ) {
				if ( list[ i ].m_table_pa == c.m_table_pa ) {
					if ( c.m_checksum_ok && !list[ i ].m_checksum_ok )
						list[ i ] = c;
					return;
				}
			}
			if ( *count < cap )
				list[ ( *count )++ ] = c;
		}

		// offer one candidate pointer value to the entry-point validator,
		// BOTH interpretations: winload hands the kernel a VA to the EPS
		// structure (primary), some firmware hands a raw physical address
		// (covered under the same DRAM gate as the sweep -- never a blind
		// frame). parse_entry_point on the actual bytes decides.
		bool eval_eps_pointer( std::uint64_t v, const physical_memory_range_t* ram,
			eps_candidate_t* out ) {
			if ( !out || !v )
				return false;
			if ( is_kernel_va( v ) ) {
				std::uint8_t eps[ 0x20 ]{ };
				eps_candidate_t c{ };
				if ( read_kernel_va( v, eps, sizeof( eps ) )
					&& parse_entry_point( eps, 0, &c ) ) {
					*out = c;
					return true;
				}
			}
			if ( !is_page_readable( ram, v & ~0xFFFull ) )
				return false;
			std::uint8_t eps[ 0x20 ]{ };
			eps_candidate_t c{ };
			if ( read_phys( v, eps, sizeof( eps ) )
				&& parse_entry_point( eps, 0, &c ) ) {
				*out = c;
				return true;
			}
			return false;
		}

		// walk every aligned qword of a plausible loader-struct, offering
		// each value as an EPS pointer. the walk stops when the memory
		// stops being a valid kernel page (the struct ended); validity is
		// checked once per 4KB page, not once per qword.
		void scan_pointer_struct( std::uint64_t base, std::uint32_t window,
			const physical_memory_range_t* ram,
			eps_candidate_t* out, int* out_count, int cap ) {
			if ( !is_kernel_va( base ) )
				return;
			if ( window > k_ext_scan_bytes )
				window = k_ext_scan_bytes;
			std::uint64_t last_page = 0;
			bool page_ok = false;
			for ( std::uint32_t off = 0; off + 8 <= window; off += 8 ) {
				const auto addr = base + off;
				const auto page = addr & ~0xFFFull;
				if ( page != last_page ) {
					last_page = page;
					page_ok = kernel::mm_is_address_valid( reinterpret_cast< void* >( addr ) );
				}
				if ( !page_ok )
					return;
				std::uint64_t v = 0;
				memcpy( &v, reinterpret_cast< const void* >( addr ), 8 );
				eps_candidate_t c{ };
				if ( eval_eps_pointer( v, ram, &c ) )
					eps_store( out, out_count, cap, c );
			}
		}

		// the locator: KeLoaderBlock -> hint pass (PDB-verified offsets
		// first, order only) -> generic two-level qword walk. every
		// candidate admitted by eval_eps_pointer points at bytes that
		// already passed the full entry-point validation, so every
		// candidate this returns is a structurally valid EPS target.
		int collect_loader_candidates( eps_candidate_t* out, int cap,
			const physical_memory_range_t* ram ) {
			if ( !out || cap <= 0 )
				return 0;
			int n = 0;
			const auto lpb = reinterpret_cast< std::uint64_t >( KeLoaderBlock );
			if ( !is_kernel_va( lpb ) )
				return 0;

			// hint pass: Extension at +0x0f0, SMBiosEPSHeader at +0x038
			// (both PDB-verified on the 26200 family; the generic pass
			// below re-derives everything anyway, so this only orders
			// the attempt)
			std::uint64_t ext = 0;
			if ( read_kernel_va( lpb + 0x0f0, &ext, 8 ) && is_kernel_va( ext ) ) {
				std::uint64_t v = 0;
				if ( read_kernel_va( ext + 0x038, &v, 8 ) ) {
					eps_candidate_t c{ };
					if ( eval_eps_pointer( v, ram, &c ) )
						eps_store( out, &n, cap, c );
				}
				// the extension's own Size field bounds its scan
				std::uint32_t ext_size = 0;
				std::uint32_t window = k_ext_scan_bytes;
				if ( read_kernel_va( ext, &ext_size, 4 )
					&& ext_size >= 8 && ext_size <= 0x100000 )
					window = ext_size;
				scan_pointer_struct( ext, window, ram, out, &n, cap );
			}

			// generic pass: every aligned qword of the LPB window, offered
			// both as a direct EPS pointer and as a struct to walk
			std::uint64_t last_page = 0;
			bool page_ok = false;
			for ( std::uint32_t off = 0; off + 8 <= k_lpb_scan_bytes; off += 8 ) {
				const auto addr = lpb + off;
				const auto page = addr & ~0xFFFull;
				if ( page != last_page ) {
					last_page = page;
					page_ok = kernel::mm_is_address_valid( reinterpret_cast< void* >( addr ) );
				}
				if ( !page_ok )
					break; // the loader parameter block's page ended
				std::uint64_t v = 0;
				memcpy( &v, reinterpret_cast< const void* >( addr ), 8 );
				eps_candidate_t c{ };
				if ( eval_eps_pointer( v, ram, &c ) )
					eps_store( out, &n, cap, c );
				if ( is_kernel_va( v ) )
					scan_pointer_struct( v, k_ext_scan_bytes, ram, out, &n, cap );
			}
			return n;
		}

		// sweep the sub-16MB physical space page by page and collect every
		// structurally valid EPS anchor (up to the cap). every page is gated
		// against the caller's RAM-list snapshot (is_page_readable): only
		// kernel-reported RAM frames and the legacy shadow window are ever
		// read -- the VGA aperture and unowned firmware-reserved low frames
		// are skipped, not trusted. anchors pointing at the same table are
		// deduped, preferring the checksum-valid one; every distinct target
		// gets its chance in patch_physical. a signature may straddle a page
		// edge -- confirmed against the first bytes of the next page, which
		// passes the same gate. pool-backed buffers: a 4KB stack local here
		// would drag the __chkstk import into the mapped image, which must
		// stay small enough to fit a contiguous zero-run in ntoskrnl data.
		int collect_eps_candidates( eps_candidate_t* out, int max_candidates,
			const physical_memory_range_t* ram_ranges ) {
			if ( !out || max_candidates <= 0 )
				return 0;
			auto* page = static_cast< std::uint8_t* >(
				stage_alloc( 0x1000, 'pSmS' ) );
			auto* next = static_cast< std::uint8_t* >(
				stage_alloc( 0x40, 'pSmS' ) );
			if ( !page || !next ) {
				if ( page )
					stage_free( page, 0x1000, 'pSmS' );
				if ( next )
					stage_free( next, 0x40, 'pSmS' );
				return 0;
			}

			int n = 0;
			auto store = [ & ]( const eps_candidate_t& c ) {
				int slot = -1;
				for ( int i = 0; i < n; ++i ) {
					if ( out[ i ].m_table_pa == c.m_table_pa ) {
						slot = i;
						break;
					}
				}
				if ( slot < 0 ) {
					if ( n >= max_candidates )
						return;
					out[ n++ ] = c;
					return;
				}
				if ( c.m_checksum_ok && !out[ slot ].m_checksum_ok )
					out[ slot ] = c;
			};

			for ( auto pa = k_eps_sweep_base; pa + 0x1000 <= k_eps_sweep_end; pa += 0x1000 ) {
				// DRAM gate: RAM-listed or legacy shadow window only. a page
				// that fails is never read -- no PTE remap of MMIO/unowned
				// frames, ever
				if ( !is_page_readable( ram_ranges, pa ) )
					continue;
				if ( !read_phys( pa, page, 0x1000 ) )
					continue;
				for ( std::uint32_t off = 0; off + 0x20 <= 0x1000; ++off ) {
					eps_candidate_t c{ };
					if ( parse_entry_point( page, off, &c ) )
						store( c );
				}
				// straddling anchors: a partial "_SM"/"_SM3" prefix cut at
				// the page edge is completed from the next page -- the next
				// page passes the SAME DRAM gate (an unreadable next page is
				// skipped, not trusted)
				for ( std::uint32_t off = 0x1000 - 8; off < 0x1000; ++off ) {
					const auto avail = 0x1000 - off;
					if ( avail >= 1 && page[ off ] != '_' )
						continue;
					if ( avail >= 2 && page[ off + 1 ] != 'S' )
						continue;
					if ( avail >= 3 && page[ off + 2 ] != 'M' )
						continue;
					if ( avail >= 4 && page[ off + 3 ] != '3' && page[ off + 3 ] != '_' )
						continue;
					if ( !is_page_readable( ram_ranges, pa + 0x1000 ) )
						continue;
					if ( !read_phys( pa + 0x1000, next, 0x40 ) )
						continue;
					std::uint8_t joined[ 0x60 ]{ };
					memcpy( joined, page + off, avail );
					memcpy( joined + avail, next, 0x40 );
					eps_candidate_t c{ };
					if ( parse_entry_point( joined, 0, &c ) )
						store( c );
				}
			}

			stage_free( page, 0x1000, 'pSmS' );
			stage_free( next, 0x40, 'pSmS' );
			return n;
		}

		// forward declarations (defined below with the boot-cache scan):
		// the boot-cache stage needs the same chain walk + candidate prober
		bool validate_table_start( std::uint64_t cand, std::uint32_t* out_len );
		bool patch_table_near( std::uint64_t match_pa );

		// in-memory counterpart of validate_table_start: walks the structure
		// chain of a table ALREADY READ into a buffer -- the exact bytes that
		// are about to be rewritten are the ones validated. same coherence
		// rules: every structure len >= 4, string sets double-NUL terminated,
		// a sane type-1 header, bounded structure count. returns true when the
		// chain reaches the type-127 end marker OR runs out of window after
		// enough coherent structures (a firmware may declare its length
		// slightly short); a malformed byte anywhere returns false. this is
		// the admission test for physical writes into firmware-reserved
		// ranges: random bytes never walk coherently.
		bool validate_table_buffer( const std::uint8_t* table, std::uint32_t table_len ) {
			if ( !table || table_len < 0x18 || table[ 0 ] != 0 )
				return false; // a SMBIOS table starts with the type-0 structure
			auto* cur = table;
			auto* end = table + table_len;
			bool saw_t1 = false;
			int coherent = 0;
			for ( int structures = 0; structures < 256; ++structures ) {
				if ( cur + sizeof( smbios_header_t ) > end )
					break; // window exhausted -- tolerated below
				const auto type = cur[ 0 ];
				const auto len = cur[ 1 ];
				if ( len < sizeof( smbios_header_t ) )
					return false; // malformed -- never tolerated
				if ( cur + len > end )
					break; // window exhausted -- tolerated below
				if ( type == 127 )
					return true; // complete chain to the end marker
				if ( type == 1 ) {
					if ( len < offsetof( smbios_type1_t, m_uuid ) + 16 || len > 0x40 )
						return false;
					saw_t1 = true;
				}
				auto* s = cur + len;
				int zeroes = 0;
				while ( s < end ) {
					if ( *s )
						zeroes = 0;
					else if ( ++zeroes == 2 )
						break;
					++s;
				}
				if ( zeroes != 2 )
					break; // string set runs past the window -- tolerated below
				cur = s + 1;
				++coherent;
			}
			return saw_t1 && coherent >= 4;
		}

		// read + validate + patch one candidate table window at a physical
		// address. the buffer is chain-validated IN MEMORY before any write,
		// so this is safe to point at firmware-reserved physical ranges the
		// kernel RAM list does not report: a structural-but-garbage EPS anchor
		// whose target does not chain-walk coherently never reaches a write.
		// dpm writes with the mapping PTE forced RW, so a patched write into
		// reserved DRAM lands.
		bool try_patch_table_at( std::uint64_t table_pa, std::uint32_t table_len,
			bios_capture_t* capture, struct cache_sig_t* sig ) {
			if ( !table_pa || table_len < 0x18 || table_len > 0x100000 )
				return false;
			auto* table = static_cast< std::uint8_t* >(
				stage_alloc( table_len, 'pSmB' ) );
			if ( !table )
				return false;
			bool ok = false;
			if ( read_phys( table_pa, table, table_len )
				&& validate_table_buffer( table, table_len ) ) {
				// derive the boot-cache scan signature from the table's OWN
				// type-0 string bytes (board-agnostic; t0 strings are never
				// patched, so it is stable pre/post-spoof)
				derive_signature( table, table_len, sig );
				if ( modify_table( table, table_len, capture ) )
					ok = write_phys( table_pa, table, table_len );
			}
			stage_free( table, table_len, 'pSmB' );
			return ok;
		}

		bool patch_physical( bios_capture_t* capture, struct cache_sig_t* sig,
			eps_candidate_t* out_targets, int out_cap, int* out_target_count ) {
			// candidate sources, both gated (see the trust model at the
			// locator above): the KeLoaderBlock pointer walk is PRIMARY
			// (the firmware-reported target, works on pure-UEFI boards the
			// sweep cannot see), the legacy-window anchor sweep is the
			// SECONDARY belt-and-suspenders source. merged and deduped by
			// target address, checksum-valid anchors outrank broken ones.
			// every distinct target is patched -- a firmware may keep more
			// than one live copy, and the copy usermode is served from
			// cannot be told apart from inside the kernel, so patching
			// all of them is the only sound choice.
			//
			// 2026-09-06 crash audit outcome, all deliberate omissions:
			//   - NO PFN-floor lowering: every gated page is at or above
			//     mm_lowest_page by construction, so the bound is never
			//     touched and no reserved/device frame is ever admitted.
			//   - NO __try/__finally: the mapped image's .pdata is not
			//     registered with the kernel, so an SEH unwind inside this
			//     image would walk ntoskrnl's unwind metadata for foreign
			//     code -- undefined behavior. every path below is balanced
			//     without exception handling.
			//   - NO EPS-less sub-1GB fallback sweep: it remapped 262K
			//     frames on the PFN span alone, frames the OS does not own.
			//     the pointer-following locator is the safe successor; a
			//     miss is reported honestly instead.
			std::uint32_t ram_count = 0;
			auto* ram = snapshot_ram_ranges( &ram_count );
			eps_candidate_t cands[ k_max_eps_candidates ]{ };
			int n = 0;
			if ( ram ) {
				n = collect_loader_candidates( cands, k_max_eps_candidates, ram );
				eps_candidate_t swept[ k_max_eps_candidates ]{ };
				const auto sn = collect_eps_candidates( swept, k_max_eps_candidates, ram );
				for ( int i = 0; i < sn; ++i )
					eps_store( cands, &n, k_max_eps_candidates, swept[ i ] );
			}
			free_ram_ranges( ram );

			bool ok = false;
			int patched_count = 0;
			for ( int pass = 0; pass < 2; ++pass ) {
				for ( int i = 0; i < n; ++i ) {
					if ( ( pass == 0 ) != cands[ i ].m_checksum_ok )
						continue;
					if ( !try_patch_table_at( cands[ i ].m_table_pa,
							cands[ i ].m_table_len, capture, sig ) )
						continue;
					ok = true;
					if ( out_targets && out_cap > 0 && patched_count < out_cap )
						out_targets[ patched_count++ ] = cands[ i ];
				}
			}

			if ( out_target_count )
				*out_target_count = patched_count;
			return ok;
		}

		bool patch_registry( bios_capture_t* capture, struct cache_sig_t* sig ) {
			HANDLE key = nullptr;
			if ( !kreg::open_key( &key,
					L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
					KEY_READ | KEY_SET_VALUE ) ) {
				return false;
			}

			auto* buf = static_cast< std::uint8_t* >(
				stage_alloc( 0x8000, 'pSmR' ) );
			if ( !buf ) {
				kreg::close_key( key );
				return false;
			}

			bool ok = false;
			ULONG type = 0;
			ULONG len = 0;
			if ( kreg::query_value( key, L"SMBiosData", &type, buf,
					0x8000 - sizeof( KEY_VALUE_PARTIAL_INFORMATION ), &len )
				&& type == REG_BINARY && len >= 8 && len <= 0x8000 ) {
				// layout: u32 total size, u32 table length, then the raw table
				std::uint32_t table_len = 0;
				memcpy( &table_len, buf + 4, sizeof( table_len ) );
				if ( table_len && table_len + 8 <= len ) {
					// signature fallback when the physical table was not
					// found: the registry cache carries the same t0 strings
					if ( sig && !sig->m_valid )
						derive_signature( buf + 8, table_len, sig );
					const auto patched = modify_table( buf + 8, table_len, capture );
					if ( patched )
						ok = kreg::set_value( key, L"SMBiosData", REG_BINARY, buf, len );
				}
			}

			stage_free( buf, 0x8000, 'pSmR' );
			kreg::close_key( key );
			return ok;
		}

		// ---- kernel boot-cache patch (physical-RAM copy scan) --------------
		//
		// SERVING MODEL (corrected by the 2026-09-06 second live test):
		// GetSystemFirmwareTable('RSMB') and the WMI MSSmBios_RawSMBiosTables
		// block are TWO DIFFERENT providers with two different sources:
		//   - the WMI path follows the mssmbios REGISTRY cache (patch_registry
		//     flips it -- verified live: Win32_ComputerSystemProduct.UUID
		//     tracked the patched SMBiosData value),
		//   - the RSMB provider serves the PHYSICAL firmware DMI table's own
		//     bytes (verified by elimination: this RAM scan patched every
		//     chain-validatable pool copy with a signature byte-identical to
		//     the firmware table's t0 strings, and RSMB still served the real
		//     uuid -- so no RAM-resident copy backs RSMB; only the physical
		//     table does).
		// this stage still runs: it sweeps EVERY physical RAM range for
		// further copies of the table and patches each one with the SAME
		// idempotent transform -- belt-and-suspenders for pool-resident
		// consumers (mssmbios internals, firmware-table caches on other
		// windows builds) and harmless everywhere else:
		//   - a copy holding the ORIGINAL bytes patches to the same spoofed
		//     bytes as the physical table (deterministic transform)
		//   - a copy ALREADY patched (this install or an earlier one this
		//     boot) produces changed=false and is left untouched -- no
		//     double-transform corruption, no ordering constraints between
		//     this scan and the physical/registry patches
		// the transform's idempotence is the whole trick: every copy in the
		// machine converges to the same bytes in ANY order.
		//
		// signature: the type-0 string area (BIOS vendor + version strings) --
		// derived at runtime from the table's own bytes, so it is
		// board-agnostic. t0 strings are NEVER patched (identity anchors),
		// which makes the signature stable pre- and post-spoof. a match is
		// only trusted after the candidate table start validates by a
		// coherent forward structure-chain walk (type/length walk reaching a
		// terminating type-127 within sane bounds) -- random pool bytes that
		// happen to contain the vendor string never patch.
		//
		// scan bound: ALL physical RAM ranges (mm_get_physical_memory_ranges
		// walks every range ascending), hard-capped at k_cache_scan_cap total
		// bytes. the first shipped cap was the low 4 GB ("kernel pool pages
		// overwhelmingly live low") -- wrong on big boxes: nonpaged pool
		// routinely allocates above 4 GB on 32 GB+ machines, and Jack's
		// 2026-09-06 diff showed exactly that (physical + registry patched,
		// RSMB-served cache copy missed). the cap exists only as a pathological
		// stop (a box reporting absurd RAM ranges cannot stall the dispatcher
		// forever); everything past it stays unscanned and the stage honestly
		// reports a miss.
		//
		// worst-case cost: one 4 KB dpm map+copy round trip per page step --
		// on the order of 0.5-2 us per page, so a fully-populated 32 GB box
		// costs ~5-30 s one-shot inside op 17, and the 64 GB hard cap is the
		// ceiling (the loader's op-17 timeout was raised to 5 min to match;
		// the acpi pool scan runs the same budget). runs SILENT: nothing
		// outside KDBG is ever emitted by this scan.

		constexpr std::uint64_t k_cache_scan_cap = 64ull << 30; // 64 GB hard cap

		// signature = the first bytes of the t0 string set (BIOS vendor +
		// version + NUL separators), capped at k_max_sig, minimum 8. the
		// strings start at formatted-area length of the first structure, and
		// every table starts with type 0.
		void derive_signature( const std::uint8_t* table, std::uint32_t table_len,
			cache_sig_t* sig ) {
			if ( !sig || sig->m_valid || !table || table_len < 8 )
				return;
			sig->m_valid = false;
			if ( table[ 0 ] != 0 ) // first structure must be type 0 (BIOS info)
				return;
			const auto str_len = table[ 1 ];
			if ( str_len < 0x12 || str_len > 0x40 || str_len + 8 > table_len )
				return;
			auto take = table_len - str_len;
			if ( take > k_max_sig )
				take = k_max_sig;
			if ( take < 8 )
				return;
			// sanity: the string area must start with printable ascii
			for ( std::uint32_t i = 0; i < 8; ++i ) {
				const auto c = static_cast< unsigned char >( table[ str_len + i ] );
				if ( c < 0x20 || c > 0x7E )
					return;
			}
			memcpy( sig->m_bytes, table + str_len, take );
			sig->m_len = take;
			sig->m_valid = true;
		}

		// validate a candidate table start by walking the structure chain
		// forward: every structure needs len >= 4, string sets terminate with
		// the double NUL, the chain must reach a type-127 end marker within
		// sane bounds. out_len receives [start, end-of-table).
		bool validate_table_start( std::uint64_t cand, std::uint32_t* out_len ) {
			std::uint64_t cursor = cand;
			std::uint8_t chunk[ 64 ]{ };
			for ( int structures = 0; structures < 256; ++structures ) {
				if ( !read_phys( cursor, chunk, 4 ) )
					return false;
				const auto type = chunk[ 0 ];
				const auto len = chunk[ 1 ];
				if ( len < sizeof( smbios_header_t ) )
					return false;
				if ( type == 127 ) {
					const auto total = cursor + len - cand;
					if ( total < 8 || total > 0x100000 )
						return false;
					*out_len = static_cast< std::uint32_t >( total );
					return true;
				}
				cursor += len;
				// skip the string set (double NUL), bounded per structure
				int zeroes = 0;
				for ( std::uint32_t scanned = 0; scanned < 0x800; scanned += sizeof( chunk ) ) {
					if ( !read_phys( cursor + scanned, chunk, sizeof( chunk ) ) )
						return false;
					for ( std::uint32_t i = 0; i < sizeof( chunk ); ++i ) {
						if ( chunk[ i ] )
							zeroes = 0;
						else if ( ++zeroes == 2 ) {
							cursor += scanned + i + 1;
							zeroes = -1; // sentinel: done
							break;
						}
					}
					if ( zeroes == -1 )
						break;
				}
				if ( zeroes != -1 )
					return false; // unterminated string set -- not a table
				if ( cursor - cand > 0x100000 )
					return false;
			}
			return false;
		}

		// probe every sane t0 length whose [type,len] header checks out at
		// cand = match_pa - t0_len, chain-validate the candidate in physical,
		// then read + patch + write the validated window. used by the
		// boot-cache walk: the walker hands us RAM-listed pages only and the
		// is_writable_ram gate is kept as the final write admission (RAM list
		// or legacy shadow window -- never reserved/unknown frames).
		// returns true when at least one candidate copy changed.
		bool patch_table_near( std::uint64_t match_pa ) {
			bool any = false;
			for ( std::uint32_t t0_len = 0x12; t0_len <= 0x40; ++t0_len ) {
				if ( match_pa < t0_len )
					continue;
				const auto cand = match_pa - t0_len;
				std::uint8_t hdr[ 2 ]{ };
				if ( !read_phys( cand, hdr, sizeof( hdr ) ) )
					continue;
				if ( hdr[ 0 ] != 0 || hdr[ 1 ] != t0_len )
					continue;
				std::uint32_t table_len = 0;
				if ( !validate_table_start( cand, &table_len ) )
					continue;
				if ( table_len < t0_len + g_scan_sig.m_len || table_len > 0x100000 )
					continue;
				// the physical firmware table is patched by patch_physical
				// with the same transform; skipping it here is
				// belt-and-suspenders (the idempotent transform would leave
				// it unchanged anyway)
				if ( g_phys_table_pa
					&& cand + table_len > g_phys_table_pa
					&& cand < g_phys_table_pa + g_phys_table_len )
					continue;
				if ( !is_writable_ram( cand, table_len ) )
					continue;

				auto* table = static_cast< std::uint8_t* >(
					stage_alloc( table_len, 'pSmC' ) );
				if ( !table )
					continue;
				if ( read_phys( cand, table, table_len ) ) {
					if ( modify_table( table, table_len ) ) {
						if ( write_phys( cand, table, table_len ) )
							any = true;
					}
				}
				stage_free( table, table_len, 'pSmC' );
			}
			return any;
		}

		// ramscan handler: find every signature occurrence in the window and
		// try to validate + patch a table around it. never stops the walk --
		// every copy in the cap gets its chance.
		bool cache_window( std::uint64_t window_pa, const std::uint8_t* window,
			std::uint32_t window_len ) {
			std::uint32_t from = 0;
			for ( ;; ) {
				std::uint32_t q = 0xFFFFFFFFu;
				for ( std::uint32_t i = from; i + g_scan_sig.m_len <= window_len; ++i ) {
					std::uint32_t j = 0;
					while ( j < g_scan_sig.m_len && window[ i + j ] == g_scan_sig.m_bytes[ j ] )
						++j;
					if ( j == g_scan_sig.m_len ) {
						q = i;
						break;
					}
				}
				if ( q == 0xFFFFFFFFu )
					return false;
				from = q + 1;

				const auto match_pa = window_pa + q;
				// the signature starts exactly at the t0 string set: the
				// shared prober walks every sane t0 length, chain-validates,
				// and patches (RAM-list gate kept -- the walker hands us
				// RAM-listed pages only)
				if ( patch_table_near( match_pa ) )
					++g_scan_patched;
			}
		}

		bool patch_boot_caches( const cache_sig_t& sig ) {
			if ( !sig.m_valid || sig.m_len < 8 )
				return false;
			g_scan_sig = sig;
			g_scan_patched = 0;

			__try {
				( void )spoof::ramscan::walk( &cache_window, k_cache_scan_cap );
			}
			__finally {
				// nothing to restore (the walker never lowers the PFN bound;
				// pool copies live in real RAM ranges), the frame exists to
				// keep the raw-access pattern uniform with patch_physical
			}
			return g_scan_patched != 0;
		}

		// ---- RSMB served-bytes verifier ----------------------------------
		//
		// the smbios stage word is honest only when the bytes actually
		// SERVED to identification kits carry the transform. the 'RSMB'
		// provider behind NtQuerySystemInformation class 76
		// (SystemFirmwareTableInformation) is the EXACT same code path
		// usermode GetSystemFirmwareTable('RSMB') rides, so a kernel-mode
		// query AFTER the patches is a faithful preview of what hwcheck
		// sees. the check is byte-exact, not field-exact: the served raw
		// table must equal the CURRENT content of one of the patched
		// physical targets. an already-spoofed served copy converges to
		// the same bytes as the patched target (the transform is
		// idempotent per install), an unspoofed source does not -- so a
		// patch that lands on a frame the provider never serves reports
		// an honest miss, which is exactly the diagnostic the live test
		// needs. served bytes layout: 16-byte query header, then the
		// provider's 8-byte RSMB header (method, major, minor, revision,
		// u32 raw-table length), then the raw table itself.
		//
		// ZwQuerySystemInformation is resolved at RUNTIME through
		// get_export -- the import surface stays the 11 names plus
		// KeLoaderBlock, nothing new. callable only at PASSIVE -- the
		// op-17 comms thread is the only caller.
		constexpr std::uint32_t k_firmware_table_info_class = 76;
		constexpr std::uint32_t k_rsmb_provider = 0x424D5352u; // bytes 'R','S','M','B'
		constexpr std::uint32_t k_rsmb_action_get = 1;         // SystemFirmwareTable_Get
		constexpr std::uint32_t k_served_len_max = 0x100000;

		// freestanding byte compare (no CRT memcmp in this image)
		bool bytes_equal( const std::uint8_t* a, const std::uint8_t* b, std::uint32_t len ) {
			for ( std::uint32_t i = 0; i < len; ++i ) {
				if ( a[ i ] != b[ i ] )
					return false;
			}
			return true;
		}

		bool verify_served_spoofed( const eps_candidate_t* targets, int target_count ) {
			if ( !targets || target_count <= 0 )
				return false;

			static auto fn_address = 0ull;
			if ( !fn_address ) {
				fn_address = kernel::get_export( kernel::m_ntoskrnl_base,
					oxorany( "ZwQuerySystemInformation" ) );
				if ( !fn_address )
					return false; // no verifier without the syscall -- honest miss
			}
			using zw_query_t = long ( * )( std::uint32_t, void*, std::uint32_t, std::uint32_t* );
			auto* zw_query = reinterpret_cast< zw_query_t >( fn_address );

			// probe with a 4KB buffer; when the served table does not fit,
			// the syscall reports the required size through ReturnLength
			// and one sized retry is made. both buffers come from the
			// stage pool and are freed on every path -- no __try needed,
			// every branch below balances its own allocation.
			auto* served = static_cast< std::uint8_t* >( stage_alloc( 0x1000, 'pSmV' ) );
			std::uint32_t served_size = 0x1000;
			bool have_served = false;
			std::uint32_t served_len = 0;
			if ( served ) {
				std::uint32_t provider = k_rsmb_provider;
				std::uint32_t action = k_rsmb_action_get;
				std::uint32_t table_id = 0;
				std::uint32_t capacity = served_size - 16;
				std::uint32_t returned = 0;
				memcpy( served + 0, &provider, 4 );
				memcpy( served + 4, &action, 4 );
				memcpy( served + 8, &table_id, 4 );
				memcpy( served + 12, &capacity, 4 );
				auto status = zw_query( k_firmware_table_info_class, served,
					served_size, &returned );
				if ( NT_SUCCESS( status ) ) {
					std::uint32_t len = 0;
					memcpy( &len, served + 16 + 4, 4 );
					if ( len >= 0x18 && len <= capacity && served[ 16 ] == 0 ) {
						served_len = len;
						have_served = true;
					}
				} else if ( returned > 16 && returned - 16 <= k_served_len_max ) {
					// table bigger than the probe: size the retry from the
					// kernel's own reported requirement
					stage_free( served, served_size, 'pSmV' );
					served_size = returned;
					served = static_cast< std::uint8_t* >( stage_alloc( served_size, 'pSmV' ) );
					if ( served ) {
						capacity = served_size - 16;
						returned = 0;
						memcpy( served + 0, &provider, 4 );
						memcpy( served + 4, &action, 4 );
						memcpy( served + 8, &table_id, 4 );
						memcpy( served + 12, &capacity, 4 );
						status = zw_query( k_firmware_table_info_class, served,
							served_size, &returned );
						if ( NT_SUCCESS( status ) ) {
							std::uint32_t len = 0;
							memcpy( &len, served + 16 + 4, 4 );
							if ( len >= 0x18 && len <= capacity && served[ 16 ] == 0 ) {
								served_len = len;
								have_served = true;
							}
						}
					}
				}
			}

			bool ok = false;
			if ( have_served ) {
				// the raw served table starts 8 bytes into the provider
				// blob, 16 bytes into the query buffer
				const auto* served_table = served + 16 + 8;
				for ( int i = 0; i < target_count && !ok; ++i ) {
					const auto tlen = targets[ i ].m_table_len;
					if ( tlen < served_len || tlen > k_served_len_max )
						continue;
					auto* target = static_cast< std::uint8_t* >(
						stage_alloc( tlen, 'pSmV' ) );
					if ( !target )
						continue;
					if ( read_phys( targets[ i ].m_table_pa, target, tlen )
						&& bytes_equal( served_table, target, served_len ) )
						ok = true;
					stage_free( target, tlen, 'pSmV' );
				}
			}

			if ( served )
				stage_free( served, served_size, 'pSmV' );
			return ok;
		}

		// restamp the volatile HKLM\HARDWARE\DESCRIPTION\System\BIOS serial
		// values with the freshly patched firmware strings (see the capture
		// block above). the key is part of the volatile HARDWARE hive --
		// windows rebuilds it from the firmware tables at every boot, so a
		// wrong-shape value cannot outlive the machine session.

		bool patch_bios_registry( const bios_capture_t& cap ) {
			if ( !cap.m_any )
				return false;

			HANDLE key = nullptr;
			if ( !kreg::open_key( &key,
					L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS",
					KEY_QUERY_VALUE | KEY_SET_VALUE ) ) {
				return false;
			}

			static const wchar_t* const k_names[ k_slot_count ] = {
				L"SystemSerialNumber",
				L"BaseBoardSerialNumber"
			};

			std::uint32_t patched = 0;
			for ( int slot = 0; slot < k_slot_count; ++slot ) {
				if ( !cap.m_set[ slot ] || !cap.m_val[ slot ][ 0 ] )
					continue;
				const auto bytes = static_cast< ULONG >(
					( kreg::wlen( cap.m_val[ slot ] ) + 1 ) * sizeof( wchar_t ) );
				if ( kreg::set_value( key, k_names[ slot ], REG_SZ,
						cap.m_val[ slot ], bytes ) ) {
					++patched;
				}
			}

			// SystemGUID: windows stamps the SMBIOS type-1 UUID into this
			// volatile value at boot (read by WMI and most identification
			// kits as the "machine uuid"); restamp it from the PATCHED uuid
			// so the registry mirror and the firmware table agree instead of
			// leaking the pre-spoof uuid to registry-first readers.
			if ( cap.m_uuid_set ) {
				wchar_t guid[ 44 ]{ };
				auto* w = guid;
				*w++ = L'{';
				for ( int i = 0; i < 16; ++i ) {
					spoof::put_hex_w( w, 2, cap.m_uuid[ i ] );
					w += 2;
					if ( i == 3 || i == 5 || i == 7 || i == 9 )
						*w++ = L'-';
				}
				*w++ = L'}';
				*w = L'\0';
				const auto bytes = static_cast< ULONG >(
					( kreg::wlen( guid ) + 1 ) * sizeof( wchar_t ) );
				if ( kreg::set_value( key, L"SystemGUID", REG_SZ, guid, bytes ) )
					++patched;
			}

			kreg::close_key( key );
			return patched != 0;
		}

	} // anonymous namespace

	bool install( ) {
		// one-shot per install: a repeated op-17 dispatch on this mapped
		// image must be a NO-OP, never a re-mutation (the transforms are
		// idempotent anyway, but the latch also skips the multi-second RAM
		// scan and keeps the reported result stable). a FRESH launch maps a
		// fresh image with a fresh nonce -- that is the rotation model and
		// still draws a fresh identity.
		static bool s_done = false;
		static bool s_result = false;
		if ( s_done )
			return s_result;
		s_done = true;
		s_result = false;
		g_stage_pool_bytes = 0; // hard per-stage pool budget, reset once

		bios_capture_t cap{ };
		reset_capture( &cap );
		cache_sig_t sig{ };
		eps_candidate_t targets[ 4 ]{ };
		int target_count = 0;
		// ORDER MATTERS: the registry stage runs FIRST -- it fills the
		// capture (the biosreg restamp depends on it) and derives the t0
		// string-set signature from this machine's own mssmbios cache,
		// which the boot-cache scan stage then uses as its runtime anchor
		// over the RAM-listed pool copies (2026-09-06 live evidence: with
		// the registry copy's t0 strings verified byte-identical to the
		// firmware table's, one signature anchors every copy class on the
		// box). the physical stage (locator + sweep) runs second and
		// hands the VERIFIED PATCHED TARGETS to the served-bytes check
		// that runs LAST, after every surface holds its final bytes.
		const auto registry_ok = patch_registry( &cap, &sig );
		const auto physical_ok = patch_physical( &cap, &sig, targets, 4, &target_count );
		g_phys_table_pa = target_count ? targets[ 0 ].m_table_pa : 0;
		g_phys_table_len = target_count ? targets[ 0 ].m_table_len : 0;
		const auto cache_ok = patch_boot_caches( sig );
		const auto bios_ok = patch_bios_registry( cap );
		// served-bytes verification: the 'RSMB' provider (the exact path
		// hwcheck's GetSystemFirmwareTable rides) must serve the SPOOFED
		// bytes for the stage word to say ok. a patch that lands on a
		// frame the provider never serves is an honest miss -- that is
		// the whole point of the check (2026-09-06 directive).
		const auto served_ok = verify_served_spoofed( targets, target_count );
		s_result = physical_ok || registry_ok || cache_ok || bios_ok;

		// per-stage report (bit layout in comm/spoof_stages.h; the dispatcher
		// copies spoof::g_stage_mask out with the op ack)
		spoof::mark_stage( spoof::stages::smbios_physical, physical_ok && served_ok );
		if ( sig.m_valid )
			spoof::mark_stage( spoof::stages::smbios_cache_scan, cache_ok );
		spoof::mark_stage( spoof::stages::smbios_mssmbios_reg, registry_ok );
		if ( cap.m_any )
			spoof::mark_stage( spoof::stages::bios_volatile_reg, bios_ok );
		return s_result;
	}

} // namespace spoof::smbios