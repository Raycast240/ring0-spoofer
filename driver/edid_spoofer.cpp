// ============================================================================
// edid_spoofer.cpp -- monitor EDID identity patch (registry surface).
//
// HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\<pnp>\<instance>\Device Parameters
//   - EDID (REG_BINARY, 128/256/384/512 bytes -- any whole number of 128-byte
//     blocks; the dev box's main monitor carries 384): classic EDID 1.x block
//   - EDID_OVERRIDE (REG_BINARY value, and on some builds a SUBKEY holding
//     EDID* REG_BINARY values) -- patched in both shapes
//
// patched, slight-change style (2026-09-06 directive -- "same model,
// different unit"):
//   - serial number u32 LE at offset 12: two nibbles are forced to
//     per-install values derived from (salt, s_boot_nonce). forcing (rather
//     than xoring) makes it idempotent: a re-run over an already-patched
//     block reproduces the same value and reports changed=false.
//   - descriptor 3 (bytes 54..71): when it is a serial-number ASCII
//     descriptor (type flag 0xFF at 54+3), the string at bytes 60..71 runs
//     through the shared slight-change transform (~2 chars drift, shape/
//     length/classes preserved, deterministic per install)
//   - the base-block checksum at byte 127 is recomputed after any change --
//     a stale checksum is itself a spoofer tell
//
// bounds discipline: EDIDs that fail the 00 FF FF FF FF FF FF 00 header
// check are rejected; only REG_BINARY values sized as whole 128-byte blocks
// (up to 512) are touched; every
// registry record goes through the strict kreg contracts. WMI's
// WmiMonitorID is served from the SAME registry EDID (monitor stack caches
// it at device start), so this patch is WMI-visible after re-enumeration /
// reboot. one-shot per install.
// ============================================================================

#include <impl/includes.h>

namespace spoof::edid {

	namespace {

		constexpr std::uint32_t k_ascii_salt = 0xED1Du; // descriptor string
		constexpr std::uint32_t k_serial_salt = 0x5EEDu; // u32 serial nibbles

		// base-block checksum: byte 127 = (0x100 - sum(bytes 0..126)) & 0xFF
		void fix_checksum( std::uint8_t* e ) {
			std::uint32_t sum = 0;
			for ( std::uint32_t i = 0; i < 127; ++i )
				sum += e[ i ];
			e[ 127 ] = static_cast< std::uint8_t >( ( 0x100 - ( sum & 0xFF ) ) & 0xFF );
		}

		bool valid_header( const std::uint8_t* e ) {
			static const std::uint8_t k_hdr[ 8 ] = {
				0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
			};
			for ( std::uint32_t i = 0; i < 8; ++i ) {
				if ( e[ i ] != k_hdr[ i ] )
					return false;
			}
			return true;
		}

		// accepted EDID sizes: any whole number of 128-byte blocks up to 4
		// (base + up to 3 extension blocks). verified against the dev box's
		// real layout 2026-09-06: Device Parameters\EDID values of 128, 256
		// AND 384 bytes exist there (the main monitor carries two extension
		// blocks) -- the old 128/256-only gate skipped that monitor entirely.
		constexpr std::uint32_t k_edid_block = 128;
		constexpr std::uint32_t k_edid_max = 512;

		// in-place slight-change patch of one EDID base block. extension
		// blocks (bytes 128.. of multi-block EDIDs) are deliberately not
		// touched -- only the identity fields of the base block are ours, and
		// the checksum fixed at byte 127 belongs to the base block.
		bool patch_block( std::uint8_t* e, std::uint32_t len ) {
			if ( !len || len % k_edid_block || len > k_edid_max )
				return false;
			if ( !valid_header( e ) )
				return false;

			bool changed = false;

			// u32 serial @12: force two nibbles to per-install targets.
			// value-independent selection + forcing = idempotent, and "a few
			// bits" is the whole point -- the number stays a plausible unit
			// serial of the same model, not a scramble.
			{
				std::uint32_t cur = 0;
				memcpy( &cur, e + 12, sizeof( cur ) );
				const auto seed = hash_bytes( nullptr, 0, k_serial_salt )
					^ ( spoof::s_boot_nonce | 0x9E3779B9u );
				auto p1 = ( seed >> 4 ) & 7u;
				auto p2 = ( ( seed >> 12 ) ^ seed ) & 7u;
				if ( p2 == p1 )
					p2 = ( p1 + 4 ) & 7u;
				const auto v1 = ( seed >> 20 ) & 0xFu;
				const auto v2 = ( seed >> 28 ) & 0xFu;
				auto forced = cur;
				forced = ( forced & ~( 0xFu << ( p1 * 4 ) ) ) | ( v1 << ( p1 * 4 ) );
				forced = ( forced & ~( 0xFu << ( p2 * 4 ) ) ) | ( v2 << ( p2 * 4 ) );
				if ( forced != cur ) {
					memcpy( e + 12, &forced, sizeof( forced ) );
					changed = true;
				}
			}

			// descriptor 3 (bytes 54..71): serial-number ASCII descriptor
			// (type flag 0xFF at 54+3), string payload at bytes 60..71
			if ( e[ 54 + 3 ] == 0xFF ) {
				char buf[ 13 ]{ };
				for ( std::uint32_t i = 0; i < 12; ++i )
					buf[ i ] = static_cast< char >( e[ 60 + i ] );
				auto slen = 12;
				while ( slen && ( buf[ slen - 1 ] == ' ' || !buf[ slen - 1 ] ) )
					--slen;
				// is_mutable gate inside randomize_serial rejects short /
				// placeholder strings -- a 3-char "serial" is not identity
				if ( slen >= 4 && randomize_serial( buf, slen, k_ascii_salt ) ) {
					for ( std::uint32_t i = 0; i < slen; ++i )
						e[ 60 + i ] = static_cast< std::uint8_t >( buf[ i ] );
					changed = true;
				}
			}

			if ( changed )
				fix_checksum( e );
			return changed;
		}

		// patch one named REG_BINARY EDID value under a Device Parameters key
		bool patch_edid_value( HANDLE params, const wchar_t* name ) {
			ULONG type = 0;
			ULONG len = 0;
			UCHAR raw[ sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + k_edid_max ]{ };
			if ( !kreg::query_value( params, name, &type, raw,
					sizeof( raw ) - sizeof( KEY_VALUE_PARTIAL_INFORMATION ), &len ) )
				return false;
			if ( type != REG_BINARY
				|| !len || len % k_edid_block || len > k_edid_max )
				return false;
			if ( !patch_block( raw, len ) )
				return false;
			return kreg::set_value( params, name, REG_BINARY, raw, len );
		}

		// some builds keep the override in a EDID_OVERRIDE SUBKEY whose values
		// are named EDID* -- patch every REG_BINARY value of that shape
		bool patch_override_subkey( HANDLE params ) {
			HANDLE ovr = nullptr;
			if ( !kreg::open_key_under( &ovr, params, L"EDID_OVERRIDE",
					KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS ) )
				return false;

			bool any = false;
			for ( ULONG i = 0;; ++i ) {
				wchar_t name[ kreg::k_max_name ]{ };
				ULONG type = 0;
				UCHAR data[ k_edid_max ]{ };
				ULONG dlen = 0;
				if ( !kreg::enum_value( ovr, i, name, kreg::k_max_name,
						&type, data, sizeof( data ), &dlen ) )
					break;
				if ( type != REG_BINARY
					|| !dlen || dlen % k_edid_block || dlen > k_edid_max )
					continue;
				if ( !kreg::wstarts( name, L"EDID" ) )
					continue;
				if ( patch_block( data, dlen )
					&& kreg::set_value( ovr, name, REG_BINARY, data, dlen ) )
					any = true;
			}

			kreg::close_key( ovr );
			return any;
		}

	} // anonymous namespace

	bool install( ) {
		// one-shot per install: repeated op-17 must never re-mutate (the
		// transforms are idempotent anyway; the latch also keeps the reported
		// result stable)
		static bool s_done = false;
		static bool s_result = false;
		if ( s_done )
			return s_result;
		s_done = true;
		s_result = false;

		HANDLE root = nullptr;
		if ( !kreg::open_key( &root,
				L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
				KEY_READ | KEY_ENUMERATE_SUB_KEYS ) ) {
			return false;
		}

		std::uint32_t patched = 0;
		for ( ULONG pi = 0;; ++pi ) {
			wchar_t pnp[ kreg::k_max_name ]{ };
			if ( !kreg::enum_subkey( root, pi, pnp, kreg::k_max_name ) )
				break;

			HANDLE pnp_key = nullptr;
			if ( !kreg::open_key_under( &pnp_key, root, pnp,
					KEY_READ | KEY_ENUMERATE_SUB_KEYS ) )
				continue;

			for ( ULONG ii = 0;; ++ii ) {
				wchar_t inst[ kreg::k_max_name ]{ };
				if ( !kreg::enum_subkey( pnp_key, ii, inst, kreg::k_max_name ) )
					break;

				HANDLE inst_key = nullptr;
				if ( !kreg::open_key_under( &inst_key, pnp_key, inst,
						KEY_READ | KEY_ENUMERATE_SUB_KEYS ) )
					continue;

				HANDLE params = nullptr;
				if ( kreg::open_key_under( &params, inst_key, L"Device Parameters",
						KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS ) ) {
					if ( patch_edid_value( params, L"EDID" ) )
						++patched;
					if ( patch_edid_value( params, L"EDID_OVERRIDE" ) )
						++patched;
					if ( patch_override_subkey( params ) )
						++patched;
					kreg::close_key( params );
				}

				kreg::close_key( inst_key );
			}
			kreg::close_key( pnp_key );
		}

		kreg::close_key( root );
		s_result = patched != 0;
		spoof::mark_stage( spoof::stages::edid, s_result );
		return s_result;
	}

} // namespace spoof::edid