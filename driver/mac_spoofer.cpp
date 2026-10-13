// ============================================================================
// mac_spoofer.cpp -- NIC MAC address spoof (registry transport).
//
// Writes a slight-change MAC into every NIC's NetworkAddress value under
// the {4d36e972-...} net class key
// (SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\NNNN):
// an adapter that already carries an override keeps its OUI (first 3 bytes)
// and only the device-specific half rotates; an adapter with no prior
// override gets a fresh locally-administered unicast address (there is no
// real MAC reachable from this driver to preserve). The adapter picks the
// override up on the next reset (disable/enable, reboot, or the game-machine
// boot cycle this driver runs ahead of). Only subkeys that carry a
// DriverDesc value (i.e. real adapter instances) are touched, mirroring the
// reference usermode spoofer. One-shot per install.
// ============================================================================

#include <impl/includes.h>

namespace spoof::mac {

	namespace {

		constexpr const wchar_t* k_nic_class_key =
			L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class"
			L"\\{4d36e972-e325-11ce-bfc1-08002be10318}";

		wchar_t hex_nibble( std::uint32_t nib ) {
			nib &= 0xFu;
			return nib < 10
				? static_cast< wchar_t >( L'0' + nib )
				: static_cast< wchar_t >( L'A' + nib - 10 );
		}

		bool is_hex_digit( wchar_t c ) {
			return ( c >= L'0' && c <= L'9' ) || ( c >= L'A' && c <= L'F' )
				|| ( c >= L'a' && c <= L'f' );
		}

		// slight-change MAC rule (2026-09-06 directive): when the adapter key
		// already carries a NetworkAddress override, KEEP its OUI (first 3
		// bytes) and rotate only the device-specific half -- before/after
		// reads as "same NIC vendor, different unit", and the address keeps
		// looking factory-issued: the locally-administered bit is the classic
		// spoofed-MAC tell, so a preserved real OUI (LA bit clear) is the
		// realistic shape. with no prior override there is no real MAC
		// reachable from this driver, so the value stays the previously
		// shipped shape: a fresh locally-administered unicast address.
		bool make_network_address( wchar_t* out, std::size_t out_cch,
			const wchar_t* existing ) {
			if ( !out || out_cch < 14 )
				return false;

			bool have_oui = false;
			if ( existing ) {
				have_oui = true;
				for ( int i = 0; i < 12; ++i )
					have_oui = have_oui && is_hex_digit( existing[ i ] );
			}

			if ( have_oui ) {
				for ( int i = 0; i < 6; ++i )
					out[ i ] = existing[ i ];
				for ( int i = 6; i < 12; ++i )
					out[ i ] = hex_nibble( spoof::rand_next( ) );
				out[ 12 ] = L'\0';
				return true;
			}

			// fresh locally-administered, unicast: second nibble in {2,6,A,E}
			static const wchar_t k_second[ ] = { L'2', L'6', L'A', L'E' };
			out[ 0 ] = L'0';
			out[ 1 ] = k_second[ spoof::rand_next( ) % 4u ];
			for ( int i = 2; i < 12; ++i )
				out[ i ] = hex_nibble( spoof::rand_next( ) );
			out[ 12 ] = L'\0';
			return true;
		}

	} // anonymous namespace

	bool install( ) {
		// one-shot per install: a repeated op-17 dispatch must never re-mutate
		// (each re-roll would drift the device half again)
		static bool s_done = false;
		static bool s_result = false;
		if ( s_done )
			return s_result;
		s_done = true;
		s_result = false;

		HANDLE class_key = nullptr;
		if ( !kreg::open_key( &class_key, k_nic_class_key,
				KEY_READ | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS ) ) {
			return false;
		}

		std::uint32_t patched = 0;
		for ( ULONG idx = 0;; ++idx ) {
			wchar_t sub[ kreg::k_max_name ]{ };
			if ( !kreg::enum_subkey( class_key, idx, sub, kreg::k_max_name ) )
				break;

			// open_key uses absolute paths (no RootDirectory), so build
			// <class>\<sub> explicitly
			wchar_t path[ 512 ]{ };
			if ( kreg::wlen( k_nic_class_key ) + 1 + kreg::wlen( sub ) >= 512 )
				continue;
			auto* w = path;
			for ( auto* p = const_cast< wchar_t* >( k_nic_class_key ); *p; )
				*w++ = *p++;
			*w++ = L'\\';
			for ( auto* p = sub; *p; )
				*w++ = *p++;

			HANDLE adapter = nullptr;
			if ( !kreg::open_key( &adapter, path, KEY_QUERY_VALUE | KEY_SET_VALUE ) )
				continue;

			// only real adapter instances: they all carry DriverDesc
			ULONG type = 0;
			ULONG len = 0;
			UCHAR desc[ 160 ]{ };
			if ( !kreg::query_value( adapter, L"DriverDesc", &type, desc,
					sizeof( desc ) - sizeof( KEY_VALUE_PARTIAL_INFORMATION ), &len ) ) {
				kreg::close_key( adapter );
				continue;
			}

			// existing override (if any) drives the OUI-preserving drift
			UCHAR raw[ sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 64 ]{ };
			wchar_t existing[ 16 ]{ };
			if ( kreg::query_value( adapter, L"NetworkAddress", &type, raw,
					sizeof( raw ) - sizeof( KEY_VALUE_PARTIAL_INFORMATION ), &len )
				&& type == REG_SZ && len >= sizeof( wchar_t ) && len <= sizeof( existing ) ) {
				const auto chars = len / sizeof( wchar_t );
				memcpy( existing, raw, len );
				existing[ chars < 16 ? chars : 15 ] = L'\0';
			}

			wchar_t address[ 16 ]{ };
			if ( make_network_address( address, 16,
					existing[ 0 ] ? existing : nullptr ) ) {
				const ULONG bytes = static_cast< ULONG >( ( kreg::wlen( address ) + 1 ) * sizeof( wchar_t ) );
				if ( kreg::set_value( adapter, L"NetworkAddress", REG_SZ, address, bytes ) )
					++patched;
			}

			kreg::close_key( adapter );
		}

		kreg::close_key( class_key );
		s_result = patched != 0;
		spoof::mark_stage( spoof::stages::mac, s_result );
		return s_result;
	}

} // namespace spoof::mac