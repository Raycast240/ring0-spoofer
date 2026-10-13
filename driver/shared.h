#pragma once

// ============================================================================
// shared.h -- NexusSpooferDrv spoof API + shared kernel-side helpers.
//
// This driver has NO device object and NO IOCTL transport: it is mapped by
// mapper.exe (kernel::entry_t handoff with EPROCESS offsets + WNF state name)
// over the WNF shared-page protocol defined in workspace/client/control.h.
// control_data_t there MUST stay ABI-identical (176 bytes) to
// comm/wnf_client.hpp on the loader side; op numbering matches too, with the
// spoofer-only extension spoof_hardware = 17.
//
// spoof stages (one .cpp each):
//   smbios_spoofer.cpp -- raw SMBIOS table patch in physical memory
//   mac_spoofer.cpp    -- NIC NetworkAddress values in the registry
//   disk_spoofer.cpp   -- disk/volume/serial identifiers in the registry
// main.cpp glues them into spoof::install() and holds the mapper entry_point.
// ============================================================================

// per-stage result bitmask -- ONE header shared with the loader transport.
// spoof_stages.h lives next to this header in driver/:
//   driver:  spoofer-src\driver\shared.h includes "spoof_stages.h"
//   loader:  cheatlabs\comm\wnf_client.hpp includes its own copy
#include "spoof_stages.h"

// ---- RNG (xorshift32 seeded from TSC; per-op reseed in install()) --------

namespace spoof {

	// stage-report state (filled by the stage install()s; read by the
	// dispatcher after spoof::install() returns)
	inline unsigned int g_stage_mask = 0;

	inline void mark_stage( stages::stage_t stage, bool changed ) {
		stages::mark( g_stage_mask, stage, changed );
	}

	inline std::uint32_t s_rng_state = 0x6d2b79f5u;

	inline void rand_seed( ) {
		s_rng_state = static_cast< std::uint32_t >( __rdtsc( ) ) | 1u;
		if ( s_rng_state == 0x6d2b79f5u )
			s_rng_state ^= 0x9e3779b9u;
	}

	inline std::uint32_t rand_next( ) {
		auto x = s_rng_state;
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		s_rng_state = x;
		return x;
	}

	// random alphanumeric char (0-9 / A-Z)
	inline char rand_alnum( ) {
		const auto r = rand_next( ) % 36u;
		return static_cast< char >( r < 10 ? ( '0' + r ) : ( 'A' + r - 10 ) );
	}

	inline wchar_t rand_alnum_w( ) {
		return static_cast< wchar_t >( rand_alnum( ) );
	}

	inline std::uint32_t rand_hex( ) {
		return rand_next( ) & 0xFu;
	}

	// ---- random GUID (version 4 / variant 1 formatting applied) -----------

	struct guid_t {
		std::uint32_t m_data1;
		std::uint16_t m_data2;
		std::uint16_t m_data3;
		std::uint8_t  m_data4[ 8 ];
	};
	static_assert( sizeof( guid_t ) == 16 );

	inline guid_t make_guid( ) {
		guid_t g{ };
		g.m_data1 = ( rand_next( ) << 15 ) ^ ( rand_next( ) << 1 ) ^ rand_next( );
		g.m_data2 = static_cast< std::uint16_t >( rand_next( ) );
		g.m_data3 = static_cast< std::uint16_t >( ( rand_next( ) & 0x0FFFu ) | 0x4000u );
		for ( auto& b : g.m_data4 )
			b = static_cast< std::uint8_t >( rand_next( ) );
		g.m_data4[ 0 ] = static_cast< std::uint8_t >( ( g.m_data4[ 0 ] & 0x3Fu ) | 0x80u );
		return g;
	}

	inline void put_hex_w( wchar_t* dst, std::uint32_t nibbles, std::uint32_t value ) {
		for ( std::uint32_t i = 0; i < nibbles; ++i ) {
			const auto nib = ( value >> ( ( nibbles - 1 - i ) * 4 ) ) & 0xFu;
			dst[ i ] = nib < 10 ? static_cast< wchar_t >( L'0' + nib )
				: static_cast< wchar_t>( L'A' + nib - 10 );
		}
	}

	// "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" -> 38 chars + NUL
	inline void format_guid( wchar_t* dst, std::size_t dst_cch, const guid_t& g ) {
		if ( !dst || dst_cch < 39 )
			return;
		std::size_t i = 0;
		dst[ i++ ] = L'{';
		put_hex_w( dst + i, 8, g.m_data1 ); i += 8;
		dst[ i++ ] = L'-';
		put_hex_w( dst + i, 4, g.m_data2 ); i += 4;
		dst[ i++ ] = L'-';
		put_hex_w( dst + i, 4, g.m_data3 ); i += 4;
		dst[ i++ ] = L'-';
		put_hex_w( dst + i, 2, g.m_data4[ 0 ] ); i += 2;
		put_hex_w( dst + i, 2, g.m_data4[ 1 ] ); i += 2;
		dst[ i++ ] = L'-';
		// data4[2..7]
		for ( auto k = 2; k < 8; ++k ) {
			put_hex_w( dst + i, 2, g.m_data4[ k ] ); i += 2;
		}
		dst[ i++ ] = L'}';
		dst[ i ] = L'\0';
	}

	// one-shot per-install nonce mixed into every deterministic string
	// transform: repeated reads of the SAME identifier inside one boot agree
	// (physical SMBIOS copy and mssmbios registry cache produce the same
	// bytes), while every fresh install produces a fresh identity.
	inline std::uint32_t s_boot_nonce = 0;

	// ---- deterministic identity transforms (shared by every stage) --------
	//
	// every randomized identity string must be IDEMPOTENT and deterministic
	// per install: output = f(shape(original), salt, s_boot_nonce), never a
	// function of the advancing rng state. two properties follow, and both
	// are load-bearing:
	//   1. repeated reads of the SAME identifier inside one boot agree across
	//      every copy it exists in (raw firmware table, kernel boot cache,
	//      mssmbios registry cache, live ioctl buffers);
	//   2. running the transform over an ALREADY-PATCHED copy is a NO-OP: the
	//      output preserves the input's shape (length, separators, class
	//      pattern, casing), so an already-spoofed copy hashes to the same
	//      seed, selects the same positions and writes the same target chars
	//      -> changed=false, no double-transform drift. this is what lets a
	//      physical-memory scan patch every copy of the SMBIOS/ACPI tables in
	//      the machine in any order, and what keeps the disk devicemap copy
	//      and the live \Driver\Disk ioctl answer glued together.
	//
	// slight-change contract (Jack's 2026-09-06 directive): a mutation must
	// read as "same model, different unit", never a scramble:
	//   - length never changes; separators (_ - space . :) copy verbatim
	//   - every position keeps its class: digit -> digit, upper -> upper,
	//     lower -> lower, any other byte is untouched
	//   - only a small subset of the alnum positions mutates: ~30%, minimum
	//     2, capped at 8, positions picked by the per-install seed so the
	//     same serial always picks the same ones. for
	//     "E823_8FA6_BF53_0001_001B_448B_472C_0D96." the model-family prefix
	//     structure stays and only scattered chars drift.
	//
	// NEVER in scope -- identity anchors, deliberately untouched by every
	// stage in this driver; if a new stage is tempted to hash one of these,
	// it is WRONG:
	//   - CPU name/brand strings (SMBIOS t4, HARDWARE\...\CentralProcessor
	//     ProcessorNameString)
	//   - GPU marketing names / vendor strings
	//   - SMBIOS t0 vendor + BIOS version strings (they are the boot-cache
	//     scan SIGNATURE -- mutating them would break the SMBIOS scan) and
	//     the t1/t2/t3 manufacturer + product strings
	//   - windows identity values outside the enumerated patch set

	// plain byte hash (used by the uuid transform: a guid has no "shape" to
	// preserve, so its seed needs no projection -- see randomize_uuid)
	inline std::uint32_t hash_bytes( const std::uint8_t* buf, std::uint32_t len, std::uint32_t salt ) {
		std::uint32_t h = 2166136261u ^ salt;
		if ( buf && len ) {
			for ( std::uint32_t i = 0; i < len; ++i ) {
				h ^= buf[ i ];
				h *= 16777619u;
			}
		}
		return h ? h : ( 0x9E3779B9u ^ salt );
	}

	// shape projection used as the transform seed: alnum bytes collapse to a
	// class marker ('d' digit / 'A' upper / 'a' lower), separator bytes and
	// the total length hash verbatim. two strings with the same shape share
	// a seed; a string ALWAYS shares a shape with its own transform output
	// (classes + separators are preserved), which is what makes the family
	// idempotent.
	inline std::uint32_t shape_hash( const char* s, std::uint32_t len, std::uint32_t salt ) {
		std::uint32_t h = 2166136261u ^ salt;
		const auto hash_len = len < 256u ? len : 256u;
		for ( std::uint32_t i = 0; i < hash_len; ++i ) {
			const auto c = static_cast< unsigned char >( s[ i ] );
			unsigned char m;
			if ( c >= '0' && c <= '9' )
				m = 'd';
			else if ( c >= 'A' && c <= 'Z' )
				m = 'A';
			else if ( c >= 'a' && c <= 'z' )
				m = 'a';
			else
				m = c;
			h ^= m;
			h *= 16777619u;
		}
		h ^= len;
		h *= 16777619u;
		return h ? h : ( 0x9E3779B9u ^ salt );
	}

	inline bool is_alnum_byte( unsigned char c ) {
		return ( c >= '0' && c <= '9' ) || ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' );
	}

	// core slight-change mutation (narrow bytes, in place, shape preserved)
	inline bool mutate_slight( char* s, std::uint32_t len, std::uint32_t salt ) {
		if ( !s || !len || len > 4096 )
			return false;

		// the first 64 alnum positions participate in the selection; anything
		// past that keeps its tail verbatim (extra conservatism -- real
		// serials are nowhere near this long)
		std::uint32_t pos[ 64 ]{ };
		std::uint32_t alnum = 0;
		for ( std::uint32_t i = 0; i < len && alnum < 64; ++i ) {
			if ( is_alnum_byte( static_cast< unsigned char >( s[ i ] ) ) )
				pos[ alnum++ ] = i;
		}
		if ( !alnum )
			return false;

		std::uint32_t k = ( alnum * 3 ) / 10 + 1; // ~30% of the alnum chars
		if ( k < 2 )
			k = 2;
		if ( k > 8 )
			k = 8;
		if ( k > alnum )
			k = alnum;

		// NEVER the advancing rng state: the seed is a pure function of the
		// shape + salt + the per-install nonce
		const auto seed = shape_hash( s, len, salt )
			^ ( spoof::s_boot_nonce | 0x9E3779B9u );

		// one rank per alnum position (position order); the k smallest win
		std::uint32_t rank[ 64 ]{ };
		auto r = seed;
		for ( std::uint32_t j = 0; j < alnum; ++j ) {
			r = r * 0x343fdu + 0x269ec3u;
			rank[ j ] = r;
		}

		bool taken[ 64 ]{ };
		bool changed = false;
		auto r2 = seed ^ 0x5bd1e995u;
		for ( std::uint32_t t = 0; t < k; ++t ) {
			std::uint32_t best = 0xFFFFFFFFu, bj = 0;
			for ( std::uint32_t j = 0; j < alnum; ++j ) {
				if ( !taken[ j ] && rank[ j ] < best ) {
					best = rank[ j ];
					bj = j;
				}
			}
			taken[ bj ] = true;
			const auto i = pos[ bj ];
			// target chars are derived from the seed + selection order ONLY
			// (never from the current char), so re-running the transform on
			// its own output reproduces the same target -> idempotent
			r2 = r2 * 0x343fdu + 0x269ec3u;
			const auto q = static_cast< std::uint8_t >( r2 >> 16 );
			const auto c = static_cast< unsigned char >( s[ i ] );
			char n = s[ i ];
			if ( c >= '0' && c <= '9' )
				n = static_cast< char >( '0' + q % 10 );
			else if ( c >= 'A' && c <= 'Z' )
				n = static_cast< char >( 'A' + q % 26 );
			else if ( c >= 'a' && c <= 'z' )
				n = static_cast< char >( 'a' + q % 26 );
			s[ i ] = n;
			if ( n != c )
				changed = true;
		}
		return changed;
	}

	// char-class-preserving slight-change transform (see the contract at the
	// top of this block): length, shape, separators and casing of the
	// original never change; only a small seeded subset of alnum positions
	// drifts. safe on in-place firmware strings and fixed-size registry
	// values alike.
	inline bool randomize_chars( char* s, std::uint32_t len, std::uint32_t salt ) {
		return mutate_slight( s, len, salt );
	}

	// wide variant for REG_SZ serials: mutates the NARROW projection of the
	// string so the same serial held as a wide registry value and as ascii
	// IOCTL bytes transforms to the same output under the same salt (devicemap
	// registry copy and live \Driver\Disk answers agree). only ascii alnum
	// positions are ever rewritten -- non-ascii wide chars are preserved.
	inline bool randomize_chars_w( wchar_t* s, std::uint32_t len, std::uint32_t salt ) {
		if ( !s || !len || len > 64 )
			return false;
		char narrow[ 64 ]{ };
		for ( std::uint32_t i = 0; i < len; ++i )
			narrow[ i ] = static_cast< char >( s[ i ] & 0xFF );
		if ( !mutate_slight( narrow, len, salt ) )
			return false;
		for ( std::uint32_t i = 0; i < len; ++i ) {
			const wchar_t c = s[ i ];
			if ( ( c >= L'0' && c <= L'9' ) || ( c >= L'A' && c <= L'Z' )
				|| ( c >= L'a' && c <= L'z' ) )
				s[ i ] = static_cast< wchar_t >( narrow[ i ] );
		}
		return true;
	}

	inline bool is_default_string( const char* s, std::uint32_t len ) {
		if ( !s || !len )
			return true;
		static const char* patterns[ ] = {
			"to be", "def", "oem", "syst", "applic", "none", "0000", "1234"
		};
		for ( auto* pat : patterns ) {
			for ( std::uint32_t p = 0; p < len; ++p ) {
				const char* c = s + p;
				int j = 0;
				while ( pat[ j ] && p + j < len
					&& ( ( unsigned char )c[ j ] | 32 ) == ( unsigned char )( pat[ j ] | 32 ) )
					++j;
				if ( !pat[ j ] )
					return true;
			}
		}
		return false;
	}

	inline bool is_mutable( const char* s, std::uint32_t len ) {
		if ( !s || len < 4 || is_default_string( s, len ) )
			return false;
		for ( std::uint32_t i = 0; i < len; ++i )
			if ( s[ i ] != ' ' && s[ i ] != '\t' && s[ i ] != '-' && s[ i ] != '_' )
				return true;
		return false;
	}

	// gated variant for firmware table strings: placeholder values ("to be
	// filled by oem...", "0000", ...) are deliberately left alone -- they
	// are factory defaults, not identity, and rewriting them is itself a
	// spoofer tell.
	inline bool randomize_serial( char* s, std::uint32_t len, std::uint32_t salt ) {
		if ( !is_mutable( s, len ) )
			return false;
		return randomize_chars( s, len, salt );
	}

	// ---- stage entry points (defined in the per-module .cpp files) --------

	namespace smbios {
		bool install( );
	}
	namespace mac {
		bool install( );
	}
	namespace disk {
		bool install( );
	}
	namespace edid {
		bool install( );
	}
	namespace acpi {
		bool install( );
	}

	// main.cpp
	bool install( );
}

// ---- kernel registry helpers (thin Zw* wrappers) ---------------------------
//
// ZwOpenKey/ZwQueryValueKey/ZwSetValueKey/ZwEnumerateKey/ZwEnumerateValueKey/
// ZwDeleteValueKey/RtlInitUnicodeString are declared by wdm.h (via ntddk.h)
// and linked against ntoskrnl.lib; the mapper resolves the resulting
// ntoskrnl.exe import entries at map time (same mechanism the main driver's
// __C_specific_handler import already uses).

namespace spoof::kreg {

	constexpr std::size_t k_max_name = 260;   // value/subkey name buffer (wchars)
	constexpr std::size_t k_max_data = 0x400; // registry data buffer (bytes)

	inline bool open_key( HANDLE* out, const wchar_t* path, ACCESS_MASK access ) {
		if ( !out || !path || !path[ 0 ] )
			return false;

		UNICODE_STRING us{ };
		RtlInitUnicodeString( &us, path );

		OBJECT_ATTRIBUTES oa{ };
		InitializeObjectAttributes(
			&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );

		const auto status = ZwOpenKey( out, access, &oa );
		return status >= 0; // NT_SUCCESS
	}

	inline void close_key( HANDLE key ) {
		if ( key )
			ZwClose( key );
	}

	// open a subkey BY NAME under an already-open parent (RootDirectory),
	// unlike open_key which takes full \REGISTRY\MACHINE\... paths only
	inline bool open_key_under( HANDLE* out, HANDLE parent, const wchar_t* name, ACCESS_MASK access ) {
		if ( !out || !parent || !name || !name[ 0 ] )
			return false;

		UNICODE_STRING us{ };
		RtlInitUnicodeString( &us, name );

		OBJECT_ATTRIBUTES oa{ };
		InitializeObjectAttributes(
			&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parent, nullptr );

		const auto status = ZwOpenKey( out, access, &oa );
		return status >= 0; // NT_SUCCESS
	}

	// query a value into a CALLER buffer: `data` must have room for
	// sizeof(KEY_VALUE_PARTIAL_INFORMATION) + capacity bytes (the kernel
	// writes its header + the value data there, then the data is moved to the
	// front). *out_len receives the real DataLength; values larger than
	// capacity are rejected rather than silently truncated.
	inline bool query_value( HANDLE key, const wchar_t* name,
		ULONG* type, void* data, ULONG capacity, ULONG* out_len ) {
		if ( !key || !name || !data || !out_len )
			return false;

		UNICODE_STRING us{ };
		RtlInitUnicodeString( &us, name );

		ULONG result_len = 0;
		const auto status = ZwQueryValueKey(
			key, &us, KeyValuePartialInformation,
			data, sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + capacity, &result_len );

		// STATUS_BUFFER_OVERFLOW is a warning (>= 0) with DataLength filled in;
		// the capacity guard below rejects values that did not fully fit
		if ( status < 0 )
			return false;

		auto* info = static_cast< KEY_VALUE_PARTIAL_INFORMATION* >( data );
		// snapshot DataLength BEFORE the move: the header (DataLength at
		// data+8 included) sits inside the destination range, so a loop
		// re-reading info->DataLength gets its bound clobbered by the copy
		// itself once i >= 8 (the 2026-09-06 18:23 0x50: a wide "M\0i\0"
		// payload turned the bound into 0x0069004D and the loop walked off
		// the kernel stack). a local bound is immune.
		const ULONG data_length = info->DataLength;
		if ( data_length > capacity )
			return false;
		if ( type )
			*type = info->Type;
		// move the payload to the front of the caller buffer (dst < src,
		// forward copy is overlap-safe)
		for ( ULONG i = 0; i < data_length; ++i )
			static_cast< std::uint8_t* >( data )[ i ] = info->Data[ i ];
		*out_len = data_length;
		return true;
	}

	inline bool set_value( HANDLE key, const wchar_t* name,
		ULONG type, const void* data, ULONG len ) {
		if ( !key || !name || !data )
			return false;

		UNICODE_STRING us{ };
		RtlInitUnicodeString( &us, name );

		return ZwSetValueKey( key, &us, 0, type,
			const_cast< void* >( data ), len ) >= 0;
	}

	inline bool delete_value( HANDLE key, const wchar_t* name ) {
		if ( !key || !name )
			return false;

		UNICODE_STRING us{ };
		RtlInitUnicodeString( &us, name );

		return ZwDeleteValueKey( key, &us ) >= 0;
	}

	// enumerate the index-th subkey name into name (wide chars, NUL-terminated)
	inline bool enum_subkey( HANDLE key, ULONG index,
		wchar_t* name, std::size_t name_cch ) {
		if ( !key || !name || !name_cch )
			return false;

		UCHAR buf[ sizeof( KEY_BASIC_INFORMATION ) + ( k_max_name * sizeof( wchar_t ) ) ]{ };
		auto* info = reinterpret_cast< KEY_BASIC_INFORMATION* >( buf );

		ULONG result_len = 0;
		const auto status = ZwEnumerateKey(
			key, index, KeyBasicInformation,
			info, sizeof( buf ) - sizeof( wchar_t ), &result_len );

		if ( status < 0 )
			return false;

		const auto copy = info->NameLength / sizeof( wchar_t );
		if ( copy >= name_cch )
			return false;
		memcpy( name, info->Name, copy * sizeof( wchar_t ) );
		name[ copy ] = L'\0';
		return true;
	}

	// enumerate the index-th value: name (+ optional type/data) in one round
	// trip. STRICT data contract: `data_capacity` is the size of the caller's
	// data buffer; if the value's data does not fully fit, the call FAILS
	// (callers either skip the value or use enum_value_alloc). this used to
	// report the full DataLength while copying only what fit, so any value
	// larger than the caller buffer made the subsequent ZwSetValueKey rewrite
	// read past the caller's kernel-stack buffer -> 0x50 in the System
	// process (the instant-crash bug on the spoof path).
	inline bool enum_value( HANDLE key, ULONG index,
		wchar_t* name, std::size_t name_cch,
		ULONG* type = nullptr, void* data = nullptr, ULONG data_capacity = 0,
		ULONG* data_len = nullptr ) {
		if ( !key || !name || !name_cch )
			return false;

		UCHAR buf[ sizeof( KEY_VALUE_FULL_INFORMATION ) + ( k_max_name * sizeof( wchar_t ) )
			+ k_max_data ]{ };
		auto* info = reinterpret_cast< KEY_VALUE_FULL_INFORMATION* >( buf );

		ULONG result_len = 0;
		const auto status = ZwEnumerateValueKey(
			key, index, KeyValueFullInformation,
			info, sizeof( buf ) - sizeof( wchar_t ), &result_len );

		if ( status < 0 )
			return false;

		const auto name_copy = info->NameLength / sizeof( wchar_t );
		if ( name_copy >= name_cch )
			return false;
		memcpy( name, info->Name, name_copy * sizeof( wchar_t ) );
		name[ name_copy ] = L'\0';

		if ( type )
			*type = info->Type;

		// reject anything that does not fully fit the caller buffer: never
		// hand out a length the caller cannot safely pass back to
		// ZwSetValueKey. the record may have come back truncated
		// (STATUS_BUFFER_OVERFLOW is a warning), so the bounds check is the
		// only thing standing between a big registry value and a kernel-stack
		// over-read in the rewrite.
		if ( data || data_len ) {
			if ( info->DataLength > data_capacity )
				return false;
			if ( data_len )
				*data_len = info->DataLength;
			if ( data && info->DataLength ) {
				if ( info->DataOffset < sizeof( *info )
					|| info->DataOffset + info->DataLength > sizeof( buf ) )
					return false;
				memcpy( data, buf + info->DataOffset, info->DataLength );
			}
		}
		return true;
	}

	// pool-backed variant for values that may legitimately be larger than a
	// kernel stack buffer can hold: `data` receives a NONPAGED pool block of
	// exactly `*data_len` bytes (caller frees with ex_free_pool_with_tag) and
	// the returned block is always safe to rewrite with ZwSetValueKey. the
	// probe buffer first learns the full record size, the second call fetches
	// it; values above k_max_alloc_data are rejected outright.
	constexpr std::size_t k_max_alloc_data = 0x10000;

	inline bool enum_value_alloc( HANDLE key, ULONG index,
		wchar_t* name, std::size_t name_cch,
		ULONG* type, std::uint8_t** data, ULONG* data_len ) {
		if ( !key || !name || !name_cch || !type || !data || !data_len )
			return false;
		*data = nullptr;
		*data_len = 0;

		UCHAR probe[ sizeof( KEY_VALUE_FULL_INFORMATION ) + 0x100 ]{ };
		ULONG probe_len = 0;
		const auto first = ZwEnumerateValueKey(
			key, index, KeyValueFullInformation,
			probe, sizeof( probe ), &probe_len );
		if ( first < 0 && first != static_cast< NTSTATUS >( 0x80000005L ) )
			return false; // end of enumeration / hard error

		auto* probe_info = reinterpret_cast< KEY_VALUE_FULL_INFORMATION* >( probe );
		const auto name_copy = probe_info->NameLength / sizeof( wchar_t );
		if ( name_copy >= name_cch )
			return false;
		const ULONG total = probe_info->DataOffset + probe_info->DataLength;
		if ( !probe_info->DataLength || probe_info->DataLength > k_max_alloc_data
			|| total > k_max_alloc_data + 0x600 )
			return false;

		auto* buf = static_cast< std::uint8_t* >(
			kernel::ex_allocate_pool_with_tag( total, 'vReS' ) );
		if ( !buf )
			return false;

		ULONG result_len = 0;
		const auto status = ZwEnumerateValueKey(
			key, index, KeyValueFullInformation,
			buf, total, &result_len );
		if ( status < 0 || result_len < total ) {
			kernel::ex_free_pool_with_tag( buf, 'vReS' );
			return false;
		}

		auto* info = reinterpret_cast< KEY_VALUE_FULL_INFORMATION* >( buf );
		// revalidate against the second, complete record (the value may have
		// changed shape between the probe and this fetch -- bound EVERY field
		// the copies below touch, including the name)
		if ( info->NameLength == 0
			|| ( info->NameLength / sizeof( wchar_t ) ) >= name_cch
			|| info->DataOffset < sizeof( *info )
			|| info->DataOffset + info->DataLength > result_len
			|| info->DataLength > k_max_alloc_data ) {
			kernel::ex_free_pool_with_tag( buf, 'vReS' );
			return false;
		}

		memcpy( name, info->Name, ( info->NameLength / sizeof( wchar_t ) ) * sizeof( wchar_t ) );
		name[ info->NameLength / sizeof( wchar_t ) ] = L'\0';
		*type = info->Type;
		*data_len = info->DataLength;

		// shift the payload to the front so the caller owns a tight block.
		// snapshot DataLength/DataOffset BEFORE the move -- the header lives
		// inside the destination range, so a loop re-reading info->DataLength
		// self-clobbers its bound (same class as the query_value 0x50: the
		// runaway variant here WRITES, so it corrupts pool memory too)
		const ULONG data_length = info->DataLength;
		const ULONG data_offset = info->DataOffset;
		for ( ULONG i = 0; i < data_length; ++i )
			buf[ i ] = buf[ data_offset + i ];
		*data = buf;
		return true;
	}

	// create (or open) a subkey under an already-open parent key
	inline bool create_subkey( HANDLE* out, HANDLE parent, const wchar_t* name ) {
		if ( !out || !parent || !name )
			return false;

		UNICODE_STRING us{ };
		RtlInitUnicodeString( &us, name );

		OBJECT_ATTRIBUTES oa{ };
		InitializeObjectAttributes(
			&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parent, nullptr );

		ULONG disposition = 0;
		return ZwCreateKey( out, KEY_ALL_ACCESS, &oa, 0, nullptr, REG_OPTION_NON_VOLATILE,
			&disposition ) >= 0;
	}

	inline bool delete_key( HANDLE key ) {
		if ( !key )
			return false;
		return ZwDeleteKey( key ) >= 0;
	}

	// ---- misc string helpers (no CRT in this image beyond std::memcpy) ----

	inline std::size_t wlen( const wchar_t* s ) {
		std::size_t n = 0;
		while ( s && s[ n ] )
			++n;
		return n;
	}

	// concat base + '\' + sub into dst; false (dst untouched) on overflow
	inline bool join_path( wchar_t* dst, std::size_t dst_cch,
		const wchar_t* base, const wchar_t* sub ) {
		if ( !dst || !base || !sub || !dst_cch )
			return false;
		if ( wlen( base ) + 1 + wlen( sub ) >= dst_cch )
			return false;
		auto* w = dst;
		while ( *base )
			*w++ = *base++;
		*w++ = L'\\';
		while ( *sub )
			*w++ = *sub++;
		*w = L'\0';
		return true;
	}

	inline bool wstarts( const wchar_t* s, const wchar_t* prefix ) {
		if ( !s || !prefix )
			return false;
		while ( *prefix ) {
			wchar_t a = *s++, b = *prefix++;
			if ( a >= L'a' && a <= L'z' )
				a -= 32;
			if ( b >= L'a' && b <= L'z' )
				b -= 32;
			if ( a != b )
				return false;
		}
		return true;
	}

} // namespace spoof::kreg

// ---- shared physical-memory helpers (smbios + acpi stages) ------------------
//
// page-clamped dpm wrappers + the RAM-window validator + a bounded physical
// page walker used by both boot-cache scans. every raw physical access in the
// spoof stages goes through these.

namespace spoof {

	// legacy firmware shadow window (RSDP / SMBIOS 2.x entry points)
	constexpr std::uint64_t k_legacy_base = 0xE0000ull;
	constexpr std::uint64_t k_legacy_size = 0x20000ull;

	inline bool read_phys( std::uint64_t pa, void* dst, std::size_t size ) {
		auto* out = static_cast< std::uint8_t* >( dst );
		while ( size ) {
			const auto room = 0x1000 - ( pa & 0xFFF );
			const auto chunk = size < room ? size : room;
			if ( !paging::dpm::read_physical( pa, out, chunk ) )
				return false;
			pa += chunk;
			out += chunk;
			size -= chunk;
		}
		return true;
	}

	inline bool write_phys( std::uint64_t pa, const void* src, std::size_t size ) {
		auto* in = static_cast< const std::uint8_t* >( src );
		while ( size ) {
			const auto room = 0x1000 - ( pa & 0xFFF );
			const auto chunk = size < room ? size : room;
			if ( !paging::dpm::write_physical(
					pa, const_cast< std::uint8_t* >( in ), chunk ) )
				return false;
			pa += chunk;
			in += chunk;
			size -= chunk;
		}
		return true;
	}

	// a physical [pa, pa+len) window is only safe for a dpm access if it is
	// backed by real RAM or sits inside the legacy BIOS shadow window. dpm's
	// PFN validation covers the [mm_lowest_page, mm_highest_page] SPAN, which
	// includes holes/MMIO gaps -- a table pointer that landed on ROM or a
	// reserved gap would fault at DPC where nothing can catch it. the kernel
	// RAM list (byte semantics) is the authority; anything not on it and not
	// in the shadow window is skipped rather than trusted.
	//
	// LEAK FIX (2026-09-06 crash audit): MmGetPhysicalMemoryRanges allocates
	// a FRESH kernel buffer on every call that the CALLER must free
	// (ExFreePool). this wrapper used to drop it on every path -- a small
	// nonpaged-pool leak per gate call on the spoof path. freed here now,
	// on every return.
	inline bool is_writable_ram( std::uint64_t pa, std::uint32_t len ) {
		if ( !pa || !len )
			return false;
		if ( pa >= k_legacy_base && pa + len <= 0x100000ull )
			return true; // legacy firmware shadow RAM
		const auto end = pa + len;
		if ( end < pa )
			return false; // wrap
		auto* ranges = kernel::mm_get_physical_memory_ranges( );
		if ( !ranges )
			return false;
		bool found = false;
		for ( auto idx = 0ul;
			ranges[ idx ].m_base_page.m_quad_part || ranges[ idx ].m_page_count.m_quad_part;
			idx++ ) {
			const auto base = static_cast< std::uint64_t >( ranges[ idx ].m_base_page.m_quad_part );
			const auto stop = base
				+ static_cast< std::uint64_t >( ranges[ idx ].m_page_count.m_quad_part );
			if ( pa >= base && end <= stop ) {
				found = true;
				break;
			}
		}
		kernel::ex_free_pool_with_tag( ranges, 0 );
		return found;
	}

	// ---- RAM-list snapshot (stage page gate) ---------------------------------
	//
	// stages that gate per-page physical reads cannot call
	// MmGetPhysicalMemoryRanges per page (fresh kernel buffer each time --
	// freeing it per page is wasteful, NOT freeing it is the leak above).
	// snapshot the list once per stage into a private pooled buffer, free the
	// kernel buffer immediately, and walk the private copy for the whole
	// stage. bounded by construction: the snapshot is (ranges + 1) entries
	// and the kernel list is a boot-time constant.
	inline physical_memory_range_t* snapshot_ram_ranges( std::uint32_t* out_count ) {
		if ( out_count )
			*out_count = 0;
		auto* ranges = kernel::mm_get_physical_memory_ranges( );
		if ( !ranges )
			return nullptr;
		std::uint32_t n = 0;
		while ( ranges[ n ].m_base_page.m_quad_part
			|| ranges[ n ].m_page_count.m_quad_part )
			++n;
		if ( !n ) {
			kernel::ex_free_pool_with_tag( ranges, 0 );
			return nullptr;
		}
		auto* copy = static_cast< physical_memory_range_t* >(
			kernel::ex_allocate_pool_with_tag(
				( n + 1 ) * sizeof( physical_memory_range_t ), 'pgRa' ) );
		if ( !copy ) {
			kernel::ex_free_pool_with_tag( ranges, 0 );
			return nullptr;
		}
		memcpy( copy, ranges, ( n + 1 ) * sizeof( physical_memory_range_t ) );
		kernel::ex_free_pool_with_tag( ranges, 0 );
		if ( out_count )
			*out_count = n;
		return copy;
	}

	inline void free_ram_ranges( physical_memory_range_t* ranges ) {
		if ( ranges )
			kernel::ex_free_pool_with_tag( ranges, 'pgRa' );
	}

	// a physical PAGE is safe for a raw dpm READ iff the kernel itself
	// reports the frame as RAM (DRAM-backed by definition) or the page lies
	// inside the legacy firmware shadow window. nothing else is safe:
	// 0xA0000-0xBFFFF is the VGA aperture -- device MMIO, not DRAM, possibly
	// owned by a runtime-suspended GPU -- and firmware-reserved low frames
	// have no ownership guarantee at all. the 2026-09-06 boot-B post-mortem:
	// the first sub-16MB sweep read the VGA aperture through a repointed PTE
	// (a bus read to whatever device owned legacy VGA decode at that moment)
	// and the box hard-froze ~2.5 min later with no dump; the prior build,
	// which only ever read RAM-listed + shadow-window frames, was stable for
	// 42 minutes. this gate makes that access class impossible.
	inline bool is_page_readable( const physical_memory_range_t* ranges, std::uint64_t page_pa ) {
		if ( page_pa >= k_legacy_base && page_pa + 0x1000 <= 0x100000ull )
			return true; // legacy firmware shadow RAM
		if ( !ranges )
			return false;
		for ( auto idx = 0ul;
			ranges[ idx ].m_base_page.m_quad_part || ranges[ idx ].m_page_count.m_quad_part;
			++idx ) {
			const auto base = static_cast< std::uint64_t >( ranges[ idx ].m_base_page.m_quad_part );
			const auto stop = base
				+ static_cast< std::uint64_t >( ranges[ idx ].m_page_count.m_quad_part );
			if ( page_pa >= base && page_pa + 0x1000 <= stop )
				return true;
		}
		return false;
	}

	// ---- bounded physical-RAM page walker ----------------------------------
	//
	// scans every real RAM page, ascending, up to `byte_cap` total bytes, and
	// hands the caller a window of [prev-page tail || current page] so
	// signatures that STRADDLE a page boundary are visible exactly once. the
	// caller's handler validates + patches; it returns true to stop the walk
	// early. everything the handler touches must itself go through
	// read_phys/write_phys + is_writable_ram (never the raw window pointer,
	// which only covers the windowed pages). the walk runs at PASSIVE; dpm
	// raises to DPC per read internally. loop bounds are all hard: one page
	// per step, `byte_cap` total, ranges from the kernel RAM list.
	namespace ramscan {

		// max signature length the carry supports (all sigs are <= 24)
		constexpr std::uint32_t k_carry = 32;

		// (window_base_pa, window bytes, window byte count). window_base_pa
		// may be up to k_carry BELOW the current page start -- the prefix is
		// the tail of the previous page, at its true physical address.
		using handler_t = bool ( * )( std::uint64_t, const std::uint8_t*, std::uint32_t );

		// returns true when the walk ran to its cap (or the handler asked to
		// stop); false on setup failure. allocation/read failures never abort
		// the whole walk -- the page is skipped and the walk continues.
		inline bool walk( handler_t handler, std::uint64_t byte_cap ) {
			if ( !handler || !byte_cap )
				return false;
			auto* ranges = kernel::mm_get_physical_memory_ranges( );
			if ( !ranges )
				return false;

			// pooled buffers only: a 4KB stack page here would drag __chkstk
			// into the image (forbidden -- the mapped image must stay small
			// enough for the ntoskrnl .data cave)
			auto* buf = static_cast< std::uint8_t* >(
				kernel::ex_allocate_pool_with_tag( 0x1000 + k_carry, 'pgWs' ) );
			if ( !buf ) {
				// LEAK FIX (2026-09-06 audit): the kernel-allocated ranges
				// buffer is owned by the CALLER of MmGetPhysicalMemoryRanges
				kernel::ex_free_pool_with_tag( ranges, 0 );
				return false;
			}

			bool stopped = false;
			__try {
				std::uint64_t scanned = 0;
				for ( auto idx = 0ul;
					ranges[ idx ].m_base_page.m_quad_part || ranges[ idx ].m_page_count.m_quad_part;
					idx++ ) {
					const auto base = static_cast< std::uint64_t >(
						ranges[ idx ].m_base_page.m_quad_part );
					const auto bytes = static_cast< std::uint64_t >(
						ranges[ idx ].m_page_count.m_quad_part );
					if ( !bytes )
						continue;

					// a fresh RAM range breaks physical continuity: reset the
					// carry so no signature can falsely join across the gap
					for ( std::uint32_t i = 0; i < k_carry; ++i )
						buf[ i ] = 0;

					for ( auto pa = base;
						pa + 0x1000 <= base + bytes && scanned < byte_cap;
						pa += 0x1000, scanned += 0x1000 ) {
						if ( !read_phys( pa, buf + k_carry, 0x1000 ) ) {
							// unreadable page: zero the carry and move on
							for ( std::uint32_t i = 0; i < k_carry; ++i )
								buf[ i ] = 0;
							continue;
						}
						if ( handler( pa - k_carry, buf, 0x1000 + k_carry ) ) {
							stopped = true;
							break;
						}
						// tail of this page becomes the next window's carry
						memcpy( buf, buf + 0x1000, k_carry );
					}
					if ( stopped )
						break;
				}
			}
			__finally {
				kernel::ex_free_pool_with_tag( buf, 'pgWs' );
			}
			// LEAK FIX (2026-09-06 audit): free the kernel-allocated ranges
			// buffer on the normal path too
			kernel::ex_free_pool_with_tag( ranges, 0 );
			return true;
		}

	} // namespace ramscan

} // namespace spoof