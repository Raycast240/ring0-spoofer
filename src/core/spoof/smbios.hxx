#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>

namespace spoof::smbios {

    using namespace helpers;

#pragma pack(push,1)
    struct SMBIOS_HEADER { std::uint8_t Type, Length; std::uint16_t Handle; };
    struct SMBIOS_TYPE1  { SMBIOS_HEADER H; std::uint8_t Manufacturer,ProductName,Version,SerialNumber; std::uint8_t UUID[16]; };
    struct SMBIOS_TYPE2  { SMBIOS_HEADER H; std::uint8_t Manufacturer,Product,Version,SerialNumber; };
    struct SMBIOS_TYPE3  { SMBIOS_HEADER H; std::uint8_t Manufacturer,Type,Version,SerialNumber,AssetTag; };
    struct SMBIOS_TYPE17 {
        SMBIOS_HEADER H;
        std::uint16_t PhysArrayHandle, MemErrHandle, TotalWidth, DataWidth, Size;
        std::uint8_t  FormFactor, DeviceSet, DeviceLocator, BankLocator, MemType;
        std::uint16_t TypeDetail, Speed;
        std::uint8_t  Manufacturer, SerialNumber, AssetTag, PartNumber;
    };
#pragma pack(pop)



    static char* get_string_at( SMBIOS_HEADER* hdr, std::uint8_t* table_end, int idx, std::uint32_t* out_len ) {
        if ( out_len ) *out_len = 0;
        if ( idx == 0 || !hdr || !table_end ) return nullptr;
        char* cur = reinterpret_cast<char*>( hdr ) + hdr->Length;
        char* lim = reinterpret_cast<char*>( table_end );
        if ( cur >= lim ) return nullptr;
        for ( int i = 0; i < idx - 1; ++i ) {
            while ( cur < lim && *cur ) ++cur;
            if ( ++cur >= lim ) return nullptr;
        }
        char* end = cur;
        while ( end < lim && *end ) ++end;
        if ( end >= lim || end == cur ) return nullptr;
        if ( out_len ) *out_len = static_cast<std::uint32_t>( end - cur );
        return cur;
    }

    static bool is_default_string( const char* s, std::uint32_t len ) {
        if ( !s || !len ) return true;
        static const char* bad[] = { "to be", "def", "oem", "syst", "applic", "none", "unknown", "0000", "1234" };
        for ( auto* pat : bad ) {
            for ( std::uint32_t p = 0; p < len; ++p ) {
                const char* c = s + p;
                int j = 0;
                while ( pat[j] && p + j < len && ( (unsigned char)c[j] | 32 ) == (unsigned char)( pat[j] | 32 ) ) ++j;
                if ( !pat[j] ) return true;
            }
        }
        return false;
    }

    static bool is_mutable( const char* s, std::uint32_t len ) {
        if ( !s || len < 4 || is_default_string( s, len ) ) return false;
        for ( std::uint32_t i = 0; i < len; ++i )
            if ( s[i] != ' ' && s[i] != '\t' && s[i] != '-' && s[i] != '_' ) return true;
        return false;
    }

    static std::uint32_t hash_bytes( const std::uint8_t* buf, std::uint32_t len, std::uint32_t salt ) {
        std::uint32_t h = 2166136261u ^ salt;
        if ( buf && len ) for ( std::uint32_t i = 0; i < len; ++i ) { h ^= buf[i]; h *= 16777619u; }
        return h ? h : ( 0x9E3779B9u ^ salt );
    }


    static bool randomize_serial( char* s, std::uint32_t len, std::uint32_t salt ) {
        if ( !is_mutable( s, len ) ) return false;
        std::uint32_t seed = hash_bytes( reinterpret_cast<std::uint8_t*>( s ), len, salt ) ^ s_rng_seed;
        bool changed = false;
        for ( std::uint32_t i = 0; i < len; ++i ) {
            char c = s[i];
            seed = seed * 0x343fdu + 0x269ec3u;
            const std::uint8_t r = static_cast<std::uint8_t>( seed >> 16 );
            if      ( c >= '0' && c <= '9' ) { s[i] = static_cast<char>( '0' + r % 10 );  changed = true; }
            else if ( c >= 'A' && c <= 'Z' ) { s[i] = static_cast<char>( 'A' + r % 26 );  changed = true; }
            else if ( c >= 'a' && c <= 'z' ) { s[i] = static_cast<char>( 'a' + r % 26 );  changed = true; }

        }
        return changed;
    }

    // old -> new serial strings, shared by every surface so the kernel
    // table, the registry copy and HARDWARE\DESCRIPTION all stay identical
    // (real boards often reuse one serial across Type 1/2/3 - kept consistent)
    static std::vector<std::pair<std::string, std::string>> s_serial_map;

    // freshly patched serials/UUID captured when the firmware original was
    // mutable - used by the HARDWARE\DESCRIPTION restamp so the mirror
    // tracks the patched table
    static std::string s_sys_serial_new;
    static std::string s_board_serial_new;
    static std::string s_uuid_new_str;

    static void capture_sys_serial( const std::string& s ) { s_sys_serial_new = s; }
    static void capture_board_serial( const std::string& s ) { s_board_serial_new = s; }

    // SMBIOS UUIDs are mixed-endian on the wire: first three fields
    // little-endian - format the way every reader prints them
    static void capture_uuid_str( const std::uint8_t* u ) {
        char buf[ 44 ] = {};
        std::snprintf( buf, sizeof( buf ),
            "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            u[ 3 ], u[ 2 ], u[ 1 ], u[ 0 ], u[ 5 ], u[ 4 ], u[ 7 ], u[ 6 ],
            u[ 8 ], u[ 9 ], u[ 10 ], u[ 11 ], u[ 12 ], u[ 13 ], u[ 14 ], u[ 15 ] );
        s_uuid_new_str = buf;
    }

    static bool mutate_serial( char* s, std::uint32_t len, std::uint32_t salt ) {
        if ( !is_mutable( s, len ) ) return false;
        std::string old( s, len );
        for ( auto& kv : s_serial_map )
            if ( kv.first == old ) { memcpy( s, kv.second.data(), len ); return true; }
        if ( !randomize_serial( s, len, salt ) ) return false;
        s_serial_map.emplace_back( old, std::string( s, len ) );
        return true;
    }

    // one row per distinct (field, old-value) - table and registry passes
    // share original strings
    static void record_change( const char* name, const char* old_value,
                               const char* new_value, bool headline ) {
        static std::vector<std::pair<std::string, std::string>> recorded;
        for ( const auto& kv : recorded )
            if ( kv.first == name && kv.second == old_value )
                return;
        recorded.emplace_back( name, old_value );
        logging::change( "SMBIOS", name, old_value, new_value, headline );
    }


    static bool randomize_uuid( std::uint8_t* uuid, std::uint32_t salt ) {
        bool all_zero = true, all_ff = true;
        for ( int i = 0; i < 16; ++i ) { all_zero = all_zero && !uuid[i]; all_ff = all_ff && uuid[i] == 0xffu; }
        if ( all_zero || all_ff ) return false;
        std::uint32_t seed = hash_bytes( uuid, 16, salt ) ^ s_rng_seed;
        for ( int i = 0; i < 16; ++i ) {
            seed = seed * 0x343fdu + 0x269ec3u;
            uuid[i] = static_cast<std::uint8_t>( seed >> 16 );
        }
        uuid[6] = static_cast<std::uint8_t>( ( uuid[6] & 0x0Fu ) | 0x40u );
        uuid[8] = static_cast<std::uint8_t>( ( uuid[8] & 0x3Fu ) | 0x80u );
        return true;
    }

    static std::uint32_t modify_table( std::uint8_t* table, std::uint32_t length ) {
        std::uint32_t patched = 0;
        for ( auto* cur = table; cur < table + length; ) {
            auto* hdr = reinterpret_cast<SMBIOS_HEADER*>( cur );
            if ( hdr->Length < sizeof( SMBIOS_HEADER ) || cur + hdr->Length > table + length ) break;
            if ( hdr->Type == 127 ) break;

            if ( hdr->Type == 1 && hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE1, SerialNumber ) + 1 ) ) {
                auto* t1 = reinterpret_cast<SMBIOS_TYPE1*>( hdr );
                std::uint32_t slen = 0;
                char* sv = get_string_at( hdr, table + length, t1->SerialNumber, &slen );
                if ( sv ) {
                    const std::string old_serial( sv, slen );
                    if ( mutate_serial( sv, slen, 0x1103u + hdr->Handle ) ) {
                        ++patched;
                        const std::string new_serial( sv, slen );
                        capture_sys_serial( new_serial );
                        record_change( "System Serial", old_serial.c_str( ), new_serial.c_str( ), true );
                    }
                }
                if ( hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE1, UUID ) + 16 ) ) {
                    std::uint8_t old_uuid[16]{};
                    std::memcpy( old_uuid, t1->UUID, 16 );
                    if ( randomize_uuid( t1->UUID, 0x1104u + hdr->Handle ) ) {
                        ++patched;
                        capture_uuid_str( t1->UUID );
                        char old_str[40]{}, new_str[40]{};
                        std::snprintf( old_str, sizeof( old_str ),
                            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                            old_uuid[3], old_uuid[2], old_uuid[1], old_uuid[0],
                            old_uuid[5], old_uuid[4], old_uuid[7], old_uuid[6],
                            old_uuid[8], old_uuid[9], old_uuid[10], old_uuid[11],
                            old_uuid[12], old_uuid[13], old_uuid[14], old_uuid[15] );
                        std::snprintf( new_str, sizeof( new_str ),
                            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                            t1->UUID[3], t1->UUID[2], t1->UUID[1], t1->UUID[0],
                            t1->UUID[5], t1->UUID[4], t1->UUID[7], t1->UUID[6],
                            t1->UUID[8], t1->UUID[9], t1->UUID[10], t1->UUID[11],
                            t1->UUID[12], t1->UUID[13], t1->UUID[14], t1->UUID[15] );
                        record_change( "System UUID", old_str, new_str, true );
                    }
                }
            } else if ( hdr->Type == 2 && hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE2, SerialNumber ) + 1 ) ) {
                auto* t2 = reinterpret_cast<SMBIOS_TYPE2*>( hdr );
                std::uint32_t slen = 0;
                char* sv = get_string_at( hdr, table + length, t2->SerialNumber, &slen );
                if ( sv ) {
                    const std::string old_serial( sv, slen );
                    if ( mutate_serial( sv, slen, 0x1203u + hdr->Handle ) ) {
                        ++patched;
                        const std::string new_serial( sv, slen );
                        capture_board_serial( new_serial );
                        record_change( "Baseboard Serial", old_serial.c_str( ), new_serial.c_str( ), true );
                    }
                }
            } else if ( hdr->Type == 3 && hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE3, SerialNumber ) + 1 ) ) {
                auto* t3 = reinterpret_cast<SMBIOS_TYPE3*>( hdr );
                std::uint32_t slen = 0;
                char* sv = get_string_at( hdr, table + length, t3->SerialNumber, &slen );
                if ( sv ) {
                    const std::string old_serial( sv, slen );
                    if ( mutate_serial( sv, slen, 0x1302u + hdr->Handle ) ) {
                        ++patched;
                        const std::string new_serial( sv, slen );
                        record_change( "Chassis Serial", old_serial.c_str( ), new_serial.c_str( ), false );
                    }
                }
                if ( hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE3, AssetTag ) + 1 ) ) {
                    std::uint32_t alen = 0;
                    char* av = get_string_at( hdr, table + length, t3->AssetTag, &alen );
                    if ( av ) {
                        const std::string old_tag( av, alen );
                        if ( mutate_serial( av, alen, 0x1304u + hdr->Handle ) ) {
                            ++patched;
                            const std::string new_tag( av, alen );
                            record_change( "Chassis Asset Tag", old_tag.c_str( ), new_tag.c_str( ), false );
                        }
                    }
                }
            } else if ( hdr->Type == 4 && hdr->Length >= 0x10 ) {
                // packed Processor ID at +0x08 (CPUID.1 EAX|EDX for x86) - a
                // fixed-offset binary field, not part of the string area
                auto* pid = reinterpret_cast<std::uint8_t*>( cur ) + 0x08;
                std::uint8_t old_pid[8]{};
                std::memcpy( old_pid, pid, 8 );
                std::uint32_t seed = hash_bytes( pid, 8, 0x1408u + hdr->Handle ) ^ s_rng_seed;
                for ( int i = 0; i < 8; ++i ) {
                    seed = seed * 0x343fdu + 0x269ec3u;
                    pid[i] = static_cast<std::uint8_t>( seed >> 16 );
                }
                ++patched;
                {
                    char old_str[24]{}, new_str[24]{};
                    for ( int i = 0; i < 8; ++i ) {
                        std::snprintf( old_str + i * 2, 3, "%02X", old_pid[i] );
                        std::snprintf( new_str + i * 2, 3, "%02X", pid[i] );
                    }
                    record_change( "Processor ID", old_str, new_str, false );
                }
            } else if ( hdr->Type == 17 && hdr->Length >= ( std::uint8_t )( offsetof( SMBIOS_TYPE17, SerialNumber ) + 1 ) ) {
                auto* t17 = reinterpret_cast<SMBIOS_TYPE17*>( hdr );
                std::uint32_t slen = 0;
                char* sv = get_string_at( hdr, table + length, t17->SerialNumber, &slen );
                if ( sv ) {
                    const std::string old_serial( sv, slen );
                    if ( mutate_serial( sv, slen, 0x1118u + hdr->Handle ) ) {
                        ++patched;
                        const std::string new_serial( sv, slen );
                        record_change( "Memory Device Serial", old_serial.c_str( ), new_serial.c_str( ), false );
                    }
                }
            }

            auto* eos = cur + hdr->Length;
            while ( eos < table + length - 1 && ( *eos || *( eos + 1 ) ) ) ++eos;
            if ( eos >= table + length - 1 ) break;
            cur = eos + 2;
        }
        return patched;
    }



    static void patch_physical() {
        const auto phys_addr_va = pdb::get_symbol_address( "WmipSMBiosTablePhysicalAddress" );
        const auto length_va    = pdb::get_symbol_address( "WmipSMBiosTableLength" );
        if ( !phys_addr_va || !length_va ) {
            logging::print( "smbios: WmipSMBiosTablePhysicalAddress/Length not found in PDB" );
            return;
        }

        const std::uint64_t phys_addr = kread_val<std::uint64_t>( phys_addr_va );
        const std::uint32_t table_len = kread_val<std::uint32_t>( length_va );
        if ( !phys_addr || !table_len || table_len > 0x100000 ) {
            logging::print( "smbios: invalid SMBIOS physical addr=0x%llx len=%u", phys_addr, table_len );
            return;
        }

        logging::print( "smbios: table pa=0x%llx len=%u", phys_addr, table_len );

        std::vector<std::uint8_t> buf( table_len );
        if ( !driver::read_physical_memory( phys_addr, buf.data(), table_len ) ) {
            logging::print( "smbios: failed to read physical table" );
            return;
        }
        const std::vector<std::uint8_t> orig( buf );

        const std::uint32_t patched = modify_table( buf.data(), table_len );
        if ( patched ) {
            driver::write_physical_memory( phys_addr, buf.data(), table_len );
            // on readback mismatch the original goes back - a partial
            // write must not leave a torn table
            std::vector<std::uint8_t> back( table_len );
            if ( !driver::read_physical_memory( phys_addr, back.data(), table_len )
                 || memcmp( back.data(), buf.data(), table_len ) != 0 ) {
                driver::write_physical_memory( phys_addr, orig.data(), table_len );
                logging::print( "smbios: physical table write failed readback - restored original" );
                return;
            }
            logging::print( "smbios: physical table patched (%u fields)", patched );
        }
    }



    static void patch_registry() {
        HKEY hk = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE,
             L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
             0, KEY_READ | KEY_WRITE, &hk ) != ERROR_SUCCESS ) {
            logging::print( "smbios: mssmbios registry key not accessible" );
            return;
        }

        DWORD sz = 0, type = 0;
        RegQueryValueExW( hk, L"SMBiosData", nullptr, nullptr, nullptr, &sz );
        if ( !sz ) { RegCloseKey( hk ); return; }

        std::vector<std::uint8_t> buf( sz );
        if ( RegQueryValueExW( hk, L"SMBiosData", nullptr, &type, buf.data(), &sz ) != ERROR_SUCCESS
             || type != REG_BINARY || sz < 8 ) {
            RegCloseKey( hk ); return;
        }

        const std::uint32_t table_len = *reinterpret_cast<std::uint32_t*>( &buf[4] );
        if ( table_len + 8 <= sz ) {
            const std::uint32_t patched = modify_table( &buf[8], table_len );
            if ( patched ) {
                RegSetValueExW( hk, L"SMBiosData", 0, REG_BINARY, buf.data(), sz );
                logging::print( "smbios: registry SMBiosData patched (%u fields)", patched );
            }
        }
        RegCloseKey( hk );
    }



    // third surface: the volatile HARDWARE hive mirrors the boot-time SMBIOS
    // strings as REG_SZ values. the mirror key is located by VALUE SHAPE -
    // a BIOS-release-date shaped REG_SZ plus a vendor-name shaped REG_SZ -
    // never by a fixed path, because 26100 no longer populates the canonical
    // values at the old BIOS location. once found:
    //  - an existing REG_SZ matching a mapped old serial is rewritten with
    //    the patched serial
    //  - the canonical SystemSerialNumber / BaseBoardSerialNumber /
    //    SystemGUID values are (re)created from the patched firmware strings
    // the hive is volatile (rebuilt from firmware every boot), so a wrong
    // value cannot outlive the session.
    static bool bios_value_is_date( const wchar_t* s ) {
        if ( !s || wcslen( s ) != 10 ) return false;
        auto dig = []( wchar_t c ) { return c >= L'0' && c <= L'9'; };
        auto sep = []( wchar_t c ) { return c == L'/' || c == L'-' || c == L'.'; };
        if ( dig( s[0] ) && dig( s[1] ) && sep( s[2] ) && dig( s[3] ) && dig( s[4] )
             && sep( s[5] ) && dig( s[6] ) && dig( s[7] ) && dig( s[8] ) && dig( s[9] ) )
            return true;                                   // mm/dd/yyyy
        return dig( s[0] ) && dig( s[1] ) && dig( s[2] ) && dig( s[3] ) && sep( s[4] )
            && dig( s[5] ) && dig( s[6] ) && sep( s[7] ) && dig( s[8] ) && dig( s[9] );  // yyyy-mm-dd
    }

    static bool bios_value_is_vendor( const wchar_t* s ) {
        if ( !s ) return false;
        const std::size_t len = wcslen( s );
        if ( len < 3 || len > 64 ) return false;
        std::size_t letters = 0, spaces = 0;
        for ( std::size_t i = 0; i < len; ++i ) {
            if ( ( s[i] >= L'a' && s[i] <= L'z' ) || ( s[i] >= L'A' && s[i] <= L'Z' ) ) ++letters;
            else if ( s[i] == L' ' ) ++spaces;
            else if ( s[i] != L'.' && s[i] != L',' && s[i] != L'&' ) return false;
        }
        return spaces >= 1 && letters >= 3;
    }

    static bool looks_like_bios_mirror_key( HKEY hk ) {
        std::uint32_t sz_count = 0;
        bool date = false, vendor = false;
        for ( DWORD vi = 0; ; ++vi ) {
            wchar_t name[128] = {};
            DWORD name_len = 128, type = 0, sz = 0;
            const LSTATUS st = RegEnumValueW( hk, vi, name, &name_len,
                nullptr, &type, nullptr, &sz );
            if ( st == ERROR_NO_MORE_ITEMS ) break;
            if ( st != ERROR_SUCCESS && st != ERROR_MORE_DATA ) continue;
            if ( type != REG_SZ || !sz || sz > 512 ) continue;
            ++sz_count;
            wchar_t val[256] = {};
            DWORD val_len = sizeof( val );
            if ( RegQueryValueExW( hk, name, nullptr, nullptr,
                 reinterpret_cast<BYTE*>( val ), &val_len ) != ERROR_SUCCESS ) continue;
            val[255] = 0;  // unterminated REG_SZ guard
            if ( !date && bios_value_is_date( val ) ) date = true;
            else if ( !vendor && bios_value_is_vendor( val ) ) vendor = true;
        }
        return sz_count >= 3 && date && vendor;
    }

    static bool widen_ascii( const std::string& s, std::vector<wchar_t>& out ) {
        const int nlen = MultiByteToWideChar( CP_UTF8, 0,
            s.data(), (int)s.size(), nullptr, 0 );
        if ( nlen <= 0 ) return false;
        out.assign( nlen + 1, L'\0' );
        MultiByteToWideChar( CP_UTF8, 0, s.data(), (int)s.size(), out.data(), nlen );
        return true;
    }

    // (re)create one canonical mirror value from a patched firmware string;
    // a value already tracking the patched table is left untouched
    static bool restamp_bios_value( HKEY hk, const wchar_t* name, const std::string& new_val ) {
        if ( new_val.empty() ) return false;  // firmware original was not mutable
        std::vector<wchar_t> wnew;
        if ( !widen_ascii( new_val, wnew ) ) return false;

        wchar_t cur[256] = {};
        DWORD cur_len = sizeof( cur );
        const bool have_cur = RegQueryValueExW( hk, name, nullptr, nullptr,
             reinterpret_cast<BYTE*>( cur ), &cur_len ) == ERROR_SUCCESS;
        cur[255] = 0;
        if ( have_cur && wcscmp( cur, wnew.data() ) == 0 )
            return false;

        if ( RegSetValueExW( hk, name, 0, REG_SZ,
             reinterpret_cast<const BYTE*>( wnew.data() ),
             (DWORD)( ( wcslen( wnew.data() ) + 1 ) * sizeof( wchar_t ) ) ) != ERROR_SUCCESS )
            return false;
        char name_buf[64] = {};
        std::snprintf( name_buf, sizeof( name_buf ), "%ls", name );
        logging::change( "SMBIOS", name_buf, have_cur ? "(stale)" : "(absent)",
                         new_val.c_str(), false );
        return true;
    }

    static std::uint32_t patch_bios_mirror_values( HKEY hk ) {
        std::uint32_t patched = 0;
        for ( DWORD vi = 0; ; ++vi ) {
            wchar_t name[128] = {};
            DWORD name_len = 128, type = 0, sz = 0;
            const LSTATUS st = RegEnumValueW( hk, vi, name, &name_len,
                nullptr, &type, nullptr, &sz );
            if ( st == ERROR_NO_MORE_ITEMS ) break;
            if ( st != ERROR_SUCCESS && st != ERROR_MORE_DATA ) continue;
            if ( type != REG_SZ || !sz || sz > 512 ) continue;

            wchar_t val[256] = {};
            DWORD val_len = sizeof( val );
            if ( RegQueryValueExW( hk, name, nullptr, nullptr,
                 reinterpret_cast<BYTE*>( val ), &val_len ) != ERROR_SUCCESS ) continue;
            val[255] = 0;  // unterminated REG_SZ guard

            for ( auto& kv : s_serial_map ) {
                const int wlen = MultiByteToWideChar( CP_UTF8, 0,
                    kv.first.data(), (int)kv.first.size(), nullptr, 0 );
                if ( wlen <= 0 || (DWORD)wlen != wcslen( val ) ) continue;
                std::wstring wold( wlen, L'\0' );
                MultiByteToWideChar( CP_UTF8, 0, kv.first.data(), (int)kv.first.size(),
                    wold.data(), wlen );
                if ( wold != val ) continue;

                const int nlen = MultiByteToWideChar( CP_UTF8, 0,
                    kv.second.data(), (int)kv.second.size(), nullptr, 0 );
                std::vector<wchar_t> wnew( nlen + 1, L'\0' );
                MultiByteToWideChar( CP_UTF8, 0, kv.second.data(), (int)kv.second.size(),
                    wnew.data(), nlen );
                if ( RegSetValueExW( hk, name, 0, REG_SZ,
                     reinterpret_cast<const BYTE*>( wnew.data() ),
                     (DWORD)( ( nlen + 1 ) * sizeof( wchar_t ) ) ) == ERROR_SUCCESS ) {
                    ++patched;
                    char name_buf[64] = {};
                    std::snprintf( name_buf, sizeof( name_buf ), "%ls", name );
                    logging::change( "SMBIOS", name_buf, kv.first.c_str(), kv.second.c_str(), false );
                }
                break;
            }
        }

        if ( restamp_bios_value( hk, L"SystemSerialNumber", s_sys_serial_new ) ) ++patched;
        if ( restamp_bios_value( hk, L"BaseBoardSerialNumber", s_board_serial_new ) ) ++patched;
        if ( restamp_bios_value( hk, L"SystemGUID", s_uuid_new_str ) ) ++patched;
        return patched;
    }

    static std::uint32_t patch_bios_tree( HKEY hk, int depth, bool* mirror_done ) {
        if ( depth > 3 ) return 0;
        std::uint32_t patched = 0;
        if ( !*mirror_done && looks_like_bios_mirror_key( hk ) ) {
            *mirror_done = true;
            patched += patch_bios_mirror_values( hk );
        }
        for ( DWORD idx = 0; ; ++idx ) {
            wchar_t sub[128] = {};
            DWORD sub_len = 128;
            if ( RegEnumKeyExW( hk, idx, sub, &sub_len,
                 nullptr, nullptr, nullptr, nullptr ) != ERROR_SUCCESS ) break;
            HKEY hSub = nullptr;
            if ( RegOpenKeyExW( hk, sub, 0, KEY_READ | KEY_SET_VALUE, &hSub ) != ERROR_SUCCESS )
                continue;
            patched += patch_bios_tree( hSub, depth + 1, mirror_done );
            RegCloseKey( hSub );
        }
        return patched;
    }

    static void patch_hardware_desc_bios() {
        HKEY hk = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System",
             0, KEY_READ | KEY_SET_VALUE, &hk ) != ERROR_SUCCESS ) {
            logging::print( "smbios: HARDWARE\\DESCRIPTION\\System not accessible" );
            return;
        }
        bool mirror_done = false;
        const std::uint32_t patched = patch_bios_tree( hk, 0, &mirror_done );
        RegCloseKey( hk );
        if ( !mirror_done )
            logging::print( "smbios: BIOS mirror key not found by value shape" );
        logging::print( "smbios: HARDWARE\\DESCRIPTION\\System\\BIOS serial copies patched (%u)", patched );
    }

    inline void install() {
        patch_physical();
        patch_registry();
        patch_hardware_desc_bios();
    }

}
