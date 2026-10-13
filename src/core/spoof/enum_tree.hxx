#pragma once
#include "helpers.hxx"
#include <string>
#include <vector>
#include <map>
#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

namespace spoof::enum_tree {

    using namespace helpers;

    // ---------------------------------------------------------------
    // HKLM\SYSTEM\CurrentControlSet\Enum keeps a per-device-instance subtree
    // with two identity surfaces: the instance key name itself (devices
    // exposing a serial become <enum>\<hwid>\<SERIAL>, admin-readable and
    // walked by every fingerprinter) and the ContainerId value (groups the
    // members of one physical device into a single container).
    //
    // Enum keys are SYSTEM-owned with admins read-only, so writing needs
    // SeTakeOwnershipPrivilege plus a temporary ownership seizure; original
    // owner + DACL of every touched key are saved and restored, the only
    // lasting change is the data. renames are copy-then-delete and the copy
    // inherits native security, so no takeover footprint survives.
    //
    // renames are restricted to genuine serial instance names: PnP location
    // ids ("6&1f4a2b5c&0&0000") are topology, not serials, and renaming one
    // forces a driver reinstall of every device behind it - Enum\PCI gets
    // ContainerId patches only.
    // ---------------------------------------------------------------

    static bool enable_privilege( const char* name ) {
        HANDLE token = nullptr;
        if ( !OpenProcessToken( GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token ) ) {
            logging::print( "enum-tree: OpenProcessToken(%s) failed rc=%lu",
                name, GetLastError() );
            return false;
        }
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        bool ok = false;
        if ( !LookupPrivilegeValueA( nullptr, name, &tp.Privileges[0].Luid ) ) {
            logging::print( "enum-tree: LookupPrivilegeValue(%s) failed rc=%lu",
                name, GetLastError() );
        } else if ( !AdjustTokenPrivileges( token, FALSE, &tp, sizeof( tp ),
                                             nullptr, nullptr ) ) {
            logging::print( "enum-tree: AdjustTokenPrivileges(%s) failed rc=%lu",
                name, GetLastError() );
        } else {
            const DWORD rc = GetLastError();   // ERROR_NOT_ALL_ASSIGNED
            if ( rc != ERROR_SUCCESS )
                logging::print( "enum-tree: privilege %s not held (rc=%lu)", name, rc );
            ok = rc == ERROR_SUCCESS;
        }
        CloseHandle( token );
        return ok;
    }

    // first failure per step only - pinpoint without spam
    static void log_first_fail( const char* step, DWORD rc ) {
        static const char* k_reported[12] = {};
        for ( auto& r : k_reported ) {
            if ( r && strcmp( r, step ) == 0 ) return;
            if ( !r ) {
                r = step;
                logging::print( "enum-tree: first failure at %s (rc=%lu)", step, rc );
                return;
            }
        }
    }

    static PSID sid_from_str( const wchar_t* s ) {
        PSID out = nullptr;
        ConvertStringSidToSidW( s, &out );
        return out;
    }

    struct key_security {
        PSID owner = nullptr;   // LocalAlloc'd copies; freed with free_security
        PACL dacl = nullptr;
        bool have_owner = false;
        bool have_dacl = false;
    };

    static void free_security( key_security* s ) {
        if ( s->owner ) LocalFree( s->owner );
        if ( s->dacl ) LocalFree( s->dacl );
        s->owner = nullptr;
        s->dacl = nullptr;
        s->have_owner = s->have_dacl = false;
    }

    static bool save_security( const std::wstring& machine_path, key_security* out ) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        PSID owner = nullptr;
        PACL dacl = nullptr;
        if ( GetNamedSecurityInfoW( machine_path.c_str(), SE_REGISTRY_KEY,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &owner, nullptr, &dacl, nullptr, &sd ) != ERROR_SUCCESS )
            return false;
        if ( owner && IsValidSid( owner ) ) {
            const DWORD len = GetLengthSid( owner );
            out->owner = static_cast<PSID>( LocalAlloc( LMEM_FIXED, len ) );
            if ( out->owner && CopySid( len, out->owner, owner ) )
                out->have_owner = true;
        }
        if ( dacl && IsValidAcl( dacl ) ) {
            ACL_SIZE_INFORMATION ai{};
            if ( GetAclInformation( dacl, &ai, sizeof( ai ), AclSizeInformation ) ) {
                out->dacl = static_cast<PACL>( LocalAlloc( LMEM_FIXED, ai.AclBytesInUse ) );
                if ( out->dacl ) {
                    memcpy( out->dacl, dacl, ai.AclBytesInUse );
                    out->have_dacl = true;
                }
            }
        }
        LocalFree( sd );
        return out->have_owner || out->have_dacl;
    }

    // owner -> Administrators, then merge an admin-full ACE; the
    // inheritance flag propagates it so a recursive delete goes through
    static bool seize_key( const std::wstring& machine_path, PSID admin_sid ) {
        DWORD rc = SetNamedSecurityInfoW( const_cast<LPWSTR>( machine_path.c_str() ),
            SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, admin_sid,
            nullptr, nullptr, nullptr );
        if ( rc != ERROR_SUCCESS ) {
            log_first_fail( "seize:owner", rc );
            return false;
        }

        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = KEY_ALL_ACCESS;
        ea.grfAccessMode       = GRANT_ACCESS;
        ea.grfInheritance      = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.ptstrName   = reinterpret_cast<LPWSTR>( admin_sid );

        PACL dacl = nullptr;
        if ( SetEntriesInAclW( 1, &ea, nullptr, &dacl ) != ERROR_SUCCESS )
            return false;
        rc = SetNamedSecurityInfoW( const_cast<LPWSTR>( machine_path.c_str() ),
            SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, dacl, nullptr );
        LocalFree( dacl );
        if ( rc != ERROR_SUCCESS )
            log_first_fail( "seize:dacl", rc );
        return rc == ERROR_SUCCESS;
    }

    // DACL first (once the original owner is back we lose implicit
    // WRITE_DAC), then the owner; PROTECTED_DACL replaces the DACL
    // with the saved bytes so no merged ACE survives
    static void restore_security( const std::wstring& machine_path, const key_security& sec ) {
        if ( sec.have_dacl )
            SetNamedSecurityInfoW( const_cast<LPWSTR>( machine_path.c_str() ),
                SE_REGISTRY_KEY,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, sec.dacl, nullptr );
        if ( sec.have_owner )
            SetNamedSecurityInfoW( const_cast<LPWSTR>( machine_path.c_str() ),
                SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
                sec.owner, nullptr, nullptr, nullptr );
    }

    static bool enum_subkeys( HKEY hk, std::vector<std::wstring>* out ) {
        for ( DWORD i = 0; ; ++i ) {
            wchar_t name[256];
            DWORD len = 256;
            const LSTATUS rc = RegEnumKeyExW( hk, i, name, &len,
                                              nullptr, nullptr, nullptr, nullptr );
            if ( rc == ERROR_NO_MORE_ITEMS ) break;
            if ( rc != ERROR_SUCCESS ) break;   // ERROR_MORE_DATA: key names cap at 255
            out->emplace_back( name, len );
        }
        return !out->empty();
    }

    static bool is_alnum( wchar_t c ) {
        return ( c >= L'0' && c <= L'9' ) || ( c >= L'A' && c <= L'Z' ) ||
               ( c >= L'a' && c <= L'z' );
    }

    // genuine serial instance names only: "0000849C08EE",
    // "GD7LE9EJR43RVNG2V". PnP location ids ("6&1f4a2b5c&0&0000") use any
    // hex char as prefix on 26xxx, so any non-alphanumeric disqualifies;
    // that also excludes SWD machine-identity and MAC-derived names
    static bool looks_like_serial( const wchar_t* name ) {
        if ( !name || !name[0] ) return false;
        std::size_t len = 0;
        for ( const wchar_t* p = name; *p; ++p, ++len )
            if ( !is_alnum( *p ) ) return false;
        return len >= 5 && len <= 64;
    }

    static void rand_alnum( wchar_t* out, std::size_t len ) {
        static const wchar_t k_chars[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for ( std::size_t i = 0; i < len; ++i )
            out[i] = k_chars[rand_next() % 36];
        out[len] = 0;
    }

    static GUID rand_guid() {
        GUID g{};
        g.Data1 = rand_next();
        g.Data2 = static_cast<WORD>( rand_next() );
        g.Data3 = static_cast<WORD>( rand_next() );
        for ( auto& b : g.Data4 ) b = static_cast<BYTE>( rand_next() & 0xFF );
        g.Data3     = static_cast<WORD>( ( g.Data3 & 0x0FFFu ) | 0x4000u );
        g.Data4[0] = static_cast<BYTE>( ( g.Data4[0] & 0x3Fu ) | 0x80u );
        return g;
    }

    static std::wstring guid_to_str( const GUID& g ) {
        wchar_t buf[64];
        swprintf_s( buf, 64,
            L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7] );
        return buf;
    }

    // Windows reserves two well-known container ids ("every device its own
    // container" / "not containerized") - rewriting them breaks semantics
    static bool is_special_container( const wchar_t* s ) {
        return _wcsicmp( s, L"{00000000-0000-0000-FFFF-FFFFFFFFFFFF}" ) == 0
            || _wcsicmp( s, L"{00000000-0000-0000-0000-000000000000}" ) == 0;
    }

    // same old container -> same new container, so devices that genuinely
    // share one physical container still share it after spoofing
    static bool map_container( const GUID& old, std::map<std::wstring, GUID>* shared, GUID* out ) {
        const std::wstring key = guid_to_str( old );
        auto it = shared->find( key );
        if ( it != shared->end() ) {
            *out = it->second;
            return true;
        }
        GUID nw = rand_guid();
        shared->emplace( key, nw );
        *out = nw;
        return true;
    }

    static bool patch_container_id( HKEY hk, std::map<std::wstring, GUID>* shared ) {
        DWORD type = 0, sz = 0;
        const LSTATUS qrc = RegQueryValueExW( hk, L"ContainerId", nullptr,
                                              &type, nullptr, &sz );
        if ( qrc != ERROR_SUCCESS ) {
            // a missing value is not a fault here - only access/layout
            // problems get logged
            if ( qrc != ERROR_FILE_NOT_FOUND )
                log_first_fail( "container:query", qrc );
            return false;
        }

        if ( type == REG_SZ && sz >= 4 && sz <= 96 ) {
            std::vector<wchar_t> v( sz / sizeof( wchar_t ) + 1, 0 );
            const LSTATUS rrc = RegQueryValueExW( hk, L"ContainerId", nullptr,
                    &type, reinterpret_cast<BYTE*>( v.data() ), &sz );
            if ( rrc != ERROR_SUCCESS ) {
                log_first_fail( "container:read", rrc );
                return false;
            }
            v[v.size() - 1] = 0;   // unterminated REG_SZ guard
            if ( is_special_container( v.data() ) ) return false;
            GUID old{};
            if ( CLSIDFromString( v.data(), &old ) != NOERROR ) {
                log_first_fail( "container:clsid", (DWORD)E_FAIL );
                return false;
            }
            GUID nw{};
            map_container( old, shared, &nw );
            const std::wstring ns = guid_to_str( nw );
            const LSTATUS wrc = RegSetValueExW( hk, L"ContainerId", 0, REG_SZ,
                reinterpret_cast<const BYTE*>( ns.c_str() ),
                static_cast<DWORD>( ( ns.size() + 1 ) * sizeof( wchar_t ) ) );
            if ( wrc != ERROR_SUCCESS )
                log_first_fail( "container:write-sz", wrc );
            return wrc == ERROR_SUCCESS;
        }

        if ( type == REG_BINARY && sz >= 16 ) {
            BYTE buf[16]{};
            DWORD got = sizeof( buf );
            if ( RegQueryValueExW( hk, L"ContainerId", nullptr, &type,
                    buf, &got ) != ERROR_SUCCESS )
                return false;
            bool zero = true;
            for ( BYTE b : buf ) if ( b ) { zero = false; break; }
            if ( zero ) return false;
            GUID old{};
            memcpy( &old, buf, sizeof( GUID ) );
            GUID nw{};
            map_container( old, shared, &nw );
            const LSTATUS wrc = RegSetValueExW( hk, L"ContainerId", 0, REG_BINARY,
                reinterpret_cast<const BYTE*>( &nw ), sizeof( GUID ) );
            if ( wrc != ERROR_SUCCESS )
                log_first_fail( "container:write-bin", wrc );
            return wrc == ERROR_SUCCESS;
        }
        return false;
    }

    struct branch_stats {
        std::uint32_t renamed    = 0;
        std::uint32_t containers = 0;
    };

    // recursively seize a key and all descendants so a recursive delete goes
    // through even where protected child DACLs block inherited ACEs
    static void seize_tree( const std::wstring& sub_path, PSID admin_sid ) {
        HKEY hk = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, sub_path.c_str(), 0,
                            KEY_READ, &hk ) == ERROR_SUCCESS ) {
            std::vector<std::wstring> kids;
            enum_subkeys( hk, &kids );
            RegCloseKey( hk );
            for ( const auto& k : kids )
                seize_tree( sub_path + L"\\" + k, admin_sid );
        }
        seize_key( L"MACHINE\\" + sub_path, admin_sid );
    }

    // full rename flow. RegCopyTreeW dies on subtrees whose protected DACLs
    // block the inherited admin ACE, so the copy goes through the
    // backup/restore APIs: RegSaveKeyW (SeBackupPrivilege reads any key)
    // into a temp hive, RegRestoreKeyW into the freshly created key. the
    // hive carries the ORIGINAL security, so the renamed copy is
    // indistinguishable from a native key; ContainerId is patched after
    // the restore under a seizure rolled back byte-exact.
    static bool rename_instance( const std::wstring& dev_path,
                                 const std::wstring& inst_path,
                                 const wchar_t* inst_name,
                                 branch_stats* st,
                                 std::map<std::wstring, GUID>* shared,
                                 PSID admin_sid ) {
        const std::size_t len = wcslen( inst_name );
        if ( !len || len > 100 ) return false;

        const std::wstring inst_mp = L"MACHINE\\" + inst_path;

        // 1) snapshot the source subtree (original security + values)
        key_security isec;
        const bool ihave = save_security( inst_mp, &isec );

        wchar_t tmp_dir[MAX_PATH] = {};
        wchar_t tmp_file[MAX_PATH] = {};
        GetTempPathW( MAX_PATH, tmp_dir );
        swprintf_s( tmp_file, MAX_PATH, L"%lsenumtree-%08x.hiv",
                     tmp_dir, rand_next() );
        DeleteFileW( tmp_file );   // RegSaveKeyW fails on an existing file

        bool saved = false;
        HKEY hsrc = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, inst_path.c_str(), 0,
                            KEY_READ, &hsrc ) == ERROR_SUCCESS ) {
            const LSTATUS src_rc = RegSaveKeyW( hsrc, tmp_file, nullptr );
            if ( src_rc != ERROR_SUCCESS )
                log_first_fail( "rename:save", src_rc );
            else
                saved = true;
            RegCloseKey( hsrc );
        } else {
            log_first_fail( "rename:open-src", GetLastError() );
        }
        if ( !saved ) {
            if ( ihave ) restore_security( inst_mp, isec );
            free_security( &isec );
            return false;
        }

        // 2) create the renamed copy + restore the hive into it
        const std::wstring dev_mp = L"MACHINE\\" + dev_path;
        key_security psec;
        const bool phave = save_security( dev_mp, &psec );
        bool done = false;
        if ( seize_key( dev_mp, admin_sid ) ) {
            wchar_t new_name[128]{};
            for ( int guard = 0; guard < 16 && !done; ++guard ) {
                rand_alnum( new_name, len );
                HKEY hchk = nullptr;
                if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE,
                        ( dev_path + L"\\" + new_name ).c_str(), 0,
                        KEY_READ, &hchk ) == ERROR_SUCCESS ) {
                    RegCloseKey( hchk );
                    continue;   // collision - reroll
                }

                HKEY hnew = nullptr;
                const std::wstring new_path = dev_path + L"\\" + new_name;
                if ( RegCreateKeyExW( HKEY_LOCAL_MACHINE, new_path.c_str(), 0,
                        nullptr, 0, KEY_WRITE, nullptr, &hnew, nullptr )
                        != ERROR_SUCCESS ) {
                    log_first_fail( "rename:create", GetLastError() );
                    break;
                }
                const LSTATUS rrc = RegRestoreKeyW( hnew, tmp_file, 0 );
                RegCloseKey( hnew );
                if ( rrc != ERROR_SUCCESS ) {
                    log_first_fail( "rename:restore", rrc );
                    SHDeleteKeyW( HKEY_LOCAL_MACHINE, new_path.c_str() );
                    break;
                }

                // patch the copy's ContainerId under a temporary seizure,
                // then put the restored (original) descriptor back
                const std::wstring new_mp = L"MACHINE\\" + new_path;
                key_security nsec;
                const bool nhave = save_security( new_mp, &nsec );
                if ( seize_key( new_mp, admin_sid ) ) {
                    HKEY hpatch = nullptr;
                    if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, new_path.c_str(), 0,
                            KEY_SET_VALUE | KEY_QUERY_VALUE, &hpatch )
                            == ERROR_SUCCESS ) {
                        if ( patch_container_id( hpatch, shared ) )
                            ++st->containers;
                        RegCloseKey( hpatch );
                    }
                }
                if ( nhave ) restore_security( new_mp, nsec );
                free_security( &nsec );

                // 3) remove the source subtree
                seize_tree( inst_path, admin_sid );
                const LSTATUS drc = SHDeleteKeyW( HKEY_LOCAL_MACHINE,
                                                  inst_path.c_str() );
                if ( drc != ERROR_SUCCESS )
                    log_first_fail( "rename:delete", drc );

                if ( drc == ERROR_SUCCESS ) {
                    logging::print( "enum-tree: %ls\\...\\%ls -> %ls",
                        dev_path.c_str() + dev_path.rfind( L'\\' ) + 1,
                        inst_name, new_name );
                    ++st->renamed;
                    done = true;
                }
            }
            if ( phave ) restore_security( dev_mp, psec );
        }
        free_security( &psec );

        // the seized source descriptor dies with the deleted key; only a
        // failed rename needs the rollback
        if ( !done && ihave ) restore_security( inst_mp, isec );
        free_security( &isec );
        DeleteFileW( tmp_file );
        return done;
    }

    static void walk_branch( const wchar_t* branch, bool allow_renames,
                             branch_stats* st, std::map<std::wstring, GUID>* shared,
                             PSID admin_sid ) {
        HKEY hroot = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, branch, 0,
                            KEY_READ, &hroot ) != ERROR_SUCCESS )
            return;

        std::vector<std::wstring> hwids;
        if ( !enum_subkeys( hroot, &hwids ) ) {
            RegCloseKey( hroot );
            return;
        }

        for ( const auto& hwid : hwids ) {
            const std::wstring dev_path = std::wstring( branch ) + L"\\" + hwid;
            HKEY hdev = nullptr;
            if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, dev_path.c_str(), 0,
                                KEY_READ, &hdev ) != ERROR_SUCCESS )
                continue;

            std::vector<std::wstring> instances;
            enum_subkeys( hdev, &instances );
            RegCloseKey( hdev );

            for ( const auto& inst : instances ) {
                const std::wstring inst_path = dev_path + L"\\" + inst;

                // serial name -> full rename; otherwise ContainerId only
                if ( allow_renames && looks_like_serial( inst.c_str() ) ) {
                    if ( rename_instance( dev_path, inst_path, inst.c_str(),
                                          st, shared, admin_sid ) )
                        continue;
                }

                // pre-check without touching security - admin reads are free
                HKEY hchk = nullptr;
                if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, inst_path.c_str(), 0,
                        KEY_QUERY_VALUE, &hchk ) != ERROR_SUCCESS )
                    continue;
                DWORD t = 0, vsz = 0;
                const bool has = RegQueryValueExW( hchk, L"ContainerId", nullptr,
                                                   &t, nullptr, &vsz ) == ERROR_SUCCESS;
                RegCloseKey( hchk );
                if ( !has ) continue;

                const std::wstring inst_mp = L"MACHINE\\" + inst_path;
                key_security sec;
                const bool have = save_security( inst_mp, &sec );
                if ( seize_key( inst_mp, admin_sid ) ) {
                    HKEY hk = nullptr;
                    // query + write rights needed below
                    if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, inst_path.c_str(), 0,
                            KEY_SET_VALUE | KEY_QUERY_VALUE, &hk )
                            == ERROR_SUCCESS ) {
                        if ( patch_container_id( hk, shared ) )
                            ++st->containers;
                        RegCloseKey( hk );
                    } else {
                        log_first_fail( "container:open", GetLastError() );
                    }
                }
                if ( have ) restore_security( inst_mp, sec );
                free_security( &sec );
            }
        }
        RegCloseKey( hroot );
    }

    inline void install() {
        enable_privilege( "SeTakeOwnershipPrivilege" );
        enable_privilege( "SeRestorePrivilege" );
        enable_privilege( "SeBackupPrivilege" );

        PSID admin_sid = sid_from_str( L"S-1-5-32-544" );
        if ( !admin_sid || !IsValidSid( admin_sid ) ) {
            logging::print( "enum-tree: admin SID resolve failed" );
            return;
        }

        // shared old->new container map keeps physical-device grouping
        // consistent across every branch and both value forms
        std::map<std::wstring, GUID> shared;

        struct branch_spec {
            const wchar_t* branch;
            bool           renames;
        };
        // SWD/PCI instance names are generated, not serials (PrintQueues,
        // MFG_... machine identity) - ContainerId patches only
        static const branch_spec k_branches[] = {
            { L"SYSTEM\\CurrentControlSet\\Enum\\HID",     true  },
            { L"SYSTEM\\CurrentControlSet\\Enum\\Battery", true  },
            { L"SYSTEM\\CurrentControlSet\\Enum\\SWD",     false },
            { L"SYSTEM\\CurrentControlSet\\Enum\\PCI",     false },
        };

        branch_stats total{};
        for ( const auto& b : k_branches ) {
            branch_stats st{};
            walk_branch( b.branch, b.renames, &st, &shared, admin_sid );
            const wchar_t* tail = b.branch + wcslen( b.branch );
            while ( tail > b.branch && tail[-1] != L'\\' ) --tail;
            logging::print( "enum-tree: %-8ls %u renamed, %u ContainerId patched",
                tail, st.renamed, st.containers );
            total.renamed    += st.renamed;
            total.containers += st.containers;
        }

        logging::print( "enum-tree: %u serial key(s) renamed, %u ContainerId(s) "
            "patched across %zu container group(s)",
            total.renamed, total.containers, shared.size() );

        LocalFree( admin_sid );
    }

}