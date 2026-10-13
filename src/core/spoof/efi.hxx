#pragma once
#include "helpers.hxx"
#include <vector>

namespace spoof::efi {

    using namespace helpers;



    static const GUID k_vendor_guid = {
        0xeaec226fu, 0xc9a3u, 0x477au,
        { 0xa8u, 0x26u, 0xddu, 0xc7u, 0x16u, 0xcdu, 0xc0u, 0xe3u }
    };



    static void enable_env_privilege() {
        HANDLE token = nullptr;
        if ( !OpenProcessToken( GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token ) )
            return;
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValueA( nullptr, "SeSystemEnvironmentPrivilege",
                               &tp.Privileges[0].Luid );
        AdjustTokenPrivileges( token, FALSE, &tp, sizeof( tp ), nullptr, nullptr );
        CloseHandle( token );
    }



    using NtSetSysEnvEx_t = NTSTATUS( __stdcall* )(
        PUNICODE_STRING, LPGUID, PVOID, ULONG, ULONG );
    using NtQuerySysEnvEx_t = NTSTATUS(NTAPI*)(PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG);

    // binary blob -> hex prefix for the change ledger (fields hold ~76 chars)
    static void format_hex_prefix( char* out, std::size_t out_size,
                                   const std::uint8_t* data, std::uint32_t size ) {
        if ( !out || out_size < 2 ) return;
        out[0] = '\0';
        if ( !data ) return;
        const std::uint32_t max_bytes = static_cast<std::uint32_t>( ( out_size - 1 ) / 2 );
        const std::uint32_t shown = size < max_bytes ? size : max_bytes;
        for ( std::uint32_t i = 0; i < shown; ++i )
            std::snprintf( out + i * 2, 3, "%02X", data[i] );
    }

    static void write_efi_var( NtSetSysEnvEx_t fn,
                               const wchar_t* name, std::uint32_t size ) {

        UNICODE_STRING uname{};
        uname.Buffer        = const_cast<wchar_t*>( name );
        uname.Length        = static_cast<USHORT>( wcslen( name ) * sizeof( wchar_t ) );
        uname.MaximumLength = static_cast<USHORT>( uname.Length + 2 );


        if ( size > 256 ) size = 256;
        std::uint8_t buf[256]{};
        for ( std::uint32_t i = 0; i < size; ++i )
            buf[i] = static_cast<std::uint8_t>( rand_next() & 0xFF );

        // capture the current variable contents before the overwrite so the
        // change ledger can show old -> new ("-" when it does not exist yet)
        char old_str[76] = "-";
        {
            const auto query_fn = reinterpret_cast<NtQuerySysEnvEx_t>(
                GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                                "NtQuerySystemEnvironmentValueEx" ) );
            if ( query_fn ) {
                ULONG osz = 0, oattrs = 0;
                if ( query_fn( &uname, const_cast<LPGUID>( &k_vendor_guid ),
                               nullptr, &osz, &oattrs ) == 0 && osz && osz <= 4096 ) {
                    std::vector<std::uint8_t> old_buf( osz );
                    if ( query_fn( &uname, const_cast<LPGUID>( &k_vendor_guid ),
                                   old_buf.data( ), &osz, &oattrs ) == 0 && osz )
                        format_hex_prefix( old_str, sizeof( old_str ), old_buf.data( ), osz );
                }
            }
        }

        const NTSTATUS st = fn( &uname,
                                const_cast<LPGUID>( &k_vendor_guid ),
                                buf, size, 0x00000007u );
        if ( st == 0 ) {
            logging::print( "efi: var '%ls' (%u bytes) -> ok", name, size );
            char name_buf[64] = {};
            std::snprintf( name_buf, sizeof( name_buf ), "%ls", name );
            char new_str[76] = {};
            format_hex_prefix( new_str, sizeof( new_str ), buf, size );
            logging::change( "EFI", name_buf, old_str, new_str, false );
        } else
            logging::print( "efi: var '%ls' status=0x%08X", name,
                            static_cast<std::uint32_t>( st ) );
    }



    // OEM/EDK2 "PlatformData" firmware variable: a machine-specific blob that
    // is otherwise untouched by any spoofing surface (dma-spoofer only fakes
    // the kernel read path via a HalGetEnvironmentVariableEx hook). We can do
    // better hookless: enumerate the firmware variable store, find the
    // variable's real GUID at runtime (no hardcoded vendor GUID), and
    // overwrite the NVRAM variable itself - every later kernel-mode
    // ExGetFirmwareEnvironmentVariable read returns our bytes.
    //
    // NtEnumerateSystemEnvironmentValuesEx class 1 returns contiguous
    // {UNICODE_STRING Name; GUID VendorGuid;} entries; Name.Buffer holds an
    // offset relative to the start of the enumeration buffer
    struct ENUM_ENV_ENTRY { UNICODE_STRING Name; GUID VendorGuid; };
    static_assert(sizeof(ENUM_ENV_ENTRY) == 32);

    using NtEnumSysEnvEx_t  = NTSTATUS(NTAPI*)(ULONG, PVOID, PULONG);

    static void spoof_platform_data() {
        const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        const auto enum_fn = reinterpret_cast<NtEnumSysEnvEx_t>(
            GetProcAddress(ntdll, "NtEnumerateSystemEnvironmentValuesEx"));
        const auto query_fn = reinterpret_cast<NtQuerySysEnvEx_t>(
            GetProcAddress(ntdll, "NtQuerySystemEnvironmentValueEx"));
        const auto set_fn = reinterpret_cast<NtSetSysEnvEx_t>(
            GetProcAddress(ntdll, "NtSetSystemEnvironmentValueEx"));
        if (!enum_fn || !query_fn || !set_fn) {
            logging::print("efi: firmware-variable APIs not found, skipping PlatformData");
            return;
        }

        ULONG len = 0x8000;
        std::vector<std::uint8_t> buf;
        NTSTATUS st = 0xC0000023 /*STATUS_BUFFER_TOO_SMALL*/;
        for (int attempt = 0; attempt < 5; ++attempt) {
            buf.assign(len, 0);
            st = enum_fn(1, buf.data(), &len);
            if (st == 0 || st != 0xC0000023) break;
            if (len <= buf.size()) { len = (ULONG)buf.size() * 2; }  // server lied, grow anyway
        }
        if (st != 0) {
            logging::print("efi: firmware variable enumeration failed (status=0x%08X)",
                static_cast<std::uint32_t>(st));
            return;
        }

        std::uint32_t found = 0;
        for (ULONG pos = 0; pos + sizeof(ENUM_ENV_ENTRY) <= len; pos += sizeof(ENUM_ENV_ENTRY)) {
            const auto* e = reinterpret_cast<const ENUM_ENV_ENTRY*>(buf.data() + pos);
            if (!e->Name.Length) break;
            // relative Buffer (values past the buffer end would be absolute
            // kernel pointers - not dereferenceable from usermode)
            const auto* name = reinterpret_cast<const wchar_t*>(
                buf.data() + reinterpret_cast<std::uintptr_t>(e->Name.Buffer));
            if (reinterpret_cast<const std::uint8_t*>(name) + e->Name.Length > buf.data() + len)
                continue;
            if (e->Name.Length != 24 || _wcsicmp(name, L"PlatformData") != 0)
                continue;  // 12 chars * 2
            ++found;

            UNICODE_STRING uname{};
            uname.Buffer = const_cast<wchar_t*>(name);
            uname.Length = uname.MaximumLength = 24;

            GUID guid = e->VendorGuid;
            ULONG sz = 0, attrs = 0;
            query_fn(&uname, &guid, nullptr, &sz, &attrs);
            if (!sz || sz > 4096) { sz = 64; attrs = 0x00000007; }

            // capture the current contents before the overwrite so the change
            // ledger can show old -> new ("-" when the size query failed)
            char old_str[76] = "-";
            {
                ULONG osz = 0, oattrs = 0;
                if (query_fn(&uname, &guid, nullptr, &osz, &oattrs) == 0 && osz && osz <= 4096) {
                    std::vector<std::uint8_t> old_data(osz);
                    if (query_fn(&uname, &guid, old_data.data(), &osz, &oattrs) == 0 && osz)
                        format_hex_prefix(old_str, sizeof(old_str), old_data.data(), osz);
                }
            }

            std::vector<std::uint8_t> data(sz);
            for (auto& b : data) b = static_cast<std::uint8_t>(rand_next() & 0xFF);

            const NTSTATUS wst = set_fn(&uname, &guid, data.data(), sz, attrs);
            logging::print("efi: PlatformData (GUID %08X-%04X-%04X) %u bytes %s (status=0x%08X)",
                guid.Data1, guid.Data2, guid.Data3, sz,
                wst == 0 ? "overwritten" : "write failed",
                static_cast<std::uint32_t>(wst));
            if (wst == 0) {
                char new_str[76] = {};
                format_hex_prefix(new_str, sizeof(new_str), data.data(), sz);
                logging::change("EFI", "PlatformData", old_str, new_str, false);
            }
        }
        if (!found)
            logging::print("efi: PlatformData variable not present in firmware store");
    }

    inline void install() {

        const std::uint64_t boot_env_va =
            pdb::get_symbol_address( "ExpBootEnvironmentInformation" );
        if ( boot_env_va ) {
            std::uint8_t old_guid[16]{};
            kread( boot_env_va, old_guid, 16 );
            logging::print( "efi: boot GUID before: "
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                old_guid[3],old_guid[2],old_guid[1],old_guid[0],
                old_guid[5],old_guid[4], old_guid[7],old_guid[6],
                old_guid[8],old_guid[9], old_guid[10],old_guid[11],
                old_guid[12],old_guid[13],old_guid[14],old_guid[15] );

            std::uint8_t new_guid[16]{};
            for ( int i = 0; i < 16; ++i )
                new_guid[i] = static_cast<std::uint8_t>( rand_next() & 0xFF );

            new_guid[6] = static_cast<std::uint8_t>( ( new_guid[6] & 0x0Fu ) | 0x40u );
            new_guid[8] = static_cast<std::uint8_t>( ( new_guid[8] & 0x3Fu ) | 0x80u );

            // identity gate: the boot environment GUID is a real machine
            // GUID set by the loader - an all-zero slot means the symbol
            // address does not hold a GUID on this build; do not write it
            bool old_zero = true;
            for ( int i = 0; i < 16; ++i )
                if ( old_guid[i] ) { old_zero = false; break; }
            if ( old_zero ) {
                logging::print( "efi: boot GUID slot at 0x%llx is zeroed - write skipped",
                    boot_env_va );
            }
            else if ( kwrite_verified( boot_env_va, new_guid, 16, "efi: boot GUID" ) ) {
                logging::print( "efi: boot GUID patched: "
                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    new_guid[3],new_guid[2],new_guid[1],new_guid[0],
                    new_guid[5],new_guid[4], new_guid[7],new_guid[6],
                    new_guid[8],new_guid[9], new_guid[10],new_guid[11],
                    new_guid[12],new_guid[13],new_guid[14],new_guid[15] );
                char old_str[40] = {}, new_str[40] = {};
                std::snprintf( old_str, sizeof( old_str ),
                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    old_guid[3],old_guid[2],old_guid[1],old_guid[0],
                    old_guid[5],old_guid[4], old_guid[7],old_guid[6],
                    old_guid[8],old_guid[9], old_guid[10],old_guid[11],
                    old_guid[12],old_guid[13],old_guid[14],old_guid[15] );
                std::snprintf( new_str, sizeof( new_str ),
                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    new_guid[3],new_guid[2],new_guid[1],new_guid[0],
                    new_guid[5],new_guid[4], new_guid[7],new_guid[6],
                    new_guid[8],new_guid[9], new_guid[10],new_guid[11],
                    new_guid[12],new_guid[13],new_guid[14],new_guid[15] );
                logging::change( "EFI", "Boot GUID", old_str, new_str, false );
            }
            else
                logging::print( "efi: boot GUID kwrite failed" );
        } else {
            logging::print( "efi: ExpBootEnvironmentInformation not found, skipping boot GUID" );
        }



        enable_env_privilege();

        auto* fn = reinterpret_cast<NtSetSysEnvEx_t>(
            GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                            "NtSetSystemEnvironmentValueEx" ) );
        if ( !fn ) {
            logging::print( "efi: NtSetSystemEnvironmentValueEx not found, skipping EFI vars" );
            return;
        }

        write_efi_var( fn, L"OfflineUniqueIDRandomSeed",  32 );
        write_efi_var( fn, L"UnlockIDCopy",               32 );
        write_efi_var( fn, L"OfflineUniqueIDEKPub",      256 );
        write_efi_var( fn, L"PlatformModuleData",         128 );

        spoof_platform_data();
    }

}
