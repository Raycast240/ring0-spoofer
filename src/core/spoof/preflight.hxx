#pragma once
#include "helpers.hxx"
#include "nic.hxx"
#include "../../symbols/pdb_offsets.hxx"

namespace spoof::preflight {

    using namespace helpers;

    // pre-spoof validation, strictly read-only: verify every transport and
    // every derived layout BEFORE the run modifies anything. a critical check
    // failing means the spoof would not work (or worse, could corrupt) on
    // this machine - the run aborts with the box untouched. warnings are
    // machine-dependent surfaces the stages handle gracefully on their own.

    struct check_t {
        const char* name;
        bool pass;
        bool critical;
    };
    static std::vector<check_t> s_checks;

    static void record( const char* name, bool pass, bool critical ) {
        s_checks.push_back( { name, pass, critical } );
        if ( pass )
            logging::print( "preflight: [+] %s", name );
        else if ( critical )
            logging::print( "preflight: [-] %s - CRITICAL, spoof will be aborted", name );
        else
            logging::print( "preflight: [!] %s - optional, stages will degrade gracefully", name );
    }

    // kernel module is present AND its PE header is readable through our
    // physical-memory translation - proves kread works on that VA region
    static bool module_readable( const wchar_t* name ) {
        const std::uint64_t base = get_kernel_module_base( name );
        if ( !base ) return false;
        char mz[2] = {};
        return kread( base, mz, 2 ) && mz[0] == 'M' && mz[1] == 'Z';
    }

    static void check_windows() {
        using fn_rtl_get_version_t = LONG( WINAPI* )( RTL_OSVERSIONINFOW* );
        const auto fn = reinterpret_cast<fn_rtl_get_version_t>(
            GetProcAddress( GetModuleHandleW( L"ntdll.dll" ), "RtlGetVersion" ) );
        RTL_OSVERSIONINFOW vi{};
        vi.dwOSVersionInfoSize = sizeof( vi );
        if ( fn && fn( &vi ) == 0 )
            logging::info( "preflight: windows %lu.%lu.%lu detected",
                vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber );
    }

    inline bool run() {
        s_checks.clear();

        logging::blank();
        logging::info( "preflight: validating spoof prerequisites (read-only, nothing is modified)" );

        check_windows();

        // ---- transports: kernel r/w must work on everything we patch -------
        record( "ntoskrnl kernel read", module_readable( L"ntoskrnl.exe" ), true );
        record( "ndis.sys kernel read", module_readable( L"ndis.sys" ), true );
        record( "tcpip.sys kernel read", module_readable( L"tcpip.sys" ), true );

        // ---- derived layouts: resolve every offset set before any write ----
        loader_offsets::ndis_offsets ndis{};
        record( "NDIS miniport/IF_BLOCK offsets", pdb_offsets::resolve_ndis( &ndis ), true );

        loader_offsets::tcpip_offsets tcpip{};
        record( "tcpip compartment/FL offsets", pdb_offsets::resolve_tcpip( &tcpip ), true );

        loader_offsets::disk_offsets disk{};
        record( "disk stack offsets", pdb_offsets::resolve_disk( &disk ), false );

        loader_offsets::dxgkrnl_offsets dxg{};
        record( "dxgkrnl offsets (GPU stage)", pdb_offsets::resolve_dxgkrnl( &dxg ), false );

        loader_offsets::usbstor_offsets usb{};
        record( "usbstor offsets (USB stage)", pdb_offsets::resolve_usbstor( &usb ), false );

        loader_offsets::nvlddmkm_offsets nv{};
        record( "nvlddmkm offsets (NVIDIA GPU stage)", pdb_offsets::resolve_nvlddmkm( &nv ), false );

        // ---- disk stack drivers: machine-dependent, warn-only -------------
        static const wchar_t* k_optional_modules[] = {
            L"storport.sys", L"stornvme.sys", L"storahci.sys", L"classpnp.sys",
            L"partmgr.sys",  L"mountmgr.sys", L"volmgr.sys",
        };
        for ( const auto* mod : k_optional_modules ) {
            char name[64] = {};
            snprintf( name, sizeof( name ), "kernel module %ls present", mod );
            record( name, module_readable( mod ), false );
        }

        // ---- adapter plan: every restartable adapter must have a class key -
        nic::build_adapter_overrides();
        if ( nic::s_overrides.empty() ) {
            record( "network adapters enumerated", false, true );
        } else {
            record( "network adapters enumerated", true, true );
            for ( const auto& o : nic::s_overrides ) {
                if ( !o.restartable ) continue;
                char name[128] = {};
                snprintf( name, sizeof( name ), "adapter class key for '%s'", o.desc );
                record( name, nic::adapter_class_key_exists( o.guid ), false );
            }
        }

        // ---- verdict -------------------------------------------------------
        std::uint32_t failed = 0, warned = 0;
        for ( const auto& c : s_checks ) {
            if ( c.pass ) continue;
            if ( c.critical ) ++failed;
            else ++warned;
        }

        logging::blank();
        if ( failed ) {
            logging::error( "preflight: %u critical check(s) FAILED, %u warning(s) - spoof aborted, nothing was modified",
                failed, warned );
            return false;
        }
        logging::success( "preflight: %u checks passed, %u warning(s) - safe to spoof",
            (unsigned)s_checks.size(), warned );
        return true;
    }

}