#pragma once
#include "helpers.hxx"
#include "../../symbols/pdb_offsets.hxx"
#include <vector>
#include <algorithm>
#include <winreg.h>
#include <setupapi.h>
#pragma comment( lib, "setupapi.lib" )
#include <cfgmgr32.h>
#pragma comment( lib, "cfgmgr32.lib" )

namespace spoof::nic {

    using namespace helpers;

    struct ndis_off_t {
        std::uint64_t miniport_list_rva  = 0;
        std::uint64_t wpp_cb_rva         = 0;
        std::uint32_t mp_next_global     = 0;
        std::uint32_t mp_eth_db          = 0;
        std::uint32_t mp_adapter_ctx     = 0;
        std::uint32_t mp_if_avail        = 0;
        std::uint32_t mp_if_block        = 0;
        std::uint32_t ifb_cur            = 0;
        std::uint32_t ifb_perm           = 0;
        std::uint32_t ifb_family         = 0;
        std::uint32_t pa_length          = 0;
        std::uint32_t pa_address         = 0;
        std::uint32_t ethdb_addr         = 0;
        bool     valid              = false;
    };

    static ndis_off_t s_off;
    static std::uint8_t s_first_mac[6];

    // per-adapter plan: NCI -> old live MAC -> new MAC, the same value going
    // to NetworkAddress and the kernel IF_BLOCK so every surface agrees
    struct adapter_override {
        wchar_t         guid[64]{};   // NetCfgInstanceId, "{...}"
        char            desc[64]{};   // GAI Description, for the summary
        std::uint8_t    old_mac[6]{};
        std::uint8_t    new_mac[6]{};
        bool            restartable = false; // real devnode we can PnP-restart
        bool            adopted     = false; // driver verifiably reports new_mac
        bool            is_radio    = false; // the WiFi radio adapter itself
        bool            wfd         = false; // Wi-Fi Direct virtual port
        // driver honors NetworkAddress? bthpan derives its MAC from the BT
        // radio and never reads it - cycling is harmless, waiting is a waste
        bool            na_adoptable = false;
        std::uint8_t    last_seen[6]{};      // what GAI last reported for it
    };
    static std::vector<adapter_override> s_overrides;

    static const adapter_override* find_override( const std::uint8_t old_mac[6] ) {
        for ( const auto& o : s_overrides )
            if ( !memcmp( o.old_mac, old_mac, 6 ) ) return &o;
        return nullptr;
    }

    // a MAC a kernel walk already wrote this session - don't re-randomize
    static const adapter_override* find_patched( const std::uint8_t mac[6] ) {
        for ( const auto& o : s_overrides )
            if ( !memcmp( o.new_mac, mac, 6 ) ) return &o;
        return nullptr;
    }

    static bool mac_is_set( const std::uint8_t mac[6] ) {
        return mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5];
    }

    static bool same_oui( const std::uint8_t a[6], const std::uint8_t b[6] ) {
        return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
    }

    // kernel-side old->new pair: kernel walks see adapters GetAdaptersInfo
    // can miss, so their pairs complete the plan
    static void record_override( const std::uint8_t old_mac[6], const std::uint8_t new_mac[6] ) {
        if ( !mac_is_set( old_mac ) || !mac_is_set( new_mac ) ) return;
        if ( !memcmp( old_mac, new_mac, 6 ) ) return;
        for ( const auto& o : s_overrides )
            if ( !memcmp( o.old_mac, old_mac, 6 ) ) return;  // already keyed
        adapter_override o{};
        memcpy( o.old_mac, old_mac, 6 );
        memcpy( o.new_mac, new_mac, 6 );
        s_overrides.push_back( o );
    }

    // true only when the driver verifiably reports this MAC after the PnP
    // restart - the FL_INTERFACE cache may only carry a value the hardware
    // actually transmits with
    static bool is_adopted( const std::uint8_t mac[6] ) {
        if ( !mac_is_set( mac ) ) return false;
        for ( const auto& o : s_overrides )
            if ( o.adopted && !memcmp( o.new_mac, mac, 6 ) ) return true;
        return false;
    }

    static bool radio_adopted() {
        for ( const auto& o : s_overrides )
            if ( o.is_radio ) return o.adopted;
        return false;
    }

    // first adopted MAC in plan order, nullptr when nothing adopted
    static const std::uint8_t* first_adopted_mac() {
        for ( const auto& o : s_overrides )
            if ( o.adopted ) return o.new_mac;
        return nullptr;
    }

    // WFD ports follow the radio - only patch once the radio adopted our MAC
    static bool override_blocked( const std::uint8_t old_mac[6] ) {
        const adapter_override* plan = find_override( old_mac );
        return plan && plan->wfd && !radio_adopted();
    }

    static void resolve_offsets() {
        loader_offsets::ndis_offsets ndis{};
        if ( !pdb_offsets::resolve_ndis( &ndis ) ) {
            logging::print( "nic: NDIS offset resolution failed" );
            return;
        }
        const std::uint64_t ndis_base = helpers::get_kernel_module_base( L"ndis.sys" );
        if ( !ndis_base ) {
            logging::print( "nic: could not find ndis.sys kernel base" );
            return;
        }
        s_off.miniport_list_rva  = ndis_base + ndis.miniport_list_rva;
        s_off.wpp_cb_rva         = ndis_base + ndis.wpp_main_cb_rva;
        s_off.mp_next_global     = ndis.mp_next_global;
        s_off.mp_eth_db          = ndis.mp_eth_db;
        s_off.mp_adapter_ctx     = ndis.mp_adapter_ctx;
        s_off.mp_if_avail        = ndis.mp_if_avail;
        s_off.mp_if_block        = ndis.mp_if_block;
        s_off.ifb_cur            = ndis.ifb_cur_phys_addr;
        s_off.ifb_perm           = ndis.ifb_perm_phys_addr;
        s_off.ifb_family         = ndis.ifb_family_entry;
        s_off.pa_length          = ndis.pa_length;
        s_off.pa_address         = ndis.pa_address;
        s_off.ethdb_addr         = ndis.ethdb_adapter_addr;
        s_off.valid              = true;
        logging::print( "nic: ndis.sys offsets: mp_next=0x%x mp_ethdb=0x%x mp_ifblock=0x%x ifb_cur=0x%x ifb_perm=0x%x ethdb_addr=0x%x",
            s_off.mp_next_global, s_off.mp_eth_db, s_off.mp_if_block,
            s_off.ifb_cur, s_off.ifb_perm, s_off.ethdb_addr );
    }

    static void generate_mac( std::uint8_t mac[6], const std::uint8_t* old_mac ) {
        FILETIME ft{}; GetSystemTimeAsFileTime( &ft );
        // counter salt: same-millisecond plans must not share a MAC suffix
        static volatile LONG s_counter = 0;
        const std::uint64_t salt = (std::uint64_t)InterlockedIncrement( &s_counter ) * 0x9E3779B97F4A7C15ULL;
        std::uint64_t seed = (std::uint64_t)ft.dwLowDateTime ^ ( (std::uint64_t)ft.dwHighDateTime << 32 ) ^ salt;
        seed = (seed ^ (seed>>30)) * 0xbf58476d1ce4e5b9ULL;
        seed = (seed ^ (seed>>27)) * 0x94d049bb133111ebULL;
        seed ^= seed >> 31;

        if ( old_mac && ( old_mac[0] || old_mac[1] || old_mac[2] ) ) {
            mac[0] = old_mac[0];
            mac[1] = old_mac[1];
            mac[2] = old_mac[2];
        } else {
            mac[0] = 0x02;
            mac[1] = (std::uint8_t)( seed >> 8 );
            mac[2] = (std::uint8_t)( seed >> 16 );
        }
        mac[3] = (std::uint8_t)( seed >> 24 );
        mac[4] = (std::uint8_t)( seed >> 32 );
        mac[5] = (std::uint8_t)( seed >> 40 );
    }

// write a MAC into an IF_BLOCK phys-addr field, gated: length must read 6,
// current value non-zero (zeroed = wrong offset for this build, writing
// poisons a neighbour), readback with restore on mismatch
static bool patch_phys_addr( std::uint64_t ifb_va, std::uint32_t field_off, const std::uint8_t mac[6] ) {
        if ( !s_off.pa_address ) return false;
        const std::uint64_t addr_va = ifb_va + field_off + s_off.pa_address;
        const std::uint16_t len = kread_val<std::uint16_t>( ifb_va + field_off + s_off.pa_length );
        if ( len != 6 ) return false;

        std::uint8_t cur[6] = {};
        if ( !kread( addr_va, cur, 6 ) ) return false;
        if ( !mac_is_set( cur ) ) {
            logging::print( "nic: IF_BLOCK field at 0x%llx is zeroed - offset wrong, write skipped", addr_va );
            return false;
        }
        kwrite( addr_va, mac, 6 );
        std::uint8_t back[6] = {};
        if ( !kread( addr_va, back, 6 ) || memcmp( back, mac, 6 ) != 0 ) {
            kwrite( addr_va, cur, 6 );
            logging::print( "nic: IF_BLOCK write at 0x%llx failed readback - restored original", addr_va );
            return false;
        }
        return true;
    }

    static void patch_miniport( std::uint64_t mp_va, const std::uint8_t mac[6] ) {

        std::uint32_t wrote = 0;
        if ( s_off.mp_if_avail && s_off.mp_if_block ) {
            const std::uint32_t avail = kread_val<std::uint32_t>( mp_va + s_off.mp_if_avail );
            if ( avail ) {
                const std::uint64_t ifb = kread_val<std::uint64_t>( mp_va + s_off.mp_if_block );
                if ( is_kva(ifb) ) {
                    if ( s_off.ifb_cur  ) wrote += patch_phys_addr( ifb, s_off.ifb_cur,  mac );
                    if ( s_off.ifb_perm ) wrote += patch_phys_addr( ifb, s_off.ifb_perm, mac );
                }
            }
        }

        if ( wrote )
            logging::print( "nic: miniport 0x%llx MAC patched %02X:%02X:%02X:%02X:%02X:%02X",
                mp_va, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5] );
        else
            logging::print( "nic: miniport 0x%llx IF_BLOCK patch skipped (unresolved/failed gates)",
                mp_va );
    }

    static std::uint32_t walk_miniport_list() {
        if ( !is_kva( s_off.miniport_list_rva ) ) return 0;


        const std::uint64_t mp_head_va = kread_val<std::uint64_t>( s_off.miniport_list_rva );
        if ( !is_kva( mp_head_va ) ) {
            logging::print( "nic: miniport list head is null or invalid (0x%llx)", mp_head_va );
            return 0;
        }

        std::uint32_t count = 0;
        std::uint64_t mp = mp_head_va;

        for ( std::uint32_t i = 0; i < 64 && is_kva(mp); ++i ) {
            const std::uint64_t ethdb = s_off.mp_eth_db ? kread_val<std::uint64_t>( mp + s_off.mp_eth_db ) : 0;
            logging::print( "nic: mp[%u]=0x%llx ethdb=0x%llx", i, mp, ethdb );

            if ( is_kva(ethdb) && s_off.ethdb_addr ) {
                std::uint8_t old_mac[6] = {};
                const bool mac_read = kread( ethdb + s_off.ethdb_addr, old_mac, 6 );
                if ( mac_read && mac_is_set( old_mac ) && !override_blocked( old_mac ) ) {
                    std::uint8_t new_mac[6] = {};
                    const adapter_override* plan = find_override( old_mac );
                    if ( plan ) {
                        memcpy( new_mac, plan->new_mac, 6 );
                    } else if ( const adapter_override* done = find_patched( old_mac ) ) {
                        // the restart made ethdb read new_mac - keep it
                        memcpy( new_mac, done->new_mac, 6 );
                    } else {
                        generate_mac( new_mac, old_mac );
                    }
                    if ( count == 0 ) memcpy( s_first_mac, new_mac, 6 );
                    record_override( old_mac, new_mac );
                    patch_miniport( mp, new_mac );
                    ++count;
                } else {
                    // diagnostics only - name the miniport and what was unreadable
                    const adapter_override* plan = mac_read ? find_override( old_mac ) : nullptr;
                    if ( !plan && mac_read ) plan = find_patched( old_mac );
                    const char* name = plan && plan->desc[0] ? plan->desc : "unknown adapter";
                    const std::uint64_t addr_va = ethdb + s_off.ethdb_addr;
                    if ( !mac_read )
                        logging::print( "nic: mp[%u] 0x%llx (%s) - read of ethdb AdapterAddress at 0x%llx (ethdb 0x%llx + 0x%x) failed - not patched",
                            i, mp, name, addr_va, ethdb, s_off.ethdb_addr );
                    else if ( !mac_is_set( old_mac ) )
                        logging::print( "nic: mp[%u] 0x%llx (%s) - ethdb AdapterAddress at 0x%llx reads zeroed %02X:%02X:%02X:%02X:%02X:%02X (offset wrong for this build?) - not patched",
                            i, mp, name, addr_va,
                            old_mac[0], old_mac[1], old_mac[2], old_mac[3], old_mac[4], old_mac[5] );
                    else
                        logging::print( "nic: mp[%u] 0x%llx (%s) - identity %02X:%02X:%02X:%02X:%02X:%02X blocked (Wi-Fi Direct port, radio not adopted) - not patched",
                            i, mp, name,
                            old_mac[0], old_mac[1], old_mac[2], old_mac[3], old_mac[4], old_mac[5] );
                }
            } else {
                // diagnostics only - say which precondition was missing
                if ( !s_off.ethdb_addr )
                    logging::print( "nic: mp[%u] 0x%llx - eth filter AdapterAddress offset unresolved - identity unreadable, not patched", i, mp );
                else if ( !s_off.mp_eth_db )
                    logging::print( "nic: mp[%u] 0x%llx - ethdb offset unresolved - identity unreadable, not patched", i, mp );
                else
                    logging::print( "nic: mp[%u] 0x%llx - ethdb pointer 0x%llx not a valid kernel address - identity unreadable, not patched", i, mp, ethdb );
            }

            if ( !s_off.mp_next_global ) break;
            mp = kread_val<std::uint64_t>( mp + s_off.mp_next_global );
        }
        return count;
    }

    static constexpr std::uint32_t kWppFamilyHeadOff = 0x128;

    static std::uint32_t walk_ifblock_family() {
        if ( !s_off.wpp_cb_rva || !s_off.ifb_family ) return 0;

        const std::uint64_t sentinel_va = s_off.wpp_cb_rva + kWppFamilyHeadOff;
        const std::uint64_t sentinel_flink = kread_val<std::uint64_t>( sentinel_va );
        const std::uint64_t sentinel_blink = kread_val<std::uint64_t>( sentinel_va + 8 );
        if ( !is_kva(sentinel_flink) || !is_kva(sentinel_blink) ) return 0;

        logging::print( "nic: ifblock sentinel=0x%llx flink=0x%llx", sentinel_va, sentinel_flink );

        std::uint32_t count = 0;
        std::uint64_t entry = sentinel_flink;
        for ( std::uint32_t i = 0; i < 128 && is_kva(entry) && entry != sentinel_va; ++i ) {
            const std::uint64_t ifb_va = entry - s_off.ifb_family;
            const std::uint64_t next   = kread_val<std::uint64_t>( entry );

            if ( s_off.ifb_cur && s_off.pa_address ) {
                const std::uint16_t cur_len = kread_val<std::uint16_t>( ifb_va + s_off.ifb_cur + s_off.pa_length );
                std::uint8_t old_mac[6] = {};
                const bool have_old = cur_len == 6 &&
                    kread( ifb_va + s_off.ifb_cur + s_off.pa_address, old_mac, 6 );
                if ( have_old && mac_is_set( old_mac ) && !override_blocked( old_mac ) ) {
                    std::uint8_t new_mac[6] = {};

                    // keep any value patched earlier this session
                    const adapter_override* plan = find_override( old_mac );
                    const adapter_override* done = find_patched( old_mac );
                    if ( plan ) {
                        memcpy( new_mac, plan->new_mac, 6 );
                    } else if ( done ) {
                        memcpy( new_mac, done->new_mac, 6 );
                    } else if ( mac_is_set( s_first_mac ) && same_oui( old_mac, s_first_mac ) ) {
                        memcpy( new_mac, s_first_mac, 6 );
                    } else {
                        generate_mac( new_mac, old_mac );
                    }

                    record_override( old_mac, new_mac );
                    patch_phys_addr( ifb_va, s_off.ifb_cur, new_mac );
                    if ( s_off.ifb_perm )
                        patch_phys_addr( ifb_va, s_off.ifb_perm, new_mac );
                    ++count;
                }
            }

            entry = next;
        }
        return count;
    }

    static void flush_arp_cache() {

        HMODULE hLib = LoadLibraryA( "iphlpapi.dll" );
        if ( !hLib ) return;


        using FlushIpNetTable2_t = DWORD( __stdcall* )( USHORT, ULONG );
        auto fn = reinterpret_cast<FlushIpNetTable2_t>(
            GetProcAddress( hLib, "FlushIpNetTable2" ) );

        if ( fn ) {

            const DWORD r = fn( 0, 0 );
            logging::print( "nic: ARP/neighbor cache flushed (status=%u)", r );
        }
        FreeLibrary( hLib );
    }

    // ---- registry NetworkAddress transport (net class {4d36e972-...}) -------
    // the one sanctioned channel for programming a MAC into the hardware: at
    // miniport init the driver reads it and adopts the value on the wire.
    // strictly transient - write, PnP restart, wait for adoption, scrub; a
    // boot never sees it. the historical code-31 boot failures were the
    // stage-13 NCI rewrite decorrelating the NDIS binding store, never this
    // value - identity rotation goes through heal_adapter_identity()

    static void build_adapter_overrides() {
        s_overrides.clear();

        // minimal GetAdaptersInfo layout - only the fields we read
        struct gai_ipstring {
            gai_ipstring* Next;
            char IpAddress[16];
            char IpMask[16];
            DWORD Context;
        };
        struct gai_info {
            gai_info* Next;
            DWORD ComboIndex;
            char AdapterName[260];
            char Description[132];
            UINT AddressLength;
            BYTE Address[8];
            DWORD Index;
        };
        using fn_get_adapters_info_t = DWORD(WINAPI*)(gai_info*, ULONG*);

        const HMODULE iphlp = GetModuleHandleW( L"iphlpapi.dll" )
                              ? GetModuleHandleW( L"iphlpapi.dll" )
                              : LoadLibraryW( L"iphlpapi.dll" );
        if ( !iphlp ) return;
        const auto fn_gai = reinterpret_cast<fn_get_adapters_info_t>(
            GetProcAddress( iphlp, "GetAdaptersInfo" ) );
        if ( !fn_gai ) return;

        ULONG sz = 0;
        fn_gai( nullptr, &sz );
        if ( !sz ) return;
        std::vector<std::uint8_t> buf( sz );
        auto* info = reinterpret_cast<gai_info*>( buf.data() );
        if ( fn_gai( info, &sz ) != ERROR_SUCCESS ) return;

        for ( auto* a = info; a; a = a->Next ) {
            if ( a->AddressLength != 6 ) continue;
            adapter_override o{};
            memcpy( o.old_mac, a->Address, 6 );
            if ( !mac_is_set( o.old_mac ) ) continue;

            // adapter GUID: "{........-....-....-....-............}"
            if ( a->AdapterName[0] != '{' ) continue;
            for ( int i = 0; i < 62 && a->AdapterName[i]; ++i )
                o.guid[i] = static_cast<wchar_t>( a->AdapterName[i] );

            generate_mac( o.new_mac, o.old_mac );

            // WFD virtuals have no MAC of their own - the driver re-derives
            // them from the radio, so restarting the radio propagates
            o.wfd         = strstr( a->Description, "Wi-Fi Direct" ) != nullptr;
            o.restartable = !o.wfd;
            o.is_radio    = !o.wfd &&
                ( strstr( a->Description, "Wi-Fi" ) != nullptr ||
                  strstr( a->Description, "WiFi" ) != nullptr );
            // bthpan.sys builds its MAC from the BT radio address and never
            // reads NetworkAddress - it can never adopt, don't wait on it
            o.na_adoptable = o.restartable &&
                strstr( a->Description, "Personal Area Network" ) == nullptr;
            snprintf( o.desc, sizeof( o.desc ), "%s", a->Description );
            s_overrides.push_back( o );
        }

        // WFD MAC = radio-derived (local-admin bit, last byte bumped) -
        // matches what the driver programs; a random value is a tell
        const adapter_override* radio = nullptr;
        for ( const auto& o : s_overrides )
            if ( o.is_radio ) { radio = &o; break; }
        if ( radio ) {
            std::uint32_t wfd_idx = 0;
            for ( auto& o : s_overrides ) {
                if ( !o.wfd ) continue;
                memcpy( o.new_mac, radio->new_mac, 6 );
                o.new_mac[0] |= 0x02;
                o.new_mac[5] = (std::uint8_t)( o.new_mac[5] + 1 + wfd_idx );
                ++wfd_idx;
            }
            if ( wfd_idx )
                logging::print( "nic: %u Wi-Fi Direct MAC(s) derived from radio override", wfd_idx );
        }
        logging::print( "nic: %u real adapter(s) planned for override (%u restartable)",
            (unsigned)s_overrides.size(),
            (unsigned)std::count_if( s_overrides.begin(), s_overrides.end(),
                []( const adapter_override& o ) { return o.restartable; } ) );
    }

    static void clean_network_address_overrides() {
        static const wchar_t* k_class_key =
            L"SYSTEM\\CurrentControlSet\\Control\\Class"
            L"\\{4d36e972-e325-11ce-bfc1-08002be10318}";

        HKEY hClass = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, k_class_key, 0,
                KEY_READ, &hClass ) != ERROR_SUCCESS ) {
            logging::print( "nic: net class key not found" );
            return;
        }

        std::uint32_t removed = 0, clean = 0;
        for ( DWORD idx = 0; ; ++idx ) {
            wchar_t sub[64] = {};
            DWORD sub_len = 64;
            if ( RegEnumKeyExW( hClass, idx, sub, &sub_len,
                                 nullptr, nullptr, nullptr, nullptr ) != ERROR_SUCCESS ) break;

            wchar_t path[256] = {};
            swprintf_s( path, L"%s\\%s", k_class_key, sub );

            HKEY hAdapter = nullptr;
            if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, path, 0,
                    KEY_QUERY_VALUE | KEY_SET_VALUE, &hAdapter ) != ERROR_SUCCESS ) continue;

            // only real adapter instance keys carry DriverDesc
            DWORD type = 0;
            if ( RegQueryValueExW( hAdapter, L"DriverDesc", nullptr, &type,
                                   nullptr, nullptr ) != ERROR_SUCCESS
                 || type != REG_SZ ) {
                RegCloseKey( hAdapter );
                continue;
            }

            // drop any override - ours or a third-party tool's; the one
            // value a stock machine never has
            if ( RegQueryValueExW( hAdapter, L"NetworkAddress", nullptr, nullptr,
                                   nullptr, nullptr ) == ERROR_SUCCESS ) {
                if ( RegDeleteValueW( hAdapter, L"NetworkAddress" ) == ERROR_SUCCESS )
                    ++removed;
                else
                    logging::print( "nic: failed to remove NetworkAddress from %ls", sub );
            } else {
                ++clean;
            }

            RegCloseKey( hAdapter );
        }
        RegCloseKey( hClass );
        logging::print( "nic: NetworkAddress overrides removed (%u), already-clean keys (%u) - persistent NIC state kept stock",
            removed, clean );
    }

    // ---- transient NetworkAddress + PnP restart = real wire adoption --------

    // preflight probe: would a NetworkAddress write find its home?
    static bool adapter_class_key_exists( const wchar_t* guid ) {
        static const wchar_t* k_class_key =
            L"SYSTEM\\CurrentControlSet\\Control\\Class"
            L"\\{4d36e972-e325-11ce-bfc1-08002be10318}";

        HKEY hClass = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, k_class_key, 0,
                KEY_READ, &hClass ) != ERROR_SUCCESS )
            return false;

        bool found = false;
        for ( DWORD idx = 0; !found; ++idx ) {
            wchar_t sub[64] = {};
            DWORD sub_len = 64;
            if ( RegEnumKeyExW( hClass, idx, sub, &sub_len,
                                 nullptr, nullptr, nullptr, nullptr ) != ERROR_SUCCESS ) break;

            wchar_t path[256] = {};
            swprintf_s( path, L"%s\\%s", k_class_key, sub );

            HKEY hAdapter = nullptr;
            if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, path, 0,
                    KEY_QUERY_VALUE, &hAdapter ) != ERROR_SUCCESS ) continue;

            wchar_t cur[64] = {};
            DWORD len = sizeof( cur );
            if ( RegQueryValueExW( hAdapter, L"NetCfgInstanceId", nullptr, nullptr,
                                   (BYTE*)cur, &len ) == ERROR_SUCCESS
                 && _wcsicmp( cur, guid ) == 0 )
                found = true;
            RegCloseKey( hAdapter );
        }
        RegCloseKey( hClass );
        return found;
    }

    static bool write_network_address( const wchar_t* guid, const std::uint8_t mac[6] ) {
        static const wchar_t* k_class_key =
            L"SYSTEM\\CurrentControlSet\\Control\\Class"
            L"\\{4d36e972-e325-11ce-bfc1-08002be10318}";

        HKEY hClass = nullptr;
        if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, k_class_key, 0,
                KEY_READ, &hClass ) != ERROR_SUCCESS )
            return false;

        bool written = false;
        for ( DWORD idx = 0; !written; ++idx ) {
            wchar_t sub[64] = {};
            DWORD sub_len = 64;
            if ( RegEnumKeyExW( hClass, idx, sub, &sub_len,
                                 nullptr, nullptr, nullptr, nullptr ) != ERROR_SUCCESS ) break;

            wchar_t path[256] = {};
            swprintf_s( path, L"%s\\%s", k_class_key, sub );

            HKEY hAdapter = nullptr;
            if ( RegOpenKeyExW( HKEY_LOCAL_MACHINE, path, 0,
                    KEY_QUERY_VALUE | KEY_SET_VALUE, &hAdapter ) != ERROR_SUCCESS ) continue;

            wchar_t cur[64] = {};
            DWORD len = sizeof( cur );
            if ( RegQueryValueExW( hAdapter, L"NetCfgInstanceId", nullptr, nullptr,
                                   (BYTE*)cur, &len ) == ERROR_SUCCESS
                 && _wcsicmp( cur, guid ) == 0 ) {
                // drivers expect 12 uppercase hex chars
                wchar_t val[13] = {};
                swprintf_s( val, L"%02X%02X%02X%02X%02X%02X",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
                if ( RegSetValueExW( hAdapter, L"NetworkAddress", 0,
                        REG_SZ, (const BYTE*)val, sizeof(val) ) == ERROR_SUCCESS )
                    written = true;
            }
            RegCloseKey( hAdapter );
        }
        RegCloseKey( hClass );
        return written;
    }

    // in-session PnP stop/start of one devnode (matched by NCI through the
    // driver key): re-runs AddDevice + miniport init, leaves no boot state
    static bool pnp_restart_adapter( const wchar_t* guid, bool enable ) {
        static const GUID k_devclass_net =
            { 0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

        const HDEVINFO devs = SetupDiGetClassDevsW( &k_devclass_net, nullptr, nullptr, DIGCF_PRESENT );
        if ( devs == INVALID_HANDLE_VALUE ) return false;

        bool acted = false;
        for ( DWORD i = 0; ; ++i ) {
            SP_DEVINFO_DATA data{};
            data.cbSize = sizeof( data );
            if ( !SetupDiEnumDeviceInfo( devs, i, &data ) ) break;

            HKEY drv = SetupDiOpenDevRegKey( devs, &data, DICS_FLAG_GLOBAL, 0,
                                             DIREG_DRV, KEY_QUERY_VALUE );
            if ( drv == INVALID_HANDLE_VALUE ) continue;

            wchar_t cur[64] = {};
            DWORD len = sizeof( cur );
            const bool match =
                RegQueryValueExW( drv, L"NetCfgInstanceId", nullptr, nullptr,
                                  (BYTE*)cur, &len ) == ERROR_SUCCESS
                && _wcsicmp( cur, guid ) == 0;
            RegCloseKey( drv );
            if ( !match ) continue;

            SP_PROPCHANGE_PARAMS pcp{};
            pcp.ClassInstallHeader.cbSize = sizeof( pcp.ClassInstallHeader );
            pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
            pcp.StateChange = enable ? DICS_ENABLE : DICS_DISABLE;
            pcp.Scope = DICS_FLAG_GLOBAL;
            if ( SetupDiSetClassInstallParamsW( devs, &data, &pcp.ClassInstallHeader, sizeof( pcp ) )
                 && SetupDiCallClassInstaller( DIF_PROPERTYCHANGE, devs, &data ) )
                acted = true;
            break;
        }
        SetupDiDestroyDeviceInfoList( devs );
        return acted;
    }

    // ---- GUID identity rotation via devnode reinstall -----------------------
    // a bare NetCfgInstanceId rewrite is the code-31 boot poison: ndisPnPAddDevice
    // resolves an installed adapter's config and bindings BY that GUID, and an
    // unknown GUID fails AddDevice with 0xC0000001. a devnode reinstall instead
    // re-runs the full netsetup install, letting Windows mint a fresh correlated
    // GUID set (NCI, Linkage, Control\Network, Tcpip) - spoofed and boot-safe
    static bool reinstall_adapter( const wchar_t* guid ) {
        static const GUID k_devclass_net =
            { 0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

        const HDEVINFO devs = SetupDiGetClassDevsW( &k_devclass_net, nullptr, nullptr, DIGCF_PRESENT );
        if ( devs == INVALID_HANDLE_VALUE ) return false;

        bool removed = false;
        wchar_t inst_prefix[128] = {};
        DEVINST parent = 0;
        for ( DWORD i = 0; ; ++i ) {
            SP_DEVINFO_DATA data{};
            data.cbSize = sizeof( data );
            if ( !SetupDiEnumDeviceInfo( devs, i, &data ) ) break;

            HKEY drv = SetupDiOpenDevRegKey( devs, &data, DICS_FLAG_GLOBAL, 0,
                                             DIREG_DRV, KEY_QUERY_VALUE );
            if ( drv == INVALID_HANDLE_VALUE ) continue;

            wchar_t cur[64] = {};
            DWORD len = sizeof( cur );
            const bool match =
                RegQueryValueExW( drv, L"NetCfgInstanceId", nullptr, nullptr,
                                  (BYTE*)cur, &len ) == ERROR_SUCCESS
                && _wcsicmp( cur, guid ) == 0;
            RegCloseKey( drv );
            if ( !match ) continue;

            // instance prefix, stable across re-adds ("PCI\VEN_...", "BTH\MS_BTHPAN")
            wchar_t inst[128] = {};
            if ( SetupDiGetDeviceInstanceIdW( devs, &data, inst, 128, nullptr ) ) {
                wchar_t* last = wcsrchr( inst, L'\\' );
                if ( last ) *last = 0;
                wcscpy_s( inst_prefix, inst );
            }
            CM_Get_Parent( &parent, data.DevInst, 0 );

            SP_REMOVEDEVICE_PARAMS rdp{};
            rdp.ClassInstallHeader.cbSize = sizeof( rdp.ClassInstallHeader );
            rdp.ClassInstallHeader.InstallFunction = DIF_REMOVE;
            rdp.Scope = DI_REMOVEDEVICE_GLOBAL;
            if ( SetupDiSetClassInstallParamsW( devs, &data, &rdp.ClassInstallHeader, sizeof( rdp ) )
                 && SetupDiCallClassInstaller( DIF_REMOVE, devs, &data ) )
                removed = true;
            break;
        }
        SetupDiDestroyDeviceInfoList( devs );

        if ( !removed || !inst_prefix[0] ) {
            logging::print( "nic: %ls devnode removal failed - identity left as-is", guid );
            return false;
        }

        // re-enumerate the parent bus; whole-tree scan is a slow (20+s) fallback
        auto kick = [&]( bool deep ) {
            if ( parent ) CM_Reenumerate_DevNode( parent, 0 );
            if ( deep ) {
                DEVINST root = 0;
                if ( CM_Locate_DevNodeW( &root, (DEVINSTID_W)L"HTREE\\ROOT\\0", 0 ) == CR_SUCCESS )
                    CM_Reenumerate_DevNode( root, 0 );
            }
        };
        kick( false );

        // wait for present+started+problem-free; re-enumeration can take tens
        // of seconds, poll long
        for ( int attempt = 0; attempt < 60; ++attempt ) {
            if ( attempt == 10 ) kick( false );  // wedge retry on the parent bus
            if ( attempt == 30 || attempt == 50 ) kick( true );  // escalate to a full tree scan

            const HDEVINFO check = SetupDiGetClassDevsW( &k_devclass_net, nullptr, nullptr, DIGCF_PRESENT );
            if ( check == INVALID_HANDLE_VALUE ) { Sleep( 500 ); continue; }
            for ( DWORD i = 0; ; ++i ) {
                SP_DEVINFO_DATA data{};
                data.cbSize = sizeof( data );
                if ( !SetupDiEnumDeviceInfo( check, i, &data ) ) break;

                wchar_t inst[128] = {};
                if ( !SetupDiGetDeviceInstanceIdW( check, &data, inst, 128, nullptr ) ) continue;
                wchar_t* last = wcsrchr( inst, L'\\' );
                if ( last ) *last = 0;
                if ( _wcsicmp( inst, inst_prefix ) != 0 ) continue;

                ULONG status = 0, problem = 0;
                if ( CM_Get_DevNode_Status( &status, &problem, data.DevInst, 0 ) == CR_SUCCESS
                     && ( status & DN_HAS_PROBLEM ) == 0
                     && ( status & DN_STARTED ) != 0 ) {
                    SetupDiDestroyDeviceInfoList( check );
                    return true;
                }
            }
            SetupDiDestroyDeviceInfoList( check );
            Sleep( 500 );
        }
        logging::print( "nic: %ls did not return after 30s - identity reinstall FAILED", guid );
        return false;
    }

    // rotate GUID identity BEFORE the final plan - the reinstall rewrites the
    // NCI the plan keys on; re-plan until GetAdaptersInfo sees every adapter
    static void heal_adapter_identity() {
        std::uint32_t want = 0;
        for ( const auto& o : s_overrides )
            if ( o.restartable ) ++want;
        if ( !want ) return;

        std::uint32_t healed = 0;
        for ( const auto& o : s_overrides ) {
            if ( !o.restartable ) continue;
            if ( reinstall_adapter( o.guid ) ) ++healed;
        }
        // "run:" survives the clean-console filter
        logging::print( "run: %u/%u adapter(s) reinstalled with fresh correlated GUID identity", healed, want );

        for ( int attempt = 0; attempt < 20; ++attempt ) {
            build_adapter_overrides();
            std::uint32_t have = 0;
            for ( const auto& o : s_overrides )
                if ( o.restartable ) ++have;
            if ( have >= want ) break;
            Sleep( 500 );
        }
    }

    // flag overrides whose adapter now reports the planned MAC
    static void poll_adoption() {
        struct gai_info {
            gai_info* Next;
            DWORD ComboIndex;
            char AdapterName[260];
            char Description[132];
            UINT AddressLength;
            BYTE Address[8];
            DWORD Index;
        };
        using fn_get_adapters_info_t = DWORD(WINAPI*)(gai_info*, ULONG*);

        const HMODULE iphlp = GetModuleHandleW( L"iphlpapi.dll" )
                              ? GetModuleHandleW( L"iphlpapi.dll" )
                              : LoadLibraryW( L"iphlpapi.dll" );
        if ( !iphlp ) return;
        const auto fn_gai = reinterpret_cast<fn_get_adapters_info_t>(
            GetProcAddress( iphlp, "GetAdaptersInfo" ) );
        if ( !fn_gai ) return;

        ULONG sz = 0;
        fn_gai( nullptr, &sz );
        if ( !sz ) return;
        std::vector<std::uint8_t> buf( sz );
        auto* info = reinterpret_cast<gai_info*>( buf.data() );
        if ( fn_gai( info, &sz ) != ERROR_SUCCESS ) return;

        for ( auto& o : s_overrides ) {
            for ( auto* a = info; a; a = a->Next ) {
                if ( a->AddressLength != 6 ) continue;
                wchar_t name[64] = {};
                if ( a->AdapterName[0] != '{' ) continue;
                for ( int i = 0; i < 62 && a->AdapterName[i]; ++i )
                    name[i] = static_cast<wchar_t>( a->AdapterName[i] );
                if ( _wcsicmp( name, o.guid ) != 0 ) continue;

                std::uint8_t mac[6] = {};
                memcpy( mac, a->Address, 6 );
                memcpy( o.last_seen, mac, 6 );
                if ( mac_is_set( mac ) && !memcmp( mac, o.new_mac, 6 ) )
                    o.adopted = true;  // latched - only ever set, never cleared
            }
        }
    }

    static void apply_overrides_via_restart() {
        bool any = false;
        for ( auto& o : s_overrides ) {
            if ( !o.restartable ) continue;

            if ( !write_network_address( o.guid, o.new_mac ) ) {
                logging::print( "nic: %ls has no matching class key - restart skipped", o.guid );
                continue;
            }
            if ( !pnp_restart_adapter( o.guid, false ) ) {
                logging::print( "nic: could not disable %ls - leaving NA in place for the scrub", o.guid );
                continue;
            }
            Sleep( 800 );
            if ( !pnp_restart_adapter( o.guid, true ) )
                logging::print( "nic: could not re-enable %ls", o.guid );
            any = true;
            logging::print( "nic: %ls restarted for MAC adoption", o.guid );
        }
        if ( !any ) return;

        // radio re-association takes seconds; WFD virtuals re-derive from the
        // radio and latch opportunistically. only NA-capable drivers can ever
        // confirm - no point waiting on bthpan
        for ( int attempt = 0; attempt < 24; ++attempt ) {
            poll_adoption();
            bool done = true;
            for ( const auto& o : s_overrides )
                if ( o.na_adoptable && !o.adopted ) { done = false; break; }
            if ( done ) break;
            Sleep( 500 );
        }

        // a driver can wedge on first init after disable (rtwlane does) - a
        // second cycle unwedges; the transport value is still in place, the
        // scrub happens after this stage
        bool any_retry = false;
        for ( auto& o : s_overrides ) {
            if ( !o.na_adoptable || o.adopted ) continue;
            logging::print( "nic: %ls not adopted - counter-restarting", o.guid );
            if ( !pnp_restart_adapter( o.guid, false ) ) continue;
            Sleep( 1500 );
            if ( !pnp_restart_adapter( o.guid, true ) ) continue;
            any_retry = true;
        }
        if ( any_retry ) {
            for ( int attempt = 0; attempt < 16; ++attempt ) {
                poll_adoption();
                bool done = true;
                for ( const auto& o : s_overrides )
                    if ( o.na_adoptable && !o.adopted ) { done = false; break; }
                if ( done ) break;
                Sleep( 500 );
            }
        }

        for ( const auto& o : s_overrides ) {
            char old_txt[24] = {}, new_txt[40] = {}, name[80] = {};
            snprintf( old_txt, sizeof( old_txt ), "%02X:%02X:%02X:%02X:%02X:%02X",
                o.old_mac[0], o.old_mac[1], o.old_mac[2],
                o.old_mac[3], o.old_mac[4], o.old_mac[5] );
            snprintf( new_txt, sizeof( new_txt ), "%02X:%02X:%02X:%02X:%02X:%02X%s",
                o.new_mac[0], o.new_mac[1], o.new_mac[2],
                o.new_mac[3], o.new_mac[4], o.new_mac[5],
                o.adopted ? "  (wire)" : "  (report-only)" );
            snprintf( name, sizeof( name ), "%s", o.desc[0] ? o.desc : "adapter" );

            if ( o.restartable ) {
                // bthpan never reads NetworkAddress - report-only is its
                // permanent state, not a failure. for real drivers show what
                // the adapter still reports so misses are diagnosable
                if ( !o.na_adoptable )
                    logging::print( "run: %ls report-only - driver ignores NetworkAddress (%02X:%02X:%02X:%02X:%02X:%02X)",
                        o.guid, o.new_mac[0], o.new_mac[1], o.new_mac[2],
                        o.new_mac[3], o.new_mac[4], o.new_mac[5] );
                else
                    logging::print( "run: %ls hardware adoption %s (%02X:%02X:%02X:%02X:%02X:%02X)",
                        o.guid, o.adopted ? "CONFIRMED" : "not confirmed",
                        o.new_mac[0], o.new_mac[1], o.new_mac[2],
                        o.new_mac[3], o.new_mac[4], o.new_mac[5] );
                if ( o.na_adoptable && !o.adopted )
                    logging::print( "run: %ls still reports %02X:%02X:%02X:%02X:%02X:%02X",
                        o.guid, o.last_seen[0], o.last_seen[1], o.last_seen[2],
                        o.last_seen[3], o.last_seen[4], o.last_seen[5] );
                logging::change( "NIC MAC", name, old_txt, new_txt, o.adopted );
            } else {
                logging::change( "NIC MAC", name, old_txt, new_txt, false );
            }
        }
    }

    inline void install() {
        // plan -> drivers adopt the exact planned MACs in hardware -> kernel walks reuse the same values
        build_adapter_overrides();
        // heal_adapter_identity(); // Bypassed: devnode removal (DIF_REMOVE) causes kernel page faults on physical NICs
        apply_overrides_via_restart();

        // registry back to stock before any kernel work
        clean_network_address_overrides();

        resolve_offsets();
        if ( !s_off.valid ) {
            logging::print( "nic: NDIS offset resolution failed - registry overrides only" );
            return;
        }

        const std::uint32_t mp_count  = walk_miniport_list();
        const std::uint32_t ifb_count = walk_ifblock_family();
        logging::print( "nic: patched %u miniport(s), %u IF_BLOCK(s)", mp_count, ifb_count );

        flush_arp_cache();
    }

}
