#include <src/symbols/includes.h>
#include <src/ui.hxx>

int main( int argc, char** argv ) {
    logging::setup_console();
    bool use_gui = true;
    bool diag_arp = false, diag_gpu = false, only_preflight = false;
    logging::set_verbose( false );
    std::vector<std::array<std::uint8_t, 6>> ref_macs;

    for ( int i = 1; i < argc; ++i ) {
        if ( !_stricmp( argv[i], oxorany( "--cli" ) ) ) {
            use_gui = false;
        }
        if ( !_stricmp( argv[i], oxorany( "--refmac" ) ) && i + 1 < argc ) {
            std::array<std::uint8_t, 6> mac{};
            unsigned parsed = 0, val = 0, digits = 0;
            for ( const char* p = argv[++i]; *p && parsed < 6; ++p ) {
                if ( *p == '-' || *p == ':' ) {
                    if ( digits ) { mac[parsed++] = (std::uint8_t)val; val = 0; digits = 0; }
                    continue;
                }
                int d = -1;
                if ( *p >= '0' && *p <= '9' ) d = *p - '0';
                else if ( *p >= 'a' && *p <= 'f' ) d = *p - 'a' + 10;
                else if ( *p >= 'A' && *p <= 'F' ) d = *p - 'A' + 10;
                if ( d < 0 ) break;
                val = val * 16 + d;
                if ( ++digits == 2 ) { mac[parsed++] = (std::uint8_t)val; val = 0; digits = 0; }
            }
            if ( parsed == 6 ) ref_macs.push_back( mac );
        }
        if ( !_stricmp( argv[i], oxorany( "--arptest" ) ) ) { diag_arp = true; use_gui = false; }
        if ( !_stricmp( argv[i], oxorany( "--gputest" ) ) ) { diag_gpu = true; use_gui = false; }
        if ( !_stricmp( argv[i], oxorany( "--preflight" ) ) ) { only_preflight = true; use_gui = false; }
        if ( !_stricmp( argv[i], oxorany( "--verbose" ) ) || !_stricmp( argv[i], oxorany( "-v" ) ) )
            logging::set_verbose( true );
        if ( !_stricmp( argv[i], oxorany( "--quiet" ) ) || !_stricmp( argv[i], oxorany( "-q" ) ) )
            logging::set_verbose( false );
        if ( !_stricmp( argv[i], oxorany( "--enumtest" ) ) ) {
            logging::set_verbose( true );
            spoof::helpers::init_rng();
            spoof::enum_tree::install();
            logging::shutdown();
            return 0;
        }
    }

    SetUnhandledExceptionFilter( handler::crash_handler );

    if ( !utility::adjust_privilege( 20 ) )
        return std::getchar();

    logging::info( oxorany( "resolving ntoskrnl PDB..." ) );
    if ( !pdb::load( oxorany( "ntoskrnl.exe" ) ) ) {
        logging::error( oxorany( "could not load PDB" ) );
        return std::getchar();
    }

    logging::success( oxorany( "loaded %zu symbols from %s" ),
        pdb::s_symbols.size(), pdb::s_module_bare.c_str() );

    if ( !service::create() ) {
        logging::error( oxorany( "could not setup service" ) );
        service::unload();
        return std::getchar();
    }

    if ( !driver::initialize() ) {
        logging::error( oxorany( "could not setup driver (EBIoDispatch device missing? HVCI must be OFF)" ) );
        service::unload();
        return std::getchar();
    }

    if ( !paging::setup() ) {
        logging::error( oxorany( "could not get directory table base" ) );
        service::unload();
        driver::unload();
        return std::getchar();
    }

    if ( !syscall::setup() ) {
        logging::error( oxorany( "could not setup kernel execution" ) );
        service::unload();
        driver::unload();
        return std::getchar();
    }

    if ( use_gui ) {
        logging::info( oxorany( "launching ImGui GUI interface..." ) );
        ui::render_gui();
    } else {
        if ( only_preflight ) {
            if ( !spoof::preflight::run() )
                logging::error( oxorany( "preflight failed" ) );
        } else if ( diag_arp ) {
            logging::info( oxorany( "arptest: read-only ARP chain diagnostic" ) );
            arp::diag( ref_macs );
        } else if ( diag_gpu ) {
            logging::info( oxorany( "gputest: read-only OBJGPU uuid diagnostic" ) );
            gpu::diag();
        } else {
            if ( !spoof::preflight::run() ) {
                logging::error( oxorany( "preflight failed - refusing to spoof" ) );
                service::unload();
                driver::unload();
                return std::getchar();
            }
            spoof::install( false );
        }
    }

    if ( !service::unload() ) {
        logging::error( oxorany( "could not unload service" ) );
        return std::getchar();
    }

    if ( !driver::unload() ) {
        logging::error( oxorany( "could not unload driver" ) );
        return std::getchar();
    }

    logging::shutdown();
    return 0;
}
