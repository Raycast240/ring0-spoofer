#pragma once

namespace service {
    static wchar_t s_driver_name[20]{};

    inline bool create() {
        if ( !load_driver_privilege( true ) ) {
            logging::print( oxorany( "Could not enable driver loading privilege.\n" ) );
            return false;
        }

        utility::gen_rnd_str( s_driver_name );
        if ( !install_service( s_driver_name ) ) {
            load_driver_privilege( false );
            return false;
        }

        return true;
    }

    inline bool cleanup() {
        std::memset( driver_bytes, 0, sizeof( driver_bytes ) );
        return true;
    }

    inline bool unload() {
        if ( !uninstall_services() ) {
            logging::error( oxorany( "could not uninstall services" ) );
            return false;
        }
        load_driver_privilege( false );
        return true;
    }
}
