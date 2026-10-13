#pragma once

namespace logging {
    enum class level {
        trace,
        info,
        stage,
        success,
        warning,
        error
    };

    namespace detail {
        inline std::mutex& output_lock( ) {
            static std::mutex lock;
            return lock;
        }

        inline level& min_level( ) {
            static level value = level::info;
            return value;
        }

        inline bool& verbose( ) {
            static bool value = false;
            return value;
        }

        inline bool& color_enabled( ) {
            static bool value = false;
            return value;
        }

        inline FILE*& log_file( ) {
            static FILE* value = nullptr;
            return value;
        }

        inline std::uint32_t& visible_warnings( ) {
            static std::uint32_t value = 0;
            return value;
        }

        inline std::uint32_t& visible_errors( ) {
            static std::uint32_t value = 0;
            return value;
        }

        inline const char* level_name( level value ) {
            switch ( value ) {
                case level::trace: return "DBG";
                case level::stage: return "STEP";
                case level::success: return "OK";
                case level::warning: return "WARN";
                case level::error: return "ERR";
                default: return "INFO";
            }
        }

        inline const char* level_color( level value ) {
            switch ( value ) {
                case level::trace: return "\x1b[38;2;125;135;165m";
                case level::stage: return "\x1b[38;2;125;215;255m";
                case level::success: return "\x1b[38;2;115;195;255m";
                case level::warning: return "\x1b[38;2;185;150;255m";
                case level::error: return "\x1b[38;2;255;115;170m";
                default: return "\x1b[38;2;170;125;255m";
            }
        }

        inline const char* time_color( ) {
            return "\x1b[38;2;105;115;150m";
        }

        inline const char* message_color( ) {
            return "\x1b[38;2;224;235;255m";
        }

        inline const char* reset_color( ) {
            return "\x1b[0m";
        }

        inline bool should_write( level value ) {
            return static_cast< int >( value ) >= static_cast< int >( min_level( ) );
        }

        inline bool contains( const std::string& text, const char* token ) {
            return text.find( token ) != std::string::npos;
        }

        inline void trim_line_end( char* text ) {
            if ( !text )
                return;

            auto length = std::strlen( text );
            while ( length && ( text[ length - 1 ] == '\n' || text[ length - 1 ] == '\r' ) )
                text[ --length ] = '\0';
        }

        inline void remove_status_markers( char* text ) {
            if ( !text )
                return;

            const char* markers[] = { "[+] ", "[-] ", "[!] ", "[~] " };
            for ( const auto marker : markers ) {
                auto marker_at = std::strstr( text, marker );
                if ( !marker_at )
                    continue;

                auto tail = marker_at + std::strlen( marker );
                std::memmove( marker_at, tail, std::strlen( tail ) + 1 );
                return;
            }
        }

        inline void normalize_message( const char* component, char* message, std::size_t message_size ) {
            if ( !message || !message_size )
                return;

            if ( component && !_stricmp( component, "spoof" ) &&
                 std::strstr( message, "driver object not found" ) ) {
                char path[ 128 ]{};
                std::size_t i = 0;
                while ( message[ i ] && message[ i ] != ' ' && i + 1 < sizeof( path ) ) {
                    path[ i ] = message[ i ];
                    ++i;
                }
                path[ i ] = '\0';

                if ( path[ 0 ] )
                    std::snprintf( message, message_size, "optional driver unavailable, skipped: %s", path );
                else
                    std::snprintf( message, message_size, "optional driver unavailable, skipped" );
            }
        }

        inline level infer_level( const char* message ) {
            std::string lowered = message ? message : "";
            std::transform( lowered.begin( ), lowered.end( ), lowered.begin( ),
                []( unsigned char ch ) { return static_cast< char >( std::tolower( ch ) ); } );

            if ( contains( lowered, "[-]" ) || contains( lowered, "failed" ) ||
                 contains( lowered, "could not" ) || contains( lowered, "invalid" ) ||
                 contains( lowered, "no suitable" ) || contains( lowered, "empty" ) )
                return level::error;

            if ( contains( lowered, "[!]" ) || contains( lowered, "[~]" ) ||
                 contains( lowered, "warning" ) || contains( lowered, "fallback" ) ||
                 contains( lowered, "skipping" ) || contains( lowered, "limited" ) ||
                 contains( lowered, "cancelled" ) || contains( lowered, "existing" ) ||
                 contains( lowered, "not found" ) )
                return level::warning;

            if ( contains( lowered, "[+]" ) || contains( lowered, "success" ) ||
                 contains( lowered, "loaded" ) || contains( lowered, "found" ) ||
                 contains( lowered, "created" ) || contains( lowered, "installed" ) ||
                 contains( lowered, "opened" ) || contains( lowered, "patched" ) ||
                 contains( lowered, "complete" ) || contains( lowered, "allocated" ) ||
                 contains( lowered, "resolved" ) || contains( lowered, "downloaded" ) ||
                 contains( lowered, "using cached" ) )
                return level::success;

            return level::info;
        }

        inline bool extract_component( char* message, char* component, std::size_t component_size ) {
            if ( !message || !component || !component_size )
                return false;

            auto colon = std::strchr( message, ':' );
            if ( !colon )
                return false;

            const auto length = static_cast< std::size_t >( colon - message );
            if ( length == 0 || length >= component_size || length > 16 )
                return false;

            for ( std::size_t i = 0; i < length; ++i ) {
                const auto ch = static_cast< unsigned char >( message[ i ] );
                if ( !std::isalnum( ch ) && ch != '_' && ch != '-' )
                    return false;
            }

            std::memcpy( component, message, length );
            component[ length ] = '\0';

            auto body = colon + 1;
            while ( *body == ' ' )
                ++body;

            std::memmove( message, body, std::strlen( body ) + 1 );
            return true;
        }

        inline bool equals( const char* left, const char* right ) {
            return _stricmp( left, right ) == 0;
        }

        inline bool is_internal_component( const char* component ) {
            const char* components[] = {
                "pdb", "spoof", "nic", "disk", "smbios", "efi", "uuid_cache",
                "monitor", "usb", "volume_guid", "product_id", "boot"
            };

            for ( const auto current : components ) {
                if ( equals( component, current ) )
                    return true;
            }

            return false;
        }

        inline bool is_important_pdb_error( const char* message ) {
            std::string lowered = message ? message : "";
            std::transform( lowered.begin( ), lowered.end( ), lowered.begin( ),
                []( unsigned char ch ) { return static_cast< char >( std::tolower( ch ) ); } );

            return contains( lowered, "pdb load failed" ) ||
                contains( lowered, "download failed" ) ||
                contains( lowered, "critical" );
        }

        inline bool should_write_message( level severity, const char* component, const char* message ) {
            if ( !should_write( severity ) )
                return false;

            if ( verbose( ) )
                return true;

            if ( equals( component, "pdb" ) )
                return severity == level::error && is_important_pdb_error( message );

            if ( is_internal_component( component ) )
                return severity == level::warning || severity == level::error;

            return true;
        }

        inline void write_file_line( const tm& local_tm, level severity, const char* component, const char* message ) {
            if ( !log_file( ) )
                return;

            std::fprintf( log_file( ), "%02d:%02d:%02d  %-4s  %-10s  %s\n",
                local_tm.tm_hour,
                local_tm.tm_min,
                local_tm.tm_sec,
                level_name( severity ),
                component,
                message );
            std::fflush( log_file( ) );
        }
    }

    inline void setup_console( const char* title = oxorany( "spoofer" ) ) {
        SetConsoleTitleA( title );
        SetConsoleOutputCP( CP_UTF8 );

        // the run log lives next to the executable (build\), not in whatever
        // directory the process happened to be launched from
        char sz_exe[MAX_PATH] = {};
        GetModuleFileNameA( nullptr, sz_exe, sizeof( sz_exe ) );
        std::string log_path( sz_exe );
        const std::size_t slash = log_path.find_last_of( "\\/" );
        if ( slash != std::string::npos )
            log_path.resize( slash + 1 );
        log_path += "spoofer.log";
        fopen_s( &detail::log_file( ), log_path.c_str( ), "w" );

        const auto std_handle = GetStdHandle( STD_OUTPUT_HANDLE );
        if ( std_handle == INVALID_HANDLE_VALUE )
            return;

        DWORD mode = 0;
        if ( !GetConsoleMode( std_handle, &mode ) )
            return;

        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        detail::color_enabled( ) = SetConsoleMode( std_handle, mode ) != FALSE;
    }

    inline void shutdown( ) {
        if ( detail::log_file( ) ) {
            std::fclose( detail::log_file( ) );
            detail::log_file( ) = nullptr;
        }
    }

    inline void set_verbose( bool enabled ) {
        detail::verbose( ) = enabled;
    }

    template<typename... Args>
    inline void write( level severity, const char* component, const char* format, Args... args ) {
        char message[ 2048 ]{};
        char source[ 32 ] = "app";

        std::snprintf( message, sizeof( message ), format, args... );
        detail::trim_line_end( message );
        detail::remove_status_markers( message );

        if ( component && component[ 0 ] )
            std::snprintf( source, sizeof( source ), "%s", component );
        else
            detail::extract_component( message, source, sizeof( source ) );
        detail::normalize_message( source, message, sizeof( message ) );

        const auto now = std::chrono::system_clock::now( );
        const auto time = std::chrono::system_clock::to_time_t( now );
        tm local_tm{};
        localtime_s( &local_tm, &time );

        std::lock_guard< std::mutex > guard( detail::output_lock( ) );
        detail::write_file_line( local_tm, severity, source, message );

        if ( !detail::should_write_message( severity, source, message ) )
            return;

        if ( detail::color_enabled( ) ) {
            std::printf( "%s%02d:%02d:%02d%s  %s%-4s%s  %s%s%s\n",
                detail::time_color( ),
                local_tm.tm_hour,
                local_tm.tm_min,
                local_tm.tm_sec,
                detail::reset_color( ),
                detail::level_color( severity ),
                detail::level_name( severity ),
                detail::reset_color( ),
                detail::message_color( ),
                message,
                detail::reset_color( ) );
        } else {
            std::printf( "%02d:%02d:%02d  %-4s  %s\n",
                local_tm.tm_hour,
                local_tm.tm_min,
                local_tm.tm_sec,
                detail::level_name( severity ),
                message );
        }

        if ( severity == level::warning )
            ++detail::visible_warnings( );
        else if ( severity == level::error )
            ++detail::visible_errors( );
    }

    template<typename... Args>
    inline void print( const char* format, Args... args ) {
        char message[ 2048 ]{};
        std::snprintf( message, sizeof( message ), format, args... );
        detail::trim_line_end( message );
        write( detail::infer_level( message ), nullptr, "%s", message );
    }

    template<typename... Args>
    inline void trace( const char* format, Args... args ) {
        write( level::trace, nullptr, format, args... );
    }

    template<typename... Args>
    inline void info( const char* format, Args... args ) {
        write( level::info, nullptr, format, args... );
    }

    template<typename... Args>
    inline void stage( std::uint32_t current, std::uint32_t total, const char* format, Args... args ) {
        char message[ 1024 ]{};
        std::snprintf( message, sizeof( message ), format, args... );
        write( level::stage, "run", "%02u/%02u  %s", current, total, message );
    }

    template<typename... Args>
    inline void success( const char* format, Args... args ) {
        write( level::success, nullptr, format, args... );
    }

    template<typename... Args>
    inline void warning( const char* format, Args... args ) {
        write( level::warning, nullptr, format, args... );
    }

    template<typename... Args>
    inline void error( const char* format, Args... args ) {
        write( level::error, nullptr, format, args... );
    }

    inline void blank( ) {
        std::lock_guard< std::mutex > guard( detail::output_lock( ) );
        if ( detail::log_file( ) ) {
            std::fprintf( detail::log_file( ), "\n" );
            std::fflush( detail::log_file( ) );
        }
        std::printf( "\n" );
    }

    inline std::uint32_t warning_count( ) {
        return detail::visible_warnings( );
    }

    inline std::uint32_t error_count( ) {
        return detail::visible_errors( );
    }

    // ---- change ledger: what the run actually spoofed -----------------------
    // stages report each old->new identity value they rewrote; the run summary
    // prints each as one compressed "name  old -> new" line, section headers
    // carry the count of values under them.

    struct change_entry {
        bool headline{ false };
        char section[ 24 ]{};
        char name[ 56 ]{};
        char old_value[ 76 ]{};
        char new_value[ 76 ]{};
    };

    namespace detail {
        inline std::vector<change_entry>& change_ledger( ) {
            static std::vector<change_entry> ledger;
            return ledger;
        }
    }

    inline void change( const char* section, const char* name,
                        const char* old_value, const char* new_value,
                        bool headline = false ) {
        if ( !section || !name )
            return;

        change_entry entry{};
        entry.headline = headline;
        snprintf( entry.section, sizeof( entry.section ), "%s", section ? section : "?" );
        snprintf( entry.name, sizeof( entry.name ), "%s", name ? name : "?" );
        snprintf( entry.old_value, sizeof( entry.old_value ), "%s", old_value ? old_value : "-" );
        snprintf( entry.new_value, sizeof( entry.new_value ), "%s", new_value ? new_value : "-" );

        // a value that did not move is not part of the spoofed story -
        // keeps no-op writes (already-zeroed timestamps etc) out of the dump
        if ( strcmp( entry.old_value, entry.new_value ) == 0 )
            return;

        std::lock_guard<std::mutex> guard( detail::output_lock( ) );
        detail::change_ledger( ).push_back( entry );
    }

    inline void render_changes( ) {
        std::vector<change_entry> items;
        {
            std::lock_guard<std::mutex> guard( detail::output_lock( ) );
            for ( const auto& entry : detail::change_ledger( ) )
                items.push_back( entry );
        }

        if ( items.empty( ) )
            return;

        // per-section totals so multi-value headers read "[Registry] x38" on
        // a screenshot - the rows themselves stay, each a compressed one-line
        // old -> new pair
        std::vector<std::pair<std::string, std::uint32_t>> section_counts;
        for ( const auto& entry : items ) {
            std::uint32_t* slot = nullptr;
            for ( auto& p : section_counts )
                if ( p.first == entry.section ) { slot = &p.second; break; }
            if ( slot ) ++*slot;
            else section_counts.push_back( { entry.section, 1 } );
        }
        auto section_count = [&]( const char* section ) -> std::uint32_t {
            for ( const auto& p : section_counts )
                if ( p.first == section ) return p.second;
            return 0;
        };

        blank( );
        if ( detail::color_enabled( ) )
            std::printf( "  \x1b[38;2;224;235;255m============ spoofed identity ============\x1b[0m\n" );
        else
            std::printf( "  ============ spoofed identity ============\n" );

        std::string current_section;
        for ( const auto& entry : items ) {
            if ( current_section != entry.section ) {
                current_section = entry.section;
                const std::uint32_t count = section_count( entry.section );
                if ( detail::color_enabled( ) ) {
                    if ( count > 1 )
                        std::printf( "  \x1b[38;2;125;215;255m[%s]\x1b[0m \x1b[38;2;105;115;150mx%u\x1b[0m\n",
                            current_section.c_str( ), count );
                    else
                        std::printf( "  \x1b[38;2;125;215;255m[%s]\x1b[0m\n", current_section.c_str( ) );
                } else {
                    if ( count > 1 )
                        std::printf( "  [%s] x%u\n", current_section.c_str( ), count );
                    else
                        std::printf( "  [%s]\n", current_section.c_str( ) );
                }
            }
            if ( detail::color_enabled( ) )
                std::printf( "    %-22s \x1b[38;2;105;115;150m%s\x1b[0m \x1b[38;2;140;160;190m->\x1b[0m \x1b[38;2;115;195;255m%s\x1b[0m\n",
                    entry.name, entry.old_value, entry.new_value );
            else
                std::printf( "    %-22s %s -> %s\n",
                    entry.name, entry.old_value, entry.new_value );
        }
    }
}
