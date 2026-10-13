#pragma once

namespace pdb {
    struct pdb_info_t {
        DWORD signature;
        GUID  guid;
        DWORD age;
        char  pdb_file_name[1];
    };

    static std::string                                        s_module_name;
    static std::string                                        s_module_bare;
    static std::string                                        s_pe_path;
    static std::string                                        s_pdb_path;
    static std::uint64_t                                      s_module_base = 0;
    static std::vector<std::pair<std::string, std::uint64_t>> s_symbols;

    static IDiaDataSource* s_p_source  = nullptr;
    static IDiaSession*    s_p_session = nullptr;
    static IDiaSymbol*     s_p_global  = nullptr;

    static std::string get_module_prefix() {
        std::string prefix = s_module_bare;
        const auto  dot    = prefix.rfind( '.' );
        if ( dot != std::string::npos )
            prefix = prefix.substr( 0, dot );
        for ( auto& c : prefix )
            c = static_cast<char>( tolower( static_cast<unsigned char>( c ) ) );
        return prefix;
    }

    static std::string get_pe_path( const char* module_name ) {
        std::string base = std::string( std::getenv( "systemroot" ) ) + "\\System32\\";
        std::string drivers_path = base + "drivers\\" + module_name;
        if ( GetFileAttributesA( drivers_path.c_str() ) != INVALID_FILE_ATTRIBUTES )
            return drivers_path;
        return base + module_name;
    }

    // the symbol cache lives next to the executable (build\), never in the
    // caller's working directory -- keeps the repo clean regardless of where
    // the process was launched from.
    static std::string get_exe_dir( ) {
        char sz_path[MAX_PATH] = {};
        if ( !GetModuleFileNameA( nullptr, sz_path, sizeof( sz_path ) ) )
            return "";

        std::string dir( sz_path );
        const std::size_t slash = dir.find_last_of( "\\/" );
        if ( slash == std::string::npos )
            return "";

        return dir.substr( 0, slash + 1 );
    }

    // a cached pdb is only usable when its name carries the guid+age of the
    // module's own debug record. a prefix-only match happily reuses a pdb
    // left over from a previous windows build, whose symbols then resolve
    // to garbage addresses inside the new image.
    static std::string find_cached_pdb( const std::string& pdb_id ) {
        if ( pdb_id.empty() )
            return "";

        const std::string exe_dir = get_exe_dir();
        if ( exe_dir.empty() )
            return "";

        const std::string suffix  = "_" + pdb_id + ".pdb";
        std::string pattern = exe_dir + get_module_prefix() + "_*.pdb";

        WIN32_FIND_DATAA fd = {};
        HANDLE h = FindFirstFileA( pattern.c_str(), &fd );
        if ( h == INVALID_HANDLE_VALUE )
            return "";

        std::string cached;
        do {
            const std::size_t name_len = std::strlen( fd.cFileName );
            if ( name_len >= suffix.size() &&
                 !_stricmp( fd.cFileName + ( name_len - suffix.size() ), suffix.c_str() ) ) {
                cached = exe_dir + fd.cFileName;
                break;
            }
        } while ( FindNextFileA( h, &fd ) );
        FindClose( h );

        if ( cached.empty() )
            return "";

        std::ifstream v( cached, std::ios::binary | std::ios::ate );
        if ( !v.is_open() || v.tellg() < 1024 )
            return "";

        return cached;
    }

    // parse the PE's CodeView debug record: yields "<guid><age>" (hex, the
    // exact string embedded in cached/downloaded pdb filenames) and the
    // pdb's own file name for the symbol-server URL. empty string on failure.
    static std::string get_pdb_id( const std::string& pe_path, std::string* pdb_file_name = nullptr ) {
        if ( pe_path.empty() ) {
            logging::print( oxorany( "pe path is empty" ) );
            return "";
        }

        char sz_temp_path[MAX_PATH] = {};
        char sz_temp_file[MAX_PATH] = {};
        bool used_temp = false;
        std::string open_path = pe_path;
        if ( GetTempPathA( MAX_PATH, sz_temp_path ) &&
             GetTempFileNameA( sz_temp_path, "pdb", 0, sz_temp_file ) ) {
            if ( CopyFileA( pe_path.c_str(), sz_temp_file, FALSE ) ) {
                open_path = sz_temp_file;
                used_temp = true;
            }
        }

        std::ifstream file( open_path, std::ios::binary | std::ios::ate );
        if ( !file.is_open() ) {
            if ( used_temp ) DeleteFileA( sz_temp_file );
            logging::print( oxorany( "failed to open PE file: %s" ), pe_path.c_str() );
            return "";
        }

        const auto size = file.tellg();
        if ( size <= 0 ) {
            file.close();
            if ( used_temp ) DeleteFileA( sz_temp_file );
            logging::print( oxorany( "PE file is empty" ) );
            return "";
        }

        file.seekg( 0, std::ios::beg );
        std::vector<char> buffer( static_cast<std::size_t>( size ) );
        if ( !file.read( buffer.data(), size ) ) {
            file.close();
            if ( used_temp ) DeleteFileA( sz_temp_file );
            logging::print( oxorany( "failed to read PE file" ) );
            return "";
        }
        file.close();
        if ( used_temp ) DeleteFileA( sz_temp_file );

        if ( buffer.size() < sizeof( IMAGE_DOS_HEADER ) ) {
            logging::print( oxorany( "file too small" ) );
            return "";
        }

        auto* p_dos = reinterpret_cast<IMAGE_DOS_HEADER*>( buffer.data() );
        if ( p_dos->e_magic != IMAGE_DOS_SIGNATURE ) {
            logging::print( oxorany( "invalid DOS signature" ) );
            return "";
        }

        if ( buffer.size() < static_cast<std::size_t>( p_dos->e_lfanew ) + sizeof( IMAGE_NT_HEADERS ) ) {
            logging::print( oxorany( "invalid PE structure" ) );
            return "";
        }

        auto* p_nt  = reinterpret_cast<IMAGE_NT_HEADERS*>( buffer.data() + p_dos->e_lfanew );
        if ( p_nt->Signature != IMAGE_NT_SIGNATURE ) {
            logging::print( oxorany( "invalid NT signature" ) );
            return "";
        }

        const bool is_x86 = ( p_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 );
        auto* p_opt32     = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>( &p_nt->OptionalHeader );
        auto* p_opt64     = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>( &p_nt->OptionalHeader );
        const auto image_size = is_x86 ? p_opt32->SizeOfImage : p_opt64->SizeOfImage;

        auto image_buffer = std::make_unique<BYTE[]>( image_size );
        if ( !image_buffer ) {
            logging::print( oxorany( "failed to allocate memory" ) );
            return "";
        }

        const auto headers_size = is_x86 ? p_opt32->SizeOfHeaders : p_opt64->SizeOfHeaders;
        std::memcpy( image_buffer.get(), buffer.data(), headers_size );

        auto* p_section = IMAGE_FIRST_SECTION( p_nt );
        for ( std::uint32_t i = 0; i < p_nt->FileHeader.NumberOfSections; ++i, ++p_section ) {
            if ( p_section->SizeOfRawData ) {
                std::memcpy( image_buffer.get() + p_section->VirtualAddress,
                    buffer.data() + p_section->PointerToRawData,
                    p_section->SizeOfRawData );
            }
        }

        IMAGE_DATA_DIRECTORY* p_data_dir = is_x86
            ? &p_opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
            : &p_opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

        if ( !p_data_dir->Size ) {
            logging::print( oxorany( "no debug directory found" ) );
            return "";
        }

        // the debug directory may hold several entries - take the first
        // CodeView/RSDS record instead of assuming entry zero
        auto* p_debug_dir = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
            image_buffer.get() + p_data_dir->VirtualAddress );

        for ( std::uint32_t i = 0; i < p_data_dir->Size / sizeof( IMAGE_DEBUG_DIRECTORY ); ++i ) {
            if ( p_debug_dir[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW )
                continue;

            auto* p_pdb_info = reinterpret_cast<pdb_info_t*>(
                image_buffer.get() + p_debug_dir[i].AddressOfRawData );

            if ( p_pdb_info->signature != 0x53445352 )
                continue;

            wchar_t w_guid[100] = {};
            if ( !StringFromGUID2( p_pdb_info->guid, w_guid, 100 ) )
                continue;

            char   a_guid[100] = {};
            std::size_t l_guid = 0;
            wcstombs_s( &l_guid, a_guid, w_guid, sizeof( a_guid ) );

            char guid_filtered[256] = {};
            for ( std::size_t j = 0; j < l_guid; ++j ) {
                const char c = a_guid[j];
                if ( ( c >= '0' && c <= '9' ) || ( c >= 'A' && c <= 'F' ) || ( c >= 'a' && c <= 'f' ) )
                    guid_filtered[std::strlen( guid_filtered )] = c;
            }

            char age_str[16] = {};
            sprintf_s( age_str, "%X", p_pdb_info->age );

            if ( pdb_file_name )
                *pdb_file_name = p_pdb_info->pdb_file_name;

            return std::string( guid_filtered ) + age_str;
        }

        logging::print( oxorany( "no CodeView debug record found" ) );
        return "";
    }

    static std::string download_pdb( const std::string& pe_path ) {
        std::string download_path = get_exe_dir();
        if ( download_path.empty() ) {
            logging::print( oxorany( "failed to resolve executable directory" ) );
            return "";
        }

        std::string pdb_file_name;
        const std::string pdb_id = get_pdb_id( pe_path, &pdb_file_name );
        if ( pdb_id.empty() || pdb_file_name.empty() ) {
            logging::print( oxorany( "failed to read pdb identifier" ) );
            return "";
        }

        std::string url = "https://msdl.microsoft.com/download/symbols/";
        url += pdb_file_name;
        url += "/";
        url += pdb_id;
        url += "/";
        url += pdb_file_name;

        const std::string pdb_path = download_path + get_module_prefix() + "_" + pdb_id + ".pdb";
        const HRESULT hr = URLDownloadToFileA( nullptr, url.c_str(), pdb_path.c_str(), 0, nullptr );
        if ( FAILED( hr ) ) {
            logging::print( oxorany( "download failed: 0x%08x" ), hr );
            return "";
        }

        std::ifstream verify( pdb_path, std::ios::binary | std::ios::ate );
        if ( !verify.is_open() || verify.tellg() < 1024 ) {
            logging::print( oxorany( "downloaded PDB is invalid or too small" ) );
            DeleteFileA( pdb_path.c_str() );
            return "";
        }
        verify.close();

        return pdb_path;
    }

    static bool enumerate_symbols() {
        if ( !s_p_global ) return false;

        CComPtr<IDiaEnumSymbols> p_enum_syms;
        HRESULT hr = s_p_global->findChildren( SymTagNull, nullptr, nsNone, &p_enum_syms );
        if ( FAILED( hr ) ) {
            logging::print( oxorany( "failed to enumerate: 0x%08x" ), hr );
            return false;
        }

        CComPtr<IDiaSymbol> p_symbol;
        ULONG celt = 0;
        while ( SUCCEEDED( p_enum_syms->Next( 1, &p_symbol, &celt ) ) && celt == 1 ) {
            BSTR name;
            if ( SUCCEEDED( p_symbol->get_name( &name ) ) ) {
                DWORD rva = 0;
                if ( SUCCEEDED( p_symbol->get_relativeVirtualAddress( &rva ) ) ) {
                    char symbol_name[1024] = {};
                    std::size_t converted  = 0;
                    wcstombs_s( &converted, symbol_name, name, sizeof( symbol_name ) - 1 );
                    if ( converted > 0 && symbol_name[0] != '\0' )
                        s_symbols.emplace_back( symbol_name, rva );
                }
                SysFreeString( name );
            }
            p_symbol.Release();
        }

        return !s_symbols.empty();
    }

    static void cleanup() {
        if ( s_p_global  ) { s_p_global->Release();  s_p_global  = nullptr; }
        if ( s_p_session ) { s_p_session->Release(); s_p_session = nullptr; }
        if ( s_p_source  ) { s_p_source->Release();  s_p_source  = nullptr; }
    }

    static std::uint64_t get_kernel_module( const char* module_name ) {
        void*         buffer      = nullptr;
        unsigned long buffer_size = 0;
        NTSTATUS status = NtQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS>( 11 ),
            buffer, buffer_size, &buffer_size
        );

        while ( status == 0xC0000004L ) {
            if ( buffer ) { VirtualFree( buffer, 0, MEM_RELEASE ); buffer = nullptr; }
            buffer = VirtualAlloc( nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            if ( !buffer ) return 0;
            status = NtQuerySystemInformation(
                static_cast<SYSTEM_INFORMATION_CLASS>( 11 ),
                buffer, buffer_size, &buffer_size
            );
        }

        if ( !NT_SUCCESS( status ) || !buffer ) {
            if ( buffer ) VirtualFree( buffer, 0, MEM_RELEASE );
            return 0;
        }

        const auto* modules = reinterpret_cast<rtl_process_modules_t*>( buffer );
        for ( auto idx = 0u; idx < modules->m_count; ++idx ) {
            const auto current_module_name = std::string(
                reinterpret_cast<const char*>( modules->m_modules[idx].m_full_path ) +
                modules->m_modules[idx].m_offset_to_file_name
            );
            if ( !_stricmp( current_module_name.c_str(), module_name ) ) {
                const auto module_base = reinterpret_cast<std::uint64_t>( modules->m_modules[idx].m_image_base );
                VirtualFree( buffer, 0, MEM_RELEASE );
                return module_base;
            }
        }

        VirtualFree( buffer, 0, MEM_RELEASE );
        return 0;
    }

    static bool s_com_initialized = false;

    inline bool load( const char* module_name ) {
        if ( !s_com_initialized ) {
            s_com_initialized = SUCCEEDED( CoInitialize( nullptr ) );
        }

        s_module_name = module_name;

        const auto slash = s_module_name.find_last_of( "\\/" );
        s_module_bare = ( slash != std::string::npos ) ? s_module_name.substr( slash + 1 ) : s_module_name;
        s_pe_path     = get_pe_path( module_name );

        s_module_base = get_kernel_module( s_module_bare.c_str() );
        if ( !s_module_base ) {
            logging::print( oxorany( "failed to find module" ) );
            return false;
        }

        s_pdb_path = find_cached_pdb( get_pdb_id( s_pe_path ) );
        if ( s_pdb_path.empty() ) {
            s_pdb_path = download_pdb( s_pe_path );
            if ( s_pdb_path.empty() ) {
                logging::print( oxorany( "failed to download PDB" ) );
                return false;
            }
        }

        HRESULT hr = S_OK;
        CComPtr<IDiaDataSource> p_source;
        hr = CoCreateInstance( CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER,
            IID_IDiaDataSource, reinterpret_cast<void**>( &p_source ) );

        if ( FAILED( hr ) ) {
            static const wchar_t* k_dia_names[] = { L"msdia140.dll", L"msdia120.dll", L"msdia110.dll" };
            for ( const auto* dll : k_dia_names ) {
                hr = NoRegCoCreate( dll, CLSID_DiaSource, IID_IDiaDataSource, reinterpret_cast<void**>( &p_source ) );
                if ( SUCCEEDED( hr ) ) break;
            }
        }

        if ( FAILED( hr ) ) {
            static const wchar_t* k_vs_roots[] = {
                L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files\\Microsoft Visual Studio\\2019\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files\\Microsoft Visual Studio\\2019\\Professional\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files\\Microsoft Visual Studio\\2019\\Enterprise\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll",
            };

            wchar_t exe_dir[MAX_PATH] = {};
            wchar_t exe_dia[MAX_PATH] = {};
            if ( GetModuleFileNameW( nullptr, exe_dir, MAX_PATH ) ) {
                wchar_t* last_slash = wcsrchr( exe_dir, L'\\' );
                if ( last_slash ) {
                    *( last_slash + 1 ) = L'\0';
                    swprintf_s( exe_dia, L"%smsdia140.dll", exe_dir );
                }
            }

            auto try_load_dia = [&]( const wchar_t* full_path ) -> bool {
                HMODULE h_dia = LoadLibraryW( full_path );
                if ( !h_dia ) return false;

                using dll_get_class_object_t = HRESULT( __stdcall* )( REFCLSID, REFIID, LPVOID* );
                auto* p_dgco = reinterpret_cast<dll_get_class_object_t>(
                    GetProcAddress( h_dia, "DllGetClassObject" ) );
                if ( !p_dgco ) { FreeLibrary( h_dia ); return false; }

                IClassFactory* p_cf = nullptr;
                HRESULT h = p_dgco( CLSID_DiaSource, IID_IClassFactory,
                                    reinterpret_cast<void**>( &p_cf ) );
                if ( FAILED( h ) || !p_cf ) { FreeLibrary( h_dia ); return false; }

                h = p_cf->CreateInstance( nullptr, IID_IDiaDataSource,
                                          reinterpret_cast<void**>( &p_source ) );
                p_cf->Release();
                if ( FAILED( h ) ) { FreeLibrary( h_dia ); return false; }

                hr = h;
                return true;
            };

            if ( exe_dia[0] && GetFileAttributesW( exe_dia ) != INVALID_FILE_ATTRIBUTES )
                try_load_dia( exe_dia );

            if ( FAILED( hr ) ) {
                for ( const auto* path : k_vs_roots ) {
                    if ( GetFileAttributesW( path ) == INVALID_FILE_ATTRIBUTES ) continue;
                    if ( try_load_dia( path ) ) break;
                }
            }

            if ( FAILED( hr ) ) {
                logging::print( oxorany( "failed to create DIA data source: 0x%08x" ), hr );
                logging::print( oxorany( "fix: copy msdia140.dll next to spoofer.exe" ) );
                return false;
            }
        }

        std::wstring wide_path( s_pdb_path.begin(), s_pdb_path.end() );
        hr = p_source->loadDataFromPdb( wide_path.c_str() );
        if ( FAILED( hr ) ) {
            logging::print( oxorany( "cached PDB load failed (0x%08x), re-downloading..." ), hr );
            DeleteFileA( s_pdb_path.c_str() );
            s_pdb_path = download_pdb( s_pe_path );
            if ( s_pdb_path.empty() ) return false;

            wide_path = std::wstring( s_pdb_path.begin(), s_pdb_path.end() );
            hr = p_source->loadDataFromPdb( wide_path.c_str() );
            if ( FAILED( hr ) ) {
                logging::print( oxorany( "failed to load re-downloaded PDB: 0x%08x" ), hr );
                return false;
            }
        }

        CComPtr<IDiaSession> p_session;
        hr = p_source->openSession( &p_session );
        if ( FAILED( hr ) ) {
            logging::print( oxorany( "failed to open DIA session: 0x%08x" ), hr );
            return false;
        }

        CComPtr<IDiaSymbol> p_global;
        hr = p_session->get_globalScope( &p_global );
        if ( FAILED( hr ) ) {
            logging::print( oxorany( "failed to get global scope: 0x%08x" ), hr );
            return false;
        }

        s_p_source  = p_source.Detach();
        s_p_session = p_session.Detach();
        s_p_global  = p_global.Detach();

        if ( !enumerate_symbols() ) {
            logging::print( oxorany( "failed to enumerate symbols" ) );
            cleanup();
            return false;
        }

        return true;
    }

    inline std::uint64_t get_symbol_address( const char* symbol_name ) {
        for ( const auto& sym : s_symbols ) {
            if ( sym.first == symbol_name )
                return s_module_base + sym.second;
        }
        return 0;
    }
}
