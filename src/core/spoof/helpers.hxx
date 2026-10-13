#pragma once
#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>
#include <winternl.h>

namespace spoof::helpers {

    inline bool kread( std::uint64_t va, void* out, std::size_t size ) {
        if ( !va || !out || !size ) return false;
        return paging::read_virtual_memory( va, out, size );
    }

    inline bool kwrite( std::uint64_t va, const void* in, std::size_t size ) {
        if ( !va || !in || !size ) return false;

        const auto* src   = static_cast<const std::uint8_t*>( in );
        std::size_t written = 0;
        while ( written < size ) {
            const std::uint64_t cur_va   = va + written;
            const auto          pa       = paging::translate_linear( cur_va );
            if ( !pa ) return false;
            const std::size_t page_off = cur_va & 0xFFF;
            const std::size_t chunk    = ( std::min )( size - written, static_cast<std::size_t>( 0x1000 - page_off ) );
            if ( !driver::write_physical_memory( pa, const_cast<std::uint8_t*>( src + written ), chunk ) )
                return false;
            written += chunk;
        }
        return true;
    }

    template<typename T>
    inline T kread_val( std::uint64_t va, T def = {} ) {
        T v{};
        return kread( va, &v, sizeof( T ) ) ? v : def;
    }

    // gated write with readback discipline (the volume_guid/nic pattern):
    // capture the CURRENT bytes first, write, read back and compare; on any
    // mismatch restore the captured bytes so a short/failed write can never
    // leave a half-mutated neighbour. an unreadable target is never written.
    inline bool kwrite_verified( std::uint64_t va, const void* in, std::size_t size,
                                 const char* tag = nullptr ) {
        if ( !va || !in || !size ) return false;
        std::vector<std::uint8_t> orig( size );
        if ( !kread( va, orig.data(), size ) ) return false;
        if ( !kwrite( va, in, size ) ) return false;
        std::vector<std::uint8_t> back( size );
        if ( kread( va, back.data(), size ) && !memcmp( back.data(), in, size ) )
            return true;
        kwrite( va, orig.data(), size );
        logging::print( "spoof: %s write at 0x%llx failed readback - restored original",
                        tag ? tag : "kernel", va );
        return false;
    }

    inline bool is_kva( std::uint64_t va ) {
        return va >= 0xFFFF000000000000ULL && va != 0xFFFFFFFFFFFFFFFFULL;
    }

    template<typename R = std::uint64_t, typename... Args>
    inline R call_fn( std::uint64_t fn, Args... args ) {
        return syscall::call_kernel<R>( fn, args... );
    }

    inline bool setup_helpers() {
        logging::print( "spoof: helpers initialised (kread-based device enumeration)" );
        return true;
    }

    static constexpr std::uint32_t kObjDirBuckets    = 37;
    static constexpr std::uint64_t kObjHdrBodyOff    = 0x30;
    static constexpr std::uint64_t kObjHdrInfoMask   = 0x1a;
    static constexpr std::uint64_t kObjNameInfoSize  = 0x20;
    static constexpr std::uint64_t kObjNameInfoLen   = 0x08;
    static constexpr std::uint64_t kObjNameInfoBuf   = 0x10;
    static constexpr std::uint64_t kDirEntryChain    = 0x00;
    static constexpr std::uint64_t kDirEntryObject   = 0x08;
    static constexpr std::uint64_t kDrvObjDeviceObj  = 0x08;
    static constexpr std::uint64_t kDevObjNextDevice = 0x10;

    static std::uint64_t s_ob_root_dir = 0;
    static std::uint64_t s_driver_dir  = 0;

    static bool obp_name_eq( std::uint64_t obj_body, const wchar_t* name ) {
        const std::uint64_t hdr   = obj_body - kObjHdrBodyOff;
        const std::uint8_t  imask = kread_val<std::uint8_t>( hdr + kObjHdrInfoMask );
        if ( !( imask & 0x02 ) ) return false;

        const std::uint64_t ninfo = hdr - kObjNameInfoSize * static_cast<std::uint64_t>( 1 + ( imask & 0x01 ) );
        const std::uint16_t nlen  = kread_val<std::uint16_t>( ninfo + kObjNameInfoLen );
        const std::uint64_t nbuf  = kread_val<std::uint64_t>( ninfo + kObjNameInfoBuf );
        const std::size_t   wlen  = wcslen( name );
        if ( !nlen || nlen != wlen * sizeof( wchar_t ) ) return false;
        if ( !is_kva( nbuf ) || nlen > 254 ) return false;
        wchar_t tmp[128] = {};
        kread( nbuf, tmp, nlen );
        for ( std::size_t i = 0; i < wlen; ++i ) {
            wchar_t a = tmp[i], b = name[i];
            if ( a >= L'a' && a <= L'z' ) a -= 32;
            if ( b >= L'a' && b <= L'z' ) b -= 32;
            if ( a != b ) return false;
        }
        return true;
    }

    static std::uint64_t obp_dir_lookup( std::uint64_t dir_va, const wchar_t* name ) {
        for ( std::uint32_t b = 0; b < kObjDirBuckets; ++b ) {
            std::uint64_t entry = kread_val<std::uint64_t>( dir_va + b * sizeof( std::uint64_t ) );
            for ( std::uint32_t i = 0; i < 32 && is_kva( entry ); ++i ) {
                const std::uint64_t obj = kread_val<std::uint64_t>( entry + kDirEntryObject ) & ~1ULL;
                if ( is_kva( obj ) && obp_name_eq( obj, name ) ) return obj;
                entry = kread_val<std::uint64_t>( entry + kDirEntryChain );
            }
        }
        return 0;
    }

    static std::uint64_t get_driver_object_kread( const wchar_t* full_name ) {
        if ( !s_ob_root_dir ) {
            const std::uint64_t p = pdb::get_symbol_address( "ObpRootDirectoryObject" );
            if ( !p ) return 0;
            s_ob_root_dir = kread_val<std::uint64_t>( p );
        }
        if ( !is_kva( s_ob_root_dir ) ) return 0;

        const wchar_t* dir_name  = L"Driver";
        const wchar_t* leaf_name = full_name;

        if ( wcslen( full_name ) > 8 && _wcsnicmp( full_name, L"\\Driver\\", 8 ) == 0 ) {
            dir_name  = L"Driver";
            leaf_name = full_name + 8;
        } else if ( wcslen( full_name ) > 12 && _wcsnicmp( full_name, L"\\FileSystem\\", 12 ) == 0 ) {
            dir_name  = L"FileSystem";
            leaf_name = full_name + 12;
        }

        std::uint64_t sub_dir = 0;
        if ( dir_name == L"Driver" || _wcsicmp( dir_name, L"Driver" ) == 0 ) {
            if ( !s_driver_dir )
                s_driver_dir = obp_dir_lookup( s_ob_root_dir, L"Driver" );
            sub_dir = s_driver_dir;
        } else {
            sub_dir = obp_dir_lookup( s_ob_root_dir, dir_name );
        }

        if ( !is_kva( sub_dir ) ) return 0;
        return obp_dir_lookup( sub_dir, leaf_name );
    }

    inline std::uint32_t enum_driver_devices( const wchar_t* driver_name,
                                               std::function<void( std::uint64_t )> cb ) {
        if ( !driver_name ) return 0;
        const std::uint64_t drv = get_driver_object_kread( driver_name );
        if ( !is_kva( drv ) ) {
            logging::print( "spoof: %ls - driver object not found", driver_name );
            return 0;
        }

        std::uint64_t dev   = kread_val<std::uint64_t>( drv + kDrvObjDeviceObj );
        std::uint32_t count = 0;
        while ( is_kva( dev ) && count < 256 ) {
            cb( dev );
            ++count;
            dev = kread_val<std::uint64_t>( dev + kDevObjNextDevice );
        }
        return count;
    }

    inline std::uint64_t get_kernel_module_base( const wchar_t* name ) {
        static std::uint64_t s_ldr_va = 0;
        if ( !s_ldr_va )
            s_ldr_va = pdb::get_symbol_address( "PsLoadedModuleList" );
        if ( !s_ldr_va ) {
            logging::print( "kmod: PsLoadedModuleList symbol unresolved - module base walk disabled" );
            return 0;
        }

        const std::size_t   name_len = wcslen( name );
        const std::uint64_t sentinel = s_ldr_va;
        std::uint64_t entry = kread_val<std::uint64_t>( sentinel );
        // one-shot diagnostic: what the walk actually sees at the head
        static bool s_walk_diag = false;
        if ( !s_walk_diag ) {
            s_walk_diag = true;
            const std::uint16_t blen = kread_val<std::uint16_t>( entry + 0x58 );
            const std::uint64_t bbuf = kread_val<std::uint64_t>( entry + 0x60 );
            const std::uint64_t dbas = kread_val<std::uint64_t>( entry + 0x30 );
            logging::print( "kmod: ldr sentinel 0x%llx head 0x%llx blen=%u bbuf=0x%llx dllbase=0x%llx",
                            sentinel, entry, blen, bbuf, dbas );
        }
        for ( int i = 0; i < 512 && is_kva( entry ) && entry != sentinel; ++i ) {
            const std::uint16_t blen = kread_val<std::uint16_t>( entry + 0x58 );
            const std::uint64_t bbuf = kread_val<std::uint64_t>( entry + 0x60 );
            if ( blen == name_len * sizeof( wchar_t ) && is_kva( bbuf ) ) {
                wchar_t tmp[64] = {};
                kread( bbuf, tmp, blen );
                bool match = true;
                for ( std::size_t j = 0; j < name_len && match; ++j ) {
                    wchar_t a = tmp[j], b = name[j];
                    if ( a >= L'a' && a <= L'z' ) a -= 32;
                    if ( b >= L'a' && b <= L'z' ) b -= 32;
                    if ( a != b ) match = false;
                }
                if ( match ) return kread_val<std::uint64_t>( entry + 0x30 );
            }
            entry = kread_val<std::uint64_t>( entry );
        }
        return 0;
    }

    static std::uint32_t s_rng_seed = 0;

    inline void init_rng() {
        FILETIME ft{};
        GetSystemTimeAsFileTime( &ft );
        s_rng_seed = ft.dwLowDateTime ^ ( ft.dwHighDateTime * 0x9E3779B9u ) ^ GetCurrentProcessId();
        if ( !s_rng_seed ) s_rng_seed = 0xDEADBEEF;
    }

    inline std::uint32_t rand_next() {
        s_rng_seed = s_rng_seed * 0x343fd + 0x269ec3;
        return ( s_rng_seed >> 16 ) & 0x7fff;
    }

    inline std::uint32_t fnv1a( const void* data, std::size_t len, std::uint32_t seed ) {
        const auto* b = static_cast<const std::uint8_t*>( data );
        std::uint32_t h = 2166136261u ^ seed;
        for ( std::size_t i = 0; i < len; ++i ) { h ^= b[i]; h *= 16777619u; }
        return h ? h : ( 0x9E3779B9u ^ seed );
    }

    struct kern_ansi_string {
        std::uint16_t Length;
        std::uint16_t MaximumLength;
        std::uint8_t  _pad[4];
        std::uint64_t Buffer;
    };
    static_assert( sizeof( kern_ansi_string ) == 16 );

    static constexpr std::uint32_t DEV_OFF_VPB             = 0x38;
    static constexpr std::uint32_t DEV_OFF_DeviceExtension = 0x40;
    static constexpr std::uint32_t DEV_OFF_DeviceType      = 0x48;

    static constexpr std::uint32_t VPB_OFF_SerialNumber    = 0x18;

    static constexpr std::uint32_t kDevTypeDisk = 7;

    inline std::uint64_t dev_extension( std::uint64_t dev_va ) {
        return kread_val<std::uint64_t>( dev_va + DEV_OFF_DeviceExtension );
    }
    inline std::uint64_t dev_vpb( std::uint64_t dev_va ) {
        return kread_val<std::uint64_t>( dev_va + DEV_OFF_VPB );
    }
    inline std::uint32_t dev_type( std::uint64_t dev_va ) {
        return kread_val<std::uint32_t>( dev_va + DEV_OFF_DeviceType );
    }
}
