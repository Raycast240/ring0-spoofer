#pragma once

namespace driver {

#pragma pack(push, 1)
    struct map_physical_input_t {
        std::uint64_t physical_address;
        std::uint64_t size;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct unmap_physical_input_t {
        std::uint64_t mapped_memory;
    };
#pragma pack(pop)

#pragma section(".text")
    __declspec( allocate( ".text" ) )
        const std::uint8_t syscall_stub[]{
            0x4C, 0x8B, 0x11,
            0x8B, 0x41, 0x08,
            0x0F, 0x05,
            0xC3
    };

    template<typename ret_type = void, typename first = void*, typename... args>
    inline ret_type syscall( DWORD index, first arg = first{}, args... next_args ) {
        struct data_struct {
            first arg1;
            DWORD syscall_id;
        } data{ arg, index };

        using call_stub = ret_type( __fastcall* )( data_struct*, args... );
        return reinterpret_cast<call_stub>( &syscall_stub[0] )( &data, next_args... );
    }

    static HANDLE s_driver_handle = INVALID_HANDLE_VALUE;

    static NTSTATUS send_cmd(
        std::uint32_t ioctl_code,
        void*         input_buffer,
        std::uint32_t input_size,
        void*         output_buffer,
        std::uint32_t output_size ) {
        if ( s_driver_handle == INVALID_HANDLE_VALUE ) {
            logging::print( "could not open driver handle." );
            return STATUS_INVALID_HANDLE;
        }

        IO_STATUS_BLOCK block{};
        return driver::syscall<NTSTATUS>( 7,
            s_driver_handle,
            nullptr,
            nullptr,
            nullptr,
            &block,
            ioctl_code,
            input_buffer,
            input_size,
            output_buffer,
            output_size
        );
    }

    inline bool initialize() {
        s_driver_handle = CreateFileW(
            oxorany( L"\\\\.\\EBIoDispatch" ),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if ( !s_driver_handle || s_driver_handle == INVALID_HANDLE_VALUE ) {
            logging::print( "could not open driver handle." );
            return false;
        }

        logging::print( "driver handle opened successfully.\n" );
        return true;
    }

    inline bool unload() {
        if ( s_driver_handle != INVALID_HANDLE_VALUE ) {
            CloseHandle( s_driver_handle );
            s_driver_handle = INVALID_HANDLE_VALUE;
        }
        return true;
    }

    static void* resolve_mapped_address( std::uint32_t truncated_addr ) {
        for ( std::uint64_t high = 0; high < 0x800; ++high ) {
            const auto test_addr = static_cast<uintptr_t>( ( high << 32 ) | static_cast<std::uint64_t>( truncated_addr ) );
            MEMORY_BASIC_INFORMATION mbi = {};
            if ( VirtualQuery( reinterpret_cast<void*>( test_addr ), &mbi, sizeof( mbi ) ) > 0 ) {
                if ( mbi.State == MEM_COMMIT &&
                     reinterpret_cast<uintptr_t>( mbi.BaseAddress ) == test_addr ) {
                    return reinterpret_cast<void*>( test_addr );
                }
            }
        }
        return nullptr;
    }

    inline void* map_physical_memory( std::uint64_t physical_address, std::uint32_t size ) {
        map_physical_input_t map_in;
        map_in.physical_address = physical_address;
        map_in.size             = size;

        std::uint32_t mapped_memory = 0;
        const auto status = send_cmd(
            0x0022E008,
            &map_in, sizeof( map_in ),
            &mapped_memory, sizeof( mapped_memory ) );
        if ( status )
            return nullptr;

        return resolve_mapped_address( mapped_memory );
    }

    inline void unmap_physical_memory( void* mapped_memory ) {
        unmap_physical_input_t unmap_in;
        unmap_in.mapped_memory = reinterpret_cast<std::uint64_t>( mapped_memory );

        send_cmd( 0x0022E00C, &unmap_in, sizeof( unmap_in ), nullptr, 0 );
    }

    inline bool read_physical_memory( std::uint64_t pa, void* buffer, std::size_t size ) {
        if ( !utility::is_physical_address_valid( pa, size ) )
            return false;

        auto*       dst    = static_cast<std::uint8_t*>( buffer );
        std::size_t offset = 0;
        while ( offset < size ) {
            const std::uint64_t cur_pa    = pa + offset;
            const std::uint64_t page_base = cur_pa & ~0xFFFULL;
            const std::uint32_t page_off  = static_cast<std::uint32_t>( cur_pa & 0xFFF );
            const std::size_t   chunk     = ( std::min )( size - offset, static_cast<std::size_t>( 0x1000 - page_off ) );

            void* view = map_physical_memory( page_base, 0x1000 );
            if ( view ) {
                std::memcpy( dst + offset, static_cast<std::uint8_t*>( view ) + page_off, chunk );
                unmap_physical_memory( view );
            }

            offset += chunk;
        }
        return true;
    }

    inline bool write_physical_memory( std::uint64_t pa, const void* buffer, std::size_t size ) {
        if ( !utility::is_physical_address_valid( pa, size ) )
            return false;

        const auto* src    = static_cast<const std::uint8_t*>( buffer );
        std::size_t offset = 0;
        while ( offset < size ) {
            const std::uint64_t cur_pa    = pa + offset;
            const std::uint64_t page_base = cur_pa & ~0xFFFULL;
            const std::uint32_t page_off  = static_cast<std::uint32_t>( cur_pa & 0xFFF );
            const std::size_t   chunk     = ( std::min )( size - offset, static_cast<std::size_t>( 0x1000 - page_off ) );

            void* view = map_physical_memory( page_base, 0x1000 );
            if ( !view ) {
                logging::print( "map failed - PA=0x%llx offset=0x%llx", pa, offset );
                return false;
            }

            std::memcpy( static_cast<std::uint8_t*>( view ) + page_off, src + offset, chunk );
            unmap_physical_memory( view );
            offset += chunk;
        }
        return true;
    }
}
