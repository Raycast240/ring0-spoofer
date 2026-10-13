#pragma once

namespace phys {
    std::uint64_t mm_lowest_page{ };
    std::uint64_t mm_highest_page{ };
    std::uint64_t m_physical_mask{ };

    bool init_ranges( ) {
        KDBG( oxorany( "[co] phys ranges begin\n" ) );
        auto physical_ranges = kernel::mm_get_physical_memory_ranges( );
        if ( !physical_ranges ) {
            KDBG( oxorany( "[co] phys ranges FAIL MmGetPhysicalMemoryRanges\n" ) );
            return false;
        }

        auto lowest_pfn = MAXULONG_PTR;
        auto highest_pfn = static_cast< std::uint64_t >( 0 );
        std::uint32_t n = 0;
        for ( auto idx = 0ul; physical_ranges[ idx ].m_base_page.m_quad_part ||
            physical_ranges[ idx ].m_page_count.m_quad_part; idx++ ) {
            auto base_address = physical_ranges[ idx ].m_base_page;
            auto number_of_bytes = physical_ranges[ idx ].m_page_count;
            if ( !number_of_bytes.m_quad_part )
                continue;

            ++n;
            auto start_pfn = static_cast< std::uint64_t >( base_address.m_quad_part >> 12 );
            auto end_pfn =
                static_cast< std::uint64_t >( ( base_address.m_quad_part + number_of_bytes.m_quad_part - 1 ) >> 12 );

            if ( start_pfn < lowest_pfn )
                lowest_pfn = start_pfn;

            if ( end_pfn > highest_pfn )
                highest_pfn = end_pfn;
        }

        mm_lowest_page = lowest_pfn;
        mm_highest_page = highest_pfn;
        KDBG( oxorany( "[co] phys ranges OK n=%u low_pfn=0x%llx high_pfn=0x%llx\n" ),
            n,
            static_cast< unsigned long long >( mm_lowest_page ),
            static_cast< unsigned long long >( mm_highest_page ) );
        return true;
    }

    void init_mask( ) {
        int regs[ 4 ]{};
        __cpuid( regs, 0x80000000 );
        unsigned max_ext = static_cast< unsigned >( regs[ 0 ] );

        unsigned phys_bits = 36;
        if ( max_ext >= 0x80000008 ) {
            __cpuid( regs, 0x80000008 );
            unsigned b = regs[ 0 ] & 0xFF;
            if ( b >= 32 && b <= 52 )
                phys_bits = b;
        }

        m_physical_mask = ( phys_bits >= 63 ) ? ~0ULL : ( ( 1ULL << phys_bits ) - 1ULL );
        KDBG( oxorany( "[co] phys mask bits=%u mask=0x%llx\n" ),
            phys_bits,
            static_cast< unsigned long long >( m_physical_mask ) );
    }

    bool is_address_valid( std::uint64_t pa, std::size_t size ) {
        if ( !size )
            return false;

        if ( ( pa & ~m_physical_mask ) != 0 )
            return false;

        const auto end_pa = pa + ( size - 1 );
        if ( end_pa < pa )
            return false;
        if ( ( end_pa & ~m_physical_mask ) != 0 )
            return false;

        auto pfn = pa >> 12;
        return pfn >= mm_lowest_page && pfn <= mm_highest_page;
    }

    std::uint64_t virtual_to_physical( std::uint64_t va ) {
        auto pa = kernel::mm_get_physical_address( reinterpret_cast< void* >( va ) );
        return pa.m_quad_part;
    }

    static_assert( sizeof( mmpfn_t ) == 0x30 );
    static_assert( offsetof( mmpfn_t, m_u3 ) + 3 == 0x23 );

    mmpfn_t* get_pfn_entry( std::uint64_t pfn ) {
        auto mm_pfn_database = kernel::get_mm_pfn_database( );
        if ( !mm_pfn_database )
            return nullptr;

        return &mm_pfn_database[ pfn ];
    }
}
