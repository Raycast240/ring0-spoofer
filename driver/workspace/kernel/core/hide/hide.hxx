#pragma once

namespace hide {
    template <typename va_t>
    bool hide_pages( va_t address, std::size_t size ) {
        const auto va0 = reinterpret_cast< std::uint64_t >( ( void* )address );
        KDBG( oxorany( "[co] hide begin va=%p size=0x%llx\n" ),
            reinterpret_cast< void* >( va0 ),
            static_cast< unsigned long long >( size ) );

        if ( !kernel::get_mm_pfn_database( ) ) {
            KDBG( oxorany( "[co] hide FAIL MmPfnDatabase null\n" ) );
            return false;
        }

        const auto ntos = kernel::m_ntoskrnl_base;
        if ( !ntos ) {
            KDBG( oxorany( "[co] hide FAIL ntos base null\n" ) );
            return false;
        }

        auto* const dos = reinterpret_cast< dos_header_t* >( ntos );
        if ( !dos || !dos->is_valid( ) ) {
            KDBG( oxorany( "[co] hide FAIL ntos dos\n" ) );
            return false;
        }

        auto* const nt = reinterpret_cast< nt_headers_t* >( ntos + dos->m_lfanew );
        if ( !nt || !nt->is_valid( ) || nt->m_size_of_image <= 0 ) {
            KDBG( oxorany( "[co] hide FAIL ntos nt\n" ) );
            return false;
        }

        const auto ntos_end = ntos + static_cast< std::uint64_t >( nt->m_size_of_image );
        if ( va0 < ntos || va0 >= ntos_end ) {
            KDBG( oxorany( "[co] hide FAIL va outside ntoskrnl\n" ) );
            return false;
        }

        const auto page_mask = paging::page_4kb_size - 1;
        const auto start = va0 & ~page_mask;
        const auto end = ( va0 + size + page_mask ) & ~page_mask;
        if ( !size || end <= start ) {
            KDBG( oxorany( "[co] hide FAIL empty range\n" ) );
            return false;
        }

        std::uint64_t pages_touched = 0;
        std::uint64_t pa_miss = 0;
        std::uint64_t pfn_miss = 0;
        std::uint64_t skipped = 0;

        for ( auto current_va = start; current_va < end; current_va += paging::page_4kb_size ) {
            if ( current_va < ntos || current_va >= ntos_end ) {
                ++skipped;
                continue;
            }

            const auto current_pa = phys::virtual_to_physical( current_va );
            if ( !current_pa ) {
                ++pa_miss;
                continue;
            }

            auto pfn_entry = phys::get_pfn_entry( current_pa >> paging::page_shift );
            if ( !pfn_entry ) {
                ++pfn_miss;
                continue;
            }

            auto* const e3_byte =
                reinterpret_cast< volatile std::uint8_t* >( pfn_entry ) + 0x23;
            *e3_byte = static_cast< std::uint8_t >( *e3_byte | 0x80 );
            ++pages_touched;
        }

        KDBG( oxorany( "[co] hide done touched=%llu pa_miss=%llu pfn_miss=%llu skipped=%llu\n" ),
            static_cast< unsigned long long >( pages_touched ),
            static_cast< unsigned long long >( pa_miss ),
            static_cast< unsigned long long >( pfn_miss ),
            static_cast< unsigned long long >( skipped ) );

        if ( size && !pages_touched ) {
            KDBG( oxorany( "[co] hide FAIL no pages touched\n" ) );
            return false;
        }

        KDBG( oxorany( "[co] hide OK\n" ) );
        return true;
    }
}
