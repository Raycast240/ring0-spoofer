#pragma once

namespace paging {
    static constexpr std::uint64_t page_4kb_size  = 0x1000ull;
    static constexpr std::uint64_t page_2mb_size  = 0x200000ull;
    static constexpr std::uint64_t page_1gb_size  = 0x40000000ull;

    static constexpr std::uint64_t page_shift     = 12ull;
    static constexpr std::uint64_t page_2mb_shift = 21ull;
    static constexpr std::uint64_t page_1gb_shift = 30ull;

    static constexpr std::uint64_t page_4kb_mask  = 0xFFFull;
    static constexpr std::uint64_t page_2mb_mask  = 0x1FFFFFull;
    static constexpr std::uint64_t page_1gb_mask  = 0x3FFFFFFFull;

    struct pt_entries_t {
        pml4e m_pml4e;
        pdpte m_pdpte;
        pde   m_pde;
        pte   m_pte;
    };

    static std::uint64_t s_directory_table_base = 0;

    static bool hyperspace_entries( pt_entries_t& entries, std::uint64_t address );

    inline bool setup() {
        auto page_buffer = std::make_unique<std::uint8_t[]>( 0x1000 );
        for ( std::uint64_t page = 0; page < 0x20000000; page += 0x1000 ) {
            if ( !driver::read_physical_memory( page, page_buffer.get(), 0x1000 ) )
                continue;

            if ( page_buffer[0] == 0xE9 && page_buffer[1] == 0x4D &&
                 page_buffer[2] == 0x06 && page_buffer[3] == 0x00 ) {
                const std::uint64_t dtb = *reinterpret_cast<std::uint64_t*>( page_buffer.get() + 0xA0 );
                if ( dtb && ( dtb & 0xFFF ) == 0 ) {
                    logging::print( oxorany( "found system cr3: 0x%llx" ), dtb );
                    s_directory_table_base = dtb;
                    return true;
                }
            }
        }
        return false;
    }

    inline std::uint64_t translate_linear( std::uint64_t addr, std::uint32_t* page_size = nullptr ) {
        pt_entries_t pt_entries{};
        if ( !hyperspace_entries( pt_entries, addr ) )
            return 0;

        if ( pt_entries.m_pdpte.hard.page_size ) {
            if ( page_size ) *page_size = static_cast<std::uint32_t>( page_1gb_size );
            return ( pt_entries.m_pdpte.hard.pfn << 12 ) + ( addr & page_1gb_mask );
        }

        if ( pt_entries.m_pde.hard.page_size ) {
            if ( page_size ) *page_size = static_cast<std::uint32_t>( page_2mb_size );
            return ( pt_entries.m_pde.hard.pfn << 12 ) + ( addr & page_2mb_mask );
        }

        if ( page_size ) *page_size = static_cast<std::uint32_t>( page_4kb_size );
        return ( pt_entries.m_pte.hard.pfn << 12 ) + ( addr & page_4kb_mask );
    }

    inline bool read_virtual_memory( std::uint64_t addr, void* buf, std::size_t size ) {
        auto* dst       = reinterpret_cast<std::uint8_t*>( buf );
        auto  remaining = size;
        auto  cur_va    = addr;

        while ( remaining > 0 ) {
            const auto pa = translate_linear( cur_va );
            if ( !pa ) return false;

            const auto page_offset = cur_va & 0xFFF;
            const auto chunk       = ( std::min )( remaining, static_cast<std::size_t>( 0x1000 - page_offset ) );

            if ( !driver::read_physical_memory( pa, dst, chunk ) )
                return false;

            cur_va    += chunk;
            dst       += chunk;
            remaining -= chunk;
        }
        return true;
    }

    static bool hyperspace_entries( pt_entries_t& entries, std::uint64_t address ) {
        virt_addr_t va{ address };

        if ( !driver::read_physical_memory(
            s_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
            &entries.m_pml4e, sizeof( pml4e ) ) )
            return false;

        if ( !entries.m_pml4e.hard.present )
            return false;

        if ( !driver::read_physical_memory(
            ( entries.m_pml4e.hard.pfn << 12 ) + ( sizeof( pdpte ) * va.pdpte_index ),
            &entries.m_pdpte, sizeof( pdpte ) ) )
            return false;

        if ( !entries.m_pdpte.hard.present )
            return false;

        if ( entries.m_pdpte.hard.page_size )
            return true;

        if ( !driver::read_physical_memory(
            ( entries.m_pdpte.hard.pfn << 12 ) + ( sizeof( pde ) * va.pde_index ),
            &entries.m_pde, sizeof( pde ) ) )
            return false;

        if ( !entries.m_pde.hard.present )
            return false;

        if ( entries.m_pde.hard.page_size )
            return true;

        if ( !driver::read_physical_memory(
            ( entries.m_pde.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
            &entries.m_pte, sizeof( pte ) ) )
            return false;

        if ( !entries.m_pte.hard.present )
            return false;

        return true;
    }
}
