#pragma once

namespace paging {
	std::uint64_t swap_context( std::uint64_t new_dtb ) {
		auto old_dtb = m_directory_table_base;
		m_directory_table_base = new_dtb;
		return old_dtb;
	}

	bool walk_page_tables( pt_entries_t& entries, std::uint64_t addr ) {
		virt_addr_t va{ addr };
		if ( !dpm::read_physical( ( m_directory_table_base & ~page_4kb_mask ) + ( va.pml4e_index * sizeof( pml4e ) ),
			&entries.m_pml4e, sizeof( pml4e ) ) )
			return false;

		if ( !entries.m_pml4e.hard.present )
			return false;

		if ( !dpm::read_physical( ( entries.m_pml4e.hard.pfn << page_shift ) + ( va.pdpte_index * sizeof( pdpte ) ),
			&entries.m_pdpte, sizeof( pdpte ) ) )
			return false;

		if ( !entries.m_pdpte.hard.present )
			return false;

		if ( entries.m_pdpte.hard.page_size )
			return true;

		if ( !dpm::read_physical( ( entries.m_pdpte.hard.pfn << page_shift ) + ( va.pde_index * sizeof( pde ) ),
			&entries.m_pde, sizeof( pde ) ) )
			return false;

		if ( !entries.m_pde.hard.present )
			return false;

		if ( entries.m_pde.hard.page_size )
			return true;

		if ( !dpm::read_physical( ( entries.m_pde.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
			&entries.m_pte, sizeof( pte ) ) )
			return false;

		if ( !entries.m_pte.hard.present )
			return false;

		return true;
	}

	bool translate_linear( std::uint64_t va, std::uint64_t* pa = nullptr, std::uint32_t* page_size = nullptr ) {
		pt_entries_t pt_entries;
		if ( !walk_page_tables( pt_entries, va ) )
			return false;

		if ( !pt_entries.m_pml4e.hard.present )
			return false;

		if ( !pt_entries.m_pdpte.hard.present )
			return false;

		if ( pt_entries.m_pdpte.hard.page_size ) {
			if ( page_size ) *page_size = page_1gb_size;
			if ( pa ) {
				*pa = ( ( pt_entries.m_pdpte.hard.pfn << page_shift ) & ~page_1gb_mask )
					| ( va & page_1gb_mask );
			}
			return true;
		}

		if ( !pt_entries.m_pde.hard.present )
			return false;

		if ( pt_entries.m_pde.hard.page_size ) {
			if ( page_size ) *page_size = page_2mb_size;
			if ( pa ) {
				*pa = ( ( pt_entries.m_pde.hard.pfn << page_shift ) & ~page_2mb_mask )
					| ( va & page_2mb_mask );
			}
			return true;
		}

		if ( !pt_entries.m_pte.hard.present )
			return false;

		if ( page_size ) *page_size = page_4kb_size;
		if ( pa )
			*pa = ( pt_entries.m_pte.hard.pfn << page_shift ) | ( va & page_4kb_mask );
		return true;
	}
}
