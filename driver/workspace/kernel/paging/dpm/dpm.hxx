#pragma once

namespace phys {
    bool is_address_valid( std::uint64_t pa, std::size_t size );
}

namespace paging {
    namespace dpm {
        struct page_mapping_t {
            std::uint64_t m_virtual_address;
            pte* m_pte_address;
            std::uint64_t m_original_pfn;
        };

        page_mapping_t m_page_mappings[ 64 ] = {};
        bool m_is_initialized = false;

        pte* get_pte_for_address( std::uint64_t address ) {
            virt_addr_t va{ address };

            auto pml4_va = kernel::mm_get_virtual_for_physical( m_directory_table_base & ~page_4kb_mask );
            if ( !pml4_va ) return nullptr;

            auto pml4 = reinterpret_cast< pml4e* >( pml4_va );
            auto pml4_entry = &pml4[ va.pml4e_index ];
            if ( !pml4_entry->hard.present ) return nullptr;

            auto pdpt_va = kernel::mm_get_virtual_for_physical( pml4_entry->hard.pfn << 12 );
            if ( !pdpt_va ) return nullptr;

            auto pdpt = reinterpret_cast< pdpte* >( pdpt_va );
            auto pdpt_entry = &pdpt[ va.pdpte_index ];
            if ( !pdpt_entry->hard.present ) return nullptr;
            if ( pdpt_entry->hard.page_size ) return nullptr;

            auto pd_va = kernel::mm_get_virtual_for_physical( pdpt_entry->hard.pfn << 12 );
            if ( !pd_va ) return nullptr;

            auto pd = reinterpret_cast< pde* >( pd_va );
            auto pd_entry = &pd[ va.pde_index ];
            if ( !pd_entry->hard.present ) return nullptr;
            if ( pd_entry->hard.page_size ) return nullptr;

            auto pt_va = kernel::mm_get_virtual_for_physical( pd_entry->hard.pfn << 12 );
            if ( !pt_va ) return nullptr;

            auto pt = reinterpret_cast< pte* >( pt_va );
            auto pt_entry = &pt[ va.pte_index ];
            if ( !pt_entry->hard.present ) return nullptr;
            return pt_entry;
        }

        constexpr std::uint32_t max_slots = 64;
        std::uint32_t m_slot_count = 0;

        bool initialize( ) {
            KDBG( oxorany( "[co] dpm init begin slots=%u cr3=0x%llx\n" ),
                max_slots,
                static_cast< unsigned long long >( m_directory_table_base ) );

            if ( m_is_initialized ) {
                KDBG( oxorany( "[co] dpm FAIL already init\n" ) );
                return false;
            }

            for ( std::uint32_t i = 0; i < max_slots; i++ ) {
                m_page_mappings[ i ].m_virtual_address = mmu::alloc_kva( page_4kb_size );
                if ( !m_page_mappings[ i ].m_virtual_address ) {
                    KDBG( oxorany( "[co] dpm FAIL alloc_kva slot=%u\n" ), i );
                    return false;
                }

                m_page_mappings[ i ].m_pte_address = get_pte_for_address( m_page_mappings[ i ].m_virtual_address );
                if ( !m_page_mappings[ i ].m_pte_address ) {
                    KDBG( oxorany( "[co] dpm FAIL pte resolve slot=%u va=%p\n" ),
                        i, reinterpret_cast< void* >( m_page_mappings[ i ].m_virtual_address ) );
                    return false;
                }

                m_page_mappings[ i ].m_original_pfn = m_page_mappings[ i ].m_pte_address->hard.pfn;
            }

            m_slot_count = max_slots;
            m_is_initialized = true;
            KDBG( oxorany( "[co] dpm OK slots=%u first_va=%p first_pte=%p\n" ),
                m_slot_count,
                reinterpret_cast< void* >( m_page_mappings[ 0 ].m_virtual_address ),
                reinterpret_cast< void* >( m_page_mappings[ 0 ].m_pte_address ) );
            return true;
        }

        static inline std::size_t clamp_to_page(
            std::uint64_t physical_address,
            std::size_t   size
        ) {
            const auto offset = physical_address & page_4kb_mask;
            const auto room = page_4kb_size - offset;
            return size < room ? size : room;
        }

        bool read_physical( std::uint64_t physical_address, void* buffer, std::size_t size ) {
            if ( !m_is_initialized || !buffer || !size )
                return false;

            const auto copy_size = clamp_to_page( physical_address, size );
            if ( copy_size != size )
                return false;

            if ( !phys::is_address_valid( physical_address, copy_size ) )
                return false;

            auto old_irql = kernel::ke_raise_irql_to_dpc_level( );

            auto processor = kernel::ke_get_current_processor_number( );
            if ( processor >= max_slots ) {
                kernel::ke_lower_irql( old_irql );
                return false;
            }

            auto& mapping = m_page_mappings[ processor ];
            if ( !mapping.m_pte_address || !mapping.m_virtual_address ) {
                kernel::ke_lower_irql( old_irql );
                return false;
            }

            auto old_pfn = mapping.m_pte_address->hard.pfn;

            _disable( );

            mapping.m_pte_address->hard.pfn = physical_address >> page_shift;
            __invlpg( reinterpret_cast< void* >( mapping.m_virtual_address ) );

            auto source_ptr = reinterpret_cast< std::uint8_t* >( mapping.m_virtual_address ) + ( physical_address & page_4kb_mask );
            __movsb( reinterpret_cast< std::uint8_t* >( buffer ), source_ptr, copy_size );

            mapping.m_pte_address->hard.pfn = old_pfn;
            __invlpg( reinterpret_cast< void* >( mapping.m_virtual_address ) );

            _enable( );

            kernel::ke_lower_irql( old_irql );
            return true;
        }

        bool write_physical( std::uint64_t physical_address, void* buffer, std::size_t size ) {
            if ( !m_is_initialized || !buffer || !size )
                return false;

            const auto copy_size = clamp_to_page( physical_address, size );
            if ( copy_size != size )
                return false;

            if ( !phys::is_address_valid( physical_address, copy_size ) )
                return false;

            auto old_irql = kernel::ke_raise_irql_to_dpc_level( );

            auto processor = kernel::ke_get_current_processor_number( );
            if ( processor >= max_slots ) {
                kernel::ke_lower_irql( old_irql );
                return false;
            }

            auto& mapping = m_page_mappings[ processor ];
            if ( !mapping.m_pte_address || !mapping.m_virtual_address ) {
                kernel::ke_lower_irql( old_irql );
                return false;
            }

            auto old_pfn = mapping.m_pte_address->hard.pfn;
            auto old_rw  = mapping.m_pte_address->hard.read_write;

            _disable( );

            mapping.m_pte_address->hard.pfn = physical_address >> page_shift;
            mapping.m_pte_address->hard.read_write = 1;
            __invlpg( reinterpret_cast< void* >( mapping.m_virtual_address ) );

            auto dest_ptr = reinterpret_cast< std::uint8_t* >( mapping.m_virtual_address ) + ( physical_address & page_4kb_mask );
            __movsb( dest_ptr, reinterpret_cast< std::uint8_t* >( buffer ), copy_size );

            mapping.m_pte_address->hard.pfn = old_pfn;
            mapping.m_pte_address->hard.read_write = old_rw;
            __invlpg( reinterpret_cast< void* >( mapping.m_virtual_address ) );

            _enable( );

            kernel::ke_lower_irql( old_irql );
            return true;
        }
    }
}
