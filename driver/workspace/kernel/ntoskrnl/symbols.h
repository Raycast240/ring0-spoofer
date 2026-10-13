#pragma once

namespace kernel {
    struct entry_t {
        struct symbols_t {
            std::uint64_t m_mm_allocate_independent_pages;
            std::uint64_t m_mm_free_independent_pages;
            std::uint64_t m_mm_pfn_database;
            std::uint64_t m_mi_get_page_table_pfn_buddy_raw;
        } m_pdb;

        struct offsets_t {
            std::uint64_t m_eprocess_active_process_links;
            std::uint64_t m_kprocess_directory_table_base;
            std::uint64_t m_eprocess_unique_process_id;
            std::uint64_t m_eprocess_active_threads;
            std::uint64_t m_mmpfn_size;
            std::uint64_t m_mmpfn_pte_address;
        } m_offsets;

        std::uint64_t m_image_base;
        std::uint64_t m_image_size;
        std::uint64_t m_ntoskrnl_base;
        std::uint64_t m_status;
        std::uint64_t m_wnf_state_name_lo;
        std::uint64_t m_wnf_state_name_hi;
    };

    enum entry_fail : std::uint64_t {
        entry_ok = 0,
        entry_null = 1,
        entry_offsets = 2,
        entry_mm_symbols = 3,
        entry_ntos_base = 4,
        entry_image = 5,
        entry_system_process = 6,
        entry_system_dtb = 7,
        entry_phys_ranges = 8,
        entry_dpm = 9,
        entry_wnf_subscribe = 11,
        entry_system_thread = 12,
        entry_pfn_cr3 = 13,
        entry_hide_pages = 14,
    };

    entry_t::symbols_t m_pdb;
}
