#pragma once

namespace offsets {
    extern std::uint32_t active_process_links;
    extern std::uint32_t kprocess_directory_table_base;
    extern std::uint32_t unique_process_id;
    extern std::uint32_t active_threads;
    extern std::uint32_t mmpfn_size;
    extern std::uint32_t mmpfn_pte_address;
}

namespace mmu {
    std::uint64_t alloc_kva( std::uint64_t size ) {
        auto buffer = kernel::mm_allocate_independent_pages( size );
        if ( !buffer )
            return {};

        memset( buffer, 0, size );
        return reinterpret_cast< std::uint64_t >( buffer );
    }
}
