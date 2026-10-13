#pragma once

namespace paging {
	namespace pfn_cr3 {

		struct mmpfn_t {
			std::uintptr_t flags;
			std::uintptr_t pte_address;
			std::uintptr_t unused_1;
			std::uintptr_t unused_2;
			std::uintptr_t unused_3;
			std::uintptr_t unused_4;
		};
		static_assert( sizeof( mmpfn_t ) == 0x30 );

		using mi_buddy_fn_t = std::uint64_t( __fastcall* )( const mmpfn_t* );
		inline mi_buddy_fn_t g_MiGetPageTablePfnBuddyRaw = nullptr;

		inline bool initialized = false;
		inline std::uint64_t pte_base = 0;
		inline std::uint64_t pde_base = 0;
		inline std::uint64_t pdpte_base = 0;
		inline std::uint64_t pml4e_base = 0;
		inline std::uint64_t cr3_ptebase = 0;
		inline physical_memory_range_t* memory_ranges = nullptr;
		inline mmpfn_t* mm_pfn_database = nullptr;

		inline std::uint64_t decode_eprocess_page_table( std::uintptr_t flags ) {
			auto e = ( static_cast< std::uint64_t >( flags ) >> 13 ) & ~0xFULL;
			e |= 0xFFFF800000000000ull;
			return e;
		}

		inline std::uint64_t decrypt_owner( const mmpfn_t* mmpfn ) {
			if ( !mmpfn )
				return 0;

			if ( g_MiGetPageTablePfnBuddyRaw ) {
				std::uint64_t eprocess = 0;
				__try {
					eprocess = g_MiGetPageTablePfnBuddyRaw( mmpfn );
				}
				__except ( 1 ) {
					return 0;
				}
				return eprocess;
			}

			return decode_eprocess_page_table( mmpfn->flags );
		}

		inline bool owner_matches_pid( std::uint64_t eprocess, std::uint64_t target_pid ) {
			if ( !eprocess || eprocess < 0xFFFF800000000000ull )
				return false;

			std::uint32_t active_threads = 0;
			__try {
				if ( !kernel::mm_is_address_valid(
					reinterpret_cast< void* >( eprocess + offsets::active_threads ) ) )
					return false;
				active_threads = *reinterpret_cast< std::uint32_t* >(
					eprocess + offsets::active_threads );
			}
			__except ( 1 ) {
				return false;
			}
			if ( !active_threads || active_threads > 10000 )
				return false;

			std::uint64_t pid = 0;
			__try {
				if ( !kernel::mm_is_address_valid(
					reinterpret_cast< void* >( eprocess + offsets::unique_process_id ) ) )
					return false;
				pid = *reinterpret_cast< std::uint64_t* >(
					eprocess + offsets::unique_process_id );
			}
			__except ( 1 ) {
				return false;
			}
			return pid == target_pid;
		}

		inline bool init_pfn_cr3( ) {
			KDBG( oxorany( "[co] pfn_cr3 init begin\n" ) );
			initialized = false;
			pte_base = pde_base = pdpte_base = pml4e_base = cr3_ptebase = 0;
			memory_ranges = nullptr;
			mm_pfn_database = nullptr;
			g_MiGetPageTablePfnBuddyRaw = nullptr;

			if ( !kernel::m_pdb.m_mm_pfn_database ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL no MmPfnDatabase symbol\n" ) );
				return false;
			}

			auto* db_var = reinterpret_cast< mmpfn_t** >( kernel::m_pdb.m_mm_pfn_database );
			if ( !kernel::mm_is_address_valid( db_var ) ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL MmPfnDatabase var invalid\n" ) );
				return false;
			}
			mm_pfn_database = *db_var;
			if ( !mm_pfn_database || !kernel::mm_is_address_valid( mm_pfn_database ) ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL MmPfnDatabase deref\n" ) );
				return false;
			}
			KDBG( oxorany( "[co] pfn_cr3 MmPfnDatabase=%p\n" ), mm_pfn_database );

			if ( kernel::m_pdb.m_mi_get_page_table_pfn_buddy_raw ) {
				g_MiGetPageTablePfnBuddyRaw = reinterpret_cast< mi_buddy_fn_t >(
					kernel::m_pdb.m_mi_get_page_table_pfn_buddy_raw );
				KDBG( oxorany( "[co] pfn_cr3 buddy_fn=%p\n" ),
					reinterpret_cast< void* >( g_MiGetPageTablePfnBuddyRaw ) );
			} else {
				KDBG( oxorany( "[co] pfn_cr3 buddy_fn=null (inline pidsafe decode)\n" ) );
			}

			if ( !offsets::active_threads || !offsets::unique_process_id ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL missing ActiveThreads/UniqueProcessId\n" ) );
				return false;
			}

			if ( offsets::mmpfn_size && offsets::mmpfn_size != sizeof( mmpfn_t ) ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL mmpfn size=0x%x want 0x30\n" ),
					offsets::mmpfn_size );
				return false;
			}
			if ( offsets::mmpfn_pte_address && offsets::mmpfn_pte_address != 8 ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL pte_address off=0x%x want 8\n" ),
					offsets::mmpfn_pte_address );
				return false;
			}

			const std::uint64_t sys_cr3_flags = __readcr3( );
			const std::uint64_t dirbase_pfn = ( sys_cr3_flags >> 12 ) & 0xFFFFFFFFFull;
			const std::uint64_t phys_system_directory = dirbase_pfn << 12;
			KDBG( oxorany( "[co] pfn_cr3 hw_cr3=0x%llx dirbase_pfn=0x%llx\n" ),
				static_cast< unsigned long long >( sys_cr3_flags ),
				static_cast< unsigned long long >( dirbase_pfn ) );

			auto* system_directory = reinterpret_cast< pml4e* >(
				kernel::mm_get_virtual_for_physical( phys_system_directory ) );
			if ( !system_directory ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL system PML4 map\n" ) );
				return false;
			}

			bool found_self = false;
			std::uint64_t self_idx = 0;
			for ( std::uint64_t i = 0; i < 512; i++ ) {
				if ( system_directory[ i ].hard.pfn != dirbase_pfn )
					continue;

				self_idx = i;
				pml4e_base = ( i + 0x1FFFE00ui64 ) << 39ui64;
				pdpte_base = ( i << 30ui64 ) + pml4e_base;
				pde_base = ( i << 30ui64 ) + pml4e_base + ( i << 21ui64 );
				pte_base = ( i << 12ui64 ) + pde_base;
				cr3_ptebase = i * 8 + pte_base;
				found_self = true;
				break;
			}
			if ( !found_self || !cr3_ptebase ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL self-map not found\n" ) );
				return false;
			}
			KDBG( oxorany( "[co] pfn_cr3 self_idx=%llu cr3_ptebase=0x%llx\n" ),
				static_cast< unsigned long long >( self_idx ),
				static_cast< unsigned long long >( cr3_ptebase ) );

			memory_ranges = kernel::mm_get_physical_memory_ranges( );
			if ( !memory_ranges ) {
				KDBG( oxorany( "[co] pfn_cr3 FAIL phys ranges\n" ) );
				return false;
			}

			std::uint32_t range_n = 0;
			for ( ; range_n < 512; ++range_n ) {
				if ( !memory_ranges[ range_n ].m_base_page.m_quad_part &&
					!memory_ranges[ range_n ].m_page_count.m_quad_part )
					break;
			}
			KDBG( oxorany( "[co] pfn_cr3 OK ranges=%u decode=%s\n" ),
				range_n,
				g_MiGetPageTablePfnBuddyRaw ? "buddy_fn" : "pidsafe" );

			initialized = true;
			return true;
		}

		struct cr3_cache_t {
			std::uint64_t pid;
			std::uint64_t cr3;
			std::uint64_t eprocess;
		};
		inline cr3_cache_t g_cr3_cache{};

		inline bool revalidate_cached_cr3( std::uint64_t target_pid, std::uint64_t* out_cr3 ) {
			if ( !out_cr3 || !g_cr3_cache.pid || g_cr3_cache.pid != target_pid || !g_cr3_cache.cr3 )
				return false;
			const auto pfn = g_cr3_cache.cr3 >> 12;
			__try {
				if ( !mm_pfn_database || !kernel::mm_is_address_valid( &mm_pfn_database[ pfn ] ) )
					return false;
				mmpfn_t cur = mm_pfn_database[ pfn ];
				if ( !cur.flags || cur.flags == 1 || cur.pte_address != cr3_ptebase )
					return false;
				if ( !owner_matches_pid( g_cr3_cache.eprocess, target_pid ) )
					return false;
				const auto e2 = decrypt_owner( &cur );
				if ( e2 && e2 != g_cr3_cache.eprocess )
					return false;
			}
			__except ( 1 ) {
				return false;
			}
			*out_cr3 = g_cr3_cache.cr3;
			return true;
		}

		inline std::uint64_t get_cr3_by_pid( std::uint64_t target_pid ) {
			if ( target_pid == 0 || target_pid > 0xFFFFFFFF ) {
				KDBG( oxorany( "[co] pfn_scan FAIL bad pid\n" ) );
				return 0;
			}
			if ( !initialized || !mm_pfn_database || !memory_ranges ) {
				KDBG( oxorany( "[co] pfn_scan FAIL not init\n" ) );
				return 0;
			}

			std::uint64_t cached = 0;
			if ( revalidate_cached_cr3( target_pid, &cached ) ) {
				KDBG( oxorany( "[co] pfn_scan CACHE HIT pid=%llu cr3=0x%llx\n" ),
					static_cast< unsigned long long >( target_pid ),
					static_cast< unsigned long long >( cached ) );
				return cached;
			}

			KDBG( oxorany( "[co] pfn_scan begin pid=%llu\n" ),
				static_cast< unsigned long long >( target_pid ) );

			std::uint64_t checked_pfns = 0;
			std::uint64_t cr3_candidates = 0;
			std::uint64_t owner_hits = 0;
			const std::uint64_t MAX_PFNS_TO_CHECK = 100000000;

			for ( std::uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++ ) {
				if ( !memory_ranges[ mem_range_count ].m_base_page.m_quad_part &&
					!memory_ranges[ mem_range_count ].m_page_count.m_quad_part )
					break;

				std::uint64_t start_pfn =
					static_cast< std::uint64_t >( memory_ranges[ mem_range_count ].m_base_page.m_quad_part >> 12 );
				std::uint64_t end_pfn = start_pfn +
					static_cast< std::uint64_t >( memory_ranges[ mem_range_count ].m_page_count.m_quad_part >> 12 );

				if ( start_pfn >= end_pfn || end_pfn > 0xFFFFFFFFF )
					continue;

				for ( std::uint64_t i = start_pfn; i < end_pfn; i++ ) {
					if ( ++checked_pfns > MAX_PFNS_TO_CHECK ) {
						KDBG( oxorany( "[co] pfn_scan FAIL max pfns checked=%llu cand=%llu\n" ),
							static_cast< unsigned long long >( checked_pfns ),
							static_cast< unsigned long long >( cr3_candidates ) );
						return 0;
					}

					mmpfn_t cur_mmpfn{};
					__try {
						auto* src = &mm_pfn_database[ i ];
						if ( !kernel::mm_is_address_valid( src ) )
							continue;
						cur_mmpfn = *src;
					}
					__except ( 1 ) {
						continue;
					}

					if ( !cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase )
						continue;

					++cr3_candidates;
					const std::uint64_t eprocess = decrypt_owner( &cur_mmpfn );
					if ( !owner_matches_pid( eprocess, target_pid ) )
						continue;

					++owner_hits;
					const std::uint64_t dirbase = i << 12;
					g_cr3_cache.pid = target_pid;
					g_cr3_cache.cr3 = dirbase;
					g_cr3_cache.eprocess = eprocess;
					KDBG( oxorany( "[co] pfn_scan HIT pid=%llu cr3=0x%llx eproc=%p checked=%llu cand=%llu\n" ),
						static_cast< unsigned long long >( target_pid ),
						static_cast< unsigned long long >( dirbase ),
						reinterpret_cast< void* >( eprocess ),
						static_cast< unsigned long long >( checked_pfns ),
						static_cast< unsigned long long >( cr3_candidates ) );
					return dirbase;
				}
			}

			if ( g_cr3_cache.pid == target_pid )
				g_cr3_cache = {};
			KDBG( oxorany( "[co] pfn_scan MISS pid=%llu checked=%llu cr3_cand=%llu\n" ),
				static_cast< unsigned long long >( target_pid ),
				static_cast< unsigned long long >( checked_pfns ),
				static_cast< unsigned long long >( cr3_candidates ) );
			return 0;
		}

	}
}
