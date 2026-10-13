#pragma once

namespace client {
	namespace control {
		struct control_initialize_t {
			std::uint64_t m_process_id;
			std::uint64_t m_base_address;
			void* m_response_semaphore;
			void* m_request_semaphore;
		};

		enum control_type {
			none = 0,
			get_directory_table_base = 6,
			swap_directory_table_base = 7,
			read_virtual = 13,
			write_virtual = 14,
			read_scatter = 15,
			query_caps = 16,
			spoof_hardware = 17, // NexusSpooferDrv extension: run the HWID spoof routine
		};

		constexpr std::uint32_t k_shared_payload_size = 0x8000;
		constexpr std::uint32_t k_max_read_chunk      = 0x8000;
		constexpr std::uint32_t k_max_scatter_ops     = 64;

		struct scatter_op_t {
			std::uint64_t va;
			std::uint32_t size;
			std::uint32_t status;
		};
		static_assert(sizeof(scatter_op_t) == 16);

		struct control_data_t {
			control_type m_request_type;
			paging::pt_entries_t m_pt_entries;
			pml4e m_pml4e;
			pdpte m_pdpte;
			pde m_pde;
			pte m_pte;
			std::uint32_t m_thread_id;
			std::uint32_t m_process_id;
			std::uint32_t m_protection;
			std::uint32_t m_count;
			std::uint32_t m_mode;
			CONTEXT* m_context;
			eprocess_t* m_process;
			eprocess_t* m_process2;
			ethread_t* m_thread;
			peb_t* m_process_peb;
			std::uint64_t m_address;
			std::uint64_t m_address1;
			void* m_address2;
			std::size_t m_size;
			bool m_remove;
			bool m_status;
		};
		static_assert( sizeof( control_data_t ) == 176 );

		// dynamic WNF state name, handed in through the mapper's entry context
		// (kernel::entry_t::m_wnf_state_name_lo/hi) so no build or customer
		// shares a name
		std::uint32_t m_wnf_state_name_lo{ 0 };
		std::uint32_t m_wnf_state_name_hi{ 0 };

		control_data_t* m_control_data{ nullptr };
		ksemaphore_t* m_response_handle{ nullptr };
		ksemaphore_t* m_request_handle{ nullptr };
		volatile long m_session_gen{ 0 };
		volatile long m_inflight{ 0 };

		bool is_valid( ) {
			return m_control_data && m_request_handle && m_response_handle;
		}
	}
}
