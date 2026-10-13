#pragma once

namespace process {
	inline std::uint64_t get_soft_directory_table_base( eprocess_t* eprocess ) {
		if ( !eprocess || !offsets::kprocess_directory_table_base )
			return 0;
		return *reinterpret_cast< std::uint64_t* >(
			reinterpret_cast< std::uint64_t >( eprocess ) + offsets::kprocess_directory_table_base );
	}

	eprocess_t* attach( eprocess_t* eprocess ) {
		if ( !eprocess )
			return nullptr;

		auto current_thread = reinterpret_cast< ethread_t* >( __readgsqword( 0x188 ) );
		if ( !current_thread ) {
			KDBG( oxorany( "[co] process::attach FAIL no ethread\n" ) );
			return nullptr;
		}

		auto directory_table_base = get_soft_directory_table_base( eprocess );
		if ( !( directory_table_base & ~0xFFFULL ) ) {
			KDBG( oxorany( "[co] process::attach FAIL soft dtb=0 eproc=%p\n" ), eprocess );
			return nullptr;
		}

		auto apc_state = &current_thread->m_kthread.m_apc_state;
		auto org_process = apc_state->m_process;
		apc_state->m_process = eprocess;
		__writecr3( directory_table_base );
		KDBG( oxorany( "[co] process::attach OK eproc=%p dtb=0x%llx\n" ),
			eprocess, static_cast< unsigned long long >( directory_table_base ) );
		return org_process;
	}
}
