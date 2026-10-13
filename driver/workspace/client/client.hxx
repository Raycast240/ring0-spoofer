#pragma once

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL static_cast< nt_status_t >( 0xC0000023L )
#endif

namespace client {
	eprocess_t* m_eprocess{ nullptr };
	mdl_t* m_comm_mdl{ nullptr };
	void* m_wnf_subscription{ };
	void* m_wnf_rundown{ };
	void* m_wnf_ctx{ };
	void* m_mapped_va{ nullptr };

	namespace thread {
		void communication_handler( void* ) {
			KDBG( oxorany( "[co] system thread running\n" ) );
			while ( true ) {
				void* wait_obj = control::m_request_handle;
				if ( !wait_obj || !control::m_control_data || !control::m_response_handle ) {
					kernel::sleep_ms( 1 );
					continue;
				}

				kernel::obf_reference_object( wait_obj );
				if ( control::m_request_handle != wait_obj ) {
					kernel::obf_dereference_object( wait_obj );
					kernel::sleep_ms( 1 );
					continue;
				}

				std::int64_t wait_5s = -50000000i64;
				auto result = kernel::ke_wait_for_single_object(
					wait_obj, 0, 0, false, &wait_5s );
				kernel::obf_dereference_object( wait_obj );

				if ( result == nt_status_t::timeout ) {
					continue;
				}
				if ( result != nt_status_t::success ) {
					kernel::sleep_ms( 1 );
					continue;
				}

				const long gen = control::m_session_gen;
				control::control_data_t* const cd = control::m_control_data;
				ksemaphore_t* const resp = control::m_response_handle;
				if ( !cd || !resp || control::m_request_handle != wait_obj ) {
					continue;
				}

				_InterlockedIncrement( &control::m_inflight );
				if ( control::m_session_gen != gen || control::m_control_data != cd ) {
					_InterlockedDecrement( &control::m_inflight );
					continue;
				}

				__try {
					const auto req = cd->m_request_type;
					cd->m_status = false;

				switch ( req ) {
				case control::control_type::query_caps: {
						cd->m_size  = control::k_shared_payload_size;
						cd->m_count = 0x3u;
						cd->m_status = true;
					} break;

					case control::control_type::spoof_hardware: {
						// runs on this PASSIVE_LEVEL system thread; spoof stages
						// only touch kernel state + the HKLM registry, never
						// the shared payload
						KDBG( oxorany( "[sp] req spoof_hardware begin\n" ) );
						// m_mode is the per-stage result transport (see
						// comm/spoof_stages.h): zero it first so a stale
						// caller-side value can never masquerade as a report
						cd->m_mode = 0;
						cd->m_status = spoof::install( );
						// per-stage bitmask out-of-band next to the boolean
						// status -- the loader logs which stage did what
						cd->m_mode = spoof::g_stage_mask;
						KDBG( oxorany( "[sp] req spoof_hardware done ok=%d stages=0x%x\n" ),
							cd->m_status ? 1 : 0, spoof::g_stage_mask );
					} break;

					case control::control_type::get_directory_table_base: {
						std::uint64_t cr3 = 0;
						const auto pid = cd->m_process_id;
						if ( !pid ) {
							KDBG( oxorany( "[co] req get_cr3 FAIL pid=0\n" ) );
						} else {
							cr3 = paging::pfn_cr3::get_cr3_by_pid( pid );
						}
						cd->m_address = cr3;
						if ( cr3 )
							cd->m_status = true;
						KDBG( oxorany( "[co] req get_cr3 pid=%u -> 0x%llx %s\n" ),
							pid,
							static_cast< unsigned long long >( cr3 ),
							cd->m_status ? "OK" : "FAIL" );
					} break;

					case control::control_type::swap_directory_table_base: {
						const auto new_cr3 = cd->m_address;
						cd->m_address1 = paging::swap_context( new_cr3 );
						cd->m_status = true;
						KDBG( oxorany( "[co] req swap_cr3 new=0x%llx old=0x%llx\n" ),
							static_cast< unsigned long long >( new_cr3 ),
							static_cast< unsigned long long >( cd->m_address1 ) );
					} break;

					case control::control_type::read_virtual: {
						auto do_read = [ ] ( std::uint64_t virtual_address, void* buffer, std::size_t size ) -> bool {
							auto current_buffer = static_cast< std::uint8_t* >( buffer );
							auto current_va = virtual_address;
							auto remaining = size;
							while ( remaining > 0 ) {
								std::uint32_t page_size = 0;
								std::uint64_t physical_address = 0;
								if ( !paging::translate_linear( current_va, &physical_address, &page_size ) )
									return false;
								const auto pa_off = physical_address & ( paging::page_4kb_size - 1ull );
								const auto room = paging::page_4kb_size - pa_off;
								auto read_size = min( static_cast< std::size_t >( room ), remaining );
								if ( !paging::dpm::read_physical( physical_address, current_buffer, read_size ) )
									return false;
								current_va += read_size;
								current_buffer += read_size;
								remaining -= read_size;
							}
							return true;
						};

						const auto va = cd->m_address;
						auto sz = cd->m_size;
						if ( !sz || sz > control::k_max_read_chunk ) {
							cd->m_status = false;
							break;
						}

						auto shared_buffer = reinterpret_cast< std::uint8_t* >( cd )
							+ sizeof( control::control_data_t );
						cd->m_status = do_read( va, shared_buffer, sz );
					} break;

					case control::control_type::read_scatter: {
						auto do_read = [ ] ( std::uint64_t virtual_address, void* buffer, std::size_t size ) -> bool {
							auto current_buffer = static_cast< std::uint8_t* >( buffer );
							auto current_va = virtual_address;
							auto remaining = size;
							while ( remaining > 0 ) {
								std::uint32_t page_size = 0;
								std::uint64_t physical_address = 0;
								if ( !paging::translate_linear( current_va, &physical_address, &page_size ) )
									return false;
								const auto pa_off = physical_address & ( paging::page_4kb_size - 1ull );
								const auto room = paging::page_4kb_size - pa_off;
								auto read_size = min( static_cast< std::size_t >( room ), remaining );
								if ( !paging::dpm::read_physical( physical_address, current_buffer, read_size ) )
									return false;
								current_va += read_size;
								current_buffer += read_size;
								remaining -= read_size;
							}
							return true;
						};

						const auto count = cd->m_count;
						if ( !count || count > control::k_max_scatter_ops ) {
							cd->m_status = false;
							break;
						}

						auto* payload = reinterpret_cast< std::uint8_t* >( cd )
							+ sizeof( control::control_data_t );
						auto* ops = reinterpret_cast< control::scatter_op_t* >( payload );
						const std::size_t ops_bytes = static_cast< std::size_t >( count )
							* sizeof( control::scatter_op_t );
						if ( ops_bytes >= control::k_shared_payload_size ) {
							cd->m_status = false;
							break;
						}

						std::size_t data_need = 0;
						bool bad_ops = false;
						for ( std::uint32_t i = 0; i < count; ++i ) {
							if ( !ops[ i ].size || ops[ i ].size > 0x1000u ) {
								bad_ops = true;
								break;
							}
							data_need += ops[ i ].size;
						}
						if ( bad_ops || ops_bytes + data_need > control::k_shared_payload_size ) {
							cd->m_status = false;
							break;
						}

						auto* data_out = payload + ops_bytes;
						bool all_ok = true;
						for ( std::uint32_t i = 0; i < count; ++i ) {
							const bool ok = do_read( ops[ i ].va, data_out, ops[ i ].size );
							ops[ i ].status = ok ? 1u : 0u;
							if ( !ok ) {
								all_ok = false;
								for ( std::uint32_t z = 0; z < ops[ i ].size; ++z )
									data_out[ z ] = 0;
							}
							data_out += ops[ i ].size;
						}
						cd->m_status = all_ok;
					} break;

					case control::control_type::write_virtual: {
						auto do_write = [ ] ( std::uint64_t virtual_address, void* buffer, std::size_t size ) -> bool {
							auto current_buffer = static_cast< std::uint8_t* >( buffer );
							auto current_va = virtual_address;
							auto remaining = size;
							while ( remaining > 0 ) {
								std::uint32_t page_size = 0;
								std::uint64_t physical_address = 0;
								if ( !paging::translate_linear( current_va, &physical_address, &page_size ) )
									return false;
								const auto pa_off = physical_address & ( paging::page_4kb_size - 1ull );
								const auto room = paging::page_4kb_size - pa_off;
								auto write_size = min( static_cast< std::size_t >( room ), remaining );
								if ( !paging::dpm::write_physical( physical_address, current_buffer, write_size ) )
									return false;
								current_va += write_size;
								current_buffer += write_size;
								remaining -= write_size;
							}
							return true;
						};

						auto sz = cd->m_size;
						if ( !sz || sz > control::k_max_read_chunk ) {
							cd->m_status = false;
							break;
						}

						auto shared_buffer = reinterpret_cast< std::uint8_t* >( cd )
							+ sizeof( control::control_data_t );
						cd->m_status = do_write( cd->m_address, shared_buffer, sz );
					} break;

					default:
						cd->m_status = false;
						KDBG( oxorany( "[co] req UNKNOWN type=%d\n" ),
							static_cast< int >( req ) );
						break;
					}
				}
				__except ( 1 ) {
					if ( control::m_session_gen == gen && control::m_control_data == cd )
						cd->m_status = false;
					KDBG( oxorany( "[co] req EXCEPTION\n" ) );
				}

				if ( control::m_session_gen == gen && resp )
					kernel::ke_release_semaphore( resp, 0, 1, false );

				_InterlockedDecrement( &control::m_inflight );
			}
		}
	}

	namespace callback {
		inline std::uint64_t g_last_create_fail = 0;

		inline void drain_handler_inflight( ) {
			for ( int i = 0; i < 5000; ++i ) {
				if ( control::m_inflight == 0 )
					return;
				kernel::sleep_ms( 1 );
			}
			KDBG( oxorany( "[co] session WARN inflight drain timeout n=%ld\n" ),
				control::m_inflight );
		}

		inline void teardown_session( ) {
			auto* req = control::m_request_handle;
			auto* resp = control::m_response_handle;
			auto* mapped = client::m_mapped_va;
			auto* mdl = client::m_comm_mdl;
			auto* eproc = client::m_eprocess;

			control::m_request_handle = nullptr;
			control::m_response_handle = nullptr;
			control::m_control_data = nullptr;
			client::m_mapped_va = nullptr;
			client::m_comm_mdl = nullptr;
			client::m_eprocess = nullptr;
			_InterlockedIncrement( &control::m_session_gen );

			drain_handler_inflight( );

			if ( mapped && mdl )
				kernel::mm_unmap_locked_pages( mapped, mdl );
			if ( mdl )
				kernel::io_free_mdl( mdl );
			if ( req )
				kernel::obf_dereference_object( req );
			if ( resp )
				kernel::obf_dereference_object( resp );
			if ( eproc )
				kernel::obf_dereference_object( eproc );
		}

		nt_status_t initialize( control::control_initialize_t* control_initialize ) {
			KDBG( oxorany( "[co] session init begin\n" ) );
			if ( !control_initialize
				|| !control_initialize->m_process_id
				|| !control_initialize->m_base_address
				|| !control_initialize->m_response_semaphore
				|| !control_initialize->m_request_semaphore ) {
				KDBG( oxorany( "[co] session FAIL bad init payload\n" ) );
				return nt_status_t::unsuccessful;
			}

			KDBG( oxorany( "[co] session pid=%u page=%p req=%p resp=%p\n" ),
				static_cast< unsigned >( control_initialize->m_process_id ),
				reinterpret_cast< void* >( control_initialize->m_base_address ),
				control_initialize->m_request_semaphore,
				control_initialize->m_response_semaphore );

			if ( control::is_valid( ) || control::m_control_data || client::m_comm_mdl ) {
				KDBG( oxorany( "[co] session teardown previous\n" ) );
				teardown_session( );
			}

			client::m_eprocess = kernel::ps_lookup_process_by_pid(
				static_cast< std::uint32_t >( control_initialize->m_process_id ) );
			if ( !client::m_eprocess ) {
				KDBG( oxorany( "[co] session FAIL PsLookupProcessByProcessId\n" ) );
				return nt_status_t::unsuccessful;
			}
			KDBG( oxorany( "[co] session client eproc=%p\n" ), client::m_eprocess );

			auto orig_process = process::attach( client::m_eprocess );
			if ( !orig_process ) {
				KDBG( oxorany( "[co] session FAIL soft attach\n" ) );
				kernel::obf_dereference_object( client::m_eprocess );
				client::m_eprocess = nullptr;
				return nt_status_t::unsuccessful;
			}
			auto orig_dtb = paging::swap_context( __readcr3( ) );

			auto data_size = sizeof( control::control_data_t )
				+ control::k_shared_payload_size;
			auto base_address = control_initialize->m_base_address;

			auto fail_cleanup = [ & ]( const char* why ) -> nt_status_t {
				KDBG( oxorany( "[co] session FAIL %s\n" ), why );
				paging::swap_context( orig_dtb );
				if ( orig_process ) process::attach( orig_process );

				auto* req = control::m_request_handle;
				auto* resp = control::m_response_handle;
				auto* mapped = client::m_mapped_va;
				auto* mdl = client::m_comm_mdl;
				auto* eproc = client::m_eprocess;
				control::m_request_handle = nullptr;
				control::m_response_handle = nullptr;
				control::m_control_data = nullptr;
				client::m_mapped_va = nullptr;
				client::m_comm_mdl = nullptr;
				client::m_eprocess = nullptr;
				_InterlockedIncrement( &control::m_session_gen );
				drain_handler_inflight( );

				if ( mapped && mdl )
					kernel::mm_unmap_locked_pages( mapped, mdl );
				if ( mdl )
					kernel::io_free_mdl( mdl );
				if ( req )
					kernel::obf_dereference_object( req );
				if ( resp )
					kernel::obf_dereference_object( resp );
				if ( eproc )
					kernel::obf_dereference_object( eproc );
				return nt_status_t::unsuccessful;
			};

			client::m_comm_mdl = reinterpret_cast< mdl_t* >(
				kernel::io_allocate_mdl( nullptr, data_size, false, false, nullptr )
			);
			if ( !client::m_comm_mdl )
				return fail_cleanup( "IoAllocateMdl" );
			KDBG( oxorany( "[co] session mdl=%p size=0x%llx\n" ),
				client::m_comm_mdl, static_cast< unsigned long long >( data_size ) );

			auto page_aligned_va = base_address & ~( paging::page_4kb_size - 1 );
			auto byte_offset = base_address & ( paging::page_4kb_size - 1 );
			auto page_count = ( ( byte_offset + data_size + paging::page_4kb_size - 1 )
				/ paging::page_4kb_size );

			client::m_comm_mdl->m_start_va = reinterpret_cast< void* >( page_aligned_va );
			client::m_comm_mdl->m_byte_offset = static_cast< std::uint32_t >( byte_offset );
			client::m_comm_mdl->m_byte_count = static_cast< std::uint32_t >( data_size );
			client::m_comm_mdl->m_mdl_flags |= 0x0001 | 0x0004;
			client::m_comm_mdl->m_process = client::m_eprocess;

			auto* pfn_array = reinterpret_cast< std::uint64_t* >(
				reinterpret_cast< std::uint8_t* >( client::m_comm_mdl ) + sizeof( mdl_t ) );

			for ( auto idx = 0ull; idx < page_count; idx++ ) {
				std::uint64_t current_pa = 0;
				auto current_va = base_address + ( idx * paging::page_4kb_size );
				if ( !paging::translate_linear( current_va, &current_pa ) || !current_pa )
					return fail_cleanup( "translate client shared page" );
				pfn_array[ idx ] = current_pa >> 12;
				KDBG( oxorany( "[co] session page[%llu] va=0x%llx pa=0x%llx\n" ),
					static_cast< unsigned long long >( idx ),
					static_cast< unsigned long long >( current_va ),
					static_cast< unsigned long long >( current_pa ) );
			}

			control::m_control_data = reinterpret_cast< control::control_data_t* >(
				kernel::mm_map_locked_pages_specify_cache(
					client::m_comm_mdl,
					0,
					1,
					nullptr,
					false,
					63
				) );
			if ( !control::m_control_data )
				return fail_cleanup( "MmMapLockedPagesSpecifyCache" );
			client::m_mapped_va = reinterpret_cast< void* >( control::m_control_data );
			KDBG( oxorany( "[co] session mapped_kva=%p\n" ), client::m_mapped_va );

			if ( kernel::ob_reference_object_by_handle(
				control_initialize->m_response_semaphore,
				0x1F0003,
				nullptr,
				0,
				reinterpret_cast< void** >( &control::m_response_handle ),
				nullptr
			) )
				return fail_cleanup( "ObRef response sem" );

			if ( kernel::ob_reference_object_by_handle(
				control_initialize->m_request_semaphore,
				0x1F0003,
				nullptr,
				0,
				reinterpret_cast< void** >( &control::m_request_handle ),
				nullptr
			) )
				return fail_cleanup( "ObRef request sem" );

			_InterlockedIncrement( &control::m_session_gen );
			KDBG( oxorany( "[co] session UP pid=%u mapped=%p req=%p resp=%p gen=%ld\n" ),
				static_cast< unsigned >( control_initialize->m_process_id ),
				client::m_mapped_va,
				control::m_request_handle,
				control::m_response_handle,
				control::m_session_gen );
			paging::swap_context( orig_dtb );
			if ( orig_process ) process::attach( orig_process );
			return nt_status_t::success;
		}

		nt_status_t wnf_callback(
			void* wnf_struct,
			PCWNF_STATE_NAME ,
			long ,
			long ,
			void* ,
			void*
		) {
			KDBG( oxorany( "[co] wnf callback fire\n" ) );
			if ( !kernel::ex_acquire_rundown_protection( &m_wnf_rundown ) ) {
				KDBG( oxorany( "[co] wnf callback rundown busy\n" ) );
				return nt_status_t::success;
			}

			ULONG buffer_size = 0;
			ULONG time_stamp = 0;

			auto result = kernel::ex_query_wnf_state_data(
				wnf_struct, &time_stamp, nullptr, &buffer_size );

			if ( result != STATUS_BUFFER_TOO_SMALL || !buffer_size ) {
				KDBG( oxorany( "[co] wnf query size FAIL st=0x%x sz=%u\n" ),
					static_cast< unsigned >( result ), buffer_size );
				kernel::ex_release_rundown_protection( &m_wnf_rundown );
				return result;
			}
			KDBG( oxorany( "[co] wnf payload size=%u\n" ), buffer_size );

			auto* wnf_data = kernel::ex_allocate_pool_with_tag( buffer_size, 'COfs' );
			if ( !wnf_data ) {
				KDBG( oxorany( "[co] wnf alloc FAIL\n" ) );
				kernel::ex_release_rundown_protection( &m_wnf_rundown );
				return nt_status_t::unsuccessful;
			}

			result = kernel::ex_query_wnf_state_data(
				wnf_struct, &time_stamp, wnf_data, &buffer_size );

			if ( !result ) {
				auto* control_data =
					reinterpret_cast< control::control_initialize_t* >( wnf_data );
				if ( buffer_size >= sizeof( control::control_initialize_t ) )
					result = initialize( control_data );
				else
					KDBG( oxorany( "[co] wnf payload too small %u\n" ), buffer_size );
			} else {
				KDBG( oxorany( "[co] wnf query data FAIL st=0x%x\n" ),
					static_cast< unsigned >( result ) );
			}

			kernel::ex_free_pool_with_tag( wnf_data, 'COfs' );
			kernel::ex_release_rundown_protection( &m_wnf_rundown );
			return result;
		}

		bool create( ) {
			g_last_create_fail = 0;
			KDBG( oxorany( "[co] wnf subscribe begin name=%08x:%08x\n" ),
				control::m_wnf_state_name_lo, control::m_wnf_state_name_hi );

			m_wnf_rundown = nullptr;
			kernel::ex_initialize_rundown_protection( &m_wnf_rundown );

			static std::uint32_t s_wnf_ctx = 0;
			s_wnf_ctx = 0;
			m_wnf_ctx = &s_wnf_ctx;

			WNF_STATE_NAME state_name{};
			state_name.Data[ 0 ] = control::m_wnf_state_name_lo;
			state_name.Data[ 1 ] = control::m_wnf_state_name_hi;

			m_wnf_subscription = nullptr;

			const auto status = kernel::ex_subscribe_wnf_state_change(
				&m_wnf_subscription,
				&state_name,
				3,
				nullptr,
				reinterpret_cast< void* >( &wnf_callback ),
				m_wnf_ctx
			);

			if ( status ) {
				if ( m_wnf_subscription ) {
					( void )kernel::ex_unsubscribe_wnf_state_change( m_wnf_subscription );
					m_wnf_subscription = nullptr;
				}
				g_last_create_fail = kernel::entry_wnf_subscribe;
				KDBG( oxorany( "[co] wnf subscribe FAIL st=0x%x\n" ),
					static_cast< unsigned >( status ) );
				return false;
			}

			if ( !m_wnf_subscription ) {
				g_last_create_fail = kernel::entry_wnf_subscribe;
				KDBG( oxorany( "[co] wnf subscribe FAIL null subscription\n" ) );
				return false;
			}

			KDBG( oxorany( "[co] wnf subscribe OK sub=%p\n" ), m_wnf_subscription );
			return true;
		}
	}
}
