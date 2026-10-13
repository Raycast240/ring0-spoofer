#pragma once

namespace kernel {
    unsigned char ke_raise_irql_to_dpc_level( ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeRaiseIrqlToDpcLevel" ) );
            if ( !fn_address ) return 0;
        }
        using function_t = unsigned char( * )( );
        return reinterpret_cast< function_t >( fn_address )( );
    }

    void ke_lower_irql( unsigned char new_irql ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "KeLowerIrql" ) );
            if ( !fn_address ) return;
        }
        using function_t = void( * )( unsigned char );
        reinterpret_cast< function_t >( fn_address )( new_irql );
    }

    bool mm_is_address_valid( void* virtual_address ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "MmIsAddressValid" ) );
            if ( !fn_address ) return {};
        }

        using function_t = bool( void* virtual_address );
        return reinterpret_cast< function_t* >( fn_address )( virtual_address );
    }

    eprocess_t* ps_initial_system_process( ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "PsInitialSystemProcess" ) );
            if ( !export_address ) return {};
        }

        return *reinterpret_cast< eprocess_t** >( export_address );
    }

    physical_memory_range_t* mm_get_physical_memory_ranges( ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmGetPhysicalMemoryRanges" ) );
            if ( !export_address ) return nullptr;
        }

        using function_t = physical_memory_range_t * ( void );
        return reinterpret_cast< function_t* >( export_address )( );
    }

    void* mm_get_virtual_for_physical( std::uintptr_t phys_addr ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmGetVirtualForPhysical" ) );
            if ( !export_address ) return nullptr;
        }

        using function_t = void* ( * )( std::uintptr_t physical_address );
        return reinterpret_cast< function_t >( export_address )( phys_addr );
    }

    physical_address_t mm_get_physical_address( void* virtual_address ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmGetPhysicalAddress" ) );
            if ( !export_address ) return { };
        }

        using function_t = physical_address_t( * )( void* virtual_address );
        return reinterpret_cast< function_t >( export_address )( virtual_address );
    }

    mmpfn_t* get_mm_pfn_database( ) {
        static mmpfn_t* cached = nullptr;
        if ( cached )
            return cached;

        if ( !m_pdb.m_mm_pfn_database )
            return nullptr;

        auto* db_var = reinterpret_cast< mmpfn_t** >( m_pdb.m_mm_pfn_database );
        if ( !db_var || !mm_is_address_valid( db_var ) )
            return nullptr;

        auto* db = *db_var;
        if ( !db || !mm_is_address_valid( db ) )
            return nullptr;

        cached = db;
        return cached;
    }

    std::uint32_t ke_get_current_processor_number( ) {
        static auto fn_ke_get_current_processor_number = 0ull;
        if ( !fn_ke_get_current_processor_number ) {
            fn_ke_get_current_processor_number = get_export( m_ntoskrnl_base, oxorany( "KeGetCurrentProcessorNumberEx" ) );
            if ( !fn_ke_get_current_processor_number ) return {};
        }

        using function_t = std::uint32_t( __int64 );
        return reinterpret_cast< function_t* >( fn_ke_get_current_processor_number )( 0 );
    }

    void* mm_allocate_independent_pages( std::size_t size ) {
        static auto mm_allocate_independent_pages = 0ull;
        if ( !mm_allocate_independent_pages ) {
            mm_allocate_independent_pages = m_pdb.m_mm_allocate_independent_pages;
            if ( !mm_allocate_independent_pages )
                return nullptr;
        }

        using function_t = void* ( * )( std::size_t, unsigned long );
        return reinterpret_cast< function_t >( mm_allocate_independent_pages )( size, 0xFFFFFFFFul );
    }

    void ex_initialize_rundown_protection( void* rundown_ref ) {
        static std::uint64_t export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExInitializeRundownProtection" ) );
            if ( !export_address ) return;
        }

        using function_t = void( * )( void* );
        reinterpret_cast< function_t >( export_address )( rundown_ref );
    }

    bool ex_acquire_rundown_protection( void* rundown_ref ) {
        static std::uint64_t export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExAcquireRundownProtection" ) );
            if ( !export_address ) return false;
        }

        using function_t = bool( * )( void* );
        return reinterpret_cast< function_t >( export_address )( rundown_ref );
    }

    void ex_release_rundown_protection( void* rundown_ref ) {
        static std::uint64_t export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExReleaseRundownProtection" ) );
            if ( !export_address ) return;
        }

        using function_t = void( * )( void* );
        reinterpret_cast< function_t >( export_address )( rundown_ref );
    }

    nt_status_t ex_subscribe_wnf_state_change(
        PVOID* wnfStruct,
        PCWNF_STATE_NAME stateName,
        ULONG eventMask,
        PULONG changeStamp,
        PVOID callback,
        PVOID callbackContext ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExSubscribeWnfStateChange" ) );
            if ( !export_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )(
            PVOID*,
            PCWNF_STATE_NAME,
            ULONG,
            PULONG,
            PVOID,
            PVOID
            );

        return reinterpret_cast< function_t >( export_address )(
            wnfStruct,
            stateName,
            eventMask,
            changeStamp,
            callback,
            callbackContext
            );
    }

    nt_status_t ex_query_wnf_state_data(
        void* wnf_struct,
        PULONG time_stamp,
        void* buffer,
        PULONG size
    ) {
        static auto function_address = 0ull;
        if ( !function_address ) {
            function_address = get_export( m_ntoskrnl_base, oxorany( "ExQueryWnfStateData" ) );
            if ( !function_address )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )( void*, PULONG, void*, PULONG );
        return reinterpret_cast< function_t >( function_address )(
            wnf_struct, time_stamp, buffer, size );
    }

    nt_status_t ex_unsubscribe_wnf_state_change( void* subscription ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExUnsubscribeWnfStateChange" ) );
            if ( !export_address )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )( void* );
        return reinterpret_cast< function_t >( export_address )( subscription );
    }

    void* ex_allocate_pool_with_tag( std::size_t size, unsigned long tag ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExAllocatePoolWithTag" ) );
            if ( !export_address )
                return nullptr;
        }

        using function_t = void* ( * )( std::uint32_t pool_type, std::size_t number_of_bytes, unsigned long tag );
        return reinterpret_cast< function_t >( export_address )( 512, size, tag );
    }

    void ex_free_pool_with_tag( void* pool, unsigned long tag ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ExFreePoolWithTag" ) );
            if ( !export_address )
                return;
        }

        using function_t = void( * )( void*, unsigned long );
        reinterpret_cast< function_t >( export_address )( pool, tag );
    }

    eprocess_t* ps_lookup_process_by_pid( std::uint32_t process_id ) {
        static void* export_address = nullptr;
        if ( !export_address ) {
            export_address = reinterpret_cast< void* >(
                kernel::get_export(
                    m_ntoskrnl_base,
                    oxorany( "PsLookupProcessByProcessId" )
                )
                );

            if ( !export_address )
                return nullptr;
        }

        eprocess_t* process = nullptr;
        using function_t = nt_status_t( * )( HANDLE process_id, eprocess_t** process );
        auto status = reinterpret_cast< function_t >( export_address )(
            reinterpret_cast< HANDLE >( static_cast< std::uintptr_t >( process_id ) ),
            &process
            );

        if ( status == nt_status_t::success && process )
            return process;

        return nullptr;
    }

    void obf_dereference_object( void* object ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ObfDereferenceObject" ) );
            if ( !export_address ) return;
        }

        using function_t = long long( __fastcall* )( void* );
        reinterpret_cast< function_t >( export_address )( object );
    }

    void obf_reference_object( void* object ) {
        if ( !object ) return;
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ObfReferenceObject" ) );
            if ( !export_address ) return;
        }

        using function_t = long long( __fastcall* )( void* );
        reinterpret_cast< function_t >( export_address )( object );
    }

    nt_status_t ke_delay_execution_thread(
        char wait_mode,
        bool alertable,
        std::int64_t* interval
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "KeDelayExecutionThread" ) );
            if ( !export_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )( char, bool, std::int64_t* );
        return reinterpret_cast< function_t >( export_address )(
            wait_mode, alertable, interval );
    }

    void sleep_ms( std::int32_t ms ) {
        if ( ms <= 0 ) return;
        std::int64_t interval = -static_cast< std::int64_t >( ms ) * 10000i64;
        ( void )ke_delay_execution_thread( 0, false, &interval );
    }

    mdl_t* io_allocate_mdl(
        void* virtual_address,
        std::size_t length,
        bool secondary_buffer,
        bool charge_quota,
        iop_irp_t* irp
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "IoAllocateMdl" ) );
            if ( !export_address ) return {};
        }

        using function_t = mdl_t * (
            void* virtual_address,
            std::size_t length,
            bool secondary_buffer,
            bool charge_quota,
            iop_irp_t* irp
            );

        return reinterpret_cast< function_t* >( export_address ) (
            virtual_address,
            length,
            secondary_buffer,
            charge_quota,
            irp );
    }

    void* mm_map_locked_pages_specify_cache( mdl_t* mdl,
        std::uint8_t access_mode,
        std::uint32_t cache_type,
        void* base_address,
        bool bug_check_on_failure,
        std::uint32_t priority
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmMapLockedPagesSpecifyCache" ) );
            if ( !export_address ) return {};
        }

        using function_t = void* (
            mdl_t* mdl,
            std::uint8_t access_mode,
            std::uint32_t cache_type,
            void* base_address,
            bool bug_check_on_failure,
            std::uint32_t priority
            );

        return reinterpret_cast< function_t* >( export_address ) (
            mdl,
            access_mode,
            cache_type,
            base_address,
            bug_check_on_failure,
            priority );
    }

    void mm_unmap_locked_pages( void* base_address, mdl_t* mdl ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "MmUnmapLockedPages" ) );
            if ( !export_address ) return;
        }

        using function_t = void ( void* base_address, mdl_t* mdl );
        reinterpret_cast< function_t* >( export_address ) ( base_address, mdl );
    }

    long ke_release_semaphore(
        ksemaphore_t* semaphore,
        long increment,
        long adjustment,
        bool wait
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "KeReleaseSemaphore" ) );
            if ( !export_address ) return {};
        }

        using function_t = long ( * )(
            ksemaphore_t*,
            long,
            long,
            bool
            );

        return reinterpret_cast< function_t >( export_address )(
            semaphore,
            increment,
            adjustment,
            wait
            );
    }

    nt_status_t ob_reference_object_by_handle(
        void* handle,
        std::uint32_t desired_access,
        void* object_type,
        std::uint8_t access_mode,
        void** object,
        void* handle_information
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "ObReferenceObjectByHandle" ) );
            if ( !export_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )(
            void*,
            std::uint32_t,
            void*,
            std::uint8_t,
            void**,
            void*
            );

        return reinterpret_cast< function_t >( export_address )(
            handle,
            desired_access,
            object_type,
            access_mode,
            object,
            handle_information
            );
    }

    void io_free_mdl( mdl_t* mdl ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "IoFreeMdl" ) );
            if ( !export_address ) return;
        }
        using function_t = void( mdl_t* mdl );
        reinterpret_cast< function_t* >( export_address )( mdl );
    }

    nt_status_t ke_wait_for_single_object(
        void* object,
        long wait_reason,
        long wait_mode,
        bool alertable,
        std::int64_t* timeout
    ) {
        static auto export_address = 0ull;
        if ( !export_address ) {
            export_address = get_export( m_ntoskrnl_base, oxorany( "KeWaitForSingleObject" ) );
            if ( !export_address ) return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( * )(
            void*,
            long,
            long,
            bool,
            std::int64_t*
            );

        return reinterpret_cast< function_t >( export_address )(
            object,
            wait_reason,
            wait_mode,
            alertable,
            timeout
            );
    }

    nt_status_t ke_wait_for_single_object(
        void* object,
        long wait_reason,
        long wait_mode,
        bool alertable,
        int wait_duration
    ) {
        std::int64_t timeout = static_cast< std::int64_t >( wait_duration ) * -10000i64;
        return ke_wait_for_single_object(
            object, wait_reason, wait_mode, alertable, &timeout );
    }

    nt_status_t create_system_thread(
        void** thread_handle,
        pkstart_routine start_routine,
        void* start_context
    ) {
        static auto fn_address = 0ull;
        if ( !fn_address ) {
            fn_address = get_export( m_ntoskrnl_base, oxorany( "PsCreateSystemThread" ) );
            if ( !fn_address )
                return nt_status_t::unsuccessful;
        }

        using function_t = nt_status_t( __stdcall* )(
            void** thread_handle,
            std::uint32_t desired_access,
            object_attributes_t* object_attributes,
            void* process_handle,
            client_id_t* client_id,
            pkstart_routine start_routine,
            void* start_context
            );

        constexpr std::uint32_t k_thread_all_access = 0x001FFFFFu;

        return reinterpret_cast< function_t >( fn_address )(
            thread_handle,
            k_thread_all_access,
            nullptr,
            nullptr,
            nullptr,
            start_routine,
            start_context
            );
    }

    template<class... args_t>
    void dbg_print( const char* format, args_t... va_args ) {
        static auto p_dbg_print = 0ull;
        static auto p_dbg_print_ex = 0ull;
        static bool resolved = false;
        if ( !resolved ) {
            resolved = true;
            if ( m_ntoskrnl_base ) {
                p_dbg_print = get_export( m_ntoskrnl_base, oxorany( "DbgPrint" ) );
                p_dbg_print_ex = get_export( m_ntoskrnl_base, oxorany( "DbgPrintEx" ) );
            }
        }
        if ( p_dbg_print ) {
            using fn_t = std::uint32_t( * )( const char*, args_t... );
            reinterpret_cast< fn_t >( p_dbg_print )( format, va_args... );
            return;
        }
        if ( p_dbg_print_ex ) {
            using fn_t = std::uint32_t( * )( std::uint32_t, std::uint32_t, const char*, args_t... );
            reinterpret_cast< fn_t >( p_dbg_print_ex )( 77u, 0u, format, va_args... );
        }
    }
}

#define KDBG( ... ) ( ( void )0 )
