#pragma once

#define image_dos_signature     0x5A4D
#define image_nt_signature      0x4550
#define image_nt_optional_hdr32	0x10B
#define image_nt_optional_hdr64	0x20B

#define image_dir_export		0
#define image_dir_import		1
#define image_dir_resource		2
#define image_dir_exception		3
#define image_dir_security		4
#define image_dir_relocs		5
#define image_dir_debug			6
#define image_dir_arch			7
#define image_dir_globalptr		8
#define image_dir_tls			9
#define image_dir_load_config	10
#define image_dir_bound_import	11
#define image_dir_iat			12
#define image_dir_delay_import	13
#define image_dir_com_desc		14
#define image_dir_entries		16

#define image_reloc_absolute	0
#define image_reloc_high		1
#define image_reloc_low			2
#define image_reloc_highlow		3
#define image_reloc_highadj		4
#define image_reloc_specific_5	5
#define image_reloc_reserved	6
#define image_reloc_specific_7	7
#define image_reloc_specific_8	8
#define image_reloc_specific_9	9
#define image_reloc_dir64		10
#define image_reloc_offset(x)	(x & 0xFFF)

struct eprocess_t;
struct peb_t;
struct ethread_t;

typedef union _virt_addr_t {
    std::uintptr_t value;
    struct {
        std::uint64_t offset : 12;
        std::uint64_t pte_index : 9;
        std::uint64_t pde_index : 9;
        std::uint64_t pdpte_index : 9;
        std::uint64_t pml4e_index : 9;
        std::uint64_t reserved : 16;
    };
    struct {
        std::uint64_t offset_4kb : 12;
        std::uint64_t pt_offset : 9;
        std::uint64_t pd_offset : 9;
        std::uint64_t pdpt_offset : 9;
        std::uint64_t pml4_offset : 9;
        std::uint64_t reserved2 : 16;
    };
    struct {
        std::uint64_t offset_2mb : 21;
        std::uint64_t pd_offset2 : 9;
        std::uint64_t pdpt_offset2 : 9;
        std::uint64_t pml4_offset2 : 9;
        std::uint64_t reserved3 : 16;
    };
    struct {
        std::uint64_t offset_1gb : 30;
        std::uint64_t pdpt_offset3 : 9;
        std::uint64_t pml4_offset3 : 9;
        std::uint64_t reserved4 : 16;
    };
} virt_addr_t, * pvirt_addr_t;

typedef union _pml4e {
    std::uint64_t value;
    struct {
        std::uint64_t present : 1;
        std::uint64_t read_write : 1;
        std::uint64_t user_supervisor : 1;
        std::uint64_t page_write_through : 1;
        std::uint64_t cached_disable : 1;
        std::uint64_t accessed : 1;
        std::uint64_t ignored0 : 1;
        std::uint64_t large_page : 1;
        std::uint64_t ignored1 : 4;
        std::uint64_t pfn : 36;
        std::uint64_t reserved : 4;
        std::uint64_t ignored2 : 11;
        std::uint64_t no_execute : 1;
    } hard;
} pml4e, * ppml4e;

typedef union _pdpte {
    std::uint64_t value;
    struct {
        std::uint64_t present : 1;
        std::uint64_t read_write : 1;
        std::uint64_t user_supervisor : 1;
        std::uint64_t page_write_through : 1;
        std::uint64_t cached_disable : 1;
        std::uint64_t accessed : 1;
        std::uint64_t dirty : 1;
        std::uint64_t page_size : 1;
        std::uint64_t ignored1 : 4;
        std::uint64_t pfn : 36;
        std::uint64_t reserved : 4;
        std::uint64_t ignored2 : 11;
        std::uint64_t no_execute : 1;
    } hard;
} pdpte, * ppdpte;

typedef union _pde {
    std::uint64_t value;
    struct {
        std::uint64_t present : 1;
        std::uint64_t read_write : 1;
        std::uint64_t user_supervisor : 1;
        std::uint64_t page_write_through : 1;
        std::uint64_t cached_disable : 1;
        std::uint64_t accessed : 1;
        std::uint64_t dirty : 1;
        std::uint64_t page_size : 1;
        std::uint64_t global : 1;
        std::uint64_t ignored1 : 3;
        std::uint64_t pfn : 36;
        std::uint64_t reserved : 4;
        std::uint64_t ignored2 : 11;
        std::uint64_t no_execute : 1;
    } hard;
} pde, * ppde;

typedef union _pte {
    std::uint64_t value;
    struct {
        std::uint64_t present : 1;
        std::uint64_t read_write : 1;
        std::uint64_t user_supervisor : 1;
        std::uint64_t page_write_through : 1;
        std::uint64_t cached_disable : 1;
        std::uint64_t accessed : 1;
        std::uint64_t dirty : 1;
        std::uint64_t pat : 1;
        std::uint64_t global : 1;
        std::uint64_t ignored1 : 3;
        std::uint64_t pfn : 36;
        std::uint64_t reserved : 4;
        std::uint64_t ignored2 : 7;
        std::uint64_t protection_key : 4;
        std::uint64_t no_execute : 1;
    } hard;
} pte, * ppte;

typedef union _cr3 {
    std::uint64_t flags;

    struct {
        std::uint64_t pcid : 12;
        std::uint64_t pfn : 36;
        std::uint64_t reserved_1 : 12;
        std::uint64_t reserved_2 : 3;
        std::uint64_t pcid_invalidate : 1;
    };
} cr3, * pcr3;

enum pe_magic_t {
    dos_header = 0x5a4d,
    nt_headers = 0x4550,
    opt_header = 0x020b
};

enum memory_caching_type_t {
    MmNonCached = 0,
    MmCached = 1,
    MmWriteCombined = 2,
    MmHardwareCoherentCached = 3,
    MmNonCachedUnordered = 4,
    MmUSWCCached = 5,
    MmMaximumCacheType = 6
};

struct dos_header_t {
    std::int16_t m_magic;
    std::int16_t m_cblp;
    std::int16_t m_cp;
    std::int16_t m_crlc;
    std::int16_t m_cparhdr;
    std::int16_t m_minalloc;
    std::int16_t m_maxalloc;
    std::int16_t m_ss;
    std::int16_t m_sp;
    std::int16_t m_csum;
    std::int16_t m_ip;
    std::int16_t m_cs;
    std::int16_t m_lfarlc;
    std::int16_t m_ovno;
    std::int16_t m_res0[ 0x4 ];
    std::int16_t m_oemid;
    std::int16_t m_oeminfo;
    std::int16_t m_res1[ 0xa ];
    std::int32_t m_lfanew;

    constexpr bool is_valid( ) {
        return m_magic == pe_magic_t::dos_header;
    }
};

struct data_directory_t {
    std::int32_t m_virtual_address;
    std::int32_t m_size;

    template< class type_t >

    type_t as_rva(
        std::uint64_t rva
    ) {
        return reinterpret_cast< type_t >( rva + m_virtual_address );
    }
};

struct import_descriptor_t {
    union {
        std::uint32_t m_characteristics;
        std::uint32_t m_original_first_thunk;
    };
    std::uint32_t m_time_date_stamp;
    std::uint32_t m_forwarder_chain;
    std::uint32_t m_name;
    std::uint32_t m_first_thunk;
};

struct image_delayload_descriptor_t {
    union {
        std::uint32_t all_attributes;
        struct {
            std::uint32_t m_rva_based : 1;
            std::uint32_t m_reverved_attributes : 1;
        };
    };

    std::uint32_t m_dll_name_rva;
    std::uint32_t m_module_handle_rva;
    std::uint32_t m_import_address_table_rva;
    std::uint32_t m_import_name_table_rva;
    std::uint32_t m_bound_import_address_table_rva;
    std::uint32_t m_unload_information_table_rva;
    std::uint32_t m_time_date_stamp;
};

struct nt_headers_t {
    std::int32_t m_signature;
    std::int16_t m_machine;
    std::int16_t m_number_of_sections;
    std::int32_t m_time_date_stamp;
    std::int32_t m_pointer_to_symbol_table;
    std::int32_t m_number_of_symbols;
    std::int16_t m_size_of_optional_header;
    std::int16_t m_characteristics;

    std::int16_t m_magic;
    std::int8_t m_major_linker_version;
    std::int8_t m_minor_linker_version;
    std::int32_t m_size_of_code;
    std::int32_t m_size_of_initialized_data;
    std::int32_t m_size_of_uninitialized_data;
    std::int32_t m_address_of_entry_point;
    std::int32_t m_base_of_code;
    std::uint64_t m_image_base;
    std::int32_t m_section_alignment;
    std::int32_t m_file_alignment;
    std::int16_t m_major_operating_system_version;
    std::int16_t m_minor_operating_system_version;
    std::int16_t m_major_image_version;
    std::int16_t m_minor_image_version;
    std::int16_t m_major_subsystem_version;
    std::int16_t m_minor_subsystem_version;
    std::int32_t m_win32_version_value;
    std::int32_t m_size_of_image;
    std::int32_t m_size_of_headers;
    std::int32_t m_check_sum;
    std::int16_t m_subsystem;
    std::int16_t m_dll_characteristics;
    std::uint64_t m_size_of_stack_reserve;
    std::uint64_t m_size_of_stack_commit;
    std::uint64_t m_size_of_heap_reserve;
    std::uint64_t m_size_of_heap_commit;
    std::int32_t m_loader_flags;
    std::int32_t m_number_of_rva_and_sizes;

    data_directory_t m_export_table;
    data_directory_t m_import_table;
    data_directory_t m_resource_table;
    data_directory_t m_exception_table;
    data_directory_t m_certificate_table;
    data_directory_t m_base_relocation_table;
    data_directory_t m_debug;
    data_directory_t m_architecture;
    data_directory_t m_global_ptr;
    data_directory_t m_tls_table;
    data_directory_t m_load_config_table;
    data_directory_t m_bound_import;
    data_directory_t m_iat;
    data_directory_t m_delay_import_descriptor;
    data_directory_t m_clr_runtime_header;
    data_directory_t m_reserved;

    constexpr bool is_valid( ) {
        return m_signature == pe_magic_t::nt_headers
            && m_magic == pe_magic_t::opt_header;
    }
};

struct export_directory_t {
    std::int32_t m_characteristics;
    std::int32_t m_time_date_stamp;
    std::int16_t m_major_version;
    std::int16_t m_minor_version;
    std::int32_t m_name;
    std::int32_t m_base;
    std::int32_t m_number_of_functions;
    std::int32_t m_number_of_names;
    std::int32_t m_address_of_functions;
    std::int32_t m_address_of_names;
    std::int32_t m_address_of_names_ordinals;
};

struct section_header_t {
    char m_name[ 0x8 ];
    union {
        std::int32_t m_physical_address;
        std::int32_t m_virtual_size;
    };
    std::int32_t m_virtual_address;
    std::int32_t m_size_of_raw_data;
    std::int32_t m_pointer_to_raw_data;
    std::int32_t m_pointer_to_relocations;
    std::int32_t m_pointer_to_line_numbers;
    std::int16_t m_number_of_relocations;
    std::int16_t m_number_of_line_numbers;
    std::int32_t m_characteristics;
};

struct unicode_string_t {
    std::uint16_t m_length;
    std::uint16_t m_maximum_length;
    wchar_t* m_buffer;
};

struct rtl_process_module_information_t {
    HANDLE  m_section;
    void* m_mapped_base;
    void* m_image_base;
    std::uint32_t m_image_size;
    std::uint32_t m_flags;
    std::uint16_t m_load_order_index;
    std::uint16_t m_init_order_index;
    std::uint16_t m_load_count;
    std::uint16_t m_offset_to_file_name;
    std::uint8_t  m_full_path[ 256 ];
};

struct rtl_process_modules_t {
    std::uint32_t    m_count;
    rtl_process_module_information_t m_modules[ 1 ];
};

struct mm_unloaded_drivers_t {
    UNICODE_STRING m_name;
    PVOID m_module_start;
    PVOID m_module_end;
    ULONG64 m_unload_time;
};

typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING 	Name;
    PVOID 			ModuleStart;
    PVOID 			ModuleEnd;
    ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

struct ex_push_lock_t {
    union {
        struct {
            std::uint64_t m_locked : 1;
            std::uint64_t m_waiting : 1;
            std::uint64_t m_waking : 1;
            std::uint64_t m_multiple_shared : 1;
            std::uint64_t m_shared : 60;
        };
        std::uint64_t m_value;
        void* m_ptr;
    };
};

struct dispatcher_header_t {
    union {
        struct {
            std::uint8_t m_type;
            union {
                std::uint8_t m_absolute_timer : 1;
                std::uint8_t m_timer_resolution : 1;
                std::uint8_t m_timer_resolution_required : 1;
                std::uint8_t m_timer_resolution_set : 1;
            };
            union {
                std::uint8_t m_inserted : 1;
                std::uint8_t m_large_stack : 1;
                std::uint8_t m_priority_boost : 1;
                std::uint8_t m_thread_control_flags;
            };
            std::uint8_t m_signal_state;
        };
        std::uint32_t m_lock;
    };
    std::uint32_t m_size;
    union {
        std::uint64_t m_reserved1;
        struct {
            std::uint8_t m_hand_size;
            std::uint8_t m_inserted_2;
        };
    };
    union {
        std::uint64_t m_signal_state_2;
        struct {
            std::uint32_t m_signal_state_3;
            std::uint32_t m_thread_apc_disable;
        };
    };
};

struct list_entry_t {
    list_entry_t* m_flink;
    list_entry_t* m_blink;
};

struct single_list_entry_t {
    single_list_entry_t* m_next;
};

struct kwait_status_register_t {
    union {
        std::uint8_t m_flags;
        struct {
            std::uint8_t m_state : 3;
            std::uint8_t m_affinity : 1;
            std::uint8_t m_priority : 1;
            std::uint8_t m_apc : 1;
            std::uint8_t m_user_apc : 1;
            std::uint8_t m_alert : 1;
        };
    };
};

struct large_integer_t {
    union {
        struct {
            std::uint32_t m_low_part;
            std::int32_t m_high_part;
        };
        struct {
            std::uint32_t m_low_part;
            std::int32_t m_high_part;
        } u;
        std::int64_t m_quad_part;
    };
};

struct kdpc_t {
    std::uint8_t m_type;
    std::uint8_t m_importance;
    std::int32_t m_number;
    list_entry_t m_dpc_list_entry;
    void* m_deferred_routine;
    void* m_deferred_context;
    void* m_system_argument_1;
    void* m_system_argument_2;
    void* m_dpc_data;
};

struct ktimer_t {
    dispatcher_header_t m_header;
    std::uint64_t m_due_time;
    list_entry_t m_timer_list_entry;
    kdpc_t* m_dpc;
    std::uint32_t m_period;
    std::uint32_t m_processor;
    std::uint32_t m_timer_type;
};

struct ktimer_table_entry_t {
    ULONG lock;
    struct list_entry_t entry;
    struct large_integer_t time;
};

struct ktimer_table_state_t {
    ULONGLONG last_timer_expiration[ 1 ];
    ULONG last_timer_hand[ 1 ];
};

struct ktimer_table_t {
    struct ktimer_t* timer_expiry[ 16 ];
    struct ktimer_table_entry_t timer_entries[ 1 ][ 256 ];
    struct ktimer_table_state_t table_state;
};

struct group_affinity_t {
    std::uint64_t m_mask;
    std::uint16_t m_group;
    std::uint16_t m_reserved[ 3 ];
};

struct kevent_t {
    dispatcher_header_t m_header;
};

struct mmsupport_t {
    list_entry_t m_work_set_exp_head;
    std::uint64_t m_flags;
    std::uint64_t m_last_trim_time;
    union {
        std::uint64_t m_page_fault_count;
        std::uint64_t m_peak_virtual_size;
        std::uint64_t m_virtual_size;
    };
    std::uint64_t m_min_ws_size;
    std::uint64_t m_max_ws_size;
    std::uint64_t m_virtual_memory_threshold;
    std::uint64_t m_working_set_size;
    std::uint64_t m_peak_working_set_size;
};

struct ex_fast_ref_t {
    union {
        void* m_object;
        std::uint64_t m_ref_cnt : 4;
        std::uint64_t m_value;
    };
};

struct kprocess_t {
    dispatcher_header_t m_header;
    list_entry_t m_profile_list_head;
    std::uint64_t m_directory_table_base;
    std::uint64_t m_flags;
    std::uint64_t m_flags2;
    std::uint64_t m_session_id;
    mmsupport_t m_mm;
    list_entry_t m_process_list_entry;
    std::uint64_t m_total_cycle_time;
    std::uint64_t m_create_time;
    std::uint64_t m_user_time;
    std::uint64_t m_kernel_time;
    list_entry_t m_active_process_links;
    std::uint64_t m_process_quota_usage[ 2 ];
    std::uint64_t m_process_quota_peak[ 2 ];
    std::uint64_t m_commit_charge;
    std::uint64_t m_peak_commit_charge;
    std::uint64_t m_peak_virtual_size;
    std::uint64_t m_virtual_size;
    std::uint32_t m_exit_status;
    std::uint32_t m_address_policy;
};

struct kapc_state_t {
    list_entry_t m_apc_list_head[ 2 ];
    eprocess_t* m_process;
    std::uint8_t m_kernel_apc_in_progress;
    std::uint8_t m_kernel_apc_pending;
    std::uint8_t m_user_apc_pending;
    std::uint8_t m_pad;
};

struct m128a {
    std::uint64_t m_low;
    std::int64_t m_high;
};

struct activation_context_stack_t {
    std::uint32_t m_flags;
    std::uint32_t m_next_cookie_sequence_number;
    void* m_active_frame;
    list_entry_t m_frame_list_cache;
    std::uint32_t m_flags2;
    std::uint32_t m_padding;
    std::uint64_t m_reserved[ 2 ];
};

struct ejob_t {
    dispatcher_header_t m_header;
    list_entry_t m_job_list_entry;
    std::uint64_t m_process_list_head;
    std::uint64_t m_job_lock;
    std::uint32_t m_total_user_time;
    std::uint32_t m_total_kernel_time;
    std::uint32_t m_total_page_fault_count;
    std::uint32_t m_total_processes;
    std::uint32_t m_active_processes;
    std::uint32_t m_total_terminated_processes;
    std::uint64_t m_per_process_user_time_limit;
    std::uint64_t m_per_job_user_time_limit;
    std::uint64_t m_limit_flags;
    std::uint64_t m_minimum_working_set_size;
    std::uint64_t m_maximum_working_set_size;
    std::uint64_t m_active_process_limit;
    std::uint64_t m_affinity;
    std::uint64_t m_priority_class;
    std::uint64_t m_per_process_memory_limit;
    std::uint64_t m_per_job_memory_limit;
    std::uint64_t m_reserved[ 2 ];
    void* m_completion_port;
    std::uint64_t m_completion_key;
    std::uint64_t m_session_id;
    std::uint64_t m_silo_root;
    std::uint64_t m_container;
    std::uint64_t m_container_silo;
    std::uint64_t m_reserved2[ 4 ];
};

struct pagefault_history_t {
    std::uint64_t m_timestamp;
    std::uint64_t m_virtual_address;
    std::uint32_t m_flags;
    std::uint32_t m_reserved;
    std::uint32_t m_process_id;
    std::uint32_t m_thread_id;
    std::uint64_t m_instruction_pointer;
    std::uint64_t m_stack_pointer;
};

struct ktrap_frame_t {
    std::uint64_t m_p1_home;
    std::uint64_t m_p2_home;
    std::uint64_t m_p3_home;
    std::uint64_t m_p4_home;
    std::uint64_t m_p5;

    std::uint8_t m_previous_mode;
    std::uint8_t m_previous_irql;
    std::uint8_t m_fault_indicator;
    std::uint8_t m_exception_active;
    std::uint32_t m_mxcsr;

    std::uint64_t m_rax;
    std::uint64_t m_rcx;
    std::uint64_t m_rdx;
    std::uint64_t m_r8;
    std::uint64_t m_r9;
    std::uint64_t m_r10;
    std::uint64_t m_r11;

    union {
        std::uint64_t m_gs_base;
        std::uint64_t m_gs_swap;
    };

    m128a m_xmm0;
    m128a m_xmm1;
    m128a m_xmm2;
    m128a m_xmm3;
    m128a m_xmm4;
    m128a m_xmm5;

    union {
        std::uint64_t m_fault_address;
        std::uint64_t m_context_record;
    };

    std::uint64_t m_dr0;
    std::uint64_t m_dr1;
    std::uint64_t m_dr2;
    std::uint64_t m_dr3;
    std::uint64_t m_dr6;
    std::uint64_t m_dr7;


    std::uint64_t m_debug_control;
    std::uint64_t m_last_branch_to_rip;
    std::uint64_t m_last_branch_from_rip;
    std::uint64_t m_last_exception_to_rip;
    std::uint64_t m_last_exception_from_rip;

    std::uint16_t m_seg_ds;
    std::uint16_t m_seg_es;
    std::uint16_t m_seg_fs;
    std::uint16_t m_seg_gs;

    std::uint64_t m_nested_trap_frame;
    std::uint64_t m_rbx;
    std::uint64_t m_rdi;
    std::uint64_t m_rsi;
    std::uint64_t m_rbp;

    union {
        std::uint64_t m_error_code;
        std::uint64_t m_exception_frame;
    };

    std::uint64_t m_rip;
    std::uint16_t m_seg_cs;
    std::uint8_t m_fill0;
    std::uint8_t m_logging;
    std::uint16_t m_fill1[ 2 ];
    std::uint32_t m_eflags;
    std::uint32_t m_fill2;
    std::uint64_t m_rsp;
    std::uint16_t m_seg_ss;
    std::uint16_t m_fill3;
    std::uint32_t m_fill4;
};

struct teb_t;
struct nt_tib_t {
    struct _exception_registration_record* m_exception_list;
    std::uint64_t m_stack_base;
    std::uint64_t m_stack_limit;
    std::uint64_t m_sub_system_tib;
    union {
        std::uint64_t m_fiber_data;
        std::uint32_t m_version;
    };
    std::uint64_t m_arbitrary_user_pointer;
    teb_t* m_self;
};

struct client_id_t {
    void* m_unique_process;
    void* m_unique_thread;
};

struct se_audit_process_creation_info_t {
    unicode_string_t* m_image_file_name;
};

struct ex_rundown_ref_t {
    union {
        std::uint64_t m_count;
        void* m_ptr;
    };
};

struct handle_table_t {
    std::uint32_t m_next_handle_needing_pool;
    std::int32_t m_extra_info_pages;
    std::uint64_t m_table_code;
    eprocess_t* m_quota_process;
    list_entry_t m_handle_table_list;
    std::uint32_t m_unique_process_id;
};

struct ps_dynamic_enforced_address_ranges_t {
    void* m_lock;
    void* m_list_head;
    std::uint32_t   m_count;
    std::uint32_t   m_maximum;
    void* m_bitmap;
};

struct ps_process_wake_information_t {
    std::uint64_t   m_notification_channel;
    std::uint64_t   m_wake_counters;
    std::uint32_t   m_wake_mask;
    std::uint32_t   m_wake_state;
    std::uint32_t   m_no_wake_reason;
    std::uint32_t   m_padding;
};

struct wnf_state_name_t {
    std::uint32_t   m_data1;
    std::uint32_t   m_data2;
};

struct ps_interlocked_timer_delay_values_t {
    union {
        std::uint64_t m_value;
        struct {
            std::uint64_t m_delay_ms : 30;
            std::uint64_t m_coalescing_window_ms : 30;
            std::uint64_t m_reserved : 1;
            std::uint64_t m_new_timer_wheel : 1;
            std::uint64_t m_retry : 1;
            std::uint64_t m_locked : 1;
        };
    };
};

struct mmsupport_full_t {


    struct mmsupport_t {
        list_entry_t     m_working_set_expansion_links;
        std::uint64_t    m_last_trim_time;
        std::uint64_t    m_flags;
        std::uint64_t    m_page_fault_count;
        std::uint64_t    m_peak_working_set_size;
        std::uint64_t    m_minimum_working_set_size;
        std::uint64_t    m_maximum_working_set_size;
        std::uint64_t    m_vm_working_set_size;

    } m_base;

    std::uint8_t     m_padding[ 0x140 ];
};

struct file_object_t {
    std::int16_t     m_type;
    std::int16_t     m_size;
    void* m_device_object;
    void* m_vpb;
    void* m_fs_context;
    void* m_fs_context2;
    void* m_section_object_pointer;
    void* m_private_cache_map;
    std::int32_t     m_final_status;
    void* m_related_file_object;
    std::uint8_t     m_lock_operation;
    std::uint8_t     m_delete_pending;
    std::uint8_t     m_read_access;
    std::uint8_t     m_write_access;
    std::uint8_t     m_delete_access;
    std::uint8_t     m_shared_read;
    std::uint8_t     m_shared_write;
    std::uint8_t     m_shared_delete;
    std::uint32_t    m_flags;
    unicode_string_t m_file_name;

};

struct ewow64process_t {
    void* m_reserved1[ 3 ];
    void* m_wow64;
    void* m_reserved2[ 2 ];
    std::uint32_t    m_flags;

};

struct eprocess_quota_block_t {
    void* m_quota_entry;
    std::uint64_t    m_quota_limit;
    std::uint64_t    m_quota_peak;
    std::uint64_t    m_quota_usage;
    std::uint32_t    m_flags;
    std::uint32_t    m_reference_count;

};

struct mm_session_space_t {
    std::uint32_t    m_reference_count;
    std::uint32_t    m_session_id;
    void* m_process_reference_to_session;
    void* m_session_page_directory_index;
    void* m_session_va_start;
    void* m_session_va_end;

};

struct rtl_avl_tree_t {
    void* m_root;
};

struct eprocess_t {

    kprocess_t m_pcb;


    ex_push_lock_t m_process_lock;
    void* m_unique_process_id;
    list_entry_t m_active_process_links;


    ex_rundown_ref_t m_rundown_protect;
    union {
        std::uint32_t m_flags2;
        struct {
            std::uint32_t m_job_not_really_active : 1;
            std::uint32_t m_accounting_folded : 1;
            std::uint32_t m_new_process_reported : 1;
            std::uint32_t m_exit_process_reported : 1;
            std::uint32_t m_report_commit_changes : 1;
            std::uint32_t m_last_report_memory : 1;
            std::uint32_t m_force_wake_charge : 1;
            std::uint32_t m_cross_session_create : 1;
            std::uint32_t m_needs_handle_rundown : 1;
            std::uint32_t m_ref_trace_enabled : 1;
            std::uint32_t m_pico_created : 1;
            std::uint32_t m_empty_job_evaluated : 1;
            std::uint32_t m_default_page_priority : 3;
            std::uint32_t m_primary_token_frozen : 1;
            std::uint32_t m_process_verifier_target : 1;
            std::uint32_t m_restrict_set_thread_context : 1;
            std::uint32_t m_affinity_permanent : 1;
            std::uint32_t m_affinity_update_enable : 1;
            std::uint32_t m_propagate_node : 1;
            std::uint32_t m_explicit_affinity : 1;
            std::uint32_t m_process_execution_state : 2;
            std::uint32_t m_enable_read_vm_logging : 1;
            std::uint32_t m_enable_write_vm_logging : 1;
            std::uint32_t m_fatal_access_termination_requested : 1;
            std::uint32_t m_disable_system_allowed_cpu_set : 1;
            std::uint32_t m_process_state_change_request : 2;
            std::uint32_t m_process_state_change_in_progress : 1;
            std::uint32_t m_in_private : 1;
        };
    };
    union {
        std::uint32_t m_flags;
        struct {
            std::uint32_t m_create_reported : 1;
            std::uint32_t m_no_debug_inherit : 1;
            std::uint32_t m_process_exiting : 1;
            std::uint32_t m_process_delete : 1;
            std::uint32_t m_manage_executable_memory_writes : 1;
            std::uint32_t m_vm_deleted : 1;
            std::uint32_t m_outswap_enabled : 1;
            std::uint32_t m_outswapped : 1;
            std::uint32_t m_fail_fast_on_commit_fail : 1;
            std::uint32_t m_wow64_va_space_4gb : 1;
            std::uint32_t m_address_space_initialized : 2;
            std::uint32_t m_set_timer_resolution : 1;
            std::uint32_t m_break_on_termination : 1;
            std::uint32_t m_deprioritize_views : 1;
            std::uint32_t m_write_watch : 1;
            std::uint32_t m_process_in_session : 1;
            std::uint32_t m_override_address_space : 1;
            std::uint32_t m_has_address_space : 1;
            std::uint32_t m_launch_prefetched : 1;
            std::uint32_t m_background : 1;
            std::uint32_t m_vm_top_down : 1;
            std::uint32_t m_image_notify_done : 1;
            std::uint32_t m_pde_update_needed : 1;
            std::uint32_t m_vdm_allowed : 1;
            std::uint32_t m_process_rundown : 1;
            std::uint32_t m_process_inserted : 1;
            std::uint32_t m_default_io_priority : 3;
            std::uint32_t m_process_self_delete : 1;
            std::uint32_t m_set_timer_resolution_link : 1;
        };
    };


    large_integer_t m_create_time;
    std::uint64_t m_process_quota_usage[ 2 ];
    std::uint64_t m_process_quota_peak[ 2 ];


    std::uint64_t m_peak_virtual_size;
    std::uint64_t m_virtual_size;


    list_entry_t m_session_process_links;
    union {
        void* m_exception_port_data;
        std::uint64_t m_exception_port_value;
        std::uint64_t m_exception_port_state : 3;
    };
    ex_fast_ref_t m_token;
    std::uint64_t m_mm_reserved;


    ex_push_lock_t m_address_creation_lock;
    ex_push_lock_t m_page_table_commitment_lock;
    ethread_t* m_rotate_in_progress;
    ethread_t* m_fork_in_progress;
    ejob_t* volatile m_commit_charge_job;


    rtl_avl_tree_t m_clone_root;
    volatile std::uint64_t m_number_of_private_pages;


    volatile std::uint64_t m_number_of_locked_pages;
    void* m_win32_process;
    struct _EJOB* volatile m_job;


    void* m_section_object;
    void* m_section_base_address;
    std::uint32_t m_cookie;


    pagefault_history_t* m_working_set_watch;
    void* m_win32_window_station;


    void* m_inherited_from_unique_process_id;
    volatile std::uint64_t m_owner_process_id;


    peb_t* m_peb;
    mm_session_space_t* m_session;


    void* m_spare1;
    eprocess_quota_block_t* m_quota_block;


    handle_table_t* m_object_table;
    void* m_debug_port;
    ewow64process_t* m_wow64_process;
    void* m_device_map;
    void* m_etw_data_source;


    std::uint64_t m_page_directory_pte;
    file_object_t* m_image_file_pointer;


    std::uint8_t m_image_file_name[ 15 ];
    std::uint8_t m_priority_class;
    void* m_security_port;
    se_audit_process_creation_info_t m_se_audit_process_creation_info;


    list_entry_t m_job_links;
    void* m_highest_user_address;
    list_entry_t m_thread_list_head;


    volatile std::uint32_t m_active_threads;
    std::uint32_t m_image_path_hash;
    std::uint32_t m_default_hard_error_processing;
    std::int32_t m_last_thread_exit_status;


    ex_fast_ref_t m_prefetch_trace;
    void* m_locked_pages_list;


    large_integer_t m_read_operation_count;
    large_integer_t m_write_operation_count;
    large_integer_t m_other_operation_count;
    large_integer_t m_read_transfer_count;
    large_integer_t m_write_transfer_count;
    large_integer_t m_other_transfer_count;


    std::uint64_t m_commit_charge_limit;
    volatile std::uint64_t m_commit_charge;
    volatile std::uint64_t m_commit_charge_peak;


    mmsupport_full_t m_vm;
    list_entry_t m_mm_process_links;


    union {
        ps_interlocked_timer_delay_values_t m_process_timer_delay;
    };
    volatile std::uint32_t m_k_timer_sets;
    volatile std::uint32_t m_k_timer2_sets;
    volatile std::uint32_t m_thread_timer_sets;
    std::uint64_t m_virtual_timer_list_lock;
    list_entry_t m_virtual_timer_list_head;


    union {
        wnf_state_name_t m_wake_channel;
        ps_process_wake_information_t m_wake_info;
    };


    union {
        std::uint32_t m_mitigation_flags;
        struct {
            std::uint32_t m_control_flow_guard_enabled : 1;
            std::uint32_t m_control_flow_guard_export_suppression_enabled : 1;
            std::uint32_t m_control_flow_guard_strict : 1;
            std::uint32_t m_disallow_stripped_images : 1;
            std::uint32_t m_force_relocate_images : 1;
            std::uint32_t m_high_entropy_aslr_enabled : 1;
            std::uint32_t m_stack_randomization_disabled : 1;
            std::uint32_t m_extension_point_disable : 1;
            std::uint32_t m_disable_dynamic_code : 1;
            std::uint32_t m_disable_dynamic_code_allow_opt_out : 1;
            std::uint32_t m_disable_dynamic_code_allow_remote_downgrade : 1;
            std::uint32_t m_audit_disable_dynamic_code : 1;
            std::uint32_t m_disallow_win32k_system_calls : 1;
            std::uint32_t m_audit_disallow_win32k_system_calls : 1;
            std::uint32_t m_enable_filtered_win32k_apis : 1;
            std::uint32_t m_audit_filtered_win32k_apis : 1;
            std::uint32_t m_disable_non_system_fonts : 1;
            std::uint32_t m_audit_non_system_font_loading : 1;
            std::uint32_t m_prefer_system32_images : 1;
            std::uint32_t m_prohibit_remote_image_map : 1;
            std::uint32_t m_audit_prohibit_remote_image_map : 1;
            std::uint32_t m_prohibit_low_il_image_map : 1;
            std::uint32_t m_audit_prohibit_low_il_image_map : 1;
            std::uint32_t m_signature_mitigation_opt_in : 1;
            std::uint32_t m_audit_block_non_microsoft_binaries : 1;
            std::uint32_t m_audit_block_non_microsoft_binaries_allow_store : 1;
            std::uint32_t m_loader_integrity_continuity_enabled : 1;
            std::uint32_t m_audit_loader_integrity_continuity : 1;
            std::uint32_t m_enable_module_tampering_protection : 1;
            std::uint32_t m_enable_module_tampering_protection_no_inherit : 1;
            std::uint32_t m_restrict_indirect_branch_prediction : 1;
            std::uint32_t m_isolate_security_domain : 1;
        } m_mitigation_flags_values;
    };


    union {
        std::uint32_t m_mitigation_flags2;
        struct {
            std::uint32_t m_enable_export_address_filter : 1;
            std::uint32_t m_audit_export_address_filter : 1;
            std::uint32_t m_enable_export_address_filter_plus : 1;
            std::uint32_t m_audit_export_address_filter_plus : 1;
            std::uint32_t m_enable_rop_stack_pivot : 1;
            std::uint32_t m_audit_rop_stack_pivot : 1;
            std::uint32_t m_enable_rop_caller_check : 1;
            std::uint32_t m_audit_rop_caller_check : 1;
            std::uint32_t m_enable_rop_sim_exec : 1;
            std::uint32_t m_audit_rop_sim_exec : 1;
            std::uint32_t m_enable_import_address_filter : 1;
            std::uint32_t m_audit_import_address_filter : 1;
            std::uint32_t m_disable_page_combine : 1;
            std::uint32_t m_speculative_store_bypass_disable : 1;
            std::uint32_t m_cet_user_shadow_stacks : 1;
            std::uint32_t m_audit_cet_user_shadow_stacks : 1;
            std::uint32_t m_audit_cet_user_shadow_stacks_logged : 1;
            std::uint32_t m_user_cet_set_context_ip_validation : 1;
            std::uint32_t m_audit_user_cet_set_context_ip_validation : 1;
            std::uint32_t m_audit_user_cet_set_context_ip_validation_logged : 1;
            std::uint32_t m_cet_user_shadow_stacks_strict_mode : 1;
            std::uint32_t m_block_non_cet_binaries : 1;
            std::uint32_t m_block_non_cet_binaries_non_ehcont : 1;
            std::uint32_t m_audit_block_non_cet_binaries : 1;
            std::uint32_t m_audit_block_non_cet_binaries_logged : 1;
            std::uint32_t m_reserved1 : 1;
            std::uint32_t m_reserved2 : 1;
            std::uint32_t m_reserved3 : 1;
            std::uint32_t m_reserved4 : 1;
            std::uint32_t m_reserved5 : 1;
            std::uint32_t m_cet_dynamic_apis_out_of_proc_only : 1;
            std::uint32_t m_user_cet_set_context_ip_validation_relaxed_mode : 1;
        } m_mitigation_flags2_values;
    };


    void* m_partition_object;
    std::uint64_t m_security_domain;
    std::uint64_t m_parent_security_domain;


    void* m_coverage_sampler_context;
    void* m_mm_hot_patch_context;
    rtl_avl_tree_t m_dynamic_eh_continuation_targets_tree;
    ex_push_lock_t m_dynamic_eh_continuation_targets_lock;
    ps_dynamic_enforced_address_ranges_t m_dynamic_enforced_cet_compatible_ranges;


    std::uint32_t m_disabled_component_flags;
    std::uint32_t* volatile m_path_redirection_hashes;
};

struct teb_t {
    nt_tib_t m_nt_tib;
    std::uint64_t m_environment_pointer;
    client_id_t m_client_id;
    std::uint64_t m_active_rpc_handle;
    std::uint64_t m_thread_local_storage_pointer;
    peb_t* m_process_environment_block;
    std::uint32_t m_last_error_value;
    std::uint32_t m_count_of_owned_critical_sections;
    std::uint64_t m_csr_client_thread;
    std::uint64_t m_win32_thread_info;
    std::uint32_t m_user32_reserved[ 26 ];
    std::uint64_t m_user_reserved[ 5 ];
    std::uint64_t m_wow32_reserved;
    std::uint32_t m_current_locale;
    std::uint32_t m_fp_software_status_register;
    std::uint64_t m_system_reserved1[ 54 ];
    std::int32_t m_exception_code;

    activation_context_stack_t* m_activation_context_stack_pointer;
    std::uint8_t m_spare_bytes[ 24 ];
    std::uint32_t m_tls_slots[ 64 ];
    list_entry_t m_tls_links;
};

struct kthread_t {

    dispatcher_header_t m_header;
    void* m_slist_fault_address;
    std::uint64_t m_quantum_target;
    void* m_initial_stack;
    void* m_stack_limit;
    void* m_stack_base;
    std::uint64_t m_thread_lock;
    std::uint64_t m_cycle_time;
    std::uint32_t m_current_run_time;
    std::uint32_t m_expected_run_time;
    void* m_kernel_stack;
    void* m_state_save_area;
    void* m_scheduling_group;
    kwait_status_register_t m_wait_register;
    std::uint8_t m_running;
    std::uint8_t m_alerted[ 2 ];
    std::uint32_t m_auto_alignment;
    std::uint8_t m_tag;
    std::uint8_t m_system_hetero_cpu_policy;
    std::uint8_t m_spare_byte;
    std::uint32_t m_system_call_number;
    std::uint32_t m_ready_time;
    void* m_first_argument;
    ktrap_frame_t* m_trap_frame;


    kapc_state_t m_apc_state;
    std::uint8_t m_apc_queueable;
    std::uint8_t m_apc_queueable_padding[ 7 ];
    void* m_service_table;
    std::uint32_t m_kernel_reserve_apc;
    std::uint32_t m_kernel_reserve_apc_padding;
    void* m_win32_thread;
    void* m_trap_frame_base;
    std::uint64_t m_wait_status;
    void* m_wait_block_list;
    void* m_queue;
    teb_t* m_teb;
    std::uint64_t m_relative_timer_bias;


    ktimer_t m_timer;
    std::uint32_t m_misc_flags;
    std::uint8_t m_kernel_apc_disable;
    std::uint8_t m_kernel_apc_pending;
    std::uint8_t m_io_pending;
    std::uint8_t m_io_pending_high;


    std::int64_t m_entropy_count;
    std::uint32_t m_permission_key;
    std::uint32_t m_permission_key_non_paged;
    void* m_wait_prcb;
    void* m_wait_next;
    void* m_wait_value;
    void* m_wait_reason;
    std::uint32_t m_wait_irql;
    std::uint8_t m_wait_mode;
    std::uint8_t m_wait_next_flag;
    std::uint8_t m_wait_reason_flag;
    std::uint8_t m_wait_response;
    void* m_wait_pointer;
    std::uint32_t m_thread_flags;
    std::uint32_t m_spare0;
    void* m_wait_block_list2;
    std::uint32_t m_wait_block_count;
    std::uint32_t m_wait_block_offset;
    void* m_wait_blocks;

    list_entry_t m_wait_list_entry;
    std::uint32_t m_wait_status2;
    std::uint32_t m_wait_state_sequence;
    std::uint32_t m_wait_irql_old;
    std::uint32_t m_wait_mode_old;
    std::uint32_t m_wait_queue_timeout;
    std::uint32_t m_wait_block_multiple;
    void* m_thread_queue_list_entry;
    list_entry_t m_queue_list_entry;
    std::uint16_t m_queue_index;
    std::uint32_t m_queue_priority;
    kprocess_t* m_process;
    group_affinity_t m_affinity;
    std::uint64_t m_affinity_version;
    void* m_npx_state;


    void* m_performance_counters;
    void* m_context_switch_count;
    void* m_scheduler_assist_thread;
    void* m_kernel_stack_control;
    void* m_kernel_stack_limit;
    void* m_kernel_stack_base;
    void* m_thread_lock_owner;
    void* m_kernel_wait_always;
    void* m_user_wait_always;
    void* m_win32k_thread;
    void* m_worker_routine;
    void* m_worker_context;
    void* m_win32_start_address;
    void* m_lpaccel;
    void* m_lpfnwndproc;
    void* m_win32k_callback;
    void* m_win32k_callback_context;


    kevent_t m_suspend_event;
    list_entry_t m_thread_list_entry;
    list_entry_t m_mutant_list_head;
    std::uint8_t m_ab_entry_summary;
    std::uint8_t m_ab_wait_entry_count;
    std::uint8_t m_ab_allocation_region_count;
    std::uint8_t m_system_priority;
    std::uint32_t m_secure_thread_cookie;
    void* m_lock_entries;
    single_list_entry_t m_propagate_boosts_entry;
    single_list_entry_t m_io_self_boosts_entry;
    std::uint8_t m_priority_floor_counts[ 16 ];
    std::uint8_t m_priority_floor_counts_reserved[ 16 ];
    std::uint32_t m_priority_floor_summary;
    std::uint32_t m_ab_completed_io_boost_count;
    std::uint32_t m_ab_completed_io_qos_boost_count;
    std::uint16_t m_ke_reference_count;
    std::uint8_t m_ab_orphaned_entry_summary;
    std::uint8_t m_ab_owned_entry_count;
    std::uint32_t m_foreground_loss_time;
    std::uint64_t m_read_operation_count;
    std::uint64_t m_write_operation_count;
    std::uint64_t m_other_operation_count;
    std::uint64_t m_read_transfer_count;
    std::uint64_t m_write_transfer_count;
    std::uint64_t m_other_transfer_count;
    void* m_queued_scb;
    std::uint32_t m_thread_timer_delay;
    void* m_tracing_private;
    void* m_scheduler_assist;
    void* m_ab_wait_object;
    std::uint32_t m_reserved_previous_ready_time_value;
    std::uint64_t m_kernel_wait_time;
    std::uint64_t m_user_wait_time;
    void* m_explicit_scheduling;
    void* m_debug_active;
    std::uint32_t m_scheduler_assist_priority_floor;
    std::uint32_t m_spare28;
    std::uint8_t m_resource_index;
    std::uint8_t m_spare31[ 3 ];
    std::uint64_t m_end_padding[ 4 ];
};

struct ethread_t {
    struct kthread_t m_kthread;
    list_entry_t m_thread_list_entry;
    void* m_create_time;
    union {
        void* m_exit_time;
        list_entry_t m_active_execution_list;
    };
    union {
        void* m_exit_status;
        void* m_post_block_old;
    };
    union {
        void* m_terminate_apc;
        void* m_terminate_pending;
    };
    union {
        void* m_thread_flags;
        union {
            std::uint32_t m_thread_flags_value;
            struct {
                std::uint32_t m_terminate_requested : 1;
                std::uint32_t m_dead_thread : 1;
                std::uint32_t m_hide_from_debugger : 1;
                std::uint32_t m_active_impersonation_info : 1;
                std::uint32_t m_system_thread : 1;
                std::uint32_t m_hard_errors_are_disabled : 1;
                std::uint32_t m_break_on_termination : 1;
                std::uint32_t m_skip_creation_msg : 1;
                std::uint32_t m_skip_termination_msg : 1;
            };
        };
        std::uint32_t m_padding;
    };
    union {
        void* m_create_info;
        void* m_win32_start_address;
    };
    void* m_teb;
    client_id_t m_client_id;
    void* m_security_port;
    void* m_previous_mode;
    void* m_resource_index;
    void* m_large_stack;
    void* m_fx_save_area;
    void* m_priority_class;
    void* m_desktop;
    void* m_suspend_semaphore;
    union {
        void* m_win32_thread;
        struct {
            std::uint32_t m_io_priority : 3;
            std::uint32_t m_memory_priority : 3;
            std::uint32_t m_absolute_cpu_priority : 1;
        };
    };
    void* m_working_on_behalf_ticket;
    void* m_impersonation_info;
    void* m_io_pending_mr;
    void* m_io_suppress_thread;
    void* m_memory_attribute;
    union {
        void* m_win32_thread_event;
        void* m_running_down;
    };
    void* m_thread_lock;
    std::uint32_t m_read_operation_count;
    std::uint32_t m_write_operation_count;
    std::uint32_t m_other_operation_count;
    std::uint32_t m_io_priority_boost;
    void* m_io_client_pointer;
    void* m_file_object;
    void* m_word_list_head;
    void* m_process_context;
    void* m_granted_access;
    void* m_cross_thread_flags;
    union {
        std::uint32_t m_cross_thread_flags_uint;
        struct {
            std::uint32_t m_terminated : 1;
            std::uint32_t m_debug_active : 1;
            std::uint32_t m_system_process : 1;
            std::uint32_t m_impersonating : 1;
            std::uint32_t m_break_on_termination : 1;
            std::uint32_t m_reserved : 27;
        };
    };
    std::uint32_t m_cross_thread_flags_padding;
    void* m_start_address;
    void* m_win32_thread_info;
    void* m_lpaccel;
    void* m_lpfnwndproc;
    void* m_win32k;
};

typedef struct hash_bucket_entry_t {
    struct hash_bucket_entry_t* m_next;
    unicode_string_t m_driver_name;
    std::uint32_t m_cert_mash[ 5 ];
};

struct balanced_links_t {
    void* m_parent;
    void* m_left;
    void* m_right;
    std::uint8_t m_balance;
    std::uint8_t m_reserved[ 3 ];
    std::uint32_t m_pad;
};

struct pool_tracker_big_pages_t {
    volatile std::uint64_t m_va;
    std::uint32_t m_key;
    std::uint32_t m_pattern : 8;
    std::uint32_t m_pool_type : 12;
    std::uint32_t m_slush_size : 12;
    std::uint64_t m_number_of_bytes;
};

struct avl_table_t {
    balanced_links_t m_balanced_root;
    void* m_ordered_pointer;
    std::uint32_t m_which_ordered_element;
    std::uint32_t m_number_generic_table_elements;
    std::uint32_t m_depth_of_tree;
    std::uint32_t m_pad1;
    void* m_restart_key;
    std::uint32_t m_delete_count;
    std::uint32_t m_pad2;
    void* m_compare_routine;
    void* m_allocate_routine;
    void* m_free_routine;
    void* m_table_context;
};

struct ldr_data_table_entry_t {
    list_entry_t m_in_load_order_module_list;
    list_entry_t m_in_memory_order_module_list;
    list_entry_t m_in_initialization_order_module_list;
    void* m_dll_base;
    void* m_entry_point;
    std::uint32_t m_size_of_image;
    unicode_string_t m_full_dll_name;
    unicode_string_t m_base_dll_name;
    std::uint32_t m_flags;
    std::uint16_t m_load_count;
    std::uint16_t m_tls_index;
    list_entry_t m_hash_links;
    void* m_section_pointer;
    std::uint32_t m_check_sum;
    std::uint32_t m_time_date_stamp;
};

struct kldr_data_table_entry_t {
    list_entry_t m_in_load_order_links;
    void* m_exception_table;
    std::uint32_t m_exception_table_size;
    void* m_gp_value;
    void* m_non_paged_debug_info;
    void* m_dll_base;
    void* m_entry_point;
    std::uint32_t m_size_of_image;
    unicode_string_t m_full_dll_name;
    unicode_string_t m_base_dll_name;
    std::uint32_t m_flags;
    std::uint16_t m_load_count;
    union {
        struct {
            std::uint16_t m_signature_level : 4;
            std::uint16_t m_signature_type : 3;
            std::uint16_t m_frozen : 2;
            std::uint16_t m_hot_patch : 1;
            std::uint16_t m_unused : 6;
        };
        std::uint16_t m_entire_field;
    } u1;
    void* m_section_pointer;
    std::uint32_t m_check_sum;
    std::uint32_t m_coverage_section_size;
    void* m_coverage_section;
    void* m_loaded_imports;
    union {
        void* m_spare;
        kldr_data_table_entry_t* m_nt_data_table_entry;
    };
    std::uint32_t m_size_of_image_not_rounded;
    std::uint32_t m_time_date_stamp;
};

struct apic_icr {
    union {
        std::uint64_t m_raw;
        struct {
            std::uint32_t m_vector : 8;
            std::uint32_t m_delivery_mode : 3;
            std::uint32_t m_destination_mode : 1;
            std::uint32_t m_delivery_status : 1;
            std::uint32_t m_reserved1 : 1;
            std::uint32_t m_level : 1;
            std::uint32_t m_trigger_mode : 1;
            std::uint32_t m_reserved2 : 2;
            std::uint32_t m_destination_shorthand : 2;
            std::uint32_t m_reserved3 : 12;

            std::uint32_t m_reserved4 : 24;
            std::uint32_t m_destination : 8;
        } m_fields;
    };
};

struct idt_entry_t {
    std::uint16_t m_offset_low;
    std::uint16_t m_selector;
    std::uint8_t m_ist;
    std::uint8_t m_attributes;
    std::uint16_t m_offset_middle;
    std::uint32_t m_offset_high;
    std::uint32_t m_reserved;
};

struct physical_address_t {
    union {
        struct {
            std::uint32_t m_low_part;
            std::int32_t m_high_part;
        };
        struct {
            std::uint64_t m_quad_part;
        };
    };
};

struct mm_copy_address_t {
    union {
        std::uint64_t m_virtual_address;
        physical_address_t m_physical_address;
    };
};

struct eresource_t {
    struct {
        void* m_flink;
        void* m_blink;
    } m_system_resource_list;

    void* m_owner_table;
    std::uint16_t m_active_count;
    union {
        std::uint16_t m_flag;
        struct {
            std::uint8_t m_shared_wait_count;
            std::uint8_t m_exclusive_wait_count;
        };
    };
    std::uint32_t m_pad1;

    void* m_shared_waiters;
    void* m_exclusive_waiters;

    struct {
        void* m_owner_thread;
        void* m_owner_count;
    } m_owner_entry;

    std::uint32_t m_active_entries;
    std::uint32_t m_contention_count;
    std::uint32_t m_shared_waiter_count;
    std::uint32_t m_exclusive_waiter_count;

    std::uint8_t m_misc_flags;
    std::uint8_t m_reserved[ 3 ];
    std::uint32_t m_timeout_count;

    union {
        void* m_descriptor;
        std::uint32_t m_converted_type;
    };

    std::uint64_t m_spin_lock;
};

struct piddb_cache_entry_t {
    list_entry_t m_list;
    unicode_string_t m_driver_name;
    std::uint32_t m_timestamp;
    std::int32_t m_load_status;
    std::uint8_t m_shim_data[ 16 ];
};

struct rtl_critical_section_t {
    void* m_debug_info;
    std::int32_t m_lock_count;
    std::int32_t m_recursion_count;
    void* m_owning_thread;
    void* m_lock_semaphore;
    std::uint32_t m_spin_count;
};

struct peb_ldr_data_t {
    std::uint32_t m_length;
    bool m_initialized;
    void* m_ss_handle;
    list_entry_t m_module_list_load_order;
    list_entry_t m_module_list_memory_order;
    list_entry_t m_module_list_in_it_order;
};

struct peb_t {
    std::uint8_t m_inherited_address_space;
    std::uint8_t m_read_image_file_exec_options;
    std::uint8_t m_being_debugged;
    std::uint8_t m_bit_field;

    struct {
        std::uint32_t m_image_uses_large_pages : 1;
        std::uint32_t m_is_protected_process : 1;
        std::uint32_t m_is_legacy_process : 1;
        std::uint32_t m_is_image_dynamically_relocated : 1;
        std::uint32_t m_spare_bits : 4;
    };

    void* m_mutant;
    void* m_image_base_address;
    peb_ldr_data_t* m_ldr;
    void* m_process_parameters;
    void* m_subsystem_data;
    void* m_process_heap;
    rtl_critical_section_t* m_fast_peb_lock;
    void* m_atl_thunk_slist_ptr;
    void* m_ifeo_key;

    struct {
        std::uint32_t m_process_in_job : 1;
        std::uint32_t m_process_initializing : 1;
        std::uint32_t m_reserved_bits0 : 30;
    } m_cross_process_flags;

    union {
        void* m_kernel_callback_table;
        void* m_user_shared_info_ptr;
    };

    std::uint32_t m_system_reserved[ 1 ];
    std::uint32_t m_spare_ulong;
    void* m_free_list;
    std::uint32_t m_tls_expansion_counter;
    void* m_tls_bitmap;
    std::uint32_t m_tls_bitmap_bits[ 2 ];
    void* m_read_only_shared_memory_base;
    void* m_hotpatch_information;
    void** m_read_only_static_server_data;
    void* m_ansi_code_page_data;
    void* m_oem_code_page_data;
    void* m_unicode_case_table_data;
    std::uint32_t m_number_of_processors;
    std::uint32_t m_nt_global_flag;
    std::int64_t m_critical_section_timeout;
    std::uint32_t m_heap_segment_reserve;
    std::uint32_t m_heap_segment_commit;
    std::uint32_t m_heap_decomit_total_free_threshold;
    std::uint32_t m_heap_decomit_free_block_threshold;
    std::uint32_t m_number_of_heaps;
    std::uint32_t m_maximum_number_of_heaps;
    void** m_process_heaps;
    void* m_gdi_shared_handle_table;
    void* m_process_starter_helper;
    std::uint32_t m_gdi_dc_attribute_list;
    rtl_critical_section_t* m_loader_lock;
    std::uint32_t m_os_major_version;
    std::uint32_t m_os_minor_version;
    std::uint16_t m_os_build_number;
    std::uint16_t m_os_csd_version;
    std::uint32_t m_os_platform_id;
    std::uint32_t m_image_subsystem;
    std::uint32_t m_image_subsystem_major_version;
    std::uint32_t m_image_subsystem_minor_version;
    std::uint32_t m_image_process_affinity_mask;
    std::uint32_t m_gdi_handle_buffer[ 34 ];
    void* m_post_process_init_routine;
    void* m_tls_expansion_bitmap;
    std::uint32_t m_tls_expansion_bitmap_bits[ 32 ];
    std::uint32_t m_session_id;
    std::uint64_t m_app_compat_flags;
    std::uint64_t m_app_compat_flags_user;
    void* m_p_shim_data;
    void* m_app_compat_info;
    unicode_string_t m_csd_version;
    void* m_activation_context_data;
    void* m_process_assembly_storage_map;
    void* m_system_default_activation_context_data;
    void* m_system_assembly_storage_map;
    std::uint32_t m_minimum_stack_commit;
    void* m_fls_callback;
    list_entry_t m_fls_list_head;
    void* m_fls_bitmap;
    std::uint32_t m_fls_bitmap_bits[ 4 ];
    std::uint32_t m_fls_high_index;
    void* m_wer_registration_data;
    void* m_wer_ship_assert_ptr;
    void* m_context_data;
    void* m_image_header_hash;
    union {
        ULONG m_tracking_flags;
        struct {
            ULONG m_heap_tracking_enabled : 1;
            ULONG m_crit_sec_tracking_enabled : 1;
            ULONG m_lib_loader_tracking_enabled : 1;
            ULONG m_spare_tracking_enabled : 29;
        };
    };
    ULONGLONG m_csr_server_read_only_shared_memory_base;
    void* m_tpp_worker_list;
    void* m_api_set_map;
};

struct mmpfnentry1_t {
    std::uint8_t m_page_location : 3;
    std::uint8_t m_write_in_progress : 1;
    std::uint8_t m_modified : 1;
    std::uint8_t m_read_in_progress : 1;
    std::uint8_t m_cache_attribute : 2;
};

struct mmpfnentry3_t {
    std::uint8_t m_priority : 1;
    std::uint8_t m_on_protected_standby : 1;
    std::uint8_t m_in_page_error : 1;
    std::uint8_t m_system_charged_page : 1;
    std::uint8_t m_removal_requested : 1;
    std::uint8_t m_rarity_error : 1;
};

struct mi_pfn_ulong5_t {
    union {
        struct {
            std::uint32_t m_modified_write_count : 16;
            std::uint32_t m_shared_count : 16;
        };
        std::uint32_t m_entire_field;
    };
};

struct mipfnblink_t {
    union {
        struct {
            std::uint64_t m_blink : 36;
            std::uint64_t m_node_blink_high : 20;
            std::uint64_t m_tb_flush_stamp : 4;
            std::uint64_t m_unused : 2;
            std::uint64_t m_sage_blink_delete_bit : 1;
            std::uint64_t m_page_blink_lock_bit : 1;
            std::uint64_t m_share_count : 62;
            std::uint64_t m_page_share_count_delete_bit : 1;
            std::uint64_t m_page_share_count_lock_bit : 1;
        };

        std::uint64_t m_entire_field;
        volatile std::uint64_t m_lock;
        struct {
            std::uint64_t m_lock_not_used : 62;
            std::uint64_t m_delete_bit : 1;
            std::uint64_t m_lock_bit : 1;
        };
    };
};

struct rtl_balanced_node_t {
    union {
        rtl_balanced_node_t* m_children[ 2 ];
        struct {
            rtl_balanced_node_t* m_left;
            rtl_balanced_node_t* m_right;
        };
    };
    union {
        std::uint8_t m_red : 1;
        rtl_balanced_node_t* m_parent;
        std::uint64_t m_value;
    };
};

struct mi_active_pfn_t {
    union {
        struct {
            std::uint64_t m_tradable : 1;
            std::uint64_t m_non_paged_buddy : 43;
        } m_leaf;
        struct {
            std::uint64_t m_tradable : 1;
            std::uint64_t m_wsle_sge : 3;
            std::uint64_t m_oldest_wsle_leaf_entries : 10;
            std::uint64_t m_oldest_wsle_leaf_age : 3;
            std::uint64_t m_non_paged_buddy : 43;
        } m_page_table;
        std::uint64_t m_entire_active_field;
    };
};

struct mmpte_hardware_t {
    std::uint64_t m_valid : 1;
    std::uint64_t m_write : 1;
    std::uint64_t m_owner : 1;
    std::uint64_t m_write_through : 1;
    std::uint64_t m_cache_disable : 1;
    std::uint64_t m_accessed : 1;
    std::uint64_t m_dirty : 1;
    std::uint64_t m_large_page : 1;
    std::uint64_t m_global : 1;
    std::uint64_t m_copy_on_write : 1;
    std::uint64_t m_prototype : 1;
    std::uint64_t m_reserved0 : 1;
    std::uint64_t m_page_frame_number : 36;
    std::uint64_t m_reserved1 : 4;
    std::uint64_t m_software_ws_index : 11;
    std::uint64_t m_no_execute : 1;
};

struct mmpte_t {
    union {
        std::uint64_t m_long;
        volatile std::uint64_t m_volatile_long;
        struct mmpte_hardware_t m_hard;






    };
};

struct mmpfn_t {
    union {
        list_entry_t m_list_entry;
        rtl_balanced_node_t m_tree_node;
        struct {
            union {
                union {
                    single_list_entry_t m_next_slist_pfn;
                    void* m_next;
                    std::uint64_t m_flink : 38;
                    std::uint64_t m_node_flink_low : 28;
                    mi_active_pfn_t m_active;
                } m_u1;

                union {
                    mmpte_t* m_pte_address;
                    std::uint64_t m_pte_long;
                };

                mmpte_t m_original_pte;
            };
        };
    };

    mipfnblink_t m_u2;

    union {
        struct {
            std::uint16_t m_reference_count;
            mmpfnentry1_t m_e1;
        };
        struct {
            mmpfnentry3_t m_e3;
            struct {
                std::uint16_t m_reference_count;
            } m_e2;
        };
        struct {
            std::uint16_t m_reference_count;
            mmpfnentry1_t m_e1;
        } m_e4;
    } m_u3;

    std::uint16_t m_node_blink_low;
    std::uint16_t m_unused : 4;
    std::uint16_t m_unused2 : 4;

    union {
        std::uint16_t m_view_count;
        std::uint16_t m_node_flink_low;

        struct {
            std::uint16_t m_modified_list_bucket_index : 4;
            std::uint16_t m_anchor_large_page_size : 2;
        } m_e2;
    };

    mi_pfn_ulong5_t m_u5;

    union {
        std::uint64_t m_pte_frame : 36;
        std::uint64_t m_resident_page : 1;
        std::uint64_t m_unused1 : 1;
        std::uint64_t m_unused2 : 1;
        std::uint64_t m_partition : 10;
        std::uint64_t m_file_only : 1;
        std::uint64_t m_pfn_exists : 1;
        std::uint64_t m_node_flink_high : 5;
        std::uint64_t m_page_identity : 3;
        std::uint64_t m_prototype_pte : 1;
        std::uint64_t m_entire_field;
    } m_u4;
};

struct physical_memory_range_t {
    large_integer_t m_base_page;
    large_integer_t m_page_count;
};

struct system_handle_table_entry_info_t {
    void* m_object;
    HANDLE m_unique_process_id;
    HANDLE m_handle_value;
    std::uint32_t m_granted_access;
    std::uint8_t m_creator_back_trace_index;
    std::uint8_t m_object_type_index;
    std::uint64_t m_handle_attributes;
    std::uint64_t m_reserved;
};

struct system_handle_information_t {
    std::uint64_t m_number_of_handles;
    std::uint64_t m_reserved;
    system_handle_table_entry_info_t m_handles[ 1 ];
};

typedef struct {

    std::uint16_t machine, number_of_sections;
    std::uint32_t time_stamp;
    std::uint32_t symbol_table, number_of_symbols;
    std::uint16_t optional_head_sz, characts;

} nt_image_file_head_t;

typedef struct {

    std::uint8_t name[ 8 ];

    union {

        std::uint32_t physical;
        std::uint32_t size;

    } misc;

    std::uint32_t va;
    std::uint32_t raw_size, raw_data;
    std::uint32_t relocs_data;
    std::uint32_t linenumbers;
    std::uint16_t relocs_cnt;
    std::uint16_t linenumbers_cnt;
    std::uint32_t characts;

} nt_image_section_head_t;

typedef struct {

    std::uint32_t va, size;

} nt_image_data_dir_t;

typedef struct {

    std::uint16_t	magic;
    std::uint8_t     major_linker_ver;
    std::uint8_t     minor_linker_ver;
    std::uint32_t    size_of_code;
    std::uint32_t    size_of_init_data;
    std::uint32_t    size_of_uninit_data;
    std::uint32_t    entry_point;
    std::uint32_t    base_of_code;
    std::uint64_t    image_base;
    std::uint32_t    section_align;
    std::uint32_t    file_align;
    std::uint16_t    major_os_ver;
    std::uint16_t    minor_os_ver;
    std::uint16_t    major_image_ver;
    std::uint16_t    minor_image_ver;
    std::uint16_t    major_subsystem_ver;
    std::uint16_t    minor_subsystem_ver;
    std::uint32_t    win32_ver;
    std::uint32_t    size_of_image;
    std::uint32_t    size_of_headers;
    std::uint32_t    checksum;
    std::uint16_t    subsystem;
    std::uint16_t    dll_characts;
    std::uint64_t    size_of_stack_reserve;
    std::uint64_t    size_of_stack_commit;
    std::uint64_t    size_of_heap_reserve;
    std::uint64_t    size_of_heap_commit;
    std::uint32_t    loader_flags;
    std::uint32_t    number_of_rva_and_sizes;

    nt_image_data_dir_t data_directory[ image_dir_entries ];

} nt_image_optional_head_t;

typedef struct {

    std::uint16_t magic;
    std::uint16_t last_page_bytes;
    std::uint16_t pages_cnt;
    std::uint16_t relocs;
    std::uint16_t header_sz;
    std::uint16_t min_alloc;
    std::uint16_t max_alloc;
    std::uint16_t ss;
    std::uint16_t sp;
    std::uint16_t checksum;
    std::uint16_t ip;
    std::uint16_t cs;
    std::uint16_t lfarlc;
    std::uint16_t overlays;
    std::uint16_t reserved[ 4 ];
    std::uint16_t oem_id;
    std::uint16_t oem_info;
    std::uint16_t reserved2[ 10 ];
    std::int32_t  lfanew;

} nt_image_dos_head_t;

typedef struct {

    std::uint32_t characts;
    std::uint32_t time_stamp_date;
    std::uint16_t major_ver;
    std::uint16_t minor_ver;
    std::uint32_t name;
    std::uint32_t base;
    std::uint32_t funcs_num;
    std::uint32_t names_num;
    std::uint32_t funcs_addr;
    std::uint32_t names_addr;
    std::uint32_t ordinals_addr;

} nt_image_export_dir_t;

typedef struct {

    union {

        std::uint32_t characts;
        std::uint32_t original;

    } thunk;

    std::uint32_t time_date_stamp;
    std::uint32_t chain;
    std::uint32_t name;
    std::uint32_t first_thunk;

} nt_image_import_desc_t;

typedef struct {

    union {
        std::uint64_t forwarder_string;
        std::uint64_t function;
        std::uint64_t ordinal;
        std::uint64_t address_of_data;
    } u1;

} nt_image_thunk_data_t;

typedef struct {

    std::uint16_t	hint;
    char		name[ 1 ];

} nt_image_import_name_t;

typedef struct {

    std::uint32_t					signature;
    nt_image_file_head_t		file;
    nt_image_optional_head_t	optional;

} nt_image_headers_t;

typedef struct {

    std::uint32_t va, size;

} nt_image_base_reloc_t;

struct rtl_avl_tree_node_t {
    void* left;
    void* right;
    void* parent_and_balance;
};

struct clone_descriptor_t {
    rtl_avl_tree_node_t node;
    std::uint64_t reserved1;
    std::uint64_t generation;
    std::uint64_t count;
    std::uint64_t* data;
    std::uint64_t size;
    std::uint64_t reserved2[ 5 ];
};