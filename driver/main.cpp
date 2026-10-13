// ============================================================================
// main.cpp -- NexusSpooferDrv entry point + spoof stage glue.
//
// Entry contract: mapper.exe maps this image into an ntoskrnl code cave,
// resolves its imports, writes a kernel::entry_t (Mm*/PFN symbols, EPROCESS
// into an ntoskrnl code cave, resolves its imports, writes a
// kernel::entry_t (Mm*/PFN symbols, EPROCESS offsets, image base/size,
// ntoskrnl base, WNF state name lo/hi) into an MmAllocateIndependentPages
// block and calls entry_point via a hijacked syscall. Any drift here means
// the image maps and instantly dies, so this stays a byte-for-byte port of
// the proven consumer side.
// ============================================================================

#include <impl/includes.h>

// single-TU layout: the copied kernel infra (workspace/kernel + client) is
// header-only with non-inline definitions, so exactly ONE translation unit
// may include impl/includes.h. the spoof modules are implementation files
// included here (impl/includes.h is pragma-once, so their own include lines
// are inert in this TU) -- do NOT add them to ClCompile in driver.vcxproj.
#include <smbios_spoofer.cpp>
#include <mac_spoofer.cpp>
#include <disk_spoofer.cpp>
#include <edid_spoofer.cpp>
#include <acpi_spoofer.cpp>

std::uint32_t offsets::active_process_links;
std::uint32_t offsets::kprocess_directory_table_base;
std::uint32_t offsets::unique_process_id;
std::uint32_t offsets::active_threads;
std::uint32_t offsets::mmpfn_size;
std::uint32_t offsets::mmpfn_pte_address;

bool spoof::install( ) {
	// one-shot HWID spoof: all stages run on the dispatcher's PASSIVE_LEVEL
	// system thread. every stage is individually best-effort -- a stage
	// failing (or finding nothing to patch) must never fail the others, and
	// the overall op only fails if NOTHING could be patched at all.
	spoof::rand_seed( );
	// per-install identity nonce: drawn ONCE here, mixed into every
	// deterministic string transform (see smbios randomize_*). repeated reads
	// of the same identifier inside this boot agree across every copy (raw
	// firmware table, mssmbios cache, HARDWARE\DESCRIPTION\System\BIOS);
	// every fresh install draws a fresh identity. never zero, so a missed
	// init can never silently zero the seed.
	spoof::s_boot_nonce = spoof::rand_next( );
	if ( !spoof::s_boot_nonce )
		spoof::s_boot_nonce = 0x6d2b79f5u;

	std::uint32_t stages_ok = 0;
	if ( spoof::smbios::install( ) )
		++stages_ok;
	if ( spoof::mac::install( ) )
		++stages_ok;
	if ( spoof::disk::install( ) )
		++stages_ok;
	// the edid + acpi stages come after the table patches: each is fully
	// self-latched + self-validated, and neither can fail the others
	if ( spoof::edid::install( ) )
		++stages_ok;
	if ( spoof::acpi::install( ) )
		++stages_ok;

	return stages_ok != 0;
}

// unmangled: the mapper locates this via the PE AddressOfEntryPoint and
// the linker /ENTRY:entry_point must resolve to exactly this symbol.
extern "C" bool entry_point( kernel::entry_t* entry ) {
	if ( !entry )
		return false;

	entry->m_status = kernel::entry_ok;
	KDBG( oxorany( "[sp] entry begin base=%p size=0x%llx\n" ),
		reinterpret_cast< void* >( entry->m_image_base ),
		static_cast< unsigned long long >( entry->m_image_size ) );

	auto fail = [ entry ]( std::uint64_t code ) -> bool {
		entry->m_status = code;
		KDBG( oxorany( "[sp] entry FAIL stage=%llu\n" ),
			static_cast< unsigned long long >( code ) );
		return false;
	};

	std::memcpy(
		&kernel::m_pdb,
		&entry->m_pdb,
		sizeof( kernel::m_pdb )
	);

	offsets::active_process_links          = static_cast< std::uint32_t >( entry->m_offsets.m_eprocess_active_process_links );
	offsets::kprocess_directory_table_base = static_cast< std::uint32_t >( entry->m_offsets.m_kprocess_directory_table_base );
	offsets::unique_process_id             = static_cast< std::uint32_t >( entry->m_offsets.m_eprocess_unique_process_id );
	offsets::active_threads                = static_cast< std::uint32_t >( entry->m_offsets.m_eprocess_active_threads );
	offsets::mmpfn_size                    = static_cast< std::uint32_t >( entry->m_offsets.m_mmpfn_size );
	offsets::mmpfn_pte_address             = static_cast< std::uint32_t >( entry->m_offsets.m_mmpfn_pte_address );

	if ( !offsets::kprocess_directory_table_base
		|| !offsets::active_process_links
		|| !offsets::unique_process_id
		|| !offsets::active_threads
		|| !offsets::mmpfn_size
		|| !offsets::mmpfn_pte_address ) {
		return fail( kernel::entry_offsets );
	}

	client::control::m_wnf_state_name_lo = static_cast< std::uint32_t >( entry->m_wnf_state_name_lo );
	client::control::m_wnf_state_name_hi = static_cast< std::uint32_t >( entry->m_wnf_state_name_hi );
	if ( !client::control::m_wnf_state_name_lo || !client::control::m_wnf_state_name_hi ) {
		return fail( kernel::entry_wnf_subscribe );
	}
	KDBG( oxorany( "[sp] offsets ok uid=0x%x ath=0x%x dtb=0x%x\n" ),
		offsets::unique_process_id, offsets::active_threads,
		offsets::kprocess_directory_table_base );

	if ( !entry->m_pdb.m_mm_allocate_independent_pages
		|| !entry->m_pdb.m_mm_free_independent_pages
		|| !entry->m_pdb.m_mm_pfn_database ) {
		return fail( kernel::entry_mm_symbols );
	}

	kernel::m_ntoskrnl_base = entry->m_ntoskrnl_base;
	if ( !kernel::m_ntoskrnl_base )
		kernel::m_ntoskrnl_base = kernel::get_ntoskrnl_base( );
	if ( !kernel::m_ntoskrnl_base )
		return fail( kernel::entry_ntos_base );

	if ( !entry->m_image_base || !entry->m_image_size )
		return fail( kernel::entry_image );

	auto system_process = kernel::ps_initial_system_process( );
	if ( !system_process )
		return fail( kernel::entry_system_process );

	paging::m_system_directory_table_base = *reinterpret_cast< std::uint64_t* >(
		reinterpret_cast< std::uint64_t >( system_process ) + offsets::kprocess_directory_table_base );
	if ( !paging::m_system_directory_table_base )
		return fail( kernel::entry_system_dtb );
	KDBG( oxorany( "[sp] system cr3=0x%llx\n" ),
		static_cast< unsigned long long >( paging::m_system_directory_table_base ) );

	phys::init_mask( );
	if ( !phys::init_ranges( ) )
		return fail( kernel::entry_phys_ranges );

	paging::swap_context( paging::m_system_directory_table_base );
	if ( !paging::dpm::initialize( ) )
		return fail( kernel::entry_dpm );

	if ( !paging::pfn_cr3::init_pfn_cr3( ) )
		return fail( kernel::entry_pfn_cr3 );

	if ( !hide::hide_pages( entry->m_image_base, entry->m_image_size ) )
		return fail( kernel::entry_hide_pages );

	if ( !client::callback::create( ) ) {
		entry->m_status = client::callback::g_last_create_fail
			? client::callback::g_last_create_fail
			: kernel::entry_wnf_subscribe;
		KDBG( oxorany( "[sp] wnf subscribe FAIL\n" ) );
		return false;
	}
	KDBG( oxorany( "[sp] wnf subscribe ok\n" ) );

	void* thread_handle = nullptr;
	const auto thread_status = kernel::create_system_thread(
		&thread_handle,
		reinterpret_cast< pkstart_routine >( client::thread::communication_handler ),
		nullptr
	);

	if ( thread_status ) {
		if ( client::m_wnf_subscription ) {
			( void )kernel::ex_unsubscribe_wnf_state_change( client::m_wnf_subscription );
			client::m_wnf_subscription = nullptr;
		}
		entry->m_status = kernel::entry_system_thread;
		KDBG( oxorany( "[sp] system thread FAIL status=0x%x\n" ),
			static_cast< unsigned >( thread_status ) );
		return false;
	}

	( void )thread_handle;
	KDBG( oxorany( "[sp] entry ok\n" ) );

	entry->m_status = kernel::entry_ok;
	return true;
}