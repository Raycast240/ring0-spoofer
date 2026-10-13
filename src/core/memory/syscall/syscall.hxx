#pragma once
#include <shared_mutex>

namespace syscall {
    static std::shared_mutex s_lock{};
    static std::uint64_t     s_ssdt_base   = 0;
    static std::uint64_t     s_entry_va    = 0;
    static std::uint64_t     s_entry_pa    = 0;
    static std::uint32_t     s_saved_entry = 0;

    inline bool setup() {
        const auto ke_service_descriptor_table =
            pdb::get_symbol_address( oxorany( "KeServiceDescriptorTable" ) );
        if ( !ke_service_descriptor_table ) {
            logging::print( "failed to resolve KeServiceDescriptorTable" );
            return false;
        }

        std::uint64_t ssdt_data[4]{};
        if ( !paging::read_virtual_memory( ke_service_descriptor_table, ssdt_data, sizeof( ssdt_data ) ) ) {
            logging::print( "failed to read KeServiceDescriptorTable" );
            return false;
        }

        s_ssdt_base      = ssdt_data[0];
        const auto count = ssdt_data[2];
        logging::print( "syscall base: 0x%llx (count=%llu)", s_ssdt_base, count );

        std::vector<std::uint32_t> table( static_cast<std::size_t>( count ) );
        if ( !paging::read_virtual_memory( s_ssdt_base, table.data(), count * sizeof( std::uint32_t ) ) ) {
            logging::print( "failed to read SSDT table" );
            return false;
        }

        const auto nt_device_ioctl =
            pdb::get_symbol_address( oxorany( "NtDeviceIoControlFile" ) );

        // primary: the syscall INDEX comes from the usermode ntdll stub  -
        // "mov r10,rcx ; mov eax,<index>" - the same index the OS itself
        // dispatches on. ntdll and the kernel are built from one syscall
        // table, so the index cannot drift across updates. locating the
        // entry by ADDRESS (the fallback below) broke on 26200.9445, where
        // the PDB symbol stopped matching the SSDT entry's implied target.
        auto* nt_fn = reinterpret_cast<const std::uint8_t*>(
            GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtDeviceIoControlFile" ) );
        if ( nt_fn ) {
            std::uint32_t idx      = 0;
            bool          have_idx = false;
            for ( std::size_t i = 0; i + 8 <= 32; ++i ) {
                // strict: mov r10,rcx ; mov eax,imm32
                if ( nt_fn[i] == 0x4C && nt_fn[i+1] == 0x8B && nt_fn[i+2] == 0xD1 &&
                     nt_fn[i+3] == 0xB8 ) {
                    idx = *reinterpret_cast<const std::uint32_t*>( nt_fn + i + 4 );
                    have_idx = true;
                    break;
                }
                // relaxed: mov eax,imm32 with a syscall soon after
                // (instrumented stub shapes)
                if ( nt_fn[i] == 0xB8 ) {
                    const std::uint32_t cand =
                        *reinterpret_cast<const std::uint32_t*>( nt_fn + i + 1 );
                    for ( std::size_t j = i + 5; j + 1 < 32 && j < i + 13; ++j ) {
                        if ( nt_fn[j] == 0x0F && nt_fn[j+1] == 0x05 ) {
                            idx = cand;
                            have_idx = true;
                            break;
                        }
                    }
                    if ( have_idx ) break;
                }
            }
            if ( !have_idx ) {
                logging::print( "no mov eax,<index> in the ntdll NtDeviceIoControlFile stub" );
            } else if ( idx >= count ) {
                logging::print( "ntdll stub index %u out of range (count=%llu)", idx, count );
            } else {
                s_saved_entry = table[ idx ];
                s_entry_va    = s_ssdt_base + idx * sizeof( std::uint32_t );
                s_entry_pa    = paging::translate_linear( s_entry_va );
                if ( s_entry_pa ) {
                    // soft cross-check only: the entry implies a kernel
                    // function address; if the PDB symbol is available and
                    // disagrees, log it - the index is authoritative, the
                    // symbol identity is what 9445 broke
                    const auto implied = s_ssdt_base + ( s_saved_entry >> 4 );
                    if ( nt_device_ioctl && implied != nt_device_ioctl )
                        logging::print( "syscall entry: idx=%u entry=0x%08x (PDB symbol 0x%llx vs implied 0x%llx - index is authoritative)",
                                        idx, s_saved_entry, nt_device_ioctl, implied );
                    else
                        logging::print( "syscall entry: idx=%u entry=0x%08x", idx, s_saved_entry );
                }
            }
        }

        // fallback: the classic address scan - kept for builds where the
        // stub cannot be parsed but the symbol identity still holds
        if ( !s_entry_pa && nt_device_ioctl ) {
            const auto target_rva = static_cast<int>( nt_device_ioctl - s_ssdt_base ) << 4;
            for ( std::size_t idx = 0; idx < count; ++idx ) {
                if ( ( table[idx] & 0xfffffff0 ) != ( target_rva & 0xfffffff0 ) )
                    continue;

                s_saved_entry = table[idx];
                s_entry_va    = s_ssdt_base + idx * sizeof( std::uint32_t );
                s_entry_pa    = paging::translate_linear( s_entry_va );

                logging::print( "syscall entry: idx=%llu entry=0x%08x (address scan)", idx, s_saved_entry );
                break;
            }
        }

        if ( !s_entry_pa ) {
            logging::print( "failed to find NtDeviceIoControlFile in SSDT" );
            return false;
        }

        logging::print( "syscall complete: 0x%llx (original: 0x%08x)\n", s_entry_va, s_saved_entry );
        return true;
    }

    template<typename ret_t = std::uint64_t,
        typename a1_t  = void*, typename a2_t  = void*,
        typename a3_t  = void*, typename a4_t  = void*,
        typename a5_t  = void*, typename a6_t  = void*,
        typename a7_t  = void*, typename a8_t  = void*,
        typename a9_t  = void*, typename a10_t = void*>
    inline ret_t call_kernel( std::uint64_t func,
        a1_t  a1 = {}, a2_t  a2 = {}, a3_t  a3 = {},
        a4_t  a4 = {}, a5_t  a5 = {}, a6_t  a6 = {},
        a7_t  a7 = {}, a8_t  a8 = {}, a9_t  a9 = {},
        a10_t a10 = {} ) {

        if ( !s_entry_pa ) {
            logging::print( "syscall not initialized" );
            if constexpr ( std::is_void_v<ret_t> ) return;
            else return ret_t{};
        }

        std::unique_lock lock( s_lock );
        const auto new_rva   = static_cast<int>( func - s_ssdt_base ) << 4;
        const auto new_entry = static_cast<std::uint32_t>( ( new_rva & 0xfffffff0 ) | ( s_saved_entry & 0xf ) );

        if ( !driver::write_physical_memory( s_entry_pa, &new_entry, sizeof( new_entry ) ) ) {
            if constexpr ( std::is_void_v<ret_t> ) return;
            else return ret_t{};
        }

        using fn_t = void* ( __stdcall* )(
            a1_t, a2_t, a3_t, a4_t, a5_t,
            a6_t, a7_t, a8_t, a9_t, a10_t );

        auto* nt_fn = reinterpret_cast<fn_t>(
            GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtDeviceIoControlFile" ) );

        void* result = nullptr;
        if ( nt_fn )
            result = nt_fn( a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 );

        driver::write_physical_memory( s_entry_pa, &s_saved_entry, sizeof( s_saved_entry ) );

        if constexpr ( std::is_void_v<ret_t> ) return;
        else return reinterpret_cast<ret_t>( result );
    }
}
