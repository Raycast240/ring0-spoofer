#pragma once

namespace utility {
    inline bool adjust_privilege( std::uint32_t privilege ) {
        auto* ntdll = GetModuleHandleA( "ntdll.dll" );
        if ( !ntdll )
            return false;

        using rtl_adjust_privilege_fn = NTSTATUS( __stdcall* )( DWORD, BOOL, INT, PBOOL );
        auto rtl_adjust_privilege = reinterpret_cast<rtl_adjust_privilege_fn>( GetProcAddress( ntdll, "RtlAdjustPrivilege" ) );

        BOOL was_enabled = FALSE;
        auto status = rtl_adjust_privilege( privilege, TRUE, FALSE, &was_enabled );
        if ( status ) {
            logging::print( "[system] adjust_privilege: Could not acquire privilege" );
            return false;
        }

        return true;
    }

    inline void gen_rnd_str( wchar_t* random_str ) {
        auto length = ( rand() % 12 ) + 8;
        for ( std::size_t i = 0; i < static_cast<std::size_t>( length ); ++i ) {
            switch ( rand() % 3 ) {
                case 0:
                    random_str[i] = static_cast<wchar_t>( 'A' + rand() % 26 );
                    break;
                case 1:
                    random_str[i] = static_cast<wchar_t>( 'a' + rand() % 26 );
                    break;
                case 2:
                    random_str[i] = static_cast<wchar_t>( '0' + rand() % 10 );
                    break;
            }
        }
        random_str[length] = 0;
    }

    inline bool is_physical_address_valid( std::uint64_t pa, std::size_t size ) {
        int regs[4]{};
        __cpuid( regs, 0x80000000 );
        unsigned max_ext  = static_cast<unsigned>( regs[0] );
        unsigned phys_bits = 36;
        if ( max_ext >= 0x80000008 ) {
            __cpuid( regs, 0x80000008 );
            unsigned b = regs[0] & 0xFF;
            if ( b >= 32 && b <= 52 )
                phys_bits = b;
        }

        const auto physical_mask = ( phys_bits >= 63 ) ? ~0ULL : ( ( 1ULL << phys_bits ) - 1ULL );
        if ( ( pa & ~physical_mask ) != 0 )
            return false;

        const auto end_pa = pa + ( size - 1 );
        if ( ( end_pa & ~physical_mask ) != 0 )
            return false;

        return true;
    }
}
