#pragma once
// wifi_drv_mac.hxx - rtwlane602.sys in-memory permanent-MAC patch
//
// rtwlane602 (Realtek 8852CE) adopts a new CURRENT address through the nic
// stage's NetworkAddress + PnP restart, but its PERMANENT field keeps the
// real EFUSE MAC for the whole session - and OID_802_3_PERMANENT_ADDRESS
// answers from it. this stage mirrors the spoofed value into that field.
//
// recon (this build of rtwlane602.sys): the frame/FW path never reads
// permanent (FW cmd builder 0x410AC, request builder 0x316C0, multicast
// filter 0x2DC9E/0x338A4 all read CURRENT; permanent feeds only OID answers
// 0x13341/0x13682/0x141C9, RX comparisons, P2P selection). re-init rewrites
// permanent from EFUSE before the permanent->current copy (0x4BA0B), so the
// patch reverts on the next init. the driver itself runs with
// current != permanent (random-MAC path), the fields are independent.
//
// no hardcoded offsets: the permanent offset is derived at runtime from the
// OID dispatcher's subtraction chain (byte pattern verified unique in the
// 9.4 MB image) and cross-checked against structural signatures. the write
// is identity-gated with readback + restore-on-mismatch.
//
// runs after the nic stage on purpose, reusing its plan (old_mac = real
// hardware MAC, new_mac = the adopted spoof) so both stages tell one story.

#include "helpers.hxx"
#include "nic.hxx"
#include <cstdio>
#include <cstring>
#include <vector>

namespace spoof::wifi_drv_mac {

    using namespace helpers;

    // ---- byte-pattern helpers ------------------------------------------------

    static std::uint32_t rd32( const std::uint8_t* p ) {
        return (std::uint32_t)p[0] | ( (std::uint32_t)p[1] << 8 ) |
               ( (std::uint32_t)p[2] << 16 ) | ( (std::uint32_t)p[3] << 24 );
    }

    static bool bytes_match( const std::uint8_t* p, const std::uint8_t* pat, std::size_t n ) {
        return memcmp( p, pat, n ) == 0;
    }

    static std::uint32_t count_pattern( const std::uint8_t* buf, std::size_t len,
                                        const std::uint8_t* pat, std::size_t n ) {
        std::uint32_t count = 0;
        if ( len < n ) return 0;
        for ( std::size_t i = 0; i + n <= len; ++i )
            if ( !memcmp( buf + i, pat, n ) ) ++count;
        return count;
    }

    static void mac_txt( char* out, std::size_t out_size, const std::uint8_t mac[6] ) {
        std::snprintf( out, out_size, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
    }

    // ---- runtime permanent-offset derivation ----------------------------------
    //
    // anchor: the OID dispatcher's subtraction chain resolving the 802.3
    // group. ecx holds the OID; the chain accumulates ecx - 0x10202 - 0xFEFF
    // - 4*1 - 0xFEFFFC == ecx - 0x1010101, so the je lands on the
    // CURRENT-address (0x1010101) handler and the fall-through (cmp eax,1)
    // is the PERMANENT-address (0x1010102) handler:
    //
    //   000132DE  b8 03 01 01 01           mov  eax, 0x1010103      (MAXLIST bound)
    //   ...       2d 02 02 01 00            sub  eax, 0x10202
    //   ...       2d ff fe 00 00            sub  eax, 0xFEFF
    //   ...       83 e8 01  (x4)            sub  eax, 1
    //   A+0       2d fc ff fe 00            sub  eax, 0xFEFFFC        <- ANCHOR
    //   A+5       0f 84 <rel32>             je   CURRENT handler      (lea rdx,[rbx+cur])
    //   A+11      83 f8 01                 cmp  eax, 1
    //   A+14      0f 85 <rel32>             jne  unsupported
    //   A+20      48 8d 93 <perm disp32>    lea  rdx, [rbx + permanent] <- TARGET
    //   A+27      48 89 55 d7              mov  [rbp-0x29], rdx        (OID answer ptr)
    //   A+31      44 8d 68 05              lea  r13d, [rax+5]         (OID answer length 6)
    //
    // the anchor byte sequence 2D FC FF FE 00 0F 84 occurs EXACTLY ONCE in
    // the entire image (verified against the on-disk build); every other
    // signature below is cross-checked relative to it. a future driver
    // build that changes the codegen fails one of these gates and the stage
    // skips - recon first, never a blind write.

    static const std::uint8_t kAnchor[]    = { 0x2D, 0xFC, 0xFF, 0xFE, 0x00, 0x0F, 0x84 };
    static const std::uint8_t kCmpOne[]    = { 0x83, 0xF8, 0x01 };                 // cmp eax,1
    static const std::uint8_t kJne[]       = { 0x0F, 0x85 };                       // jne
    static const std::uint8_t kLeaRbxD[]   = { 0x48, 0x8D, 0x93 };                 // lea rdx,[rbx+disp32]
    static const std::uint8_t kAnswerPtr[] = { 0x48, 0x89, 0x55, 0xD7 };           // mov [rbp-0x29],rdx
    static const std::uint8_t kAnswerLen[] = { 0x44, 0x8D, 0x68, 0x05 };           // lea r13d,[rax+5]
    static const std::uint8_t kSubBase[]   = { 0x2D, 0x02, 0x02, 0x01, 0x00 };     // sub eax,0x10202
    static const std::uint8_t kSubMid[]    = { 0x2D, 0xFF, 0xFE, 0x00, 0x00 };     // sub eax,0xFEFF
    static const std::uint8_t kSubOne[]    = { 0x83, 0xE8, 0x01 };                 // sub eax,1  (x4)
    static const std::uint8_t kMovBound[]  = { 0xB8, 0x03, 0x01, 0x01, 0x01 };    // mov eax,0x1010103
    static const std::uint8_t kCurLen6[]   = { 0x41, 0xBD, 0x06, 0x00, 0x00, 0x00 }; // mov r13d,6

    static bool scan_perm_offset( std::uint64_t drv_base,
                                  std::uint32_t* perm_off, std::uint32_t* cur_off,
                                  std::uint64_t* anchor_va ) {
        *perm_off = *cur_off = 0;
        *anchor_va = 0;

        // in-memory PE headers of the loaded image
        std::vector<std::uint8_t> hdr( 0x1000 );
        if ( !kread( drv_base, hdr.data(), hdr.size() ) ) {
            logging::print( "wifi_drv_mac: rtwlane602 image headers unreadable" );
            return false;
        }
        if ( hdr[0] != 'M' || hdr[1] != 'Z' ) return false;
        const std::uint32_t e_lfanew = rd32( hdr.data() + 0x3C );
        if ( e_lfanew == 0 || e_lfanew + 24 + 0x400 > hdr.size() ) return false;
        if ( hdr[e_lfanew] != 'P' || hdr[e_lfanew+1] != 'E' ) return false;
        const std::uint32_t nsec = hdr[e_lfanew+6] | ( (std::uint32_t)hdr[e_lfanew+7] << 8 );
        const std::uint32_t opt  = hdr[e_lfanew+20] | ( (std::uint32_t)hdr[e_lfanew+21] << 8 );
        const std::uint32_t sec_tab = e_lfanew + 24 + opt;
        if ( nsec == 0 || nsec > 32 || sec_tab + nsec * 40 > hdr.size() ) return false;

        // first executable section = .text (the dispatcher is code)
        std::uint64_t sec_va = 0, sec_size = 0;
        for ( std::uint32_t i = 0; i < nsec; ++i ) {
            const std::uint8_t* s = hdr.data() + sec_tab + i * 40;
            const std::uint32_t vsize = rd32( s + 8 );
            const std::uint32_t va    = rd32( s + 12 );
            const std::uint32_t chars = rd32( s + 36 );
            if ( ( chars & 0x20000000 ) && vsize > 0x1000 ) {  // IMAGE_SCN_MEM_EXECUTE
                sec_va   = drv_base + va;
                sec_size = vsize;
                break;
            }
        }
        if ( !sec_va ) {
            logging::print( "wifi_drv_mac: no executable section in rtwlane602" );
            return false;
        }

        // whole-section scan for the anchor - must be exactly one occurrence
        constexpr std::size_t kChunk = 0x40000, kOverlap = 0x100;
        std::vector<std::uint8_t> buf( kChunk );
        std::uint64_t hit_va = 0;
        std::uint32_t hits = 0;
        for ( std::uint64_t off = 0; off < sec_size && hits <= 1; off += ( kChunk - kOverlap ) ) {
            const std::size_t len = static_cast<std::size_t>(
                ( kChunk < sec_size - off ) ? kChunk : ( sec_size - off ) );
            if ( len < sizeof( kAnchor ) ) break;
            if ( !kread( sec_va + off, buf.data(), len ) ) {
                logging::print( "wifi_drv_mac: rtwlane602 .text chunk at 0x%llx unreadable",
                                sec_va + off );
                return false;
            }
            const std::size_t i_start = off ? kOverlap : 0;  // overlap region was scanned last chunk
            for ( std::size_t i = i_start; i + sizeof( kAnchor ) <= len; ++i ) {
                if ( bytes_match( buf.data() + i, kAnchor, sizeof( kAnchor ) ) ) {
                    ++hits;
                    hit_va = sec_va + off + i;
                }
            }
        }
        if ( hits != 1 ) {
            logging::print( "wifi_drv_mac: OID dispatcher anchor %s (%u hit(s)) - build changed, recon needed",
                            hits ? "not unique" : "not found", hits );
            return false;
        }

        // structural validation of the analyzed build, all relative to the anchor
        const std::uint64_t A = hit_va;
        std::uint8_t win[0xA0] = {};
        if ( !kread( A - 0x60, win, sizeof( win ) ) ) {
            logging::print( "wifi_drv_mac: dispatcher window unreadable at 0x%llx", A );
            return false;
        }
        constexpr std::size_t kA = 0x60;
        if ( !bytes_match( win + kA, kAnchor, sizeof( kAnchor ) ) ) return false;
        if ( !bytes_match( win + kA + 11, kCmpOne, sizeof( kCmpOne ) ) ) return false;
        if ( !bytes_match( win + kA + 14, kJne, sizeof( kJne ) ) ) return false;
        if ( !bytes_match( win + kA + 20, kLeaRbxD, sizeof( kLeaRbxD ) ) ) return false;
        if ( !bytes_match( win + kA + 27, kAnswerPtr, sizeof( kAnswerPtr ) ) ) return false;
        if ( !bytes_match( win + kA + 31, kAnswerLen, sizeof( kAnswerLen ) ) ) return false;

        // the subtraction chain leading up to the anchor must resolve
        // 0x1010101: base - 0x10202 - 0xFEFF - 4*1 - 0xFEFFFC == 0x1010101
        if ( count_pattern( win, kA, kSubBase, sizeof( kSubBase ) ) != 1 ) return false;
        if ( count_pattern( win, kA, kSubMid, sizeof( kSubMid ) ) != 1 ) return false;
        if ( count_pattern( win, kA, kSubOne, sizeof( kSubOne ) ) != 4 ) return false;
        if ( count_pattern( win, kA, kMovBound, sizeof( kMovBound ) ) != 1 ) return false;

        const std::uint32_t perm = rd32( win + kA + 23 );
        if ( perm < 0x1000 || perm >= 0x400000 ) {
            logging::print( "wifi_drv_mac: permanent offset 0x%x out of plausible range", perm );
            return false;
        }

        // the je target is the CURRENT handler: same lea form, answer length
        // 6, and its field sits exactly 6 bytes before the permanent field
        // (the two 6-byte fields are adjacent in the adapter struct)
        const std::int32_t rel = static_cast<std::int32_t>( rd32( win + kA + 7 ) );
        const std::uint64_t T = A + 11 + (std::int64_t)rel;
        std::uint8_t tbuf[16] = {};
        if ( !kread( T, tbuf, sizeof( tbuf ) ) ) return false;
        if ( !bytes_match( tbuf, kLeaRbxD, sizeof( kLeaRbxD ) ) ) return false;
        if ( !bytes_match( tbuf + 7, kCurLen6, sizeof( kCurLen6 ) ) ) return false;
        const std::uint32_t cur = rd32( tbuf + 3 );
        if ( cur + 6 != perm ) {
            logging::print( "wifi_drv_mac: current/permanent adjacency check failed (cur=0x%x perm=0x%x)",
                            cur, perm );
            return false;
        }

        *perm_off  = perm;
        *cur_off   = cur;
        *anchor_va = A;
        return true;
    }

    // ---- the gated patch -------------------------------------------------------

    static void install() {
        std::uint32_t patched = 0;

        // nic stage plan: old_mac = real hardware MAC (what rtwlane602
        // keeps in permanent), new_mac = what the system now reports
        if ( !nic::s_off.valid )
            nic::resolve_offsets();

        const nic::adapter_override* radio = nullptr;
        for ( const auto& o : nic::s_overrides )
            if ( o.is_radio && nic::mac_is_set( o.old_mac ) &&
                 nic::mac_is_set( o.new_mac ) ) { radio = &o; break; }
        if ( !radio || !memcmp( radio->old_mac, radio->new_mac, 6 ) ) {
            logging::print( "wifi_drv_mac: no Wi-Fi radio adapter plan - skipped" );
            return;
        }
        if ( !nic::s_off.valid || !nic::s_off.mp_next_global || !nic::s_off.mp_eth_db ||
             !nic::s_off.ethdb_addr || !nic::s_off.mp_adapter_ctx ) {
            logging::print( "wifi_drv_mac: NDIS offsets unresolved - skipped" );
            return;
        }

        // find the radio's miniport by its eth filter identity: it reads the
        // old hardware MAC before adoption and the adopted MAC afterwards
        const std::uint64_t head = kread_val<std::uint64_t>( nic::s_off.miniport_list_rva );
        if ( !is_kva( head ) ) {
            logging::print( "wifi_drv_mac: NDIS miniport list unreadable - skipped" );
            return;
        }
        std::uint64_t radio_mp = 0;
        for ( std::uint64_t mp = head, i = 0; i < 64 && is_kva( mp ); ++i ) {
            const std::uint64_t ethdb = kread_val<std::uint64_t>( mp + nic::s_off.mp_eth_db );
            if ( is_kva( ethdb ) ) {
                std::uint8_t id[6] = {};
                if ( kread( ethdb + nic::s_off.ethdb_addr, id, 6 ) ) {
                    if ( !memcmp( id, radio->old_mac, 6 ) ||
                         !memcmp( id, radio->new_mac, 6 ) ) {
                        radio_mp = mp;
                        break;
                    }
                }
            }
            mp = kread_val<std::uint64_t>( mp + nic::s_off.mp_next_global );
        }
        if ( !radio_mp ) {
            char old_txt[24] = {};
            mac_txt( old_txt, sizeof( old_txt ), radio->old_mac );
            logging::print( "wifi_drv_mac: no miniport carries the radio MAC %s - skipped", old_txt );
            return;
        }

        // the driver's MiniportAdapterContext = the rtwlane602 adapter struct
        const std::uint64_t ctx = kread_val<std::uint64_t>( radio_mp + nic::s_off.mp_adapter_ctx );
        if ( !is_kva( ctx ) ) {
            logging::print( "wifi_drv_mac: miniport 0x%llx has no adapter context - skipped", radio_mp );
            return;
        }

        // mirror what NDIS answers for permanent - the IF_BLOCK permanent
        // field the nic stage patched; fall back to the planned radio MAC
        std::uint8_t target[6] = {};
        bool have_target = false;
        if ( nic::s_off.mp_if_avail && nic::s_off.mp_if_block && nic::s_off.ifb_perm &&
             nic::s_off.pa_address ) {
            if ( kread_val<std::uint32_t>( radio_mp + nic::s_off.mp_if_avail ) ) {
                const std::uint64_t ifb = kread_val<std::uint64_t>( radio_mp + nic::s_off.mp_if_block );
                if ( is_kva( ifb ) ) {
                    const std::uint16_t plen = kread_val<std::uint16_t>(
                        ifb + nic::s_off.ifb_perm + nic::s_off.pa_length );
                    if ( plen == 6 &&
                         kread( ifb + nic::s_off.ifb_perm + nic::s_off.pa_address, target, 6 ) &&
                         nic::mac_is_set( target ) )
                        have_target = true;
                }
            }
        }
        if ( !have_target )
            memcpy( target, radio->new_mac, 6 );
        if ( memcmp( target, radio->new_mac, 6 ) != 0 ) {
            char ifb_txt[24] = {}, plan_txt[24] = {};
            mac_txt( ifb_txt, sizeof( ifb_txt ), target );
            mac_txt( plan_txt, sizeof( plan_txt ), radio->new_mac );
            logging::print( "wifi_drv_mac: IF_BLOCK permanent (%s) differs from the radio plan (%s) - mirroring the live IF_BLOCK value",
                            ifb_txt, plan_txt );
        }

        // derive the permanent/current field offsets from the loaded image
        const std::uint64_t drv_base = get_kernel_module_base( L"rtwlane602.sys" );
        if ( !drv_base ) {
            logging::print( "wifi_drv_mac: rtwlane602.sys not loaded - skipped" );
            return;
        }
        std::uint32_t perm_off = 0, cur_off = 0;
        std::uint64_t anchor_va = 0;
        if ( !scan_perm_offset( drv_base, &perm_off, &cur_off, &anchor_va ) ) {
            logging::print( "wifi_drv_mac: permanent field offset not derivable - skipped (OID leak stays, no write made)" );
            return;
        }
        logging::print( "wifi_drv_mac: dispatcher anchor 0x%llx -> permanent +0x%x, current +0x%x",
                        anchor_va, perm_off, cur_off );

        // the CURRENT field must read a MAC this session can account for -
        // hardware, adopted, or recorded from a kernel walk (an old spoof on
        // the wire counts). anything else means the offsets don't describe
        // this adapter struct
        std::uint8_t cur_addr[6] = {};
        if ( !kread( ctx + cur_off, cur_addr, 6 ) ) {
            logging::print( "wifi_drv_mac: current field at 0x%llx unreadable - skipped", ctx + cur_off );
            return;
        }
        if ( memcmp( cur_addr, radio->old_mac, 6 ) != 0 &&
             memcmp( cur_addr, radio->new_mac, 6 ) != 0 &&
             !nic::find_override( cur_addr ) && !nic::find_patched( cur_addr ) ) {
            char cur_txt[24] = {};
            mac_txt( cur_txt, sizeof( cur_txt ), cur_addr );
            logging::print( "wifi_drv_mac: current field reads %s - not a MAC this session knows (hardware, adopted or previously spoofed) - offsets suspect, skipped",
                            cur_txt );
            return;
        }

        // identity gate + write + readback + restore, the patch_phys_addr pattern
        const std::uint64_t perm_va = ctx + perm_off;
        std::uint8_t perm_cur[6] = {};
        if ( !kread( perm_va, perm_cur, 6 ) ) {
            logging::print( "wifi_drv_mac: permanent field at 0x%llx unreadable - skipped", perm_va );
            return;
        }

        char old_txt[24] = {}, new_txt[24] = {};
        mac_txt( old_txt, sizeof( old_txt ), perm_cur );
        mac_txt( new_txt, sizeof( new_txt ), target );

        if ( !memcmp( perm_cur, target, 6 ) ) {
            logging::print( "wifi_drv_mac: driver permanent already reads %s - nothing to do",
                           new_txt );
            return;
        }
        if ( memcmp( perm_cur, radio->old_mac, 6 ) != 0 ) {
            // bytes must be EXACTLY the captured hardware MAC - a mismatch
            // means the plan holds something else (Windows random hardware
            // addresses, a later re-spoof) and the identity is unproven
            char hw_txt[24] = {};
            mac_txt( hw_txt, sizeof( hw_txt ), radio->old_mac );
            logging::print( "wifi_drv_mac: permanent field at 0x%llx reads %s, expected the real hardware MAC %s - identity gate failed, skipped",
                            perm_va, old_txt, hw_txt );
            return;
        }

        if ( !kwrite( perm_va, target, 6 ) ) {
            logging::print( "wifi_drv_mac: permanent field write at 0x%llx failed - skipped", perm_va );
            return;
        }
        std::uint8_t back[6] = {};
        if ( !kread( perm_va, back, 6 ) || memcmp( back, target, 6 ) != 0 ) {
            kwrite( perm_va, perm_cur, 6 );  // restore the original bytes
            logging::print( "wifi_drv_mac: permanent field write at 0x%llx failed readback - original restored",
                            perm_va );
            return;
        }

        logging::change( "NIC MAC", "rtwlane602 permanent (OID query)", old_txt, new_txt, false );
        logging::print( "wifi_drv_mac: driver permanent MAC patched %s -> %s (OID_802_3_PERMANENT_ADDRESS now answers the spoof)",
                        old_txt, new_txt );
        ++patched;
        logging::print( "wifi_drv_mac: done (%u permanent field(s) patched)", patched );
    }

}