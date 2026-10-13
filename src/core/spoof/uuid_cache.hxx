#pragma once
#include "helpers.hxx"
#include "nic.hxx"

namespace spoof::uuid_cache {
    using namespace helpers;

    static std::uint64_t locate_node_va( std::uint64_t fn_va ) {
        if ( !fn_va ) return 0;

        std::uint8_t body[ 0x300 ] = {};
        if ( !kread( fn_va, body, sizeof( body ) ) ) return 0;

        for ( std::uint32_t i = 0; i + 7 <= sizeof( body ); ++i ) {
            if ( body[ i ] == 0x0F && body[ i + 1 ] == 0xB7 && body[ i + 2 ] == 0x05 ) {
                std::int32_t disp = *reinterpret_cast<const std::int32_t*>( body + i + 3 );

                std::uint64_t word_va = ( fn_va + i + 7 ) + static_cast<std::int64_t>( disp );
                return word_va - 4;
            }
        }
        return 0;
    }

    inline void install() {
        // the node MAC must be an address a NIC on this box actually
        // transmits with. a planned MAC whose adapter never adopted it on
        // the wire would embed an address no hardware uses - an
        // internal-consistency leak - so only a verifiably adopted
        // override qualifies
        std::uint8_t node[ 6 ] = {};
        bool adopted_node = false;
        if ( const std::uint8_t* adopted = spoof::nic::first_adopted_mac() ) {
            memcpy( node, adopted, 6 );
            adopted_node = true;
            logging::print( "uuid_cache: node MAC taken from first adopted adapter" );
        } else {
            // nothing adopted: a fresh locally-administered unicast MAC of
            // our own - never a planned-but-unadopted value
            node[ 0 ] = 0x02; // bit0 clear = unicast, bit1 set = locally administered
            for ( std::uint32_t i = 1; i < 6; ++i )
                node[ i ] = static_cast<std::uint8_t>( rand_next() & 0xFF );
            logging::print( "uuid_cache: no adapter adopted its override, generated fresh node MAC" );
        }

        // final gate: whatever produced the bytes, a UUID node must be a set,
        // unicast MAC - multicast is malformed and worse than no patch. an
        // adopted adapter MAC is a real IEEE 802 address exactly as a stock
        // machine's UUIDs carry, so only unicast is required there; the
        // generated fallback must also be locally administered
        const bool node_bad = !spoof::nic::mac_is_set( node )
                           || ( node[ 0 ] & 0x01 ) != 0
                           || ( !adopted_node && ( node[ 0 ] & 0x02 ) == 0 );
        if ( node_bad ) {
            logging::print( "uuid_cache: node %02X:%02X:%02X:%02X:%02X:%02X failed unicast%s gate - write skipped",
                node[0], node[1], node[2], node[3], node[4], node[5],
                adopted_node ? "" : "+local-admin" );
            return;
        }

        const std::uint64_t fn_va = pdb::get_symbol_address( "NtAllocateUuids" );
        if ( !fn_va ) {
            logging::print( "uuid_cache: NtAllocateUuids not found in PDB" );
            return;
        }

        const std::uint64_t node_va = locate_node_va( fn_va );
        if ( !node_va ) {
            logging::print( "uuid_cache: UUID node pattern not found in NtAllocateUuids" );
            return;
        }

        std::uint8_t old_node[ 6 ] = {};
        kread( node_va, old_node, 6 );
        logging::print( "uuid_cache: node at 0x%llx cur=%02X:%02X:%02X:%02X:%02X:%02X",
            node_va,
            old_node[0], old_node[1], old_node[2], old_node[3], old_node[4], old_node[5] );

        if ( !kwrite_verified( node_va, node, 6, "uuid_cache: node MAC" ) ) return;

        logging::print( "uuid_cache: patched to %02X:%02X:%02X:%02X:%02X:%02X",
            node[0], node[1], node[2], node[3], node[4], node[5] );
    }

}
