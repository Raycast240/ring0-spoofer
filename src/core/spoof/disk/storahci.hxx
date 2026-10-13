#pragma once
#include "storport.hxx"

namespace spoof::disk::storahci {
    using namespace helpers;

    inline void install() {
        storport::spoof_raid_units(L"\\Driver\\storahci", false);
    }

}
