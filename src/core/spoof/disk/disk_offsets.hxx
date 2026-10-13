#pragma once
#include "../../../symbols/pdb_offsets.hxx"

namespace spoof::disk {

    using disk_off_t = loader_offsets::disk_offsets;

    inline disk_off_t& g_disk_off() {
        static disk_off_t off{};
        return off;
    }

    inline void resolve_disk_offsets() {
        auto& off = g_disk_off();
        if (!pdb_offsets::resolve_disk(&off))
            logging::warning("pdb: disk offset resolution incomplete - some disk layers may be limited");
    }

}
