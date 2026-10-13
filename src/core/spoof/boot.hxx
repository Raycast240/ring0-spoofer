#pragma once
#include "helpers.hxx"

namespace boot {

    static constexpr std::uint64_t KUSER_SHARED_DATA_VA = 0xFFFFF78000000000ULL;
    static constexpr std::uint32_t BOOT_ID_OFF          = 0x2C4u;

    inline void install() {
        using namespace spoof::helpers;

        const std::uint32_t old_id = kread_val<std::uint32_t>(KUSER_SHARED_DATA_VA + BOOT_ID_OFF);
        // BootId counts boots, one per boot - a plausible spoof is exactly one
        // increment; a random value jumps the counter by hundreds and is
        // itself a fingerprint tell
        const std::uint32_t new_id = old_id + 1;
        // identity gate: BootId is a small per-boot counter; a huge value
        // means the shared-data read is not the BootId field - skip rather
        // than write over an unrelated KUSER_SHARED_DATA field
        if (old_id <= 100000u) {
            const bool id_written = kwrite_verified(KUSER_SHARED_DATA_VA + BOOT_ID_OFF,
                                                    &new_id, sizeof(new_id), "boot: BootId");
            logging::print("spoof: BootId -> %u", new_id);
            if (id_written) {
                char old_str[16] = {}, new_str[16] = {};
                std::snprintf(old_str, sizeof(old_str), "%u", old_id);
                std::snprintf(new_str, sizeof(new_str), "%u", new_id);
                logging::change("Boot", "BootId", old_str, new_str, false);
            }
        } else {
            logging::print("spoof: BootId readback %u implausible - write skipped", old_id);
        }

        const std::uint64_t ke_boot_va = pdb::get_symbol_address("KeBootTime");
        if (ke_boot_va) {
            const std::int64_t cur = static_cast<std::int64_t>(kread_val<std::uint64_t>(ke_boot_va));
            // identity gate: KeBootTime is the boot instant in 100ns units
            // since 1601 - outside the ~2011..2293 window the symbol does
            // not hold a system time on this build and a write would land
            // in a neighbouring field
            if (cur >= 100000000000000000LL && cur <= 250000000000000000LL) {

                const std::int64_t days  = static_cast<std::int64_t>((rand_next() % 30) + 1);
                const std::int64_t sign  = (rand_next() & 1) ? 1LL : -1LL;
                const std::int64_t delta = sign * days * 864000000000LL;
                const std::int64_t new_time = cur + delta;
                const bool time_written = kwrite_verified(ke_boot_va, &new_time, sizeof(new_time),
                                                          "boot: KeBootTime");
                logging::print("spoof: KeBootTime shifted by %+lld days", static_cast<long long>(sign * days));
                if (time_written) {
                    char old_str[24] = {}, new_str[24] = {};
                    std::snprintf(old_str, sizeof(old_str), "%lld", static_cast<long long>(cur));
                    std::snprintf(new_str, sizeof(new_str), "%lld", static_cast<long long>(cur + delta));
                    logging::change("Boot", "KeBootTime", old_str, new_str, false);
                }
            }
        } else {
            logging::print("spoof: KeBootTime symbol not found - skipping");
        }
    }

}
