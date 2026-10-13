#pragma once
#include "shared.hxx"
#include "disk_offsets.hxx"

namespace spoof::disk::partmgr {
    using namespace helpers;

    static constexpr std::uint32_t kPartStyle         = 0;
    static constexpr std::uint32_t kPartStartOff      = 8;
    static constexpr std::uint32_t kPartLengthOff     = 16;
    static constexpr std::uint32_t kPartNumberOff     = 24;

    static constexpr std::uint32_t kPartGptTypeOff    = 32;
    static constexpr std::uint32_t kPartGptIdOff      = 48;

    static constexpr std::uint32_t kDriveLayoutPartitionEntryOff = 48;
    static constexpr std::uint32_t kPartInfoExSize    = 144;
    static constexpr std::uint32_t kPartStyleGPT      = 1;

    static bool looks_like_partition_info(std::uint64_t info_va) {
        if (!is_kva(info_va)) return false;
        std::uint32_t style = kread_val<std::uint32_t>(info_va + kPartStyle);
        if (style != kPartStyleGPT) return false;
        std::int64_t length = kread_val<std::int64_t>(info_va + kPartLengthOff);
        return length > 0 && length < (std::int64_t)0x1000000000000000LL;
    }

    static void format_guid_txt(char* out, std::size_t out_size, const std::uint8_t* raw) {
        if (!out || !raw || out_size < 40) return;
        snprintf(out, out_size, "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            (unsigned long)(raw[0] | (raw[1] << 8) | (raw[2] << 16) | ((unsigned long)raw[3] << 24)),
            (unsigned)(raw[4] | (raw[5] << 8)),
            (unsigned)(raw[6] | (raw[7] << 8)),
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
    }

    static void record_guid_change(const char* name, const std::uint8_t* old_raw,
                                    const std::uint8_t* new_raw) {
        if (!name || memcmp(old_raw, new_raw, 16) == 0) return;
        char old_txt[48] = {}, new_txt[48] = {};
        format_guid_txt(old_txt, sizeof(old_txt), old_raw);
        format_guid_txt(new_txt, sizeof(new_txt), new_raw);
        logging::change("Disk", name, old_txt, new_txt, false);
    }

    static void patch_guid(const char* chg_name, std::uint64_t guid_va) {
        std::uint8_t old_raw[16] = {};
        bool have_old = kread(guid_va, old_raw, 16);
        spoof_guid_va(guid_va);
        std::uint8_t new_raw[16] = {};
        if (have_old && kread(guid_va, new_raw, 16))
            record_guid_change(chg_name, old_raw, new_raw);
    }

    static std::uint32_t patch_mountdev_unique_id(std::uint64_t uid_va, const std::uint8_t* guid_bytes) {
        if (!is_kva(uid_va)) return 0;
        std::uint16_t length = kread_val<std::uint16_t>(uid_va);
        if (length < 24 || length > 0x100) return 0;
        std::uint64_t data_va = uid_va + sizeof(std::uint16_t);
        std::uint8_t data[8] = {};
        if (!kread(data_va, data, 8)) return 0;
        static const std::uint8_t dmio_prefix[] = { 'D','M','I','O',':','I','D',':' };
        if (memcmp(data, dmio_prefix, 8) != 0) return 0;
        std::uint8_t old_uid[16] = {};
        bool have_old = kread(data_va + 8, old_uid, 16);
        if (!kwrite_verified(data_va + 8, guid_bytes, 16, "partmgr: unique ID"))
            return 0;
        if (have_old)
            record_guid_change("unique ID (DMIO:ID:)", old_uid, guid_bytes);
        return 1;
    }

    static std::uint32_t patch_partition_extension(std::uint64_t ext_va, std::uint32_t salt) {
        const auto& off = g_disk_off();
        if (!off.partmgr_partition_info_ex) return 0;

        std::uint64_t info_va = ext_va + off.partmgr_partition_info_ex;
        if (!looks_like_partition_info(info_va)) return 0;

        std::uint32_t patched = 0;


        std::uint64_t part_id_va = info_va + kPartGptIdOff;
        patch_guid("GPT partition ID", part_id_va);
        ++patched;


        if (off.partmgr_partition_stable_guid) {
            std::uint8_t new_guid[16];
            kread(part_id_va, new_guid, 16);
            std::uint8_t old_stable[16] = {};
            bool have_old = kread(ext_va + off.partmgr_partition_stable_guid, old_stable, 16);
            // identity gate on the PDB-derived stable-GUID offset: a mounted
            // partition always carries a non-zero stable GUID - a zeroed (or
            // unreadable) slot means the offset is wrong for this build and
            // writing there would run into a neighbouring field
            bool all_zero = true;
            for (int i = 0; i < 16; ++i) if (old_stable[i]) { all_zero = false; break; }
            if (!have_old || all_zero) {
                logging::print("disk: partmgr stable GUID at 0x%llx %s - write skipped",
                               ext_va + off.partmgr_partition_stable_guid,
                               have_old ? "is zeroed" : "unreadable");
            } else if (kwrite_verified(ext_va + off.partmgr_partition_stable_guid,
                                      new_guid, 16, "partmgr: stable GUID")) {
                record_guid_change("stable partition GUID", old_stable, new_guid);
                ++patched;
            }
        }


        if (off.partmgr_partition_unique_id) {
            std::uint64_t uid_slot_va = ext_va + off.partmgr_partition_unique_id;
            std::uint64_t uid_va = kread_val<std::uint64_t>(uid_slot_va);
            if (is_kva(uid_va)) {
                std::uint8_t guid_bytes[16];
                kread(part_id_va, guid_bytes, 16);
                patched += patch_mountdev_unique_id(uid_va, guid_bytes);
            }
        }

        return patched;
    }

    static bool valid_drive_layout(std::uint64_t layout_va) {
        if (!is_kva(layout_va)) return false;
        std::uint32_t style = kread_val<std::uint32_t>(layout_va);
        if (style != kPartStyleGPT) return false;
        std::uint32_t count = kread_val<std::uint32_t>(layout_va + 4);
        return count > 0 && count <= 256;
    }

    static std::uint32_t patch_drive_layout(std::uint64_t layout_va, std::uint32_t salt) {
        if (!valid_drive_layout(layout_va)) return 0;
        const auto& off = g_disk_off();
        std::uint32_t patched = 0;


        patch_guid("disk GUID (layout)", layout_va + off.partmgr_layout_disk_id);
        ++patched;


        std::uint32_t count = kread_val<std::uint32_t>(layout_va + 4);
        for (std::uint32_t i = 0; i < count && i < 256; ++i) {
            std::uint64_t entry_va = layout_va + kDriveLayoutPartitionEntryOff + (std::uint64_t)i * kPartInfoExSize;
            std::uint32_t entry_style = kread_val<std::uint32_t>(entry_va + kPartStyle);
            std::int64_t  entry_len   = kread_val<std::int64_t>(entry_va + kPartLengthOff);
            if (entry_style != kPartStyleGPT || entry_len <= 0) continue;
            char chg_name[56] = {};
            snprintf(chg_name, sizeof(chg_name), "GPT partition ID (%u)", i);
            patch_guid(chg_name, entry_va + kPartGptIdOff);
            ++patched;
        }
        return patched;
    }

    static bool has_layout_owner_storage(std::uint64_t ext_va) {
        const auto& off = g_disk_off();
        if (off.partmgr_layout_cache && valid_drive_layout(ext_va + off.partmgr_layout_cache))
            return true;
        if (off.partmgr_layout_pointer) {
            std::uint64_t layout_va = kread_val<std::uint64_t>(ext_va + off.partmgr_layout_pointer);
            if (is_kva(layout_va) && valid_drive_layout(layout_va)) return true;
        }
        return false;
    }

    static std::uint32_t patch_layout_owner(std::uint64_t ext_va, std::uint32_t salt) {
        const auto& off = g_disk_off();
        std::uint32_t patched = 0;
        if (off.partmgr_layout_cache)
            patched += patch_drive_layout(ext_va + off.partmgr_layout_cache, salt);
        if (off.partmgr_layout_pointer) {
            std::uint64_t layout_va = kread_val<std::uint64_t>(ext_va + off.partmgr_layout_pointer);
            if (is_kva(layout_va))
                patched += patch_drive_layout(layout_va, salt + 19);
        }
        return patched;
    }


    inline std::uint32_t patch_device(std::uint64_t dev_va, std::uint32_t index) {
        std::uint64_t ext_va = dev_extension(dev_va);
        if (!is_kva(ext_va)) return 0;
        std::uint32_t patched = 0;
        if (has_layout_owner_storage(ext_va)) {
            patched += patch_layout_owner(ext_va, index);
        } else {
            patched += patch_partition_extension(ext_va, index);
        }
        if (patched) logging::print("disk: partmgr device 0x%llx patched (%u fields)", dev_va, patched);
        return patched;
    }


    static std::uint32_t patch_device_heuristic(std::uint64_t dev_va) {
        std::uint64_t ext_va = dev_extension(dev_va);
        if (!is_kva(ext_va)) return 0;
        std::vector<std::uint8_t> ext(0x800);
        if (!kread(ext_va, ext.data(), ext.size())) return 0;

        for (std::uint32_t off = 0; off + (std::uint32_t)sizeof(std::uint32_t)*4 <= (std::uint32_t)ext.size(); off += 8) {
            std::uint32_t style  = *reinterpret_cast<const std::uint32_t*>(ext.data() + off);
            if (style != kPartStyleGPT) continue;
            if (off + 24 > (std::uint32_t)ext.size()) continue;
            std::int64_t length = *reinterpret_cast<const std::int64_t*>(ext.data() + off + 16);
            std::int64_t start  = *reinterpret_cast<const std::int64_t*>(ext.data() + off + 8);
            if (length <= 0 || length >= (std::int64_t)0x1000000000000000LL || start < 0) continue;

            if (off + 48 + 16 > (std::uint32_t)ext.size()) continue;

            // sibling cross-validation (volume_guid discipline): the shape
            // hit must also carry a plausible PARTITION_INFORMATION_EX
            // partition number and a non-zero GPT type GUID - a false
            // positive from another build's layout virtually never has
            // both siblings sane, so it cannot earn a write
            std::uint32_t part_number = *reinterpret_cast<const std::uint32_t*>(ext.data() + off + kPartNumberOff);
            if (!part_number || part_number >= 1024) continue;
            bool type_zero = true;
            for (int i = 0; i < 16; ++i)
                if (ext[off + kPartGptTypeOff + i]) { type_zero = false; break; }
            if (type_zero) {
                logging::print("disk: partmgr heuristic hit at ext+0x%x has zero GPT type GUID - skipped", off);
                continue;
            }
            std::uint8_t old_id[16] = {};
            bool have_old = kread(ext_va + off + 48, old_id, 16);
            bool id_zero = true;
            for (int i = 0; i < 16; ++i) if (old_id[i]) { id_zero = false; break; }
            if (!have_old || id_zero) {
                logging::print("disk: partmgr heuristic hit at ext+0x%x has zero partition ID - skipped", off);
                continue;
            }

            char chg_name[56] = {};
            snprintf(chg_name, sizeof(chg_name), "GPT partition ID (ext+0x%x)", off);
            patch_guid(chg_name, ext_va + off + 48);
            logging::print("disk: partmgr heuristic device 0x%llx patched at ext+0x%x", dev_va, off);
            return 1;
        }
        return 0;
    }

    inline void install() {
        const auto& off = g_disk_off();
        std::uint32_t patched = 0;
        std::uint32_t index = 0;
        enum_driver_devices(L"\\Driver\\partmgr", [&](std::uint64_t dev_va) {
            if (off.partmgr_partition_info_ex || off.partmgr_layout_cache) {
                patched += patch_device(dev_va, index++);
            } else {
                patched += patch_device_heuristic(dev_va);
                ++index;
            }
        });
        logging::print("disk: partmgr patched %u fields", patched);
    }

}
