#pragma once
#include "shared.hxx"
#include "disk_offsets.hxx"

namespace spoof::disk::mountmgr {
    using namespace helpers;

    static constexpr std::uint32_t kUniqueIdMax = 0x100;
    static constexpr std::uint32_t kMaxListEntries = 256;

    static bool is_valid_list_entry(std::uint64_t flink, std::uint64_t blink) {
        return is_kva(flink) && is_kva(blink);
    }

    // sibling cross-validation (volume_guid discipline) for the flink/blink
    // heuristic: a genuine LIST_ENTRY head is doubly linked - the head's
    // flink has its blink back at the head AND the head's blink has its
    // flink back at the head. a random pair of pool pointers that merely
    // look like kernel addresses virtually never satisfies both, so a
    // false-positive scan hit on a different build cannot earn a write
    static bool looks_like_list_head(std::uint64_t head_va) {
        std::uint64_t flink = kread_val<std::uint64_t>(head_va);
        std::uint64_t blink = kread_val<std::uint64_t>(head_va + 8);
        if (!is_valid_list_entry(flink, blink)) return false;
        if (flink == head_va && blink == head_va) return true;   // empty list
        return kread_val<std::uint64_t>(flink + 8) == head_va &&
               kread_val<std::uint64_t>(blink)     == head_va;
    }

    static void format_uid_txt(char* out, std::size_t out_size, const std::uint8_t* data, std::uint32_t length) {
        if (!out || !out_size || !data) return;
        out[0] = '\0';
        bool printable = length > 0;
        for (std::uint32_t i = 0; i < length; ++i) {
            if (data[i] < 0x20 || data[i] > 0x7e) { printable = false; break; }
        }
        if (printable) {
            std::uint32_t show = length < 32 ? length : 32;
            snprintf(out, out_size, "%.*s%s", (int)show, (const char*)data, length > 32 ? "..." : "");
            return;
        }
        std::uint32_t show = length < 16 ? length : 16;
        std::size_t pos = 0;
        for (std::uint32_t i = 0; i < show; ++i) {
            if (pos + 3 > out_size) break;
            snprintf(out + pos, out_size - pos, "%02X", data[i]);
            pos += 2;
        }
        if (length > show && pos + 4 <= out_size)
            snprintf(out + pos, out_size - pos, "...");
    }

    static void record_uid_change(const char* name, std::uint64_t data_va,
                                  const std::vector<std::uint8_t>& old_uid, std::uint32_t length) {
        if (!name || !length || old_uid.size() < length) return;
        std::vector<std::uint8_t> new_uid(length);
        if (!kread(data_va, new_uid.data(), length)) return;
        if (memcmp(old_uid.data(), new_uid.data(), length) == 0) return;
        char old_txt[80] = {}, new_txt[80] = {};
        format_uid_txt(old_txt, sizeof(old_txt), old_uid.data(), length);
        format_uid_txt(new_txt, sizeof(new_txt), new_uid.data(), length);
        logging::change("Disk", name, old_txt, new_txt, false);
    }

    static std::uint32_t patch_unique_id_buf(std::uint64_t buf_va) {
        if (!is_kva(buf_va)) return 0;
        std::uint16_t length = kread_val<std::uint16_t>(buf_va);
        if (!length || length > kUniqueIdMax) return 0;
        std::uint64_t data_va = buf_va + sizeof(std::uint16_t);

        std::uint8_t prefix[8] = {};
        kread(data_va, prefix, 8);

        std::vector<std::uint8_t> old_uid(length);
        bool have_old = kread(data_va, old_uid.data(), length);

        static const std::uint8_t dmio[] = { 'D','M','I','O',':','I','D',':' };
        if (length >= 24 && memcmp(prefix, dmio, 8) == 0) {
            spoof_guid_va(data_va + 8);
            if (have_old) record_uid_change("unique ID (DMIO:ID:)", data_va, old_uid, length);
            return 1;
        } else if (length == 16) {
            spoof_guid_va(data_va);
            if (have_old) record_uid_change("unique ID (GUID)", data_va, old_uid, length);
            return 1;
        } else if (length >= 2) {
            spoof_general_buf_va(data_va, length);
            if (have_old) record_uid_change("unique ID", data_va, old_uid, length);
            return 1;
        }
        return 0;
    }

    static std::uint32_t walk_mounted_list(std::uint64_t head_va, std::uint32_t unique_id_off) {
        std::uint64_t flink = kread_val<std::uint64_t>(head_va);
        std::uint64_t blink = kread_val<std::uint64_t>(head_va + 8);
        if (!is_valid_list_entry(flink, blink)) return 0;
        // back-reference cross-check: only a genuine doubly linked list
        // passes - a stray pointer pair inside some other structure fails
        if (!looks_like_list_head(head_va)) return 0;

        std::uint32_t patched = 0;
        std::uint32_t visited = 0;
        std::uint64_t entry = flink;
        while (entry != head_va && visited < kMaxListEntries && is_kva(entry)) {
            std::uint64_t next = kread_val<std::uint64_t>(entry);
            if (!is_kva(next)) break;
            // sibling: the entry's own blink must also be a kernel link
            if (!is_kva(kread_val<std::uint64_t>(entry + 8))) break;

            if (unique_id_off) {
                std::uint64_t uid_slot_va = entry + unique_id_off;
                std::uint64_t uid_va = kread_val<std::uint64_t>(uid_slot_va);
                if (is_kva(uid_va)) patched += patch_unique_id_buf(uid_va);
            } else {

                std::uint8_t entry_data[128] = {};
                if (kread(entry, entry_data, sizeof(entry_data))) {
                    for (std::uint32_t k = 0; k + 8 <= (std::uint32_t)sizeof(entry_data); k += 8) {
                        std::uint64_t ptr = *reinterpret_cast<const std::uint64_t*>(entry_data + k);
                        if (!is_kva(ptr)) continue;
                        std::uint16_t uid_len = kread_val<std::uint16_t>(ptr);
                        if (uid_len >= 4 && uid_len <= kUniqueIdMax) {
                            patched += patch_unique_id_buf(ptr);
                            if (patched) break;
                        }
                    }
                }
            }

            entry = next;
            ++visited;
        }
        return patched;
    }

    static std::uint32_t patch_mountmgr_device(std::uint64_t dev_va) {
        std::uint64_t ext_va = dev_extension(dev_va);
        if (!is_kva(ext_va)) return 0;

        const auto& off = g_disk_off();
        std::uint32_t patched = 0;

        if (off.mountmgr_device_mounted_list) {
            std::uint64_t head_va = ext_va + off.mountmgr_device_mounted_list;
            patched += walk_mounted_list(head_va, off.mountmgr_mounted_unique_id);
        } else {

            std::vector<std::uint8_t> ext(0x400);
            if (!kread(ext_va, ext.data(), ext.size())) return 0;

            for (std::uint32_t o = 0; o + 16 <= (std::uint32_t)ext.size(); o += 8) {
                std::uint64_t flink = *reinterpret_cast<const std::uint64_t*>(ext.data() + o);
                std::uint64_t blink = *reinterpret_cast<const std::uint64_t*>(ext.data() + o + 8);
                if (!is_valid_list_entry(flink, blink)) continue;
                std::uint64_t head_va = ext_va + o;
                // both neighbours must point back at the candidate head  -
                // the flink/blink shape alone is not enough to trust a hit
                if (!looks_like_list_head(head_va)) continue;
                std::uint32_t p = walk_mounted_list(head_va, 0 );
                if (p) { patched += p; break; }
            }
        }

        if (patched) logging::print("disk: mountmgr device 0x%llx patched %u unique IDs", dev_va, patched);
        return patched;
    }

    inline void install() {
        std::uint32_t patched = 0;
        enum_driver_devices(L"\\Driver\\mountmgr", [&](std::uint64_t dev_va) {
            patched += patch_mountmgr_device(dev_va);
        });
        logging::print("disk: mountmgr patched %u unique IDs", patched);
    }

}
