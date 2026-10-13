#pragma once
#include "shared.hxx"
#include "disk_offsets.hxx"

namespace spoof::disk::stornvme {
    using namespace helpers;

    static bool id_descriptor_has_identity(std::uint8_t type, std::uint8_t len) {
        return (type==1&&len==8)||(type==2&&len==16)||(type==3&&len==16);
    }

    static bool ansi_serial_to_wide(const char* ser_buf, std::uint16_t ser_len,
                                     wchar_t* out_wide, std::uint16_t out_chars) {
        if (!ser_buf || !ser_len || !out_wide || !out_chars) return false;
        int r = MultiByteToWideChar(CP_ACP, 0, ser_buf, (int)ser_len,
                                     out_wide, (int)(out_chars - 1));
        if (r <= 0) return false;
        out_wide[r] = L'\0';
        return true;
    }

    static void record_id_change(const char* name, std::uint64_t buf_va,
                                 const std::uint8_t* old_bytes, std::uint32_t length) {
        if (!name || !buf_va || !length || length > 64) return;
        std::uint8_t new_bytes[64] = {};
        if (!kread(buf_va, new_bytes, length)) return;
        if (memcmp(old_bytes, new_bytes, length) == 0) return;
        char old_txt[80] = {};
        char new_txt[80] = {};
        format_hex_bytes(old_txt, sizeof(old_txt), old_bytes, length);
        format_hex_bytes(new_txt, sizeof(new_txt), new_bytes, length);
        logging::change("Disk", name, old_txt, new_txt, true);
    }

    static bool sync_wide_serial_cache_slot(std::uint64_t slot_va, const wchar_t* wide_buf, std::uint16_t wide_len) {
        if (!slot_va || !wide_buf || !wide_len) return false;
        std::size_t bytes = (wide_len + 1) * sizeof(wchar_t);
        std::uint64_t cur = kread_val<std::uint64_t>(slot_va);
        if (is_kva(cur)) {
            wchar_t old_wide[64] = {};
            char old_txt[168] = {};
            bool have_old = kread(cur, old_wide, sizeof(old_wide) - sizeof(wchar_t));
            if (have_old) {
                old_wide[63] = L'\0';
                snprintf(old_txt, sizeof(old_txt), "%ls", old_wide);
            }
            // identity gate: the slot must point at a buffer we can read  -
            // an unreadable target means the offset is wrong for this build
            if (!kwrite_verified(cur, wide_buf, bytes, "stornvme: serial cache")) return false;
            char new_txt[168] = {};
            snprintf(new_txt, sizeof(new_txt), "%ls", wide_buf);
            if (have_old && strcmp(old_txt, new_txt) != 0)
                logging::change("Disk", "adapter serial cache", old_txt, new_txt, true);
            return true;
        }

        std::uint64_t ex_alloc = pdb::get_symbol_address("ExAllocatePoolWithTag");
        if (!ex_alloc) return false;
        std::uint64_t new_buf = call_fn<std::uint64_t>(ex_alloc,
            (std::uint64_t)512,
            (std::uint64_t)bytes,
            (std::uint64_t)0x6b627344u);
        if (!is_kva(new_buf)) return false;
        if (!kwrite_verified(new_buf, wide_buf, bytes, "stornvme: fresh serial cache")) return false;
        char new_txt[168] = {};
        snprintf(new_txt, sizeof(new_txt), "%ls", wide_buf);
        logging::change("Disk", "adapter serial cache", "(none)", new_txt, true);
        if (!kwrite_verified(slot_va, &new_buf, sizeof(new_buf), "stornvme: serial cache slot"))
            return false;
        return true;
    }

    static std::uint64_t resolve_raid_adapter(std::uint64_t unit_ext_va) {
        const auto& off = g_disk_off();
        if (!off.raid_unit_adapter) return 0;
        return kread_val<std::uint64_t>(unit_ext_va + off.raid_unit_adapter);
    }

    static std::uint64_t resolve_nvme_adapter_extension(std::uint64_t raid_adapter_va) {
        const auto& off = g_disk_off();
        if (!off.raid_adapter_miniport || !off.raid_miniport_private_device_ext) return 0;
        if (!is_kva(raid_adapter_va)) return 0;
        std::uint64_t private_slot_va = raid_adapter_va + off.raid_adapter_miniport + off.raid_miniport_private_device_ext;
        std::uint64_t private_wrapper = kread_val<std::uint64_t>(private_slot_va);
        if (!is_kva(private_wrapper)) return 0;
        if (!off.raid_hw_device_extension) return 0;
        return private_wrapper + off.raid_hw_device_extension;
    }

    static std::uint32_t patch_descriptor_list(std::uint64_t descriptor_va,
                                           const char* ser_buf, std::uint16_t ser_len) {
        if (!descriptor_va || !ser_buf || !ser_len) return 0;
        std::uint32_t patched = 0;
        std::uint32_t desc_off = 0;
        for (;;) {
            std::uint8_t entry[4 + 20] = {};
            if (!kread(descriptor_va + desc_off, entry, sizeof(entry))) break;
            std::uint8_t type   = entry[0];
            std::uint8_t length = entry[1];
            if (!type || !length) break;
            std::uint32_t next = desc_off + length + 4;
            if (next <= desc_off || next > 0x1000) break;
            if (id_descriptor_has_identity(type, length)) {
                std::uint64_t ident_va = descriptor_va + desc_off + 4;
                std::uint8_t old_ident[16] = {};
                bool have_old = kread(ident_va, old_ident, length);
                fill_identity_bytes(ident_va, length);
                if (have_old) {
                    const char* ident_name =
                        type==1 ? "NVMe namespace EUI64" :
                        type==2 ? "NVMe namespace NGUID" : "NVMe namespace UUID";
                    record_id_change(ident_name, ident_va, old_ident, length);
                }
                ++patched;
            }
            desc_off = next;
            if (desc_off >= 0x1000) break;
        }
        return patched;
    }

    static std::uint32_t patch_identify_namespace(std::uint64_t identify_va) {
        const auto& off = g_disk_off();
        std::uint32_t patched = 0;
        if (off.nvme_identify_namespace_nguid && is_kva(identify_va)) {
            std::uint64_t nguid_va = identify_va + off.nvme_identify_namespace_nguid;
            std::uint8_t old_nguid[16] = {};
            bool have_old = kread(nguid_va, old_nguid, 16);
            fill_identity_bytes(nguid_va, 16);
            if (have_old) record_id_change("NVMe namespace NGUID", nguid_va, old_nguid, 16);
            ++patched;
        }
        if (off.nvme_identify_namespace_eui64 && is_kva(identify_va)) {
            std::uint64_t eui64_va = identify_va + off.nvme_identify_namespace_eui64;
            std::uint8_t old_eui64[8] = {};
            bool have_old = kread(eui64_va, old_eui64, 8);
            fill_identity_bytes(eui64_va, 8);
            if (have_old) record_id_change("NVMe namespace EUI64", eui64_va, old_eui64, 8);
            ++patched;
        }
        return patched;
    }

    static bool patch_identify_controller_ieee(std::uint64_t identify_va) {
        const auto& off = g_disk_off();
        if (!identify_va || !off.nvme_identify_controller_ieee) return false;
        std::uint64_t ieee_va = identify_va + off.nvme_identify_controller_ieee;
        std::uint8_t old_ieee[3] = {};
        bool have_old = kread(ieee_va, old_ieee, 3);
        fill_identity_bytes(ieee_va, 3);
        if (have_old) record_id_change("NVMe controller IEEE", ieee_va, old_ieee, 3);
        return true;
    }

    static bool patch_identify_controller_serial(std::uint64_t identify_va,
                                                   const char* ser_buf, std::uint16_t ser_len) {
        const auto& off = g_disk_off();
        if (!identify_va || !off.nvme_identify_controller_serial || !ser_buf || !ser_len) return false;
        std::uint64_t serial_va = identify_va + off.nvme_identify_controller_serial;
        char old_serial[21] = {};
        bool have_old = kread(serial_va, old_serial, 20);
        fill_identity_ascii(serial_va, 20);
        if (have_old) {
            char new_serial[21] = {};
            kread(serial_va, new_serial, 20);
            if (memcmp(old_serial, new_serial, 20) != 0) {
                // identify serials are space-padded - trim so the summary shows
                // the string a tool would print
                std::uint32_t old_len = 20, new_len = 20;
                while (old_len && (old_serial[old_len-1]==' ' || old_serial[old_len-1]=='\0')) --old_len;
                while (new_len && (new_serial[new_len-1]==' ' || new_serial[new_len-1]=='\0')) --new_len;
                char old_txt[24] = {}, new_txt[24] = {};
                snprintf(old_txt, sizeof(old_txt), "%.*s", (int)old_len, old_serial);
                snprintf(new_txt, sizeof(new_txt), "%.*s", (int)new_len, new_serial);
                logging::change("Disk", "NVMe controller serial", old_txt, new_txt, true);
            }
        }
        return true;
    }

    static bool patch_identify_controller(std::uint64_t identify_va,
                                           const char* ser_buf, std::uint16_t ser_len) {
        bool p = patch_identify_controller_serial(identify_va, ser_buf, ser_len);
        p = patch_identify_controller_ieee(identify_va) || p;
        return p;
    }

    static bool patch_internal_identify_controller(std::uint64_t nvme_ext_va,
                                                    const char* ser_buf, std::uint16_t ser_len) {
        const auto& off = g_disk_off();
        if (!nvme_ext_va || !off.stornvme_internal_identify_controller) return false;
        std::uint64_t identify_slot_va = nvme_ext_va + off.stornvme_internal_identify_controller;
        std::uint64_t identify_va = kread_val<std::uint64_t>(identify_slot_va);
        if (!is_kva(identify_va)) return false;
        return patch_identify_controller(identify_va, ser_buf, ser_len);
    }

    static std::uint32_t patch_private_namespace_entry(std::uint64_t entry_va) {
        const auto& off = g_disk_off();
        if (!entry_va) return 0;
        std::uint32_t patched = 0;
        if (off.stornvme_namespace_nguid) {
            std::uint64_t nguid_va = entry_va + off.stornvme_namespace_nguid;
            std::uint8_t old_nguid[16] = {};
            bool have_old = kread(nguid_va, old_nguid, 16);
            fill_identity_bytes(nguid_va, 16);
            if (have_old) record_id_change("NVMe namespace NGUID", nguid_va, old_nguid, 16);
            ++patched;
        }
        if (off.stornvme_namespace_eui64) {
            std::uint64_t eui64_va = entry_va + off.stornvme_namespace_eui64;
            std::uint8_t old_eui64[8] = {};
            bool have_old = kread(eui64_va, old_eui64, 8);
            fill_identity_bytes(eui64_va, 8);
            if (have_old) record_id_change("NVMe namespace EUI64", eui64_va, old_eui64, 8);
            ++patched;
        }
        return patched;
    }

    static std::uint32_t patch_private_namespace_table(std::uint64_t nvme_ext_va,
                                                    const char* ser_buf, std::uint16_t ser_len) {
        const auto& off = g_disk_off();
        if (!nvme_ext_va || !off.stornvme_namespace_count || !off.stornvme_namespace_table) return 0;
        std::uint32_t count = kread_val<std::uint32_t>(nvme_ext_va + off.stornvme_namespace_count);
        if (!count || count > 1024) return 0;
        std::uint32_t patched = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint64_t ns_slot_va = nvme_ext_va + off.stornvme_namespace_table + (std::uint64_t)i * sizeof(std::uint64_t);
            std::uint64_t entry_va = kread_val<std::uint64_t>(ns_slot_va);
            if (!is_kva(entry_va)) continue;
            patched += patch_private_namespace_entry(entry_va);
        }
        return patched;
    }

    static bool patch_controller_identify_data(std::uint64_t nvme_ext_va,
                                                const char* ser_buf, std::uint16_t ser_len) {
        const auto& off = g_disk_off();
        if (!nvme_ext_va || !off.nvme_adapter_controller) return false;
        std::uint64_t controller_slot_va = nvme_ext_va + off.nvme_adapter_controller;
        std::uint64_t controller_va = kread_val<std::uint64_t>(controller_slot_va);
        if (!is_kva(controller_va)) return false;
        if (!off.nvme_controller_identify_controller_data) return false;
        std::uint64_t identify_slot_va = controller_va + off.nvme_controller_identify_controller_data;
        std::uint64_t identify_va = kread_val<std::uint64_t>(identify_slot_va);
        if (is_kva(identify_va)) {
            if (patch_identify_controller(identify_va, ser_buf, ser_len)) return true;
        }

        return patch_identify_controller(controller_va + off.nvme_controller_identify_controller_data,
                                          ser_buf, ser_len);
    }

    inline void patch_namespace_identity(std::uint64_t unit_ext_va, const char* ser_buf, std::uint16_t ser_len) {
        if (!unit_ext_va || !ser_buf || !ser_len) return;
        const auto& off = g_disk_off();
        std::uint32_t patched = 0;

        if (off.raid_unit_identify_namespace_data) {
            std::uint64_t identify_slot_va = unit_ext_va + off.raid_unit_identify_namespace_data;
            std::uint64_t identify_va = kread_val<std::uint64_t>(identify_slot_va);
            if (is_kva(identify_va))
                patched += patch_identify_namespace(identify_va);
        }

        if (off.raid_unit_unit_extension) {
            std::uint64_t ns_slot_va = unit_ext_va + off.raid_unit_unit_extension;
            std::uint64_t ns_ext_va = kread_val<std::uint64_t>(ns_slot_va);
            if (is_kva(ns_ext_va)) {
                if (off.nvme_namespace_identify_descriptor) {
                    std::uint64_t desc_slot_va = ns_ext_va + off.nvme_namespace_identify_descriptor;
                    std::uint64_t desc_va = kread_val<std::uint64_t>(desc_slot_va);
                    if (is_kva(desc_va))
                        patched += patch_descriptor_list(desc_va, ser_buf, ser_len);
                }
                if (off.nvme_namespace_identify_data) {
                    std::uint64_t id_slot_va = ns_ext_va + off.nvme_namespace_identify_data;
                    std::uint64_t id_va = kread_val<std::uint64_t>(id_slot_va);
                    if (is_kva(id_va))
                        patched += patch_identify_namespace(id_va);
                }
            }
        }

        std::uint64_t raid_adapter_va = resolve_raid_adapter(unit_ext_va);
        std::uint64_t nvme_ext_va = is_kva(raid_adapter_va) ? resolve_nvme_adapter_extension(raid_adapter_va) : 0;
        if (is_kva(nvme_ext_va)) {
            if (patch_internal_identify_controller(nvme_ext_va, ser_buf, ser_len)) ++patched;
            patched += patch_private_namespace_table(nvme_ext_va, ser_buf, ser_len);
        }

        if (patched) logging::print("disk: stornvme namespace identity patched (%u)", patched);
    }

    inline void sync_adapter_serial_cache(std::uint64_t unit_ext_va, const char* ser_buf, std::uint16_t ser_len) {
        if (!unit_ext_va || !ser_buf || !ser_len) return;
        std::uint64_t raid_adapter_va = resolve_raid_adapter(unit_ext_va);
        if (!is_kva(raid_adapter_va)) return;

        wchar_t wide_buf[128] = {};
        if (!ansi_serial_to_wide(ser_buf, ser_len, wide_buf, 128)) return;
        std::uint16_t wide_len = (std::uint16_t)wcslen(wide_buf);

        const auto& off = g_disk_off();


        std::uint64_t raid_cache_slot_va = 0;
        if (off.raid_adapter_serial_number) {
            raid_cache_slot_va = raid_adapter_va + off.raid_adapter_serial_number;
            sync_wide_serial_cache_slot(raid_cache_slot_va, wide_buf, wide_len);
        }

        std::uint64_t nvme_ext_va = resolve_nvme_adapter_extension(raid_adapter_va);
        if (!is_kva(nvme_ext_va)) return;


        if (off.nvme_adapter_serial_number) {
            std::uint64_t nvme_cache_slot_va = nvme_ext_va + off.nvme_adapter_serial_number;
            std::uint64_t nvme_cache_cur = kread_val<std::uint64_t>(nvme_cache_slot_va);
            if (raid_cache_slot_va) {
                std::uint64_t raid_cache = kread_val<std::uint64_t>(raid_cache_slot_va);
                if (is_kva(raid_cache) && !is_kva(nvme_cache_cur)) {
                    // adopt the sibling raid slot's (already synced) buffer;
                    // readback-verified so a bad slot write cannot leave a
                    // half-updated pointer behind
                    kwrite_verified(nvme_cache_slot_va, &raid_cache, sizeof(raid_cache),
                                    "stornvme: nvme cache slot");
                } else {
                    sync_wide_serial_cache_slot(nvme_cache_slot_va, wide_buf, wide_len);
                }
            } else {
                sync_wide_serial_cache_slot(nvme_cache_slot_va, wide_buf, wide_len);
            }
        }

        bool ctrl_patched = patch_controller_identify_data(nvme_ext_va, ser_buf, ser_len);
        ctrl_patched = patch_internal_identify_controller(nvme_ext_va, ser_buf, ser_len) || ctrl_patched;
        std::uint32_t ns_patched = patch_private_namespace_table(nvme_ext_va, ser_buf, ser_len);

        if (ctrl_patched) logging::print("disk: stornvme identify controller caches patched");
        if (ns_patched)   logging::print("disk: stornvme private namespace table patched (%u)", ns_patched);
    }

    inline void install() {


    }

}
