#pragma once
#include "shared.hxx"
#include "disk_offsets.hxx"

namespace spoof::disk::stornvme {
    void sync_adapter_serial_cache(std::uint64_t unit_ext_va, const char* ser_buf, std::uint16_t ser_len);
    void patch_namespace_identity(std::uint64_t unit_ext_va, const char* ser_buf, std::uint16_t ser_len);
}

namespace spoof::disk::storport {
    using namespace helpers;

    struct RaidExtLayout {
        std::uint32_t serial_string_off;
        std::uint32_t device_id_ptr_off;
        std::uint32_t rich_desc_ptr_off;
        std::uint32_t vendor_id_off;
    };

    inline RaidExtLayout current_raid_layout() {
        const auto& d = g_disk_off();
        return {
            d.raid_unit_identity + d.stor_identity_serial_number,
            d.raid_unit_identity + d.stor_identity_device_id,
            d.raid_unit_identity + d.stor_identity_rich_device_description,
            d.raid_unit_vendor_id,
        };
    }

    inline bool ascii_contains_eui(const std::uint8_t* buf, std::uint32_t len) {
        if (!buf || len < 4) return false;
        for (std::uint32_t i = 0; i + 3 < len; ++i) {
            if ((buf[i]|0x20)=='e' && (buf[i+1]|0x20)=='u' && (buf[i+2]|0x20)=='i') return true;
        }
        return false;
    }


    inline std::uint32_t patch_vpd_identification_page(std::uint64_t page_va,
                                                   const char* ser_buf, std::uint16_t ser_len) {
        if (!page_va || !ser_buf || !ser_len) return 0;


        std::uint8_t hdr[4] = {};
        if (!kread(page_va, hdr, 4)) return 0;
        std::uint32_t page_data_len = ((std::uint32_t)hdr[2] << 8) | hdr[3];
        if (page_data_len < 4 || page_data_len > 0x1000) return 0;
        std::uint32_t total_len = page_data_len + 4;

        std::vector<std::uint8_t> page(total_len);
        if (!kread(page_va, page.data(), total_len)) return 0;

        std::uint32_t patched = 0;
        for (std::uint32_t off = 4; off + 4 <= total_len; ) {
            std::uint8_t* desc = page.data() + off;
            std::uint8_t code_set  = desc[0] & 0x0f;
            std::uint8_t id_type   = desc[1] & 0x0f;
            std::uint8_t id_len    = desc[3];
            if (!id_len || off + 4 + id_len > total_len) break;

            if ((id_type==2||id_type==3||id_type==8||id_type==0) &&
                (id_len==8||id_len==16||id_len==20)) {

                std::uint8_t old_id[20] = {};
                memcpy(old_id, desc+4, id_len);
                if (!s_serial_len) ensure_canonical_from_bytes(desc+4, id_len);
                if (s_identity_len) {
                    if (id_len <= s_identity_len) {
                        std::uint32_t src = s_identity_len - id_len;
                        memcpy(desc+4, s_identity+src, id_len);
                    } else {
                        for (std::uint32_t i = 0; i < id_len; ++i)
                            desc[4+i] = s_identity[i % s_identity_len];
                    }
                }
                if (memcmp(old_id, desc+4, id_len) != 0) {
                    char old_txt[80] = {}, new_txt[80] = {};
                    format_hex_bytes(old_txt, sizeof(old_txt), old_id, id_len);
                    format_hex_bytes(new_txt, sizeof(new_txt), desc+4, id_len);
                    logging::change("Disk", "VPD page device ID", old_txt, new_txt, true);
                }
                ++patched;
            } else if ((code_set==2||code_set==3) && id_len <= 128 &&
                       (ascii_contains_eui(desc+4, id_len) ||
                        ascii_printable(reinterpret_cast<char*>(desc+4), id_len))) {

                char old_serial[129] = {};
                memcpy(old_serial, desc+4, id_len);
                if (s_serial_len) {
                    char* cbuf = reinterpret_cast<char*>(desc+4);
                    std::uint32_t start = 0;
                    if (id_len > 4 && (cbuf[0]|0x20)=='e' && (cbuf[1]|0x20)=='u' && (cbuf[2]|0x20)=='i' && cbuf[3]=='.')
                        start = 4;
                    std::uint32_t src = 0;
                    for (std::uint32_t i = start; i < id_len; ++i) {
                        if (start!=4 && (cbuf[i]=='.'||cbuf[i]=='_'||cbuf[i]=='-'||cbuf[i]==' ')) continue;
                        while (src < s_serial_len && (s_serial[src]=='_'||s_serial[src]=='-'||s_serial[src]==' ')) ++src;
                        cbuf[i] = src < s_serial_len ? s_serial[src++] : '0';
                    }
                }
                if (memcmp(old_serial, desc+4, id_len) != 0) {
                    char old_txt[132] = {}, new_txt[132] = {};
                    snprintf(old_txt, sizeof(old_txt), "%.*s", (int)id_len, old_serial);
                    snprintf(new_txt, sizeof(new_txt), "%.*s", (int)id_len, reinterpret_cast<char*>(desc+4));
                    logging::change("Disk", "VPD page serial", old_txt, new_txt, true);
                }
                ++patched;
            }
            off += 4 + id_len;
        }

        if (patched) {
            if (!kwrite_verified(page_va, page.data(), total_len, "storport: VPD page"))
                return 0;
        }
        return patched;
    }

    inline bool valid_ansi_serial_at(std::uint64_t ext_va, std::uint32_t string_off) {
        if (!ext_va || !string_off) return false;
        kern_ansi_string as{};
        if (!kread(ext_va + string_off, &as, sizeof(as))) return false;
        if (!as.Length || as.Length > 128 || as.MaximumLength < as.Length) return false;
        if (!is_kva(as.Buffer)) return false;
        char tmp[129] = {};
        if (!kread(as.Buffer, tmp, as.Length)) return false;
        return ascii_printable(tmp, as.Length);
    }

    inline bool raid_layout_matches(std::uint64_t ext_va, const RaidExtLayout& layout) {
        return valid_ansi_serial_at(ext_va, layout.serial_string_off);
    }

    inline void scramble_ascii_va(std::uint64_t buf_va, std::uint32_t length) {
        if (!buf_va || !length) return;
        std::vector<char> buf(length + 1, '\0');
        if (!kread(buf_va, buf.data(), length)) return;
        if (!ascii_printable(buf.data(), length)) return;
        for (std::uint32_t i = 0; i < length; ++i) {
            if (buf[i]==' '||buf[i]=='-'||buf[i]=='_') continue;
            buf[i] = (char)('A' + ((unsigned char)buf[i] + i*13) % 26);
        }
        kwrite_verified(buf_va, buf.data(), length, "storport: ascii id");
    }

    inline bool is_standard_vendor_id(const char* s, std::uint32_t len) {
        if (!s) return false;
        std::uint32_t n = len;
        while (n && (s[n-1] == ' ' || s[n-1] == '\0')) --n;
        auto eq = [&](const char* lit, std::uint32_t ll) {
            if (n != ll) return false;
            for (std::uint32_t i = 0; i < ll; ++i)
                if ((s[i]|0x20) != (lit[i]|0x20)) return false;
            return true;
        };
        // "NVMe"/"ATA" are bus-standard constants - every unit of that bus
        // type reports the same one, so scrambling them is a fingerprint
        // tell; only a real per-OEM vendor string is identity worth spoiling
        return eq("NVMe", 4) || eq("ATA", 3);
    }

    inline void patch_rich_description_va(std::uint64_t ext_va, const RaidExtLayout& layout) {
        if (!ext_va || !layout.rich_desc_ptr_off) return;
        std::uint64_t rich_slot_va = ext_va + layout.rich_desc_ptr_off;
        std::uint64_t rich_va = kread_val<std::uint64_t>(rich_slot_va);
        if (!is_kva(rich_va)) return;
        const auto& off = g_disk_off();
        if (off.rich_desc_vendor_id) {
            std::uint64_t vendor_va = rich_va + off.rich_desc_vendor_id;
            char old_vendor[17] = {};
            bool have_old = kread(vendor_va, old_vendor, 16);
            if (!have_old || !is_standard_vendor_id(old_vendor, 16)) {
                scramble_ascii_va(vendor_va, 16);
                char new_vendor[17] = {};
                kread(vendor_va, new_vendor, 16);
                if (have_old && strcmp(old_vendor, new_vendor) != 0)
                    logging::change("Disk", "vendor ID (rich desc)", old_vendor, new_vendor, true);
            }
        }
    }

    inline void patch_raid_device_id_page_va(std::uint64_t ext_va, const RaidExtLayout& layout,
                                              const char* ser_buf, std::uint16_t ser_len) {
        if (!ext_va || !layout.device_id_ptr_off || !ser_buf || !ser_len) return;
        std::uint64_t dev_id_slot_va = ext_va + layout.device_id_ptr_off;
        std::uint64_t dev_id_va = kread_val<std::uint64_t>(dev_id_slot_va);
        if (!is_kva(dev_id_va)) {
            logging::print("disk: RAID VPD device-id slot at +0x%x -> not a KVA", layout.device_id_ptr_off);
            return;
        }
        std::uint32_t p = patch_vpd_identification_page(dev_id_va, ser_buf, ser_len);
        if (p) logging::print("disk: RAID VPD device-id page patched (%u identifiers)", p);
    }

    inline void patch_raid_extension_extras_va(std::uint64_t ext_va, const RaidExtLayout& layout) {
        if (!ext_va) return;
        if (layout.vendor_id_off) {
            std::uint64_t vendor_va = ext_va + layout.vendor_id_off;
            char old_vendor[9] = {};
            bool have_old = kread(vendor_va, old_vendor, 8);
            if (!have_old || !is_standard_vendor_id(old_vendor, 8)) {
                scramble_ascii_va(vendor_va, 8);
                char new_vendor[9] = {};
                kread(vendor_va, new_vendor, 8);
                if (have_old && strcmp(old_vendor, new_vendor) != 0)
                    logging::change("Disk", "vendor ID (unit ext)", old_vendor, new_vendor, true);
            }
        }
        patch_rich_description_va(ext_va, layout);
    }

    inline void spoof_raid_units(const wchar_t* driver_name, bool sync_nvme) {
        if (!driver_name) return;
        if (!g_disk_off().raid_unit_identity) {
            logging::print("disk: storport skipping %ls - disk offsets not resolved", driver_name);
            return;
        }

        const RaidExtLayout layout = current_raid_layout();
        std::uint32_t patched = 0;

        enum_driver_devices(driver_name, [&](std::uint64_t dev_va) {
            if (dev_type(dev_va) != kDevTypeDisk) return;
            std::uint64_t ext_va = dev_extension(dev_va);
            if (!is_kva(ext_va)) return;

            if (!raid_layout_matches(ext_va, layout)) return;

            kern_ansi_string as{};
            if (!kread(ext_va + layout.serial_string_off, &as, sizeof(as))) return;
            if (!as.Length || as.Length > 128 || !is_kva(as.Buffer)) return;

            char cur_serial[129] = {};
            kread(as.Buffer, cur_serial, as.Length);
            ensure_canonical(cur_serial, as.Length);
            if (!s_serial_len) return;

            logging::print("disk: RAID[%ls] serial before '%.*s'", driver_name, (int)as.Length, cur_serial);

            if (sync_nvme) {
                stornvme::sync_adapter_serial_cache(ext_va, s_serial, s_serial_len);
                stornvme::patch_namespace_identity(ext_va, s_serial, s_serial_len);
            }

            std::uint64_t len_va = ext_va + layout.serial_string_off;
            std::size_t cap = as.MaximumLength ? (std::size_t)as.MaximumLength : (std::size_t)as.Length;
            std::size_t copy = (std::size_t)s_serial_len < cap - 1 ? (std::size_t)s_serial_len : cap - 1;
            char new_serial[96] = {};
            snprintf(new_serial, sizeof(new_serial), "%.*s", (int)copy, s_serial);
            if (s_trailing && copy + 1 < cap) {
                std::size_t tail = strlen(new_serial);
                snprintf(new_serial + tail, sizeof(new_serial) - tail, "%c", s_trailing);
            }
            write_canonical(as.Buffer, as.MaximumLength ? as.MaximumLength : as.Length, len_va);
            char chg_name[56] = {};
            snprintf(chg_name, sizeof(chg_name), "RAID serial (%ls)", driver_name);
            logging::change("Disk", chg_name, cur_serial, new_serial, true);

            if (sync_nvme) {
                stornvme::sync_adapter_serial_cache(ext_va, s_serial, s_serial_len);
                stornvme::patch_namespace_identity(ext_va, s_serial, s_serial_len);
            }

            patch_raid_extension_extras_va(ext_va, layout);
            patch_raid_device_id_page_va(ext_va, layout, s_serial, s_serial_len);
            ++patched;

            logging::print("disk: RAID[%ls] serial after '%.*s'", driver_name, (int)s_serial_len, s_serial);
        });

        logging::print("disk: storport patched %u RAID units (%ls)", patched, driver_name);
    }

}
