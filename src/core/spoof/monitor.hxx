#pragma once
#include "helpers.hxx"
#include "../../symbols/pdb_offsets.hxx"
#include <vector>
#include <winreg.h>

namespace monitor {

    static void patch_edid_binary(HKEY hk) {
        DWORD sz = 0, type = 0;
        RegQueryValueExW(hk, L"EDID", nullptr, &type, nullptr, &sz);
        if (!sz || type != REG_BINARY || sz < 128) return;

        std::vector<std::uint8_t> edid(sz);
        if (RegQueryValueExW(hk, L"EDID", nullptr, &type,
                             edid.data(), &sz) != ERROR_SUCCESS) return;

        static constexpr std::uint8_t HDR[8] = {
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
        };
        if (memcmp(edid.data(), HDR, 8) != 0) return;

        using namespace spoof::helpers;

        const std::uint8_t old_serial[4] = { edid[12], edid[13], edid[14], edid[15] };
        bool desc_hit[4] = {};
        char old_desc[4][9] = {};

        // all-identical serial bytes are the vendor "no serial" default
        // (01010101, 00000000 ...) - keep them stock; random hex where the
        // model ships a placeholder is a fingerprint tell
        const bool serial_stock = old_serial[0] == old_serial[1] &&
                                  old_serial[1] == old_serial[2] &&
                                  old_serial[2] == old_serial[3];
        if (!serial_stock) {
            edid[12] = static_cast<std::uint8_t>(rand_next());
            edid[13] = static_cast<std::uint8_t>(rand_next());
            edid[14] = static_cast<std::uint8_t>(rand_next());
            edid[15] = static_cast<std::uint8_t>(rand_next());
        }

        for (int d = 0; d < 4; ++d) {
            const int base = 54 + d * 18;
            if (edid[base] != 0 || edid[base+1] != 0 || edid[base+2] != 0) continue;
            if (edid[base+3] != 0xFF) continue;
            bool desc_stock = true;
            for (int s = 1; s < 8; ++s)
                if (edid[base + 5 + s] != edid[base + 5]) { desc_stock = false; break; }
            if (desc_stock) continue;   // placeholder descriptor, keep stock
            desc_hit[d] = true;
            for (int s = 0; s < 8; ++s) {
                const std::uint8_t ch = edid[base + 5 + s];
                old_desc[d][s] = ch >= 0x20 && ch <= 0x7E ? static_cast<char>(ch) : '.';
            }
            for (int s = 0; s < 8; ++s) {
                const std::uint8_t r = static_cast<std::uint8_t>(rand_next() % 36);
                edid[base + 5 + s] = r < 10 ? static_cast<std::uint8_t>('0' + r)
                                             : static_cast<std::uint8_t>('A' + r - 10);
            }
            edid[base+13] = 0x0A;
            edid[base+14] = edid[base+15] = edid[base+16] = edid[base+17] = 0x20;
        }

        std::uint8_t sum = 0;
        for (int s = 0; s < 127; ++s) sum += edid[s];
        edid[127] = static_cast<std::uint8_t>(256u - sum);

        RegSetValueExW(hk, L"EDID", 0, REG_BINARY, edid.data(), sz);

        if (!serial_stock) {
            char old_serial_s[16] = {}, new_serial_s[16] = {};
            snprintf(old_serial_s, sizeof(old_serial_s), "%02X%02X%02X%02X",
                old_serial[0], old_serial[1], old_serial[2], old_serial[3]);
            snprintf(new_serial_s, sizeof(new_serial_s), "%02X%02X%02X%02X",
                edid[12], edid[13], edid[14], edid[15]);
            logging::change("Monitor", "EDID serial (registry)", old_serial_s, new_serial_s, true);
        }

        for (int d = 0; d < 4; ++d) {
            if (!desc_hit[d]) continue;
            char new_desc[9] = {};
            for (int s = 0; s < 8; ++s)
                new_desc[s] = static_cast<char>(edid[54 + d * 18 + 5 + s]);
            char name[56] = {};
            snprintf(name, sizeof(name), "EDID serial descriptor (registry, desc %d)", d);
            logging::change("Monitor", name, old_desc[d], new_desc);
        }
    }

    static void patch_registry_edid() {
        HKEY hDisplay = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
                0, KEY_READ, &hDisplay) != ERROR_SUCCESS) return;

        std::uint32_t patched = 0;

        for (DWORD ci = 0; ; ++ci) {
            wchar_t cls[256] = {};
            DWORD cls_len = 256;
            if (RegEnumKeyExW(hDisplay, ci, cls, &cls_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            HKEY hCls = nullptr;
            if (RegOpenKeyExW(hDisplay, cls, 0, KEY_READ, &hCls) != ERROR_SUCCESS) continue;

            for (DWORD ii = 0; ; ++ii) {
                wchar_t inst[256] = {};
                DWORD inst_len = 256;
                if (RegEnumKeyExW(hCls, ii, inst, &inst_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                HKEY hInst = nullptr;
                if (RegOpenKeyExW(hCls, inst, 0, KEY_READ, &hInst) != ERROR_SUCCESS) continue;

                HKEY hDevParam = nullptr;
                if (RegOpenKeyExW(hInst, L"Device Parameters",
                                  0, KEY_READ | KEY_SET_VALUE, &hDevParam) == ERROR_SUCCESS) {
                    patch_edid_binary(hDevParam);
                    RegCloseKey(hDevParam);
                    ++patched;
                }
                RegCloseKey(hInst);
            }
            RegCloseKey(hCls);
        }
        RegCloseKey(hDisplay);

        HKEY hGfxCfg = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration",
                0, KEY_READ, &hGfxCfg) == ERROR_SUCCESS) {
            for (DWORD ci = 0; ; ++ci) {
                wchar_t sub[256] = {};
                DWORD sub_len = 256;
                if (RegEnumKeyExW(hGfxCfg, ci, sub, &sub_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                HKEY hSub = nullptr;
                if (RegOpenKeyExW(hGfxCfg, sub, 0, KEY_SET_VALUE, &hSub) != ERROR_SUCCESS) continue;
                const std::uint64_t zero = 0;
                RegSetValueExW(hSub, L"Timestamp", 0, REG_QWORD,
                    reinterpret_cast<const BYTE*>(&zero), sizeof(zero));
                RegCloseKey(hSub);
            }
            RegCloseKey(hGfxCfg);
        }

        logging::print("spoof: monitor - registry EDID patched (%u display(s))", patched);
    }

    // the kernel cache is only populated after dxgkrnl has queried monitor
    // descriptors (WDDM paths/DWM activity) - force it from usermode so the
    // walk doesn't race an empty cache
    static void warm_edid_cache() {
        using QueryDisplayConfig_t = LONG(WINAPI*)(UINT32, UINT32*, DISPLAYCONFIG_PATH_INFO*,
            UINT32*, DISPLAYCONFIG_MODE_INFO*, HWND);
        using GetSizes_t = LONG(WINAPI*)(UINT32, UINT32*, UINT32*);

        const HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (!user32) return;
        const auto get_sizes = reinterpret_cast<GetSizes_t>(
            GetProcAddress(user32, "GetDisplayConfigBufferSizes"));
        const auto query = reinterpret_cast<QueryDisplayConfig_t>(
            GetProcAddress(user32, "QueryDisplayConfig"));
        if (!get_sizes || !query) return;

        UINT32 paths = 0, modes = 0;
        if (get_sizes(QDC_ONLY_ACTIVE_PATHS, &paths, &modes) != 0 || !paths) return;

        std::vector<DISPLAYCONFIG_PATH_INFO> path_buf(paths);
        std::vector<DISPLAYCONFIG_MODE_INFO> mode_buf(modes ? modes : 1);
        query(QDC_ONLY_ACTIVE_PATHS, &paths, path_buf.data(),
            &modes, mode_buf.data(), nullptr);
        logging::print("spoof: monitor - display-config warm-up done (%u path(s))", paths);
    }

    inline void install() {
        using namespace spoof::helpers;

        loader_offsets::dxgkrnl_offsets off{};
        if (!pdb_offsets::resolve_dxgkrnl(&off)) {
            logging::print("spoof: monitor - dxgkrnl PDB resolution failed");
            return;
        }

        const std::uint64_t dxgkrnl_base = get_kernel_module_base(L"dxgkrnl.sys");
        if (!dxgkrnl_base) {
            logging::print("spoof: monitor - dxgkrnl.sys not found in module list");
            return;
        }

        // dxgkrnl can free/recreate the cache object (MonitorInitializeGlobal /
        // DeleteGlobalCache) - the pointer is read fresh on every install
        const std::uint64_t cache_ptr_va = dxgkrnl_base + off.edid_cache_rva;

        warm_edid_cache();

        const std::uint64_t cache_va = kread_val<std::uint64_t>(cache_ptr_va);
        if (!is_kva(cache_va)) {
            logging::print("spoof: monitor - s_pEdidCache not valid (ptr=0x%llX)",
                (unsigned long long)cache_ptr_va);
            patch_registry_edid();
            return;
        }

        static constexpr std::uint8_t EDID_HDR[8] = {
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
        };

        std::uint32_t count = 0, free_slots = 0, bad_edid = 0;

        for (std::uint32_t i = 0; i < off.max_entries; ++i) {
            const std::uint64_t entry = cache_va + static_cast<std::uint64_t>(i) * off.entry_stride;

            // timestamp==0 marks a free slot - the same gate GetEdids uses
            const std::uint64_t ts = kread_val<std::uint64_t>(entry + off.entry_timestamp);
            if (!ts) { ++free_slots; continue; }

            std::uint8_t edid[128] = {};
            if (!kread(entry + off.entry_edid_data, edid, 128) ||
                memcmp(edid, EDID_HDR, 8) != 0) {
                logging::print("spoof: monitor - slot %u occupied (ts=0x%llX) but EDID header invalid",
                    i, (unsigned long long)ts);
                ++bad_edid;
                continue;
            }
            std::uint8_t orig_edid[128];
            memcpy(orig_edid, edid, sizeof(orig_edid));

            const std::uint8_t old_serial[4] = { edid[12], edid[13], edid[14], edid[15] };
            bool desc_hit[4] = {};
            char old_desc[4][9] = {};

            // same placeholder rule as the registry pass: all-identical
            // serial bytes/descriptor chars stay stock
            const bool serial_stock = old_serial[0] == old_serial[1] &&
                                      old_serial[1] == old_serial[2] &&
                                      old_serial[2] == old_serial[3];
            if (!serial_stock) {
                edid[12] = static_cast<std::uint8_t>(rand_next());
                edid[13] = static_cast<std::uint8_t>(rand_next());
                edid[14] = static_cast<std::uint8_t>(rand_next());
                edid[15] = static_cast<std::uint8_t>(rand_next());
            }

            for (int d = 0; d < 4; ++d) {
                const int base = 54 + d * 18;
                if (edid[base] != 0 || edid[base + 1] != 0 || edid[base + 2] != 0) continue;
                if (edid[base + 3] != 0xFF) continue;
                bool desc_stock = true;
                for (int s = 1; s < 8; ++s)
                    if (edid[base + 5 + s] != edid[base + 5]) { desc_stock = false; break; }
                if (desc_stock) continue;   // placeholder descriptor, keep stock
                desc_hit[d] = true;
                for (int s = 0; s < 8; ++s) {
                    const std::uint8_t ch = edid[base + 5 + s];
                    old_desc[d][s] = ch >= 0x20 && ch <= 0x7E ? static_cast<char>(ch) : '.';
                }
                for (int s = 0; s < 8; ++s) {
                    const std::uint8_t r = static_cast<std::uint8_t>(rand_next() % 36);
                    edid[base + 5 + s] = r < 10 ? static_cast<std::uint8_t>('0' + r)
                                                 : static_cast<std::uint8_t>('A' + r - 10);
                }
                edid[base + 13] = 0x0A;
                edid[base + 14] = 0x20;
                edid[base + 15] = 0x20;
                edid[base + 16] = 0x20;
                edid[base + 17] = 0x20;
            }

            std::uint8_t sum = 0;
            for (int s = 0; s < 127; ++s) sum += edid[s];
            edid[127] = static_cast<std::uint8_t>(static_cast<std::uint32_t>(256) - sum);

            // readback: the entry must hold exactly the mutated EDID after
            // the write; on mismatch the captured original goes back
            std::uint8_t back[128] = {};
            kwrite(entry + off.entry_edid_data, edid, 128);
            if (!kread(entry + off.entry_edid_data, back, 128) ||
                memcmp(back, edid, sizeof(back)) != 0) {
                kwrite(entry + off.entry_edid_data, orig_edid, sizeof(orig_edid));
                logging::print("spoof: monitor - slot %u EDID write failed readback - restored",
                    i);
                continue;
            }
            ++count;

            if (!serial_stock) {
                char old_serial_s[16] = {}, new_serial_s[16] = {};
                snprintf(old_serial_s, sizeof(old_serial_s), "%02X%02X%02X%02X",
                    old_serial[0], old_serial[1], old_serial[2], old_serial[3]);
                snprintf(new_serial_s, sizeof(new_serial_s), "%02X%02X%02X%02X",
                    edid[12], edid[13], edid[14], edid[15]);
                char name[56] = {};
                snprintf(name, sizeof(name), "EDID serial (kernel cache slot %u)", i);
                logging::change("Monitor", name, old_serial_s, new_serial_s, true);
            }

            for (int d = 0; d < 4; ++d) {
                if (!desc_hit[d]) continue;
                char new_desc[9] = {};
                for (int s = 0; s < 8; ++s)
                    new_desc[s] = static_cast<char>(edid[54 + d * 18 + 5 + s]);
                char name[56] = {};
                snprintf(name, sizeof(name), "EDID serial descriptor (kernel cache slot %u, desc %d)", i, d);
                logging::change("Monitor", name, old_desc[d], new_desc);
            }

            logging::print("spoof: monitor - patched EDID entry %u (ts=0x%llX)",
                i, (unsigned long long)ts);
        }

        logging::print("spoof: monitor - %u EDID entr%s patched (%u free slot(s)%s)",
            count, count == 1 ? "y" : "ies", free_slots,
            bad_edid ? ", some occupied slots had invalid EDID" : "");
        if (!count && free_slots == off.max_entries)
            logging::print("spoof: monitor - kernel cache empty (no monitor descriptors cached yet)");

        patch_registry_edid();
    }

}
