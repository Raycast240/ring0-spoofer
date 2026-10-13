#pragma once
#include "helpers.hxx"
#include "disk/disk_offsets.hxx"
#include "disk/shared.hxx"
#include <vector>
#include <string>

namespace volume_guid {

    static DWORD make_rand_dword() {
        return (spoof::helpers::rand_next() << 15u) ^
               (spoof::helpers::rand_next() << 1u)  ^
                spoof::helpers::rand_next();
    }

    static void format_volume_name(wchar_t* buf, std::size_t buf_cch,
                                   const wchar_t* prefix, const GUID& g) {
        swprintf_s(buf, buf_cch,
            L"%s{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            prefix,
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1],
            g.Data4[2], g.Data4[3], g.Data4[4],
            g.Data4[5], g.Data4[6], g.Data4[7]);
    }

    static GUID make_rand_guid() {
        GUID g{};
        g.Data1 = make_rand_dword();
        g.Data2 = static_cast<WORD>(spoof::helpers::rand_next());
        g.Data3 = static_cast<WORD>((spoof::helpers::rand_next() & 0x0FFFu) | 0x4000u);
        const DWORD d4a = make_rand_dword();
        const DWORD d4b = make_rand_dword();
        memcpy(g.Data4,     &d4a, 4);
        memcpy(g.Data4 + 4, &d4b, 4);
        g.Data4[0] = static_cast<BYTE>((g.Data4[0] & 0x3Fu) | 0x80u);
        return g;
    }

    struct volume_entry {
        std::wstring old_name;
        DWORD        type;
        std::vector<BYTE> data;
    };



    static void patch_hardware_config_guid() {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\HardwareConfig",
                0, KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS) {
            logging::print("spoof: volume_guid - HardwareConfig not accessible");
            return;
        }

        wchar_t old_val[64] = {};
        DWORD   old_sz      = sizeof(old_val);
        DWORD   type        = 0;
        RegQueryValueExW(hk, L"LastConfig", nullptr, &type,
                         reinterpret_cast<LPBYTE>(old_val), &old_sz);

        const GUID new_g = make_rand_guid();
        wchar_t    new_val[48] = {};
        swprintf_s(new_val, 48,
            L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            new_g.Data1, new_g.Data2, new_g.Data3,
            new_g.Data4[0], new_g.Data4[1],
            new_g.Data4[2], new_g.Data4[3], new_g.Data4[4],
            new_g.Data4[5], new_g.Data4[6], new_g.Data4[7]);

        const DWORD new_sz = static_cast<DWORD>((wcslen(new_val) + 1) * sizeof(wchar_t));
        if (RegSetValueExW(hk, L"LastConfig", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(new_val), new_sz) == ERROR_SUCCESS) {
            char old_txt[76] = {}, new_txt[76] = {};
            snprintf(old_txt, sizeof(old_txt), "%ls", old_val[0] ? old_val : L"(absent)");
            snprintf(new_txt, sizeof(new_txt), "%ls", new_val);
            logging::change("Volume", "HardwareConfig LastConfig", old_txt, new_txt, false);
            logging::print("spoof: volume_guid - HardwareConfig\\LastConfig patched");
        } else {
            logging::print("spoof: volume_guid - HardwareConfig\\LastConfig write failed");
        }


        if (old_val[0] == L'{') {
            HKEY hOld = nullptr;
            if (RegOpenKeyExW(hk, old_val, 0, KEY_READ, &hOld) == ERROR_SUCCESS) {
                HKEY hNew = nullptr;
                if (RegCreateKeyExW(hk, new_val, 0, nullptr, 0,
                                    KEY_WRITE, nullptr, &hNew, nullptr) == ERROR_SUCCESS) {
                    for (DWORD vi = 0; ; ++vi) {
                        wchar_t vname[256] = {};
                        DWORD   vname_len  = 256;
                        DWORD   vtype      = 0;
                        DWORD   vdata_len  = 0;
                        LSTATUS vs = RegEnumValueW(hOld, vi, vname, &vname_len,
                                                   nullptr, &vtype, nullptr, &vdata_len);
                        if (vs == ERROR_NO_MORE_ITEMS) break;
                        if (vs != ERROR_SUCCESS && vs != ERROR_MORE_DATA) continue;
                        std::vector<BYTE> vdata(vdata_len);
                        vname_len = 256;
                        if (RegQueryValueExW(hOld, vname, nullptr, &vtype,
                                             vdata.data(), &vdata_len) == ERROR_SUCCESS)
                            RegSetValueExW(hNew, vname, 0, vtype, vdata.data(), vdata_len);
                    }
                    RegCloseKey(hNew);
                }
                RegCloseKey(hOld);
                RegDeleteKeyW(hk, old_val);
            }
        }

        RegCloseKey(hk);
    }

    // the volmgr chain contains volume device objects AND the
    // \Device\VolMgrControl control device, whose extension is NOT a
    // VM_VOLUME_EXTENSION - a blind write there once dropped GUID bytes
    // over a DEVOBJ_EXTENSION and bugchecked 0x7E at shutdown. this gate
    // proves a genuine volume extension before anything is written.
    static bool looks_like_vm_volume_extension(std::uint64_t ext_va, ULONG guid_off, GUID& old_g) {
        using spoof::helpers::kread;
        using spoof::helpers::kread_val;

        if (!spoof::helpers::kread(ext_va + guid_off, &old_g, sizeof(old_g))) return false;

        const auto* p = reinterpret_cast<const std::uint8_t*>(&old_g);
        bool all_zero = true;
        for (std::size_t i = 0; i < sizeof(old_g); ++i)
            if (p[i]) { all_zero = false; break; }
        if (all_zero) return false;

        // a volume UniqueGuid is a version-4 GUID: version nibble and
        // variant bits always set - a neighbour pool block of pointers and
        // flags essentially never passes both shape checks
        if (((old_g.Data3 & 0xF000) != 0x4000) ||
            ((old_g.Data4[0] & 0xC0) != 0x80))
            return false;

        // cross-validate sibling fields: sane disk number, MBR/GPT flag 0/1,
        // plausible partition length
        const auto& off = spoof::disk::g_disk_off();
        if (off.volmgr_volume_disk_number) {
            const std::uint32_t disk = kread_val<std::uint32_t>(ext_va + off.volmgr_volume_disk_number);
            if (disk >= 4096) return false;
        }
        if (off.volmgr_volume_is_gpt) {
            const std::uint32_t gpt = kread_val<std::uint32_t>(ext_va + off.volmgr_volume_is_gpt);
            if (gpt > 1) return false;
        }
        if (off.volmgr_volume_partition_length) {
            const std::uint64_t plen = kread_val<std::uint64_t>(ext_va + off.volmgr_volume_partition_length);
            if (!plen || plen >= 0x0001000000000000ULL) return false;
        }
        return true;
    }

    static void format_guid_txt(char* out, std::size_t out_size, const GUID& g) {
        snprintf(out, out_size, "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1],
            g.Data4[2], g.Data4[3], g.Data4[4],
            g.Data4[5], g.Data4[6], g.Data4[7]);
    }

    static void patch_volmgr_unique_guid() {
        const ULONG guid_off = spoof::disk::g_disk_off().volmgr_volume_unique_guid;
        if (!guid_off) {
            logging::print("volume_guid: volmgr UniqueGuid offset not resolved, skipping kernel patch");
            return;
        }

        using spoof::helpers::enum_driver_devices;
        using spoof::helpers::kread;
        using spoof::helpers::kwrite;

        std::uint32_t patched = 0, rejected = 0;
        enum_driver_devices(L"\\Driver\\volmgr", [&](std::uint64_t dev_va) {
            const std::uint64_t ext_va = spoof::helpers::kread_val<std::uint64_t>(dev_va + 0x40);
            if (!spoof::helpers::is_kva(ext_va)) return;

            GUID old_g{};
            if (!looks_like_vm_volume_extension(ext_va, guid_off, old_g)) {
                ++rejected;
                return;
            }

            const GUID new_g = make_rand_guid();
            kwrite(ext_va + guid_off, &new_g, sizeof(new_g));

            // never assume a write into paged-out memory landed
            GUID chk{};
            if (!kread(ext_va + guid_off, &chk, sizeof(chk)) ||
                memcmp(&chk, &new_g, sizeof(chk)) != 0) {
                logging::print("volume_guid: volmgr UniqueGuid write at 0x%llx failed readback",
                               ext_va + guid_off);
                return;
            }

            char old_txt[76] = {}, new_txt[76] = {};
            format_guid_txt(old_txt, sizeof(old_txt), old_g);
            format_guid_txt(new_txt, sizeof(new_txt), new_g);
            logging::change("Volume", "volmgr UniqueGuid", old_txt, new_txt, false);
            ++patched;
        });

        logging::print("volume_guid: volmgr kernel UniqueGuid patched (%u volume(s), %u rejected as non-volume)",
                       patched, rejected);
    }

    // mount points carry either prefix: older builds write
    // \DosDevices\Volume{GUID}, current builds \??\Volume{GUID}. both are
    // accepted case-insensitively and a rename keeps the prefix family the
    // OS itself wrote.
    static bool is_volume_mount_point(const wchar_t* name) {
        return _wcsnicmp(name, L"\\??\\Volume{", 12) == 0 ||
               _wcsnicmp(name, L"\\DosDevices\\Volume{", 19) == 0;
    }

    static const wchar_t* volume_name_prefix(const wchar_t* name) {
        return (_wcsnicmp(name, L"\\??\\", 4) == 0)
            ? L"\\??\\Volume{"
            : L"\\DosDevices\\Volume{";
    }

    static bool is_drive_letter(wchar_t c) {
        return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
    }

    // drive-letter mount points keep their name, only the identity blob is
    // synced below. anything but \DosDevices\X: / \??\X: is left untouched.
    static bool is_drive_letter_mount(const wchar_t* name) {
        if (_wcsnicmp(name, L"\\DosDevices\\", 12) == 0)
            return is_drive_letter(name[12]) && name[13] == L':' && name[14] == L'\0';
        if (_wcsnicmp(name, L"\\??\\", 4) == 0)
            return is_drive_letter(name[4]) && name[5] == L':' && name[6] == L'\0';
        return false;
    }

    static const BYTE kDmioId[8] = { 'D','M','I','O',':','I','D',':' };

    // a drive-letter value's data is "DMIO:ID:" + the 16-byte GPT partition
    // GUID (MBR entries carry a 4-byte disk signature instead - left alone).
    // the disk stage rewrites every kernel copy via disk::spoof_guid_va
    // (partmgr partition ID, mountdev unique ID, mountmgr database): first
    // 14 bytes survive, last two become fnv1a(first 14, s_vol_seed). the
    // registry cache is the one copy the kernel stages never reach, so the
    // same pure transform is applied here - bit-identical to the kernel GUID.
    static bool spoof_dmio_identity_guid(std::vector<BYTE>& data) {
        if (data.size() != sizeof(kDmioId) + sizeof(GUID)) return false;
        if (memcmp(data.data(), kDmioId, sizeof(kDmioId)) != 0) return false;

        BYTE* guid = data.data() + sizeof(kDmioId);
        const std::uint32_t h = spoof::helpers::fnv1a(guid, 14, spoof::disk::s_vol_seed);
        const BYTE lo = static_cast<BYTE>(h & 0xFF);
        const BYTE hi = static_cast<BYTE>((h >> 8) & 0xFF);
        if (guid[14] == lo && guid[15] == hi) return false;
        guid[14] = lo;
        guid[15] = hi;
        return true;
    }

    inline void install() {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\MountedDevices",
                0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
            logging::print("spoof: volume_guid - failed to open MountedDevices (need admin)");
        } else {
            std::vector<volume_entry> entries;
            std::vector<volume_entry> drive_letters;

            DWORD idx = 0;
            while (true) {
                wchar_t name[256]  = {};
                DWORD   name_len   = 256;
                DWORD   type       = 0;
                DWORD   data_len   = 0;
                LSTATUS s = RegEnumValueW(hKey, idx, name, &name_len,
                                          nullptr, &type, nullptr, &data_len);
                if (s == ERROR_NO_MORE_ITEMS) break;
                ++idx;
                if (s != ERROR_SUCCESS && s != ERROR_MORE_DATA) continue;

                const bool vol_mount = is_volume_mount_point(name);
                if (!vol_mount && !is_drive_letter_mount(name)) continue;

                volume_entry e;
                e.old_name = name;
                e.type     = type;
                e.data.resize(data_len);
                name_len = 256;
                if (RegQueryValueExW(hKey, name, nullptr, &type,
                                     e.data.data(), &data_len) != ERROR_SUCCESS) continue;
                e.data.resize(data_len);
                if (vol_mount) entries.push_back(std::move(e));
                else           drive_letters.push_back(std::move(e));
            }

            if (entries.empty()) {
                logging::print("spoof: volume_guid - no Volume{GUID} entries found");
            } else {
                std::uint32_t count = 0;
                for (const auto& e : entries) {
                    const GUID new_g = make_rand_guid();
                    wchar_t    new_name[80] = {};
                    format_volume_name(new_name, 80,
                                       volume_name_prefix(e.old_name.c_str()), new_g);
                    if (RegSetValueExW(hKey, new_name, 0, e.type,
                                       e.data.data(),
                                       static_cast<DWORD>(e.data.size())) != ERROR_SUCCESS)
                        continue;

                    const wchar_t* old_g = wcschr(e.old_name.c_str(), L'{');
                    const wchar_t* new_g_str = wcschr(new_name, L'{');
                    char old_txt[76] = {}, new_txt[76] = {};
                    snprintf(old_txt, sizeof(old_txt), "%ls",
                             old_g ? old_g : e.old_name.c_str());
                    snprintf(new_txt, sizeof(new_txt), "%ls",
                             new_g_str ? new_g_str : new_name);
                    logging::change("Volume", "MountedDevices Volume GUID",
                                    old_txt, new_txt, false);

                    RegDeleteValueW(hKey, e.old_name.c_str());
                    ++count;
                }
                logging::print("spoof: volume_guid - renamed %u MountedDevices GUID(s)", count);
            }

            std::uint32_t synced = 0;
            for (const auto& e : drive_letters) {
                std::vector<BYTE> new_data = e.data;
                if (!spoof_dmio_identity_guid(new_data)) continue;
                if (RegSetValueExW(hKey, e.old_name.c_str(), 0, e.type,
                                   new_data.data(),
                                   static_cast<DWORD>(new_data.size())) != ERROR_SUCCESS)
                    continue;

                GUID old_g{}, new_g{};
                memcpy(&old_g, e.data.data() + sizeof(kDmioId), sizeof(old_g));
                memcpy(&new_g, new_data.data() + sizeof(kDmioId), sizeof(new_g));
                char chg_name[64] = {};
                snprintf(chg_name, sizeof(chg_name), "MountedDevices identity (%ls)",
                         e.old_name.c_str());
                char old_txt[76] = {}, new_txt[76] = {};
                format_guid_txt(old_txt, sizeof(old_txt), old_g);
                format_guid_txt(new_txt, sizeof(new_txt), new_g);
                logging::change("Volume", chg_name, old_txt, new_txt, false);
                ++synced;
            }
            logging::print("spoof: volume_guid - synced %u identity GUID(s) with the spoofed disk identity",
                           synced);

            RegCloseKey(hKey);
        }

        patch_hardware_config_guid();
        patch_volmgr_unique_guid();
    }

}
