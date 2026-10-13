#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

namespace spoof::bluetooth {

    using namespace helpers;

    // short hex tail of a binary registry value for the change ledger
    static void blob_snippet(const std::vector<BYTE>& blob, char* out, std::size_t out_len) {
        if (!out || !out_len) return;
        out[0] = '\0';
        std::size_t pos = 0;
        const std::size_t show = blob.size() < 8 ? blob.size() : 8;
        if (show < blob.size())
            pos += static_cast<std::size_t>(snprintf(out, out_len, ".."));
        const std::size_t start = blob.size() - show;
        for (std::size_t i = 0; i < show && pos + 3 <= out_len; ++i)
            pos += static_cast<std::size_t>(snprintf(out + pos, out_len - pos,
                "%02X", blob[start + i]));
    }

    static void spoof_bthport_keys() {
        static const wchar_t k_path[] =
            L"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys";
        HKEY hKeys = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ, &hKeys) != ERROR_SUCCESS) return;

        std::uint32_t count = 0;
        for (DWORD i = 0; ; ++i) {
            wchar_t adapter[64] = {};
            DWORD adapter_len = 64;
            if (RegEnumKeyExW(hKeys, i, adapter, &adapter_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

            wchar_t full[256] = {};
            swprintf_s(full, L"%s\\%s", k_path, adapter);
            HKEY hAdapter = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, full, 0, KEY_READ | KEY_SET_VALUE, &hAdapter) != ERROR_SUCCESS)
                continue;

            for (DWORD vi = 0; ; ++vi) {
                wchar_t vname[128] = {};
                DWORD vname_len = 128, vtype = 0, vdata_len = 0;
                LSTATUS vs = RegEnumValueW(hAdapter, vi, vname, &vname_len,
                                           nullptr, &vtype, nullptr, &vdata_len);
                if (vs == ERROR_NO_MORE_ITEMS) break;
                if (vs != ERROR_SUCCESS) continue;
                if (vtype == REG_BINARY && vdata_len >= 16) {
                    std::vector<BYTE> buf(vdata_len);
                    vname_len = 128;
                    if (RegQueryValueExW(hAdapter, vname, nullptr, &vtype,
                                         buf.data(), &vdata_len) == ERROR_SUCCESS) {
                        const std::vector<BYTE> old_buf(buf);
                        for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                        RegSetValueExW(hAdapter, vname, 0, REG_BINARY, buf.data(), vdata_len);
                        ++count;
                        char name[56] = {}, old_s[24] = "-", new_s[24] = "-";
                        snprintf(name, sizeof(name), "link key %ls", vname);
                        blob_snippet(old_buf, old_s, sizeof(old_s));
                        blob_snippet(buf, new_s, sizeof(new_s));
                        logging::change("Bluetooth", name, old_s, new_s);
                    }
                }
            }
            RegCloseKey(hAdapter);
        }
        RegCloseKey(hKeys);
        logging::print("bluetooth: BTHPORT link keys randomized (%u)", count);
    }

    static void spoof_radio_address() {
        static const wchar_t k_path[] = L"SOFTWARE\\Microsoft\\Bluetooth";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;

        DWORD sz = 0, type = 0;
        if (RegQueryValueExW(hk, L"RadioAddress", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
            && sz >= 6 && type == REG_BINARY) {
            std::vector<BYTE> buf(sz);
            if (RegQueryValueExW(hk, L"RadioAddress", nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                const std::vector<BYTE> old_buf(buf);
                for (DWORD i = 3; i < sz && i < 6; ++i)
                    buf[i] = static_cast<BYTE>(rand_next() & 0xFF);
                RegSetValueExW(hk, L"RadioAddress", 0, REG_BINARY, buf.data(), sz);
                char old_s[24] = "-", new_s[24] = "-";
                snprintf(old_s, sizeof(old_s), "%02X:%02X:%02X:%02X:%02X:%02X",
                    old_buf[0], old_buf[1], old_buf[2], old_buf[3], old_buf[4], old_buf[5]);
                snprintf(new_s, sizeof(new_s), "%02X:%02X:%02X:%02X:%02X:%02X",
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
                logging::change("Bluetooth", "RadioAddress (adapter MAC)", old_s, new_s);
            }
        }
        RegCloseKey(hk);
        logging::print("bluetooth: RadioAddress randomized");
    }

    static void spoof_bth_params() {
        static const wchar_t* k_paths[] = {
            L"SYSTEM\\CurrentControlSet\\Services\\BTHLEParameters",
            L"SYSTEM\\CurrentControlSet\\Services\\RFCOMM\\Parameters",
            L"SYSTEM\\CurrentControlSet\\Services\\OBEX\\Parameters",
        };
        for (const auto* path : k_paths) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
                continue;
            DWORD sz = 0, type = 0;
            if (RegQueryValueExW(hk, L"AuthValue", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
                && sz && type == REG_BINARY) {
                std::vector<BYTE> buf(sz);
                if (RegQueryValueExW(hk, L"AuthValue", nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                    const std::vector<BYTE> old_buf(buf);
                    for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                    RegSetValueExW(hk, L"AuthValue", 0, REG_BINARY, buf.data(), sz);
                    const wchar_t* svc = path;
                    if (const wchar_t* found = wcsstr(path, L"Services\\"))
                        svc = found + 9;
                    char name[56] = {}, old_s[24] = "-", new_s[24] = "-";
                    snprintf(name, sizeof(name), "%ls AuthValue", svc);
                    blob_snippet(old_buf, old_s, sizeof(old_s));
                    blob_snippet(buf, new_s, sizeof(new_s));
                    logging::change("Bluetooth", name, old_s, new_s);
                }
            }
            RegCloseKey(hk);
        }
        logging::print("bluetooth: BTH service AuthValues randomized");
    }

    static void spoof_bthenum_containerids() {
        static const wchar_t k_path[] = L"SYSTEM\\CurrentControlSet\\Enum\\BTHENUM";
        HKEY hRoot = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ, &hRoot) != ERROR_SUCCESS) return;

        std::uint32_t count = 0;
        for (DWORD i = 0; ; ++i) {
            wchar_t dev[256] = {};
            DWORD dev_len = 256;
            if (RegEnumKeyExW(hRoot, i, dev, &dev_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

            wchar_t dev_path[512] = {};
            swprintf_s(dev_path, L"%s\\%s", k_path, dev);
            HKEY hDev = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, dev_path, 0, KEY_READ, &hDev) != ERROR_SUCCESS) continue;

            for (DWORD j = 0; ; ++j) {
                wchar_t inst[256] = {};
                DWORD inst_len = 256;
                if (RegEnumKeyExW(hDev, j, inst, &inst_len,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

                wchar_t inst_path[1024] = {};
                swprintf_s(inst_path, L"%s\\%s", dev_path, inst);
                HKEY hInst = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, inst_path, 0,
                                  KEY_READ | KEY_SET_VALUE, &hInst) != ERROR_SUCCESS) continue;

                DWORD sz = 0, type = 0;
                if (RegQueryValueExW(hInst, L"ContainerId", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
                    && type == REG_SZ) {
                    // capture the original ContainerId before it is replaced
                    char old_s[76] = "-";
                    std::vector<wchar_t> old_buf((sz / sizeof(wchar_t)) + 1, L'\0');
                    if (RegQueryValueExW(hInst, L"ContainerId", nullptr, &type,
                            reinterpret_cast<LPBYTE>(old_buf.data()), &sz) == ERROR_SUCCESS)
                        snprintf(old_s, sizeof(old_s), "%ls", old_buf.data());

                    DWORD d1 = (rand_next() << 17u) ^ (rand_next() << 2u) ^ rand_next();
                    WORD  d2 = static_cast<WORD>(rand_next());
                    WORD  d3 = static_cast<WORD>((rand_next() & 0x0FFFu) | 0x4000u);
                    BYTE  d4[8]; for (auto& b : d4) b = static_cast<BYTE>(rand_next() & 0xFF);
                    d4[0] = static_cast<BYTE>((d4[0] & 0x3Fu) | 0x80u);
                    wchar_t guid[48] = {};
                    swprintf_s(guid, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                        d1, d2, d3,
                        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]);
                    const DWORD gsz = static_cast<DWORD>((wcslen(guid) + 1) * sizeof(wchar_t));
                    RegSetValueExW(hInst, L"ContainerId", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(guid), gsz);
                    ++count;

                    char new_s[76] = {}, name[56] = {};
                    snprintf(new_s, sizeof(new_s), "%ls", guid);
                    snprintf(name, sizeof(name), "ContainerId (%ls)", dev);
                    logging::change("Bluetooth", name, old_s, new_s);
                }
                RegCloseKey(hInst);
            }
            RegCloseKey(hDev);
        }
        RegCloseKey(hRoot);
        logging::print("bluetooth: BTHENUM ContainerIds randomized (%u)", count);
    }

    inline void install() {
        spoof_bthport_keys();
        spoof_radio_address();
        spoof_bth_params();
        spoof_bthenum_containerids();
    }

}
