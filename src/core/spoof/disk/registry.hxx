#pragma once
#include "shared.hxx"
#include <windows.h>

namespace spoof::disk::registry {
    using namespace helpers;

    static void scramble_wide(wchar_t* buf, std::uint32_t chars) {
        std::uint32_t start = chars > 20 ? chars - 20 : 0;
        for (std::uint32_t i = start; i < chars; ++i)
            buf[i] = L'A' + ((buf[i] + i * 7) % 26);
    }

    static void spoof_reg_value(HKEY hKey) {
        static const wchar_t* kNames[] = {
            L"SerialNumber", L"Identifier", L"PhysicalSerialNumber"
        };
        for (auto* name : kNames) {
            wchar_t val[256] = {};
            DWORD type = 0, size = sizeof(val);
            if (RegQueryValueExW(hKey, name, nullptr, &type, (LPBYTE)val, &size) != ERROR_SUCCESS) continue;
            if (type != REG_SZ) continue;
            std::uint32_t chars = size / sizeof(wchar_t);
            if (chars < 2) continue;

            val[sizeof(val)/sizeof(val[0]) - 1] = L'\0';
            wchar_t old_val[256] = {};
            memcpy(old_val, val, sizeof(val));
            scramble_wide(val, chars > 0 ? chars - 1 : 0);
            char chg_name[56] = {};
            snprintf(chg_name, sizeof(chg_name), "registry %ls", name);
            char old_txt[168] = {}, new_txt[168] = {};
            snprintf(old_txt, sizeof(old_txt), "%ls", old_val);
            snprintf(new_txt, sizeof(new_txt), "%ls", val);
            if (strcmp(old_txt, new_txt) != 0)
                logging::change("Disk", chg_name, old_txt, new_txt, false);
            RegSetValueExW(hKey, name, 0, REG_SZ, (const BYTE*)val, size);
        }
    }

    inline void install() {
        HKEY hScsi = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Enum\\SCSI",
            0, KEY_READ, &hScsi) != ERROR_SUCCESS) return;

        std::uint32_t patched = 0;


        for (DWORD ci = 0; ; ++ci) {
            wchar_t class_name[256] = {};
            DWORD class_len = sizeof(class_name)/sizeof(class_name[0]);
            if (RegEnumKeyExW(hScsi, ci, class_name, &class_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

            HKEY hClass = nullptr;
            if (RegOpenKeyExW(hScsi, class_name, 0, KEY_READ, &hClass) != ERROR_SUCCESS) continue;


            for (DWORD ii = 0; ; ++ii) {
                wchar_t inst_name[256] = {};
                DWORD inst_len = sizeof(inst_name)/sizeof(inst_name[0]);
                if (RegEnumKeyExW(hClass, ii, inst_name, &inst_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

                HKEY hInst = nullptr;
                if (RegOpenKeyExW(hClass, inst_name, 0, KEY_READ | KEY_WRITE, &hInst) != ERROR_SUCCESS) continue;


                HKEY hDevParams = nullptr;
                if (RegOpenKeyExW(hInst, L"Device Parameters", 0, KEY_READ | KEY_WRITE, &hDevParams) == ERROR_SUCCESS) {
                    spoof_reg_value(hDevParams);
                    ++patched;
                    RegCloseKey(hDevParams);
                }


                spoof_reg_value(hInst);
                RegCloseKey(hInst);
            }
            RegCloseKey(hClass);
        }
        RegCloseKey(hScsi);
        logging::print("disk: registry patched %u SCSI device keys", patched);
    }

}
