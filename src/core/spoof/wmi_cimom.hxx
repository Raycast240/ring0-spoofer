#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>

namespace spoof::wmi_cimom {

    using namespace helpers;

    static void set_sz(HKEY hk, const wchar_t* name, const wchar_t* value) {
        const DWORD sz = static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t));
        RegSetValueExW(hk, name, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value), sz);
    }

    static void perturb_sz(HKEY hk, const wchar_t* name) {
        wchar_t buf[256] = {};
        DWORD sz = sizeof(buf), type = 0;
        if (RegQueryValueExW(hk, name, nullptr, &type,
                              reinterpret_cast<BYTE*>(buf), &sz) != ERROR_SUCCESS
            || type != REG_SZ) return;
        const DWORD chars = sz / sizeof(wchar_t);
        for (DWORD i = 0; i < chars && buf[i]; ++i) {
            wchar_t c = buf[i];
            if      (c >= L'0' && c <= L'9') buf[i] = L'0' + static_cast<wchar_t>(rand_next() % 10);
            else if (c >= L'A' && c <= L'Z') buf[i] = L'A' + static_cast<wchar_t>(rand_next() % 26);
            else if (c >= L'a' && c <= L'z') buf[i] = L'a' + static_cast<wchar_t>(rand_next() % 26);
        }
        RegSetValueExW(hk, name, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(buf), sz);
    }

    static void rand_hex_str(wchar_t* out, std::size_t cch, std::uint32_t len) {
        static const wchar_t k_hex[] = L"0123456789ABCDEF";
        for (std::uint32_t i = 0; i < len && i + 1 < cch; ++i)
            out[i] = k_hex[rand_next() % 16];
        out[len < cch ? len : cch - 1] = 0;
    }

    static void walk_class(const wchar_t* base,
                           void(*patch_fn)(HKEY)) {
        HKEY hBase = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base, 0, KEY_READ, &hBase) != ERROR_SUCCESS) return;

        for (DWORD i = 0; ; ++i) {
            wchar_t sub[256] = {};
            DWORD sub_len = 256;
            if (RegEnumKeyExW(hBase, i, sub, &sub_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            wchar_t path[1024] = {};
            swprintf_s(path, L"%s\\%s", base, sub);
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
                continue;
            patch_fn(hk);
            RegCloseKey(hk);
        }
        RegCloseKey(hBase);
    }

    static void patch_disk_drive(HKEY hk) {
        perturb_sz(hk, L"SerialNumber");
        perturb_sz(hk, L"Model");
        perturb_sz(hk, L"FirmwareRevision");
    }

    static void patch_computer_system(HKEY hk) {
        perturb_sz(hk, L"Manufacturer");
        perturb_sz(hk, L"Model");
        perturb_sz(hk, L"SystemSKUNumber");
    }

    static void patch_baseboard(HKEY hk) {
        perturb_sz(hk, L"SerialNumber");
        perturb_sz(hk, L"Version");
        perturb_sz(hk, L"AssetTag");
    }

    static void patch_bios(HKEY hk) {
        perturb_sz(hk, L"SerialNumber");
        perturb_sz(hk, L"SMBIOSBIOSVersion");
    }

    static void patch_processor(HKEY hk) {
        DWORD sz = 0;
        if (RegQueryValueExW(hk, L"ProcessorId", nullptr, nullptr, nullptr, &sz) == ERROR_SUCCESS) {
            wchar_t hex[20] = {};
            rand_hex_str(hex, 20, 16);
            set_sz(hk, L"ProcessorId", hex);
        }
    }

    static void patch_video_controller(HKEY hk) {
        perturb_sz(hk, L"DeviceID");
        perturb_sz(hk, L"PNPDeviceID");
    }

    static void patch_physical_memory(HKEY hk) {
        perturb_sz(hk, L"SerialNumber");
        perturb_sz(hk, L"PartNumber");
    }

    static void patch_logical_disk(HKEY hk) {
        perturb_sz(hk, L"VolumeSerialNumber");
    }

    static void patch_disk_partition(HKEY hk) {
        perturb_sz(hk, L"DeviceID");
    }

    static void patch_system_enclosure(HKEY hk) {
        perturb_sz(hk, L"SerialNumber");
        perturb_sz(hk, L"SMBIOSAssetTag");
    }

    static void patch_operating_system(HKEY hk) {
        perturb_sz(hk, L"SerialNumber");
    }

    inline void install() {
        static const struct {
            const wchar_t* base;
            void(*fn)(HKEY);
        } k_classes[] = {
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_DiskDrive",       patch_disk_drive       },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_ComputerSystem",  patch_computer_system  },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_BaseBoard",       patch_baseboard        },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_BIOS",            patch_bios             },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_Processor",       patch_processor        },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_VideoController", patch_video_controller },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_PhysicalMemory",  patch_physical_memory  },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_LogicalDisk",     patch_logical_disk     },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_DiskPartition",   patch_disk_partition   },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_SystemEnclosure", patch_system_enclosure },
            { L"SOFTWARE\\Microsoft\\WBEM\\CIMOM\\Win32_OperatingSystem", patch_operating_system },
        };

        for (const auto& c : k_classes)
            walk_class(c.base, c.fn);

        logging::print("wmi_cimom: WMI CIMOM cache patched (%zu classes)",
            sizeof(k_classes) / sizeof(k_classes[0]));
    }

}
