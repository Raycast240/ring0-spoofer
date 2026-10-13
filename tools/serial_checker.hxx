#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winreg.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

namespace checker {

    inline void print_header(const std::string& title) {
        std::cout << "\n==================================================\n";
        std::cout << "  " << title << "\n";
        std::cout << "==================================================\n";
    }

    inline void print_kv(const std::string& label, const std::string& val) {
        std::cout << "  " << std::left << std::setw(28) << (label + ":") << (val.empty() ? "<empty/not found>" : val) << "\n";
    }

    inline std::string trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    inline std::string read_reg_string(HKEY hKeyRoot, const wchar_t* subKey, const wchar_t* valueName) {
        HKEY hKey;
        if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            return "";
        BYTE buf[1024] = { 0 };
        DWORD dwSize = sizeof(buf);
        DWORD type = 0;
        LSTATUS status = RegQueryValueExW(hKey, valueName, nullptr, &type, buf, &dwSize);
        RegCloseKey(hKey);
        if (status != ERROR_SUCCESS) return "";

        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            std::wstring ws(reinterpret_cast<wchar_t*>(buf));
            std::string res;
            res.reserve(ws.size());
            for (wchar_t wc : ws) res.push_back(static_cast<char>(wc));
            return res;
        } else if (type == REG_DWORD) {
            DWORD val = *reinterpret_cast<DWORD*>(buf);
            std::stringstream ss;
            ss << "0x" << std::hex << std::uppercase << val << " (" << std::dec << val << ")";
            return ss.str();
        } else if (type == REG_BINARY) {
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0');
            DWORD show = (std::min)(dwSize, (DWORD)32);
            for (DWORD i = 0; i < show; ++i) {
                ss << std::setw(2) << (int)buf[i] << " ";
            }
            if (dwSize > show) ss << "... (" << dwSize << " bytes)";
            return ss.str();
        }
        return "";
    }

    // 1. SMBIOS Firmware Tables (GetSystemFirmwareTable 'RSMB')
#pragma pack(push, 1)
    struct RawSMBIOSData {
        BYTE  Used20CallingMethod;
        BYTE  MajorVersion;
        BYTE  MinorVersion;
        BYTE  DmiRevision;
        DWORD Length;
        BYTE  SMBIOSTableData[1];
    };

    struct dmi_header {
        BYTE type;
        BYTE length;
        WORD handle;
    };
#pragma pack(pop)

    inline std::string get_smbios_string(const dmi_header* hdr, const BYTE* tableEnd, BYTE idx) {
        if (idx == 0 || !hdr || !tableEnd) return "";
        const char* cur = reinterpret_cast<const char*>(hdr) + hdr->length;
        const char* lim = reinterpret_cast<const char*>(tableEnd);
        if (cur >= lim) return "";
        for (int i = 0; i < idx - 1; ++i) {
            while (cur < lim && *cur) ++cur;
            if (++cur >= lim) return "";
        }
        const char* end = cur;
        while (end < lim && *end) ++end;
        if (end >= lim || end == cur) return "";
        return std::string(cur, end - cur);
    }

    inline void check_smbios() {
        print_header("SMBIOS FIRMWARE TABLES (GetSystemFirmwareTable)");

        DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (size == 0) {
            std::cout << "  [-] Failed to get SMBIOS table size.\n";
            return;
        }

        std::vector<BYTE> buffer(size);
        if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), size) != size) {
            std::cout << "  [-] Failed to read SMBIOS table data.\n";
            return;
        }

        RawSMBIOSData* smbios = reinterpret_cast<RawSMBIOSData*>(buffer.data());
        const BYTE* data = smbios->SMBIOSTableData;
        const BYTE* dataEnd = smbios->SMBIOSTableData + smbios->Length;

        while (data + sizeof(dmi_header) <= dataEnd) {
            const dmi_header* hdr = reinterpret_cast<const dmi_header*>(data);
            if (hdr->length < sizeof(dmi_header)) break;

            if (hdr->type == 1 && data + 0x19 <= dataEnd) { // System Info
                BYTE manufacturer_idx = data[4];
                BYTE product_idx      = data[5];
                BYTE version_idx      = data[6];
                BYTE serial_idx       = data[7];
                print_kv("System Manufacturer", trim(get_smbios_string(hdr, dataEnd, manufacturer_idx)));
                print_kv("System Product Name", trim(get_smbios_string(hdr, dataEnd, product_idx)));
                print_kv("System Version", trim(get_smbios_string(hdr, dataEnd, version_idx)));
                print_kv("System Serial Number", trim(get_smbios_string(hdr, dataEnd, serial_idx)));

                const BYTE* uuid = data + 8;
                char uuidStr[64] = { 0 };
                sprintf_s(uuidStr, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    uuid[3], uuid[2], uuid[1], uuid[0],
                    uuid[5], uuid[4], uuid[7], uuid[6],
                    uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
                print_kv("System UUID", uuidStr);
            }
            else if (hdr->type == 2 && data + 0x08 <= dataEnd) { // Baseboard Info
                BYTE manufacturer_idx = data[4];
                BYTE product_idx      = data[5];
                BYTE version_idx      = data[6];
                BYTE serial_idx       = data[7];
                print_kv("Baseboard Manufacturer", trim(get_smbios_string(hdr, dataEnd, manufacturer_idx)));
                print_kv("Baseboard Product", trim(get_smbios_string(hdr, dataEnd, product_idx)));
                print_kv("Baseboard Version", trim(get_smbios_string(hdr, dataEnd, version_idx)));
                print_kv("Baseboard Serial", trim(get_smbios_string(hdr, dataEnd, serial_idx)));
            }
            else if (hdr->type == 3 && data + 0x07 <= dataEnd) { // Chassis Info
                BYTE manufacturer_idx = data[4];
                BYTE version_idx      = data[6];
                BYTE serial_idx       = data[7];
                BYTE asset_idx        = data[8];
                print_kv("Chassis Manufacturer", trim(get_smbios_string(hdr, dataEnd, manufacturer_idx)));
                print_kv("Chassis Version", trim(get_smbios_string(hdr, dataEnd, version_idx)));
                print_kv("Chassis Serial", trim(get_smbios_string(hdr, dataEnd, serial_idx)));
                print_kv("Chassis Asset Tag", trim(get_smbios_string(hdr, dataEnd, asset_idx)));
            }
            else if (hdr->type == 17 && data + 0x18 <= dataEnd) { // Memory Device
                BYTE serial_idx = data[0x18];
                BYTE part_idx   = data[0x1A];
                std::string sn = trim(get_smbios_string(hdr, dataEnd, serial_idx));
                std::string pn = trim(get_smbios_string(hdr, dataEnd, part_idx));
                if (!sn.empty() || !pn.empty()) {
                    print_kv("RAM Serial", sn);
                    print_kv("RAM Part Number", pn);
                }
            }

            const BYTE* next = data + hdr->length;
            while (next + 1 < dataEnd && !(next[0] == 0 && next[1] == 0)) ++next;
            data = next + 2;
        }

        // Registry Mirror Check (HARDWARE\DESCRIPTION\System\BIOS)
        print_kv("Reg BIOS SystemBiosDate", read_reg_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemBiosDate"));
        print_kv("Reg BIOS SystemProductName", read_reg_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName"));
        print_kv("Reg BIOS SystemSerialNumber", read_reg_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemSerialNumber"));
        print_kv("Reg BIOS BaseBoardSerialNumber", read_reg_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardSerialNumber"));
    }

    // 2. Physical Disks & Storage (IOCTL Storage Query)
    inline void check_disks() {
        print_header("PHYSICAL DISKS & STORAGE (IOCTL Storage Query)");

        for (int i = 0; i < 16; ++i) {
            std::string devicePath = "\\\\.\\PhysicalDrive" + std::to_string(i);
            HANDLE hDevice = CreateFileA(devicePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hDevice == INVALID_HANDLE_VALUE) {
                hDevice = CreateFileA(devicePath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            }
            if (hDevice == INVALID_HANDLE_VALUE) continue;

            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType  = PropertyStandardQuery;

            BYTE buffer[1024] = { 0 };
            DWORD bytesReturned = 0;
            if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer, sizeof(buffer), &bytesReturned, nullptr)) {
                STORAGE_DEVICE_DESCRIPTOR* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer);
                std::string vendor = desc->VendorIdOffset ? reinterpret_cast<char*>(buffer + desc->VendorIdOffset) : "";
                std::string product = desc->ProductIdOffset ? reinterpret_cast<char*>(buffer + desc->ProductIdOffset) : "";
                std::string serial = desc->SerialNumberOffset ? reinterpret_cast<char*>(buffer + desc->SerialNumberOffset) : "";

                std::cout << "  [Drive " << i << "] " << trim(vendor) << " " << trim(product) << "\n";
                print_kv("    Device Serial Number", trim(serial));
            }

            CloseHandle(hDevice);
        }

        // SCSI Registry Map Check
        print_kv("Reg SCSI Disk Serial 0", read_reg_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"SerialNumber"));
        print_kv("Reg SCSI Disk Serial 1", read_reg_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"SerialNumber"));
    }

    // 3. Volume Serials & GUIDs (GetVolumeInformationA)
    inline void check_volumes() {
        print_header("LOGICAL VOLUMES & GUIDs (GetVolumeInformation)");

        char driveLetters[] = "CDEFGHIJKLMNOPQRSTUVWXYZ";
        for (int i = 0; driveLetters[i]; ++i) {
            std::string root = std::string(1, driveLetters[i]) + ":\\";
            UINT type = GetDriveTypeA(root.c_str());
            if (type == DRIVE_REMOVABLE || type == DRIVE_FIXED) {
                DWORD serialNumber = 0;
                char volumeName[MAX_PATH] = { 0 };
                char fsName[MAX_PATH] = { 0 };
                if (GetVolumeInformationA(root.c_str(), volumeName, MAX_PATH, &serialNumber, nullptr, nullptr, fsName, MAX_PATH)) {
                    std::stringstream ss;
                    ss << std::hex << std::uppercase << std::setfill('0')
                       << std::setw(4) << ((serialNumber >> 16) & 0xFFFF) << "-"
                       << std::setw(4) << (serialNumber & 0xFFFF);
                    print_kv("Volume " + root + " Serial", ss.str());
                }
            }
        }

        // Check MountedDevices
        print_kv("Reg MountedDevices \\DosDevices\\C:", read_reg_string(HKEY_LOCAL_MACHINE, L"SYSTEM\\MountedDevices", L"\\DosDevices\\C:"));
    }

    // 4. Network Interfaces (GetAdaptersAddresses & NetworkAddress)
    inline void check_network() {
        print_header("NETWORK INTERFACES & MAC ADDRESSES (GetAdaptersAddresses)");

        ULONG outBufLen = 15000;
        std::vector<BYTE> buffer(outBufLen);
        PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

        DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            buffer.resize(outBufLen);
            pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
            dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
        }

        if (dwRetVal == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses; pCurrAddresses = pCurrAddresses->Next) {
                if (pCurrAddresses->PhysicalAddressLength == 6) {
                    char macStr[32] = { 0 };
                    sprintf_s(macStr, "%02X-%02X-%02X-%02X-%02X-%02X",
                        pCurrAddresses->PhysicalAddress[0], pCurrAddresses->PhysicalAddress[1],
                        pCurrAddresses->PhysicalAddress[2], pCurrAddresses->PhysicalAddress[3],
                        pCurrAddresses->PhysicalAddress[4], pCurrAddresses->PhysicalAddress[5]);

                    std::wstring name(pCurrAddresses->FriendlyName);
                    std::string nStr;
                    for (wchar_t wc : name) nStr.push_back(static_cast<char>(wc));
                    print_kv("Adapter (" + nStr + ")", macStr);
                }
            }
        }

        // Check Registry NetworkAddress Overrides
        HKEY hClassKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}", 0, KEY_READ, &hClassKey) == ERROR_SUCCESS) {
            for (DWORD i = 0; i < 30; ++i) {
                wchar_t subKeyName[16] = { 0 };
                swprintf_s(subKeyName, L"%04d", i);
                std::string netAddr = read_reg_string(hClassKey, subKeyName, L"NetworkAddress");
                if (!netAddr.empty()) {
                    print_kv("Reg NetAddress [" + std::string(subKeyName, subKeyName + 4) + "]", netAddr);
                }
            }
            RegCloseKey(hClassKey);
        }
    }

    // 5. Windows OS Identity
    inline void check_windows_id() {
        print_header("WINDOWS OS IDENTIFIERS (Registry Native API)");

        print_kv("Cryptography MachineGuid", read_reg_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid"));
        print_kv("Windows ProductId", read_reg_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId"));
        print_kv("Windows BuildLabEx", read_reg_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"BuildLabEx"));
        print_kv("SQM Client MachineId", read_reg_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId"));

        char computerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
        DWORD size = sizeof(computerName);
        if (GetComputerNameA(computerName, &size)) {
            print_kv("System Hostname", computerName);
        }
    }

    // 6. EFI Environment Variables
    inline void check_efi() {
        print_header("EFI FIRMWARE VARIABLES (GetFirmwareEnvironmentVariable)");

        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            TOKEN_PRIVILEGES tp;
            LookupPrivilegeValueW(nullptr, L"SeSystemEnvironmentPrivilege", &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            CloseHandle(hToken);
        }

        BYTE buf[512] = { 0 };
        DWORD len = GetFirmwareEnvironmentVariableW(L"BootOrder", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", buf, sizeof(buf));
        if (len > 0) {
            print_kv("EFI BootOrder", std::to_string(len) + " bytes present");
        } else {
            print_kv("EFI BootOrder", "Not Accessible / Legacy BIOS");
        }

        print_kv("Reg NVRAM LkgPciCompState", read_reg_string(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Nls\\MUILanguages", L"LkgPciCompState"));
    }

    // 7. GPU & Display Identities
    inline void check_gpu() {
        print_header("GPU & DISPLAY IDENTIFIERS (SetupAPI)");

        HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISPLAY, nullptr, nullptr, DIGCF_PRESENT);
        if (hDevInfo != INVALID_HANDLE_VALUE) {
            SP_DEVINFO_DATA devInfoData{};
            devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
            for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); ++i) {
                wchar_t devId[512] = { 0 };
                if (CM_Get_Device_IDW(devInfoData.DevInst, devId, 512, 0) == CR_SUCCESS) {
                    std::wstring ws(devId);
                    std::string res;
                    for (wchar_t wc : ws) res.push_back(static_cast<char>(wc));
                    print_kv("GPU Device Instance ID", res);
                }
            }
            SetupDiDestroyDeviceInfoList(hDevInfo);
        }

        hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_MONITOR, nullptr, nullptr, DIGCF_PRESENT);
        if (hDevInfo != INVALID_HANDLE_VALUE) {
            SP_DEVINFO_DATA devInfoData{};
            devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
            for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); ++i) {
                wchar_t devId[512] = { 0 };
                if (CM_Get_Device_IDW(devInfoData.DevInst, devId, 512, 0) == CR_SUCCESS) {
                    std::wstring ws(devId);
                    std::string res;
                    for (wchar_t wc : ws) res.push_back(static_cast<char>(wc));
                    print_kv("Monitor Instance ID", res);
                }
            }
            SetupDiDestroyDeviceInfoList(hDevInfo);
        }
    }

    // 8. TPM Serials
    inline void check_tpm() {
        print_header("TPM IDENTIFIERS (Registry & Hardware)");

        print_kv("Reg TPM ManufacturerId", read_reg_string(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\properties", L"ManufacturerId"));
        print_kv("Reg TPM EndorsementKey", read_reg_string(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement", L"EK"));
    }

    inline void run_all() {
        std::cout << "==============================================================\n";
        std::cout << "        CRACKED-2M96 HARDWARE SERIAL CHECKER (NO WMIC)\n";
        std::cout << "==============================================================\n";

        check_smbios();
        check_disks();
        check_volumes();
        check_network();
        check_windows_id();
        check_efi();
        check_gpu();
        check_tpm();

        std::cout << "\n==============================================================\n";
        std::cout << "  Check complete.\n";
        std::cout << "==============================================================\n";
    }
}
