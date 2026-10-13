#pragma once
#include "helpers.hxx"
#include <aclapi.h>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")

namespace spoof::filetimes {

    using namespace helpers;

    static void enable_privilege(const char* name) {
        HANDLE tok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValueA(nullptr, name, &tp.Privileges[0].Luid);
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(tok);
    }

    static FILETIME random_filetime() {

        FILETIME now{};
        GetSystemTimeAsFileTime(&now);
        const std::uint64_t now64 = (static_cast<std::uint64_t>(now.dwHighDateTime) << 32)
                                  | now.dwLowDateTime;

        const std::uint64_t range = 63ULL * 24 * 3600 * 10000000ULL;
        const std::uint64_t delta = (static_cast<std::uint64_t>(rand_next()) * rand_next()) % range;
        const std::uint64_t fake = now64 - delta;
        FILETIME ft{};
        ft.dwLowDateTime  = static_cast<DWORD>(fake & 0xFFFFFFFFu);
        ft.dwHighDateTime = static_cast<DWORD>(fake >> 32);
        return ft;
    }

    static void touch_file(const wchar_t* path) {

        HANDLE hf = CreateFileW(path, FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

        if (hf == INVALID_HANDLE_VALUE) {

            PSID pAdminSid = nullptr;
            SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;
            AllocateAndInitializeSid(&NtAuth, 2,
                SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                0, 0, 0, 0, 0, 0, &pAdminSid);

            if (SetNamedSecurityInfoW(
                    const_cast<wchar_t*>(path),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    pAdminSid, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {

                EXPLICIT_ACCESS_W ea{};
                ea.grfAccessPermissions = FILE_WRITE_ATTRIBUTES | WRITE_DAC | READ_CONTROL;
                ea.grfAccessMode        = GRANT_ACCESS;
                ea.grfInheritance       = NO_INHERITANCE;
                ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
                ea.Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
                ea.Trustee.ptstrName    = reinterpret_cast<wchar_t*>(pAdminSid);

                PACL pNewDacl = nullptr;
                SetEntriesInAclW(1, &ea, nullptr, &pNewDacl);
                if (pNewDacl) {
                    SetNamedSecurityInfoW(
                        const_cast<wchar_t*>(path),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, pNewDacl, nullptr);
                    LocalFree(pNewDacl);
                }

                hf = CreateFileW(path, FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            }

            if (pAdminSid) FreeSid(pAdminSid);
        }

        if (hf == INVALID_HANDLE_VALUE) return;

        FILETIME ft = random_filetime();
        SetFileTime(hf, &ft, nullptr, &ft);
        CloseHandle(hf);
    }

    static void patch_machine_guid_file() {
        wchar_t sysdir[MAX_PATH] = {};
        GetSystemDirectoryW(sysdir, MAX_PATH);

        wchar_t path[MAX_PATH] = {};
        wcscpy_s(path, sysdir);
        wcscat_s(path, L"\\restore\\MachineGuid.txt");


        GUID g{};
        auto rw = []() -> DWORD {
            return (rand_next() << 15u) ^ (rand_next() << 1u) ^ rand_next();
        };
        g.Data1 = rw();
        g.Data2 = static_cast<WORD>(rand_next());
        g.Data3 = static_cast<WORD>((rand_next() & 0x0FFFu) | 0x4000u);
        DWORD da = rw(), db = rw();
        memcpy(g.Data4,     &da, 4);
        memcpy(g.Data4 + 4, &db, 4);
        g.Data4[0] = static_cast<BYTE>((g.Data4[0] & 0x3Fu) | 0x80u);

        char guid_str[40] = {};
        sprintf_s(guid_str,
            "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1],
            g.Data4[2], g.Data4[3], g.Data4[4],
            g.Data4[5], g.Data4[6], g.Data4[7]);


        PSID pAdminSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &pAdminSid);
        if (pAdminSid) {
            SetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                pAdminSid, nullptr, nullptr, nullptr);

            EXPLICIT_ACCESS_W ea{};
            ea.grfAccessPermissions = GENERIC_WRITE | WRITE_DAC | READ_CONTROL;
            ea.grfAccessMode        = GRANT_ACCESS;
            ea.grfInheritance       = NO_INHERITANCE;
            ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
            ea.Trustee.ptstrName    = reinterpret_cast<wchar_t*>(pAdminSid);

            PACL pDacl = nullptr;
            if (SetEntriesInAclW(1, &ea, nullptr, &pDacl) == ERROR_SUCCESS && pDacl) {
                SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, pDacl, nullptr);
                LocalFree(pDacl);
            }
            FreeSid(pAdminSid);
        }

        HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            logging::print("filetimes: MachineGuid.txt not accessible (err=%u)",
                GetLastError());
            return;
        }
        SetEndOfFile(hf);
        DWORD written = 0;
        WriteFile(hf, guid_str, static_cast<DWORD>(strlen(guid_str)), &written, nullptr);
        CloseHandle(hf);
        logging::print("filetimes: MachineGuid.txt -> %s", guid_str);
    }

    inline void install() {
        enable_privilege("SeBackupPrivilege");
        enable_privilege("SeRestorePrivilege");
        enable_privilege("SeTakeOwnershipPrivilege");


        patch_machine_guid_file();


        wchar_t sysdir[MAX_PATH] = {};
        GetSystemDirectoryW(sysdir, MAX_PATH);


        static const wchar_t* k_files[] = {
            L"\\ntoskrnl.exe",
            L"\\hal.dll",
            L"\\drivers\\disk.sys",
            L"\\drivers\\ndis.sys",
            L"\\drivers\\tcpip.sys",
            L"\\drivers\\dxgkrnl.sys",
            L"\\drivers\\nvlddmkm.sys",
            L"\\drivers\\usbhub.sys",
            L"\\drivers\\usbstor.sys",
            L"\\drivers\\storport.sys",
            L"\\drivers\\storahci.sys",
            L"\\drivers\\stornvme.sys",
            L"\\drivers\\partmgr.sys",
            L"\\drivers\\volmgr.sys",
            L"\\drivers\\mountmgr.sys",
        };

        std::uint32_t touched = 0;
        for (const auto* rel : k_files) {
            wchar_t full[MAX_PATH] = {};
            wcscpy_s(full, sysdir);
            wcscat_s(full, rel);
            touch_file(full);
            ++touched;
        }

        logging::print("filetimes: touched %u system file timestamps", touched);
    }

}
