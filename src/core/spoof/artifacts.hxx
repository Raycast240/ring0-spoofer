#pragma once
#include "helpers.hxx"
#include <vector>
#include <string>
#include <aclapi.h>
#pragma comment(lib, "advapi32.lib")

namespace spoof::artifacts {

    using namespace helpers;

    static std::uint32_t delete_dir_contents(const wchar_t* dir, bool recurse = true) {
        std::uint32_t deleted = 0;
        wchar_t pattern[MAX_PATH] = {};
        wcscpy_s(pattern, dir);
        wcscat_s(pattern, L"\\*");

        WIN32_FIND_DATAW fd{};
        HANDLE hFind = FindFirstFileW(pattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return 0;

        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            wchar_t full[MAX_PATH] = {};
            wcscpy_s(full, dir);
            wcscat_s(full, L"\\");
            wcscat_s(full, fd.cFileName);

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (recurse) {
                    deleted += delete_dir_contents(full, true);
                    RemoveDirectoryW(full);
                }
            } else {

                SetFileAttributesW(full, FILE_ATTRIBUTE_NORMAL);
                if (DeleteFileW(full)) ++deleted;
            }
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        return deleted;
    }

    static bool take_ownership(const wchar_t* path) {
        PSID pAdminSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&ntAuth, 2,
                SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                0, 0, 0, 0, 0, 0, &pAdminSid)) return false;

        bool ok = SetNamedSecurityInfoW(
            const_cast<wchar_t*>(path), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            pAdminSid, nullptr, nullptr, nullptr) == ERROR_SUCCESS;

        if (ok) {
            EXPLICIT_ACCESS_W ea{};
            ea.grfAccessPermissions = GENERIC_ALL;
            ea.grfAccessMode        = GRANT_ACCESS;
            ea.grfInheritance       = NO_INHERITANCE;
            ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
            ea.Trustee.ptstrName    = reinterpret_cast<wchar_t*>(pAdminSid);

            PACL pDacl = nullptr;
            if (SetEntriesInAclW(1, &ea, nullptr, &pDacl) == ERROR_SUCCESS && pDacl) {
                SetNamedSecurityInfoW(
                    const_cast<wchar_t*>(path), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, pDacl, nullptr);
                LocalFree(pDacl);
            }
        }
        FreeSid(pAdminSid);
        return ok;
    }

    static void clear_prefetch() {
        wchar_t windir[MAX_PATH] = {};
        GetWindowsDirectoryW(windir, MAX_PATH);

        wchar_t pf_dir[MAX_PATH] = {};
        wcscpy_s(pf_dir, windir);
        wcscat_s(pf_dir, L"\\Prefetch");

        const std::uint32_t deleted = delete_dir_contents(pf_dir, false);

        wchar_t rb_dir[MAX_PATH] = {};
        wcscpy_s(rb_dir, pf_dir);
        wcscat_s(rb_dir, L"\\ReadyBoot");
        const std::uint32_t rb_deleted = delete_dir_contents(rb_dir, false);

        logging::print("artifacts: Prefetch - deleted %u .pf file(s), %u ReadyBoot file(s)",
            deleted, rb_deleted);
    }

    static void clear_amcache() {
        wchar_t windir[MAX_PATH] = {};
        GetWindowsDirectoryW(windir, MAX_PATH);

        wchar_t path[MAX_PATH] = {};
        wcscpy_s(path, windir);
        wcscat_s(path, L"\\AppCompat\\Programs\\Amcache.hve");


        wchar_t path_log1[MAX_PATH] = {}, path_log2[MAX_PATH] = {};
        wcscpy_s(path_log1, path); wcscat_s(path_log1, L".LOG1");
        wcscpy_s(path_log2, path); wcscat_s(path_log2, L".LOG2");


        {
            SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (hSCM) {
                SC_HANDLE hSvc = OpenServiceW(hSCM, L"PcaSvc",
                    SERVICE_STOP | SERVICE_QUERY_STATUS);
                if (hSvc) {
                    SERVICE_STATUS ss{};
                    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);

                    for (int w = 0; w < 20; ++w) {
                        QueryServiceStatus(hSvc, &ss);
                        if (ss.dwCurrentState == SERVICE_STOPPED) break;
                        Sleep(100);
                    }
                    CloseServiceHandle(hSvc);
                }
                CloseServiceHandle(hSCM);
            }
        }

        take_ownership(path);
        SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);

        bool deleted = DeleteFileW(path) != FALSE;
        DeleteFileW(path_log1);
        DeleteFileW(path_log2);

        if (!deleted) {

            MoveFileExW(path,   nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            MoveFileExW(path_log1, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            MoveFileExW(path_log2, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            logging::print("artifacts: Amcache.hve locked - scheduled for deletion on reboot");
        } else {
            logging::print("artifacts: Amcache.hve deleted");
        }
    }

    static void clear_event_logs() {
        static const wchar_t* k_logs[] = {
            L"System",
            L"Application",
            L"Security",
            L"Setup",
            L"Microsoft-Windows-Kernel-PnP/Configuration",
            L"Microsoft-Windows-Kernel-Boot/Operational",
            L"Microsoft-Windows-Kernel-General/Information",
        };

        std::uint32_t cleared = 0;

        for (const auto* log : k_logs) {
            HANDLE hLog = OpenEventLogW(nullptr, log);
            if (hLog) {
                if (ClearEventLogW(hLog, nullptr)) ++cleared;
                CloseEventLog(hLog);
            } else {

                wchar_t cmd[256] = {};
                swprintf_s(cmd, L"wevtutil.exe cl \"%s\"", log);

                wchar_t full_cmd[320] = {};
                swprintf_s(full_cmd, L"cmd.exe /c %s 2>nul", cmd);

                STARTUPINFOW si{};
                PROCESS_INFORMATION pi{};
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;

                if (CreateProcessW(nullptr, full_cmd, nullptr, nullptr,
                                   FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, 10000);
                    DWORD ec = 0;
                    GetExitCodeProcess(pi.hProcess, &ec);
                    if (ec == 0) ++cleared;
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
            }
        }

        logging::print("artifacts: cleared %u event log channel(s)", cleared);
    }

    static void clear_minidumps() {
        wchar_t windir[MAX_PATH] = {};
        GetWindowsDirectoryW(windir, MAX_PATH);

        wchar_t dump_dir[MAX_PATH] = {};
        swprintf_s(dump_dir, L"%s\\Minidump", windir);
        const std::uint32_t n = delete_dir_contents(dump_dir, false);

        wchar_t live_dir[MAX_PATH] = {};
        swprintf_s(live_dir, L"%s\\LiveKernelReports", windir);
        const std::uint32_t n2 = delete_dir_contents(live_dir, true);

        logging::print("artifacts: minidumps/LiveKernelReports - deleted %u + %u file(s)", n, n2);
    }

    static void clear_wer_reports() {
        std::uint32_t deleted = 0;

        wchar_t sys_wer[MAX_PATH] = {};
        ExpandEnvironmentStringsW(L"%ProgramData%\\Microsoft\\Windows\\WER", sys_wer, MAX_PATH);
        deleted += delete_dir_contents(sys_wer, true);

        wchar_t user_wer[MAX_PATH] = {};
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", user_wer, MAX_PATH)) {
            wcscat_s(user_wer, L"\\Microsoft\\Windows\\WER");
            deleted += delete_dir_contents(user_wer, true);
        }

        logging::print("artifacts: WER reports - deleted %u file(s)", deleted);
    }

    static void clear_driver_etw_channels() {
        static const wchar_t* k_channels[] = {
            L"Microsoft-Windows-CodeIntegrity/Operational",
            L"Microsoft-Windows-DriverFrameworks-UserMode/Operational",
            L"Microsoft-Windows-Kernel-IO/Operational",
            L"Microsoft-Windows-Kernel-Process/Analytic",
            L"Microsoft-Windows-PnpDevice/Operational",
            L"Microsoft-Windows-PnpDevice/Admin",
            L"Microsoft-Windows-StorDiag/Operational",
            L"Microsoft-Windows-WER-Diag/Operational",
            L"Microsoft-Windows-Kernel-EventTracing/Admin",
        };

        std::uint32_t cleared = 0;
        wchar_t sys[MAX_PATH] = {};
        GetSystemDirectoryW(sys, MAX_PATH);

        for (const auto* ch : k_channels) {
            wchar_t cmd[512] = {};
            swprintf_s(cmd, L"cmd.exe /c \"%s\\wevtutil.exe\" cl \"%s\" 2>nul", sys, ch);

            STARTUPINFOW si{};
            PROCESS_INFORMATION pi{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;

            if (CreateProcessW(nullptr, cmd, nullptr, nullptr,
                               FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 8000);
                DWORD ec = 0;
                GetExitCodeProcess(pi.hProcess, &ec);
                if (ec == 0) ++cleared;
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
        logging::print("artifacts: driver ETW channels cleared (%u/%zu)", cleared,
            sizeof(k_channels) / sizeof(k_channels[0]));
    }

    static void clear_etl_traces() {
        std::uint32_t deleted = 0;

        wchar_t win[MAX_PATH] = {}, sys[MAX_PATH] = {};
        GetWindowsDirectoryW(win, MAX_PATH);
        GetSystemDirectoryW(sys, MAX_PATH);

        wchar_t autolog[MAX_PATH] = {};
        swprintf_s(autolog, L"%s\\System32\\LogFiles\\WMI", win);
        deleted += delete_dir_contents(autolog, true);

        wchar_t wdi[MAX_PATH] = {};
        swprintf_s(wdi, L"%s\\wdi\\LogFiles", sys);
        deleted += delete_dir_contents(wdi, true);

        wchar_t diagtrack[MAX_PATH] = {};
        ExpandEnvironmentStringsW(
            L"%ProgramData%\\Microsoft\\Diagnosis\\ETLLogs\\AutoLogger",
            diagtrack, MAX_PATH);
        deleted += delete_dir_contents(diagtrack, false);

        wchar_t wmi_logs[MAX_PATH] = {};
        swprintf_s(wmi_logs, L"%s\\wbem\\Logs", sys);
        deleted += delete_dir_contents(wmi_logs, false);

        logging::print("artifacts: ETL trace files - deleted %u file(s)", deleted);
    }

    static void clear_ci_traces() {
        std::uint32_t deleted = 0;
        wchar_t win[MAX_PATH] = {};
        GetWindowsDirectoryW(win, MAX_PATH);

        wchar_t audit[MAX_PATH] = {};
        swprintf_s(audit, L"%s\\System32\\CodeIntegrity\\audit.csv", win);
        SetFileAttributesW(audit, FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(audit)) ++deleted;

        static const wchar_t* k_ci_files[] = {
            L"\\System32\\CodeIntegrity\\bootcat.cache",
        };
        for (const auto* rel : k_ci_files) {
            wchar_t full[MAX_PATH] = {};
            wcscpy_s(full, win);
            wcscat_s(full, rel);
            SetFileAttributesW(full, FILE_ATTRIBUTE_NORMAL);
            if (!DeleteFileW(full))
                MoveFileExW(full, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            else
                ++deleted;
        }

        logging::print("artifacts: CI traces - deleted %u file(s)", deleted);
    }

    static void clear_crypto_containers() {
        wchar_t appdata[MAX_PATH] = {};
        if (!GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH)) return;

        std::uint32_t deleted = 0;

        wchar_t rsa_dir[MAX_PATH] = {};
        wcscpy_s(rsa_dir, appdata);
        wcscat_s(rsa_dir, L"\\Microsoft\\Crypto\\RSA");
        deleted += delete_dir_contents(rsa_dir, true);

        wchar_t protect_dir[MAX_PATH] = {};
        wcscpy_s(protect_dir, appdata);
        wcscat_s(protect_dir, L"\\Microsoft\\Protect");
        deleted += delete_dir_contents(protect_dir, true);

        logging::print("artifacts: crypto containers - deleted %u file(s)", deleted);
    }

    inline void install() {
        clear_prefetch();
        clear_amcache();
        clear_event_logs();
        clear_driver_etw_channels();
        // clear_crypto_containers(); // Omitted: DPAPI / Protect folder deletion causes logout on Chrome/Discord/Steam
        clear_minidumps();
        clear_wer_reports();
        clear_etl_traces();
        clear_ci_traces();
    }

}
