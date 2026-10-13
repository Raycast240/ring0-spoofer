#pragma once
#include "helpers.hxx"
#include <winioctl.h>

namespace spoof::usn_journal {

    static void rotate_volume(wchar_t letter) {
        wchar_t path[8] = {};
        swprintf_s(path, 8, L"\\\\.\\%lc:", letter);

        HANDLE hVol = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hVol == INVALID_HANDLE_VALUE) return;


        USN_JOURNAL_DATA jd{};
        DWORD bytes = 0;
        if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL,
                             nullptr, 0, &jd, sizeof(jd), &bytes, nullptr)) {
            CloseHandle(hVol);
            return;
        }


        DELETE_USN_JOURNAL_DATA dujd{};
        dujd.UsnJournalID  = jd.UsnJournalID;
        dujd.DeleteFlags   = 0x00000001u;
        DeviceIoControl(hVol, FSCTL_DELETE_USN_JOURNAL,
                        &dujd, sizeof(dujd), nullptr, 0, &bytes, nullptr);


        CREATE_USN_JOURNAL_DATA cujd{};
        cujd.MaximumSize    = jd.MaximumSize    ? jd.MaximumSize    : 0x800000ULL;
        cujd.AllocationDelta = jd.AllocationDelta ? jd.AllocationDelta : 0x100000ULL;
        DeviceIoControl(hVol, FSCTL_CREATE_USN_JOURNAL,
                        &cujd, sizeof(cujd), nullptr, 0, &bytes, nullptr);

        CloseHandle(hVol);
        logging::print("usn_journal: rotated journal on %lc:", letter);
    }

    inline void install() {

        const DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (!(drives & (1u << i))) continue;
            wchar_t root[4] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
            const UINT type = GetDriveTypeW(root);

            if (type != DRIVE_FIXED) continue;
            rotate_volume(static_cast<wchar_t>(L'A' + i));
        }
    }

}
