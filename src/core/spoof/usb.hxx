#pragma once
#include "helpers.hxx"
#include "../../symbols/pdb_offsets.hxx"
#include <winreg.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

namespace usb {

    static loader_offsets::usbstor_offsets s_off{};
    static bool s_resolved = false;

    static bool resolve_offsets() {
        if (s_resolved) return true;
        if (!pdb_offsets::resolve_usbstor(&s_off)) {
            logging::print("spoof: usb - USBSTOR offset resolution failed");
            return false;
        }
        s_resolved = true;
        return true;
    }


    static void gen_serial(std::uint8_t* buf, std::uint32_t len) {
        using namespace spoof::helpers;
        for (std::uint32_t i = 0; i < len; ++i) {
            const std::uint32_t r = spoof::helpers::rand_next() % 36;
            buf[i] = r < 10 ? static_cast<std::uint8_t>('0' + r)
                             : static_cast<std::uint8_t>('A' + r - 10);
        }
    }

    static void spoof_pdo(std::uint64_t dev_va) {
        using namespace spoof::helpers;


        const std::uint64_t pdo_ext = dev_extension(dev_va);
        if (!is_kva(pdo_ext)) return;


        const std::uint64_t fdo_ext = kread_val<std::uint64_t>(pdo_ext + s_off.pdo_to_fdo);
        if (!is_kva(fdo_ext)) return;


        const std::uint32_t serial_len = kread_val<std::uint32_t>(fdo_ext + s_off.fdo_serial_len);
        if (!serial_len || serial_len > 64) return;


        std::uint8_t first_byte = kread_val<std::uint8_t>(fdo_ext + s_off.fdo_serial_bytes);
        if (first_byte < 0x20 || first_byte > 0x7E) return;


        std::uint8_t new_serial[64] = {};
        gen_serial(new_serial, serial_len);

        std::uint8_t old_serial[64] = {};
        if (!kread(fdo_ext + s_off.fdo_serial_bytes, old_serial, serial_len)) return;

        // identity gate: a USBSTOR serial is plain printable ASCII over its
        // whole length - any non-printable byte means the derived offset is
        // wrong for this build and a write could hit a neighbouring field
        for (std::uint32_t i = 0; i < serial_len; ++i) {
            if (old_serial[i] < 0x20 || old_serial[i] > 0x7E) {
                logging::print("spoof: usb - serial bytes not ASCII - write skipped");
                return;
            }
        }

        if (!kwrite_verified(fdo_ext + s_off.fdo_serial_bytes, new_serial, serial_len,
                             "usb: serial"))
            return;

        char old_serial_s[65] = {}, new_serial_s[65] = {};
        for (std::uint32_t i = 0; i < serial_len; ++i) {
            old_serial_s[i] = old_serial[i] >= 0x20 && old_serial[i] <= 0x7E
                ? static_cast<char>(old_serial[i]) : '.';
            new_serial_s[i] = static_cast<char>(new_serial[i]);
        }
        logging::change("USB", "USBSTOR serial", old_serial_s, new_serial_s);






        const std::uint64_t inq_ptr_va   = kread_val<std::uint64_t>(fdo_ext + s_off.fdo_inq_ptr);
        if (!is_kva(inq_ptr_va)) return;

        const std::uint64_t inq_data_va  = kread_val<std::uint64_t>(inq_ptr_va + s_off.inq_data_off);
        if (!is_kva(inq_data_va)) return;

        const std::uint64_t desc_va      = kread_val<std::uint64_t>(inq_data_va + s_off.inq_serial_desc);
        if (!is_kva(desc_va)) return;

        const std::uint8_t b_len  = kread_val<std::uint8_t>(desc_va);
        const std::uint8_t b_type = kread_val<std::uint8_t>(desc_va + 1);


        if (b_type != 0x03 || b_len < 4) return;


        const std::uint32_t desc_chars = (static_cast<std::uint32_t>(b_len) - 2u) / 2u;
        const std::uint32_t write_cnt  = desc_chars < serial_len ? desc_chars : serial_len;
        if (!write_cnt || write_cnt * 2u > 128u) return;

        std::uint8_t old_desc[128] = {};
        kread(desc_va + 2u, old_desc, write_cnt * 2u);

        // write the UTF-16LE serial pairs as one verified region: readback
        // compares the whole string area and restores the captured original
        // bytes on mismatch, so a partial descriptor write cannot linger
        std::uint8_t wide_pairs[128] = {};
        for (std::uint32_t i = 0; i < write_cnt; ++i) {
            wide_pairs[i * 2u]     = new_serial[i];
            wide_pairs[i * 2u + 1] = 0x00u;
        }
        if (!kwrite_verified(desc_va + 2u, wide_pairs, write_cnt * 2u, "usb: descriptor serial"))
            return;

        char old_desc_s[65] = {}, new_desc_s[65] = {};
        for (std::uint32_t i = 0; i < write_cnt; ++i) {
            const std::uint8_t ch = old_desc[i * 2u];
            old_desc_s[i] = ch >= 0x20 && ch <= 0x7E ? static_cast<char>(ch) : '.';
            new_desc_s[i] = static_cast<char>(new_serial[i]);
        }
        logging::change("USB", "USBSTOR descriptor serial", old_desc_s, new_desc_s);

        logging::print("spoof: usb - PDO 0x%llX serial spoofed (%u chars)",
            (unsigned long long)dev_va, serial_len);
    }

    static void clean_usb_registry() {
        SHDeleteKeyW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");
        SHDeleteKeyW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Enum\\USB");
        logging::print("spoof: USB - USBSTOR / USB registry cache wiped");
    }

    static void clean_setupapi_logs() {
        wchar_t windir[MAX_PATH] = {};
        GetWindowsDirectoryW(windir, MAX_PATH);
        const wchar_t* logs[] = {
            L"\\INF\\setupapi.dev.log",
            L"\\INF\\setupapi.setup.log",
        };
        for (const auto* suffix : logs) {
            wchar_t path[MAX_PATH] = {};
            wcscpy_s(path, windir);
            wcscat_s(path, suffix);
            HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                                    TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf != INVALID_HANDLE_VALUE) {
                CloseHandle(hf);
                logging::print("spoof: USB - truncated %ls", path);
            }
        }
    }

    inline void install() {
        using namespace spoof::helpers;

        if (!resolve_offsets()) return;

        std::uint32_t total = 0;
        enum_driver_devices(L"\\Driver\\USBSTOR", [&](std::uint64_t dev_va) {
            spoof_pdo(dev_va);
            ++total;
        });

        logging::print("spoof: USB - checked %u USBSTOR device object(s)", total);

        clean_usb_registry();
        clean_setupapi_logs();
    }

}
