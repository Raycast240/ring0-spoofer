#pragma once
#include "helpers.hxx"
#include <vector>
#include <functional>
#include <winternl.h>

namespace spoof::acpi {

    using namespace helpers;

#pragma pack(push, 1)
    struct AcpiTableHeader {
        char     Signature[4];
        std::uint32_t Length;
        std::uint8_t  Revision;
        std::uint8_t  Checksum;
        char     OemId[6];       // offset 10
        char     OemTableId[8];  // offset 16
        std::uint32_t OemRevision;
        char     CreatorId[4];
        std::uint32_t CreatorRevision;
    };
    static_assert(sizeof(AcpiTableHeader) == 36, "");

    struct Rsdp20 {
        char     Signature[8];   // "RSD PTR "
        std::uint8_t  Checksum;
        char     OemId[6];
        std::uint8_t  Revision;
        std::uint32_t RsdtAddress;    // ACPI 1.0 32-bit PA
        std::uint32_t Length;         // ACPI 2.0+
        std::uint64_t XsdtAddress;    // ACPI 2.0+ 64-bit PA
        std::uint8_t  ExtChecksum;
        std::uint8_t  Reserved[3];
    };
    static_assert(sizeof(Rsdp20) == 36, "");
#pragma pack(pop)

    static char s_oem_id[6]      = {};
    static char s_oem_table_id[8]= {};
    static bool s_profile_set    = false;

    static void pick_oem_profile() {
        if (s_profile_set) return;
        struct Profile { const char oem_id[7]; const char table_id[9]; };
        static const Profile k_profiles[] = {
            { "ALASKA", "A M I   " },
            { "INTEL ", "INTEL   " },
            { "DELL  ", "CBX3    " },
            { "LENOVO", "CB-01   " },
            { "MSI   ", "MS-7D25 " },
        };
        const auto& p = k_profiles[rand_next() % 5];
        memcpy(s_oem_id,       p.oem_id,    6);
        memcpy(s_oem_table_id, p.table_id,  8);
        s_profile_set = true;
    }

    static void patch_header_oem(std::uint8_t* buf, std::uint32_t size) {
        if (size < 36) return;
        auto* hdr = reinterpret_cast<AcpiTableHeader*>(buf);
        memcpy(hdr->OemId,      s_oem_id,       6);
        memcpy(hdr->OemTableId, s_oem_table_id, 8);
        const std::uint32_t chk_len = hdr->Length <= size ? hdr->Length : size;
        hdr->Checksum = 0;
        std::uint8_t sum = 0;
        for (std::uint32_t i = 0; i < chk_len; ++i) sum += buf[i];
        hdr->Checksum = static_cast<std::uint8_t>(0 - sum);
    }

    static bool valid_acpi_sig(const char* sig) {
        for (int i = 0; i < 4; ++i)
            if (sig[i] < 0x20 || sig[i] > 0x7E) return false;
        return true;
    }

    static std::uint64_t find_rsdp_pa() {
        static const std::uint64_t k_ranges[][2] = {
            { 0x000E0000ULL, 0x000FFFFFULL },   // BIOS ROM shadow (legacy + UEFI compat)
            { 0x00080000ULL, 0x0009FFFFULL },    // EBDA area
        };
        std::vector<std::uint8_t> chunk;

        for (const auto& r : k_ranges) {
            const std::uint64_t pa_start = r[0];
            const std::uint64_t pa_end   = r[1];
            const std::uint32_t size     = static_cast<std::uint32_t>(pa_end - pa_start + 1);
            chunk.resize(size);
            if (!driver::read_physical_memory(pa_start, chunk.data(), size)) continue;

            for (std::uint32_t off = 0; off + sizeof(Rsdp20) <= size; off += 16) {
                if (memcmp(&chunk[off], "RSD PTR ", 8) != 0) continue;
                return pa_start + off;
            }
        }

        {
            const std::uint64_t smbios_pa_sym = pdb::get_symbol_address("WmipSMBiosTablePhysicalAddress");
            std::uint64_t smbios_pa = 0;
            if (smbios_pa_sym) smbios_pa = kread_val<std::uint64_t>(smbios_pa_sym);

            const std::uint64_t scan_start = smbios_pa > 0x08000000ULL
                                        ? smbios_pa - 0x08000000ULL : 0x00001000ULL;
            const std::uint64_t scan_end   = scan_start + 0x10000000ULL; // +256MB window
            const std::uint32_t chunk_sz   = 0x10000; // 64KB
            chunk.resize(chunk_sz);

            for (std::uint64_t pa = scan_start; pa < scan_end; pa += chunk_sz) {
                const std::uint32_t rd = static_cast<std::uint32_t>(
                    (pa + chunk_sz < scan_end) ? chunk_sz : scan_end - pa);
                if (!driver::read_physical_memory(pa, chunk.data(), rd)) continue;
                for (std::uint32_t off = 0; off + sizeof(Rsdp20) <= rd; off += 16) {
                    if (memcmp(&chunk[off], "RSD PTR ", 8) != 0) continue;
                    return pa + off;
                }
            }
        }

        return 0;
    }

    static std::uint32_t patch_tables_via_xsdt(std::uint64_t rsdp_pa) {
        Rsdp20 rsdp{};
        if (!driver::read_physical_memory(rsdp_pa, &rsdp, sizeof(rsdp))) return 0;
        if (memcmp(rsdp.Signature, "RSD PTR ", 8) != 0) return 0;

        const bool use_xsdt   = (rsdp.Revision >= 2 && rsdp.XsdtAddress != 0);
        const std::uint64_t sdt_pa = use_xsdt ? rsdp.XsdtAddress
                                         : static_cast<std::uint64_t>(rsdp.RsdtAddress);
        if (!sdt_pa) return 0;

        AcpiTableHeader sdt_hdr{};
        if (!driver::read_physical_memory(sdt_pa, &sdt_hdr, sizeof(sdt_hdr))) return 0;
        if (!valid_acpi_sig(sdt_hdr.Signature)) return 0;
        if (sdt_hdr.Length < 36 + 4 || sdt_hdr.Length > 0x10000) return 0;

        std::vector<std::uint8_t> sdt_buf(sdt_hdr.Length);
        if (!driver::read_physical_memory(sdt_pa, sdt_buf.data(), sdt_hdr.Length)) return 0;

        const std::uint32_t entry_size = use_xsdt ? 8u : 4u;
        const std::uint32_t n_entries  = (sdt_hdr.Length - 36) / entry_size;
        const std::uint8_t* entries    = sdt_buf.data() + 36;

        std::uint32_t patched = 0;

        auto patch_one = [&](std::uint64_t table_pa) {
            if (!table_pa) return;

            AcpiTableHeader hdr{};
            if (!driver::read_physical_memory(table_pa, &hdr, sizeof(hdr))) return;
            if (!valid_acpi_sig(hdr.Signature)) return;
            if (hdr.Length < 36 || hdr.Length > 0x200000) return;

            std::vector<std::uint8_t> buf(hdr.Length);
            if (!driver::read_physical_memory(table_pa, buf.data(), hdr.Length)) return;

            // keep the pre-patch bytes so a failed readback can be undone
            const std::vector<std::uint8_t> orig(buf);

            patch_header_oem(buf.data(), hdr.Length);
            if (driver::write_physical_memory(table_pa, buf.data(), hdr.Length)) {
                // readback discipline: the table must hold exactly the mutated
                // bytes after the write; on any mismatch the captured original
                // goes back so a short/failed write cannot leave a half-
                // checksummed table for the interpreter
                std::vector<std::uint8_t> back(hdr.Length);
                if (!driver::read_physical_memory(table_pa, back.data(), hdr.Length)
                    || back != buf) {
                    driver::write_physical_memory(table_pa, orig.data(), orig.size());
                    logging::print("acpi: %.4s at PA=0x%llx write failed readback - restored",
                        hdr.Signature, static_cast<unsigned long long>(table_pa));
                    return;
                }
                logging::print("acpi: patched %.4s at PA=0x%llx",
                    hdr.Signature, static_cast<unsigned long long>(table_pa));
                ++patched;
            }
        };

        patch_one(sdt_pa);

        for (std::uint32_t i = 0; i < n_entries; ++i) {
            std::uint64_t child_pa = 0;
            if (use_xsdt) memcpy(&child_pa, entries + i * 8, 8);
            else { std::uint32_t tmp = 0; memcpy(&tmp, entries + i * 4, 4); child_pa = tmp; }
            patch_one(child_pa);
        }

        for (std::uint32_t i = 0; i < n_entries; ++i) {
            std::uint64_t child_pa = 0;
            if (use_xsdt) memcpy(&child_pa, entries + i * 8, 8);
            else { std::uint32_t tmp = 0; memcpy(&tmp, entries + i * 4, 4); child_pa = tmp; }
            if (!child_pa) continue;

            AcpiTableHeader child_hdr{};
            if (!driver::read_physical_memory(child_pa, &child_hdr, sizeof(child_hdr))) continue;
            if (memcmp(child_hdr.Signature, "FACP", 4) != 0) continue;

            if (child_hdr.Length > 148) {
                std::uint64_t dsdt_pa64 = 0;
                driver::read_physical_memory(child_pa + 140, &dsdt_pa64, 8);
                if (dsdt_pa64) patch_one(dsdt_pa64);
            }
            if (child_hdr.Length > 44) {
                std::uint32_t dsdt_pa32 = 0;
                driver::read_physical_memory(child_pa + 40, &dsdt_pa32, 4);
                if (dsdt_pa32) patch_one(static_cast<std::uint64_t>(dsdt_pa32));
            }
        }

        return patched;
    }

    static void enable_restore_priv() {
        HANDLE tok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValueA(nullptr, "SeRestorePrivilege", &tp.Privileges[0].Luid);
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(tok);
    }

    static std::uint32_t patch_registry_tree(HKEY hk, int depth) {
        if (depth > 5) return 0;
        std::uint32_t patched = 0;

        DWORD vsz = 0, vtype = 0;
        if (RegQueryValueExW(hk, L"00000000", nullptr, &vtype, nullptr, &vsz) == ERROR_SUCCESS
            && vtype == REG_BINARY && vsz >= 36) {
            std::vector<BYTE> buf(vsz);
            if (RegQueryValueExW(hk, L"00000000", nullptr, &vtype,
                                  buf.data(), &vsz) == ERROR_SUCCESS) {
                auto* hdr = reinterpret_cast<AcpiTableHeader*>(buf.data());
                if (valid_acpi_sig(hdr->Signature) && hdr->Length >= 36 && hdr->Length <= vsz) {
                    patch_header_oem(buf.data(), vsz);
                    if (RegSetValueExW(hk, L"00000000", 0, REG_BINARY,
                                       buf.data(), vsz) == ERROR_SUCCESS)
                        ++patched;
                }
            }
        }

        for (DWORD i = 0; ; ++i) {
            wchar_t sub[128] = {};
            DWORD sub_len = 128;
            if (RegEnumKeyExW(hk, i, sub, &sub_len,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(hk, sub, REG_OPTION_BACKUP_RESTORE,
                              KEY_READ | KEY_SET_VALUE, &hSub) != ERROR_SUCCESS) continue;
            patched += patch_registry_tree(hSub, depth + 1);
            RegCloseKey(hSub);
        }
        return patched;
    }

    static void patch_registry() {
        enable_restore_priv();
        HKEY hBase = nullptr;
        const LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI",
                                         REG_OPTION_BACKUP_RESTORE,
                                         KEY_READ | KEY_SET_VALUE, &hBase);
        if (st != ERROR_SUCCESS) {
            logging::print("acpi: HARDWARE\\ACPI open failed (0x%lx)", static_cast<long>(st));
            return;
        }
        const std::uint32_t patched = patch_registry_tree(hBase, 0);
        RegCloseKey(hBase);
        logging::print("acpi: registry blobs patched (%u)", patched);
    }


    inline void install() {
        pick_oem_profile();
        logging::print("acpi: OEM profile '%.6s' / '%.8s'", s_oem_id, s_oem_table_id);

        const std::uint64_t rsdp_pa = find_rsdp_pa();
        if (rsdp_pa) {
            logging::print("acpi: RSDP found at PA=0x%llx",
                static_cast<unsigned long long>(rsdp_pa));
            const std::uint32_t n = patch_tables_via_xsdt(rsdp_pa);
            logging::print("acpi: %u physical table(s) patched", n);
        } else {
            logging::print("acpi: RSDP not found, physical patch skipped");
        }

        patch_registry();
    }

}
