#pragma once
#include "helpers.hxx"

namespace spoof::product_id {

    using namespace helpers;

    static void gen_segment(char* out, std::uint32_t& seed) {
        static const char k_chars[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        for (int i = 0; i < 5; ++i) {
            seed = seed * 0x343fdu + 0x269ec3u;
            out[i] = k_chars[(seed >> 16) % 32];
        }
        out[5] = '\0';
    }

    static void write_product_id(HKEY root, const wchar_t* subkey, const char* ledger_name) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;

        wchar_t old_id[64] = {};
        DWORD old_sz = sizeof(old_id), old_type = 0;
        const bool had_old = RegQueryValueExW(hk, L"ProductId", nullptr, &old_type,
            reinterpret_cast<BYTE*>(old_id), &old_sz) == ERROR_SUCCESS && old_type == REG_SZ;
        old_id[63] = 0;

        std::uint32_t seed = s_rng_seed ^ static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(subkey) & 0xFFFFFFFFu);
        char seg[4][6] = {};
        gen_segment(seg[0], seed);
        gen_segment(seg[1], seed);
        gen_segment(seg[2], seed);
        gen_segment(seg[3], seed);

        char id[24] = {};
        id[0]  = seg[0][0]; id[1]  = seg[0][1]; id[2]  = seg[0][2];
        id[3]  = seg[0][3]; id[4]  = seg[0][4];
        id[5]  = '-';
        id[6]  = seg[1][0]; id[7]  = seg[1][1]; id[8]  = seg[1][2];
        id[9]  = seg[1][3]; id[10] = seg[1][4];
        id[11] = '-';
        id[12] = seg[2][0]; id[13] = seg[2][1]; id[14] = seg[2][2];
        id[15] = seg[2][3]; id[16] = seg[2][4];
        id[17] = '-';
        id[18] = seg[3][0]; id[19] = seg[3][1]; id[20] = seg[3][2];
        id[21] = seg[3][3]; id[22] = seg[3][4];
        id[23] = '\0';


        wchar_t wid[24] = {};
        for (int i = 0; i < 23; ++i) wid[i] = static_cast<wchar_t>(id[i]);

        RegSetValueExW(hk, L"ProductId", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(wid),
                       static_cast<DWORD>(24 * sizeof(wchar_t)));

        char old_txt[76] = {}, new_txt[76] = {};
        snprintf(old_txt, sizeof(old_txt), "%ls", had_old ? old_id : L"(absent)");
        snprintf(new_txt, sizeof(new_txt), "%s", id);
        logging::change("Registry", ledger_name, old_txt, new_txt, false);

        logging::print("product_id: %s -> %s", id,
                       subkey[0] == L'H' ? "HKCU path" : "done");
        RegCloseKey(hk);
    }

    inline void install() {
        write_product_id(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId (NT HKLM)");
        write_product_id(HKEY_CURRENT_USER,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId (NT HKCU)");
        write_product_id(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId (Windows HKLM)");
        logging::print("product_id: ProductId spoofed");
    }

}
