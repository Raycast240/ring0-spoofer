#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>

namespace spoof::hostname {

    using namespace helpers;

    static wchar_t s_hostname[32] = {};

    static void set_sz(HKEY root, const wchar_t* subkey,
                       const wchar_t* value, const wchar_t* data,
                       const char* ledger_name) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;

        wchar_t old_data[128] = {};
        DWORD old_sz = sizeof(old_data), old_type = 0;
        const bool had_old = RegQueryValueExW(hk, value, nullptr, &old_type,
            reinterpret_cast<BYTE*>(old_data), &old_sz) == ERROR_SUCCESS
            && (old_type == REG_SZ || old_type == REG_EXPAND_SZ);
        old_data[127] = 0;

        const DWORD sz = static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t));
        const bool ok = RegSetValueExW(hk, value, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(data), sz) == ERROR_SUCCESS;
        RegCloseKey(hk);

        if (ok) {
            char old_txt[76] = {}, new_txt[76] = {};
            snprintf(old_txt, sizeof(old_txt), "%ls", had_old ? old_data : L"(absent)");
            snprintf(new_txt, sizeof(new_txt), "%ls", data);
            logging::change("Hostname", ledger_name, old_txt, new_txt, false);
        }
    }

    static void gen_hostname(wchar_t* out, std::size_t cch) {
        const DWORD hex = (rand_next() << 15u) ^ rand_next();
        swprintf_s(out, cch, L"DESKTOP-%07X", hex & 0x0FFFFFFFu);
    }

    static void spoof_computer_name() {
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
            L"ComputerName", s_hostname, "ComputerName");
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
            L"ComputerName", s_hostname, "ComputerName (Active)");
        logging::print("hostname: ComputerName -> %ls", s_hostname);
    }

    static void spoof_tcpip_hostname() {
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            L"Hostname", s_hostname, "Tcpip Hostname");
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            L"NV Hostname", s_hostname, "Tcpip NV Hostname");
        logging::print("hostname: Tcpip Hostname -> %ls", s_hostname);
    }

    static void spoof_env_computername() {
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            L"COMPUTERNAME", s_hostname, "COMPUTERNAME (Environment)");
        logging::print("hostname: Environment COMPUTERNAME -> %ls", s_hostname);
    }

    static void spoof_pnp_dnsfqdn() {
        set_sz(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PnP",
            L"DnsFQDN", s_hostname, "PnP DnsFQDN");
        logging::print("hostname: PnP DnsFQDN -> %ls", s_hostname);
    }

    static void fmt_bin_preview(char* out, std::size_t out_sz,
                                const BYTE* data, DWORD sz) {
        if (!data || !sz) {
            snprintf(out, out_sz, "%s", "(absent)");
            return;
        }
        char hex[24] = {};
        const DWORD n = sz < 8 ? sz : 8;
        for (DWORD i = 0; i < n; ++i)
            snprintf(hex + i * 2, 3, "%02X", data[i]);
        snprintf(out, out_sz, "%s.. (%u byte(s))", hex, static_cast<unsigned>(sz));
    }

    static void spoof_dhcpv6_duid() {
        static const wchar_t k_path[] =
            L"SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return;

        DWORD sz = 0, type = 0;
        if (RegQueryValueExW(hk, L"Dhcpv6DUID", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
            && sz && type == REG_BINARY) {
            std::vector<BYTE> buf(sz);
            if (RegQueryValueExW(hk, L"Dhcpv6DUID", nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                const std::vector<BYTE> old_buf(buf);
                for (DWORD i = 4; i < sz; ++i)
                    buf[i] = static_cast<BYTE>(rand_next() & 0xFF);
                if (RegSetValueExW(hk, L"Dhcpv6DUID", 0, REG_BINARY, buf.data(), sz) == ERROR_SUCCESS) {
                    char old_txt[76] = {}, new_txt[76] = {};
                    fmt_bin_preview(old_txt, sizeof(old_txt), old_buf.data(),
                        static_cast<DWORD>(old_buf.size()));
                    fmt_bin_preview(new_txt, sizeof(new_txt), buf.data(), sz);
                    logging::change("Hostname", "Dhcpv6DUID", old_txt, new_txt, false);
                }
            }
        }
        RegCloseKey(hk);
        logging::print("hostname: Dhcpv6DUID randomized");
    }

    inline void install() {
        gen_hostname(s_hostname, 32);

        spoof_computer_name();
        spoof_tcpip_hostname();
        spoof_dhcpv6_duid();
        spoof_env_computername();
        spoof_pnp_dnsfqdn();


    }

}
