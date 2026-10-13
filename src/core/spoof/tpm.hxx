#pragma once
#include "helpers.hxx"
#include <vector>
#include <winreg.h>

namespace spoof::tpm {

    using namespace helpers;

    // short hex tail of a binary registry value for the change ledger
    // (the unique part of an RSA-key blob is the trailing modulus)
    static void blob_snippet(const std::vector<BYTE>& blob, char* out, std::size_t out_len) {
        if (!out || !out_len) return;
        out[0] = '\0';
        std::size_t pos = 0;
        const std::size_t show = blob.size() < 8 ? blob.size() : 8;
        if (show < blob.size())
            pos += static_cast<std::size_t>(snprintf(out, out_len, ".."));
        const std::size_t start = blob.size() - show;
        for (std::size_t i = 0; i < show && pos + 3 <= out_len; ++i)
            pos += static_cast<std::size_t>(snprintf(out + pos, out_len - pos,
                "%02X", blob[start + i]));
    }

    static bool randomize_binary(HKEY root, const wchar_t* subkey, const wchar_t* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return false;
        DWORD sz = 0, type = 0;
        bool patched = false;
        if (RegQueryValueExW(hk, value, nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
            && sz && type == REG_BINARY) {
            std::vector<BYTE> buf(sz);
            if (RegQueryValueExW(hk, value, nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                const std::vector<BYTE> old_buf(buf);
                for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                patched = RegSetValueExW(hk, value, 0, REG_BINARY, buf.data(), sz) == ERROR_SUCCESS;
                if (patched) {
                    char name[56] = {}, old_s[24] = "-", new_s[24] = "-";
                    snprintf(name, sizeof(name), "%ls", value);
                    blob_snippet(old_buf, old_s, sizeof(old_s));
                    blob_snippet(buf, new_s, sizeof(new_s));
                    logging::change("TPM", name, old_s, new_s);
                }
            }
        }
        RegCloseKey(hk);
        return patched;
    }

    static void delete_value(HKEY root, const wchar_t* subkey, const wchar_t* value) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;
        RegDeleteValueW(hk, value);
        RegCloseKey(hk);
    }

    // Endorsement\EkPub is a CNG BCRYPT "RSA1" public-key blob:
    //   magic(4) "RSA1" | bitlen(4) | cbExp(4) | cbMod(4) | cbP1(4) | cbP2(4)
    //   | publicExponent | modulus
    // only the modulus is the unique identity - keep everything else intact so
    // the blob stays structurally valid (big-endian, top bit set, odd, like a
    // real RSA-2048 modulus)
    static bool mutate_rsa_pub_blob(std::vector<BYTE>& blob) {
        if (blob.size() < 0x14) return false;
        if (memcmp(blob.data(), "RSA1", 4) != 0) return false;
        const DWORD cb_exp = *reinterpret_cast<const DWORD*>(blob.data() + 8);
        const DWORD cb_mod = *reinterpret_cast<const DWORD*>(blob.data() + 12);
        const std::size_t mod_off = 0x14 + cb_exp;
        if (!cb_mod || mod_off + cb_mod > blob.size()) return false;

        for (DWORD i = 0; i < cb_mod; ++i)
            blob[mod_off + i] = static_cast<BYTE>(rand_next() & 0xFF);
        blob[mod_off] |= 0x80;                       // 2048-bit modulus has the top bit set
        blob[mod_off + cb_mod - 1] |= 0x01;         // ...and is odd
        return true;
    }

    static bool randomize_blob_write(const wchar_t* subkey, const wchar_t* value,
                                     const std::vector<BYTE>& blob) {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
            return false;
        const bool ok = RegSetValueExW(hk, value, 0, REG_BINARY,
            blob.data(), (DWORD)blob.size()) == ERROR_SUCCESS;
        RegCloseKey(hk);
        return ok;
    }

    static void spoof_endorsement_key() {
        static const wchar_t k_path[] =
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk)
                != ERROR_SUCCESS)
            return;

        DWORD sz = 0, type = 0;
        std::uint32_t patched = 0;
        if (RegQueryValueExW(hk, L"EkPub", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
            && sz && type == REG_BINARY) {
            std::vector<BYTE> buf(sz);
            if (RegQueryValueExW(hk, L"EkPub", nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                const std::vector<BYTE> old_buf(buf);
                bool ok = mutate_rsa_pub_blob(buf);
                if (!ok) {
                    // non-RSA blob (ECC EK etc.) - fall back to a full randomize
                    for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                    ok = true;
                }
                if (ok && RegSetValueExW(hk, L"EkPub", 0, REG_BINARY, buf.data(), sz) == ERROR_SUCCESS) {
                    ++patched;
                    char old_s[24] = "-", new_s[24] = "-";
                    blob_snippet(old_buf, old_s, sizeof(old_s));
                    blob_snippet(buf, new_s, sizeof(new_s));
                    logging::change("TPM", "Endorsement EkPub", old_s, new_s);
                }

                // ProvisionInfo\LastEkPub is a byte-identical copy of EkPub  -
                // keep the pair consistent
                char last_old_s[24] = "-";
                {
                    HKEY hk_prov = nullptr;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\ProvisionInfo",
                            0, KEY_READ, &hk_prov) == ERROR_SUCCESS) {
                        DWORD lsz = 0, ltype = 0;
                        if (RegQueryValueExW(hk_prov, L"LastEkPub", nullptr, &ltype,
                                nullptr, &lsz) == ERROR_SUCCESS
                            && lsz && ltype == REG_BINARY) {
                            std::vector<BYTE> old_last(lsz);
                            if (RegQueryValueExW(hk_prov, L"LastEkPub", nullptr, &ltype,
                                    old_last.data(), &lsz) == ERROR_SUCCESS)
                                blob_snippet(old_last, last_old_s, sizeof(last_old_s));
                        }
                        RegCloseKey(hk_prov);
                    }
                }
                if (ok && randomize_blob_write(
                        L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\ProvisionInfo",
                        L"LastEkPub", buf)) {
                    ++patched;
                    char new_s[24] = "-";
                    blob_snippet(buf, new_s, sizeof(new_s));
                    logging::change("TPM", "ProvisionInfo LastEkPub", last_old_s, new_s);
                }
            }
        }
        RegCloseKey(hk);

        // the EK certificate is vendor-signed and binds to the real EK - a
        // spoofed EkPub can never match it, so remove the cached cert state
        // entirely (absent EK cert is a normal Windows state and Windows
        // refetches it only on its own schedule)
        delete_value(HKEY_LOCAL_MACHINE, k_path, L"EKCertStore");
        delete_value(HKEY_LOCAL_MACHINE, k_path, L"EKCertStoreECC");
        delete_value(HKEY_LOCAL_MACHINE, k_path, L"IntermediateCACertStore");
        delete_value(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\ProvisionInfo",
            L"LastRsaEkCertThumbprint");
        delete_value(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\ProvisionInfo",
            L"LastEccEkCertThumbprint");

        logging::print("tpm: EK public key mutated (%u value(s)), EK cert state cleared",
            patched);
    }

    static void spoof_tpm_main() {
        static const wchar_t k_path[] = L"SOFTWARE\\Microsoft\\TPM";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk)
                != ERROR_SUCCESS)
            return;

        std::uint32_t patched = 0;
        static const wchar_t* k_blobs[] = { L"EkCert", L"StorageKey", L"EkPub" };
        for (const auto* val : k_blobs) {
            DWORD sz = 0, type = 0;
            if (RegQueryValueExW(hk, val, nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
                && sz && type == REG_BINARY) {
                std::vector<BYTE> buf(sz);
                if (RegQueryValueExW(hk, val, nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                    const std::vector<BYTE> old_buf(buf);
                    for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                    if (RegSetValueExW(hk, val, 0, REG_BINARY, buf.data(), sz) == ERROR_SUCCESS) {
                        ++patched;
                        char name[56] = {}, old_s[24] = "-", new_s[24] = "-";
                        snprintf(name, sizeof(name), "TPM %ls", val);
                        blob_snippet(old_buf, old_s, sizeof(old_s));
                        blob_snippet(buf, new_s, sizeof(new_s));
                        logging::change("TPM", name, old_s, new_s);
                    }
                }
            }
        }
        RegCloseKey(hk);
        if (patched)
            logging::print("tpm: TPM main registry values randomized (%u)", patched);
    }

    static void spoof_calipower() {
        static const wchar_t k_path[] =
            L"SOFTWARE\\Microsoft\\Cryptography\\Calipower";
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_path, 0, KEY_READ | KEY_SET_VALUE, &hk)
                != ERROR_SUCCESS)
            return;

        std::uint32_t patched = 0;
        static const wchar_t* k_blobs[] = { L"EkCert", L"CardId", L"SessionId" };
        for (const auto* val : k_blobs) {
            DWORD sz = 0, type = 0;
            if (RegQueryValueExW(hk, val, nullptr, &type, nullptr, &sz) == ERROR_SUCCESS
                && sz && type == REG_BINARY) {
                std::vector<BYTE> buf(sz);
                if (RegQueryValueExW(hk, val, nullptr, &type, buf.data(), &sz) == ERROR_SUCCESS) {
                    const std::vector<BYTE> old_buf(buf);
                    for (auto& b : buf) b = static_cast<BYTE>(rand_next() & 0xFF);
                    if (RegSetValueExW(hk, val, 0, REG_BINARY, buf.data(), sz) == ERROR_SUCCESS) {
                        ++patched;
                        char name[56] = {}, old_s[24] = "-", new_s[24] = "-";
                        snprintf(name, sizeof(name), "Calipower %ls", val);
                        blob_snippet(old_buf, old_s, sizeof(old_s));
                        blob_snippet(buf, new_s, sizeof(new_s));
                        logging::change("TPM", name, old_s, new_s);
                    }
                }
            }
        }
        RegCloseKey(hk);
        if (patched)
            logging::print("tpm: Calipower keys randomized (%u)", patched);
    }

    static void spoof_tpm_service() {
        std::uint32_t patched = 0;
        if (randomize_binary(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID", L"RandomSeed")) ++patched;
        if (randomize_binary(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", L"WindowsAIKHash")) ++patched;
        if (randomize_binary(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", L"PlatformModuleData")) ++patched;
        // Admin\SRKPub holds the (self-contained) SHA-256 of the SRK public
        if (randomize_binary(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin", L"SRKPub")) ++patched;
        delete_value(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM", L"Policy");
        if (patched)
            logging::print("tpm: TPM service data randomized (%u value(s))", patched);
    }

    inline void install() {
        spoof_endorsement_key();
        spoof_tpm_main();
        spoof_calipower();
        spoof_tpm_service();
    }

}