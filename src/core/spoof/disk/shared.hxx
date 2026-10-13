#pragma once
#include "../helpers.hxx"
#include <cstring>
#include <vector>

namespace spoof::disk {

    static void format_hex_bytes(char* out, std::size_t out_size,
                                 const std::uint8_t* bytes, std::uint32_t length) {
        if (!out || !out_size) return;
        out[0] = '\0';
        std::size_t pos = 0;
        for (std::uint32_t i = 0; i < length && pos + 3 <= out_size; ++i) {
            snprintf(out + pos, out_size - pos, "%02X", bytes[i]);
            pos += 2;
        }
    }

    using namespace helpers;


    static char     s_serial[80]   = {};
    static std::uint16_t s_serial_len   = 0;
    static char     s_trailing    = 0;   // '.', ' ' or 0 - stripped from the raw serial, re-appended on output
    static std::uint8_t  s_identity[32] = {};
    static std::uint32_t s_identity_len = 0;
    static std::uint32_t s_vol_seed     = 0;


    static bool ascii_printable(const char* buf, std::size_t len) {
        if (!buf || !len) return false;
        for (std::size_t i = 0; i < len; ++i)
            if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7e) return false;
        return true;
    }

    static bool hex_value(char c, std::uint8_t& out) {
        if (c >= '0' && c <= '9') { out = (std::uint8_t)(c - '0');       return true; }
        if (c >= 'a' && c <= 'f') { out = (std::uint8_t)(c - 'a' + 10);  return true; }
        if (c >= 'A' && c <= 'F') { out = (std::uint8_t)(c - 'A' + 10);  return true; }
        return false;
    }


    static char disk_hex_char(std::uint8_t v) {
        static const char d[] = "0123456789ABCDEF";
        return d[v & 0xf];
    }

    static void rebuild_identity_bytes() {
        s_identity_len = 0;
        bool have_hi = false; std::uint8_t hi = 0;
        for (std::uint16_t i = 0; i < s_serial_len && s_identity_len < sizeof(s_identity); ++i) {
            std::uint8_t n = 0;
            if (!hex_value(s_serial[i], n)) continue;
            if (!have_hi) { hi = n; have_hi = true; }
            else { s_identity[s_identity_len++] = (std::uint8_t)((hi << 4) | n); have_hi = false; }
        }
    }

    static bool mutate_last_group() {
        std::int32_t pos[4] = { -1,-1,-1,-1 };
        std::uint32_t found = 0;
        for (std::int32_t i = s_serial_len - 1; i >= 0 && found < 4; --i) {
            std::uint8_t dummy = 0;
            if (hex_value(s_serial[i], dummy)) pos[3 - found++] = i;
        }
        if (found != 4) return false;
        std::uint8_t n[4] = {};
        for (int k = 0; k < 4; ++k) hex_value(s_serial[pos[k]], n[k]);
        std::uint16_t old_val = (std::uint16_t)((n[0]<<12)|(n[1]<<8)|(n[2]<<4)|n[3]);
        FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
        std::uint64_t v = (std::uint64_t)ft.dwLowDateTime ^ ((std::uint64_t)ft.dwHighDateTime << 32);
        v = (v ^ (v>>30)) * 0xbf58476d1ce4e5b9ULL;
        v = (v ^ (v>>27)) * 0x94d049bb133111ebULL;
        v ^= v >> 31;
        std::uint16_t new_val = (std::uint16_t)v;
        if (new_val == old_val) new_val ^= 0x5A5A;
        s_serial[pos[0]] = disk_hex_char((std::uint8_t)(new_val >> 12));
        s_serial[pos[1]] = disk_hex_char((std::uint8_t)(new_val >> 8));
        s_serial[pos[2]] = disk_hex_char((std::uint8_t)(new_val >> 4));
        s_serial[pos[3]] = disk_hex_char((std::uint8_t) new_val);
        return true;
    }

    static void ensure_canonical(const char* serial, std::size_t length) {
        if (s_serial_len || !serial || length < 4 || !ascii_printable(serial, length)) return;
        const std::size_t raw_len = length;
        while (length && (serial[length-1]=='\0'||serial[length-1]=='.'||serial[length-1]==' ')) --length;
        // remember a stripped '.'/' ' so every written copy keeps the exact
        // shape the real serial had (e.g. the trailing '.' on Samsung/NVMe
        // inquiry serials - losing it is a diffable tell)
        s_trailing = (length < raw_len && (serial[length]=='.'||serial[length]==' ')) ? serial[length] : 0;
        if (!length || length >= sizeof(s_serial)) return;
        memset(s_serial, 0, sizeof(s_serial));
        memcpy(s_serial, serial, length);
        s_serial_len = (std::uint16_t)length;
        if (!mutate_last_group()) { s_serial_len = 0; memset(s_serial, 0, sizeof(s_serial)); return; }
        rebuild_identity_bytes();
        logging::print("disk: canonical serial '%.*s' (%u identity bytes)", (int)s_serial_len, s_serial, s_identity_len);
    }

    static void ensure_canonical_from_bytes(const std::uint8_t* bytes, std::uint32_t length) {
        if (s_serial_len || !bytes || length < 8) return;
        std::uint32_t use = length >= 16 ? 16 : 8;
        memset(s_serial, 0, sizeof(s_serial));
        std::uint32_t out = 0;
        for (std::uint32_t i = 0; i < use && out + 5 < sizeof(s_serial); ++i) {
            if (i && (i%2)==0) s_serial[out++] = '_';
            s_serial[out++] = disk_hex_char(bytes[i] >> 4);
            s_serial[out++] = disk_hex_char(bytes[i]);
        }
        s_serial_len = (std::uint16_t)out;
        mutate_last_group();
        rebuild_identity_bytes();
        logging::print("disk: canonical serial (from bytes) '%.*s'", (int)s_serial_len, s_serial);
    }

    static void write_canonical(std::uint64_t buf_va, std::size_t capacity, std::uint64_t len_va) {
        if (!buf_va || !capacity || !s_serial_len) return;
        std::size_t copy = (std::min)((std::size_t)s_serial_len, capacity - 1);
        std::vector<char> tmp(capacity, '\0');
        memcpy(tmp.data(), s_serial, copy);
        if (s_trailing && copy + 1 < capacity) tmp[copy++] = s_trailing;
        if (!kwrite_verified(buf_va, tmp.data(), capacity, "disk: serial buffer")) return;
        if (len_va) {
            const std::uint16_t new_len = (std::uint16_t)copy;
            kwrite_verified(len_va, &new_len, sizeof(new_len), "disk: serial length");
        }
    }

    static void fill_identity_bytes(std::uint64_t buf_va, std::uint32_t length) {
        if (!buf_va || !length) return;
        std::vector<std::uint8_t> buf(length);
        kread(buf_va, buf.data(), length);
        if (!s_serial_len) ensure_canonical_from_bytes(buf.data(), length);
        if (s_identity_len) {
            if (length <= s_identity_len) {
                std::uint32_t src = s_identity_len - length;
                kwrite_verified(buf_va, s_identity + src, length, "disk: identity bytes");
            } else {
                for (std::uint32_t i = 0; i < length; ++i)
                    buf[i] = s_identity[i % s_identity_len];
                kwrite_verified(buf_va, buf.data(), length, "disk: identity bytes");
            }
        }
    }

    static void fill_identity_ascii(std::uint64_t buf_va, std::uint32_t length) {
        if (!buf_va || !length || !s_serial_len) return;
        std::vector<char> buf(length + 1, '\0');
        kread(buf_va, buf.data(), length);
        std::uint32_t start = 0;
        if (length > 4 && (buf[0]|0x20)=='e' && (buf[1]|0x20)=='u' && (buf[2]|0x20)=='i' && buf[3]=='.')
            start = 4;
        std::uint32_t src = 0;
        for (std::uint32_t i = start; i < length; ++i) {
            if (start != 4 && (buf[i]=='.'||buf[i]=='_'||buf[i]=='-'||buf[i]==' ')) continue;
            while (src < s_serial_len && (s_serial[src]=='_'||s_serial[src]=='-'||s_serial[src]==' ')) ++src;
            buf[i] = src < s_serial_len ? s_serial[src++] : '0';
        }
        kwrite_verified(buf_va, buf.data(), length, "disk: ascii identity");
    }

    static void spoof_guid_va(std::uint64_t guid_va) {
        std::uint8_t raw[16];
        if (!kread(guid_va, raw, 16)) return;
        // identity gate: a real partition/volume GUID is never all zero - a
        // zeroed slot means the derived offset is wrong for this build, and
        // writing into it would poison a neighbour
        bool all_zero = true;
        for (int i = 0; i < 16; ++i) if (raw[i]) { all_zero = false; break; }
        if (all_zero) {
            logging::print("disk: GUID slot at 0x%llx is zeroed - offset wrong, write skipped", guid_va);
            return;
        }
        std::uint32_t h = fnv1a(raw, 14, s_vol_seed);
        raw[14] = (std::uint8_t)(h & 0xFF);
        raw[15] = (std::uint8_t)((h >> 8) & 0xFF);
        kwrite_verified(guid_va, raw, 16, "disk: GUID");
    }

    static void spoof_general_buf_va(std::uint64_t buf_va, std::uint32_t length) {
        if (!buf_va || length < 2) return;
        std::vector<std::uint8_t> raw(length);
        if (!kread(buf_va, raw.data(), length)) return;
        // identity gate: a real mount-manager unique ID is not all zero
        bool all_zero = true;
        for (std::uint32_t i = 0; i < length; ++i) if (raw[i]) { all_zero = false; break; }
        if (all_zero) {
            logging::print("disk: unique ID buffer at 0x%llx is zeroed - write skipped", buf_va);
            return;
        }
        std::uint32_t h = fnv1a(raw.data(), length - 2, s_vol_seed);
        raw[length-2] = (std::uint8_t)(h & 0xFF);
        raw[length-1] = (std::uint8_t)((h >> 8) & 0xFF);
        kwrite_verified(buf_va, raw.data(), length, "disk: unique ID");
    }

}
