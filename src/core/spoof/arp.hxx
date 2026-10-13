#pragma once
#include "helpers.hxx"
#include "nic.hxx"
#include "../../symbols/pdb_offsets.hxx"
#include <vector>
#include <array>

namespace arp {

    static loader_offsets::tcpip_offsets s_off{};
    static bool s_resolved = false;

    struct arp_ip_addr_string {
        arp_ip_addr_string* Next;
        char IpAddress[16];
        char IpMask[16];
        DWORD Context;
    };
    struct arp_adapter_info {
        arp_adapter_info* Next;
        DWORD   ComboIndex;
        char    AdapterName[260];
        char    Description[132];
        UINT    AddressLength;
        BYTE    Address[8];
        DWORD   Index;
        UINT    Type;
        UINT    DhcpEnabled;
        arp_ip_addr_string* CurrentIpAddress;
        arp_ip_addr_string  IpAddressList;
        arp_ip_addr_string  GatewayList;
        arp_ip_addr_string  DhcpServer;
        BOOL    HaveWins;
        arp_ip_addr_string  PrimaryWinsServer;
        arp_ip_addr_string  SecondaryWinsServer;
        std::uint64_t LeaseObtained;
        std::uint64_t LeaseExpires;
    };

    using fn_get_adapters_info_t = DWORD(WINAPI*)(arp_adapter_info*, ULONG*);
    using fn_send_arp_t          = DWORD(WINAPI*)(DWORD, DWORD, void*, ULONG*);


    static DWORD parse_ipv4(const char* s) {
        DWORD result = 0;
        for (int shift = 0; shift < 32; shift += 8) {
            DWORD octet = 0;
            while (*s >= '0' && *s <= '9') octet = octet * 10 + (*s++ - '0');
            if (octet > 255) return 0;
            result |= (octet << shift);
            if (*s == '.') ++s;
        }
        return result;
    }

    static std::vector<std::array<std::uint8_t, 6>> get_protected_macs() {
        std::vector<std::array<std::uint8_t, 6>> result;

        const HMODULE iphlp = GetModuleHandleW(L"iphlpapi.dll")
                           ? GetModuleHandleW(L"iphlpapi.dll")
                           : LoadLibraryW(L"iphlpapi.dll");
        if (!iphlp) return result;

        const auto fn_gai = reinterpret_cast<fn_get_adapters_info_t>(
            GetProcAddress(iphlp, "GetAdaptersInfo"));
        const auto fn_arp = reinterpret_cast<fn_send_arp_t>(
            GetProcAddress(iphlp, "SendARP"));
        if (!fn_gai || !fn_arp) return result;

        ULONG sz = 0;
        fn_gai(nullptr, &sz);
        if (!sz) return result;
        std::vector<std::uint8_t> buf(sz);
        auto* info = reinterpret_cast<arp_adapter_info*>(buf.data());
        if (fn_gai(info, &sz) != ERROR_SUCCESS) return result;

        for (auto* a = info; a; a = a->Next) {
            for (auto* gw = &a->GatewayList; gw; gw = gw->Next) {
                const DWORD ip = parse_ipv4(gw->IpAddress);
                if (!ip) continue;

                std::array<std::uint8_t, 6> mac{};
                ULONG mac_len = 6;
                if (fn_arp(ip, 0, mac.data(), &mac_len) == 0 && mac_len == 6) {
                    bool all_zero = true;
                    for (auto b : mac) if (b) { all_zero = false; break; }
                    if (!all_zero) {
                        logging::print("spoof: arp - protecting gateway MAC %02X:%02X:%02X:%02X:%02X:%02X",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        result.push_back(mac);
                    }
                }
            }
        }
        return result;
    }

    // current (possibly spoofed) NDIS MAC per ethernet interface keyed by
    // NET_LUID - fallback when the FL cache lags NDIS
    struct luid_mac {
        std::uint64_t luid;
        std::uint8_t  mac[6];
    };

    using fn_conv_index_luid_t = DWORD(WINAPI*)(std::uint32_t, std::uint64_t*);

    static std::vector<luid_mac> get_luid_mac_map() {
        std::vector<luid_mac> result;

        const HMODULE iphlp = GetModuleHandleW(L"iphlpapi.dll")
                           ? GetModuleHandleW(L"iphlpapi.dll")
                           : LoadLibraryW(L"iphlpapi.dll");
        if (!iphlp) return result;

        const auto fn_gai = reinterpret_cast<fn_get_adapters_info_t>(
            GetProcAddress(iphlp, "GetAdaptersInfo"));
        const auto fn_luid = reinterpret_cast<fn_conv_index_luid_t>(
            GetProcAddress(iphlp, "ConvertInterfaceIndexToLuid"));
        if (!fn_gai || !fn_luid) return result;

        ULONG sz = 0;
        fn_gai(nullptr, &sz);
        if (!sz) return result;
        std::vector<std::uint8_t> buf(sz);
        auto* info = reinterpret_cast<arp_adapter_info*>(buf.data());
        if (fn_gai(info, &sz) != ERROR_SUCCESS) return result;

        for (auto* a = info; a; a = a->Next) {
            // no Type filter - WiFi reports a non-ethernet iftype; garbage
            // self-filters out via AddressLength / zero-MAC
            if (a->AddressLength != 6) continue;
            bool zero = true;
            for (UINT i = 0; i < 6; ++i) if (a->Address[i]) { zero = false; break; }
            if (zero) continue;

            std::uint64_t luid = 0;
            if (fn_luid(a->Index, &luid) != 0) continue;

            luid_mac lm{};
            lm.luid = luid;
            memcpy(lm.mac, a->Address, 6);
            result.push_back(lm);
        }
        return result;
    }

    inline bool resolve_offsets() {
        if (s_resolved) return true;
        if (!pdb_offsets::resolve_tcpip(&s_off)) {
            logging::print("spoof: arp - tcpip offset resolution failed");
            return false;
        }
        s_resolved = true;
        return true;
    }

    // a valid compartment hash set: sane TableSize and a kernel directory ptr
    static bool set_looks_valid(std::uint64_t set_va) {
        using namespace spoof::helpers;
        if (!set_va || !is_kva(set_va)) return false;
        const std::uint32_t count = kread_val<std::uint32_t>(set_va + s_off.cs_count);
        const std::uint64_t table = kread_val<std::uint64_t>(set_va + s_off.cs_table);
        return count > 0 && count <= 4096 && is_kva(table);
    }

    // read one interface's af length through the compartment descriptor
    // chain (4 = IPv4 set, 16 = IPv6 set)
    static std::uint32_t probe_set_af_len(std::uint64_t set_va) {
        using namespace spoof::helpers;
        const std::uint32_t count     = kread_val<std::uint32_t>(set_va + s_off.cs_count);
        const std::uint64_t table_ptr = kread_val<std::uint64_t>(set_va + s_off.cs_table);
        if (!count || count > 4096 || !is_kva(table_ptr)) return 0;
        if (!s_off.dl_p2_off || !s_off.dl_cur_off || !s_off.dl_len_off) return 0;

        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint64_t bucket = table_ptr + static_cast<std::uint64_t>(i) * s_off.cs_bucket_stride;
            std::uint64_t cur = kread_val<std::uint64_t>(bucket);
            for (std::uint32_t depth = 0;
                 depth < 16 && is_kva(cur) && cur != bucket;
                 ++depth, cur = kread_val<std::uint64_t>(cur))
            {
                const std::uint64_t compartment = cur - s_off.cs_entry_offset;
                if (!s_off.compartment_if_list || !s_off.if_compartment_link) break;
                const std::uint64_t if_list_va = compartment + s_off.compartment_if_list;
                std::uint64_t if_flink = kread_val<std::uint64_t>(if_list_va);
                for (std::uint32_t j = 0;
                     j < 16 && is_kva(if_flink) && if_flink != if_list_va;
                     ++j, if_flink = kread_val<std::uint64_t>(if_flink))
                {
                    const std::uint64_t iface = if_flink - s_off.if_compartment_link;
                    const std::uint64_t p1 = kread_val<std::uint64_t>(iface);
                    if (!is_kva(p1)) continue;
                    const std::uint64_t p2 = kread_val<std::uint64_t>(p1 + s_off.dl_p2_off);
                    if (!is_kva(p2)) continue;
                    const std::uint64_t blk = kread_val<std::uint64_t>(p2 + s_off.dl_cur_off);
                    if (!is_kva(blk)) continue;
                    const std::uint32_t len = kread_val<std::uint32_t>(blk + s_off.dl_len_off);
                    if (len == 4 || len == 16) return len;
                    return 0;
                }
            }
        }
        return 0;
    }

    // candidate compartment sets with their af length (4 = IPv4, 16 = IPv6)
    static std::vector<std::pair<std::uint64_t, std::uint32_t>> find_valid_sets(
        std::uint64_t tcpip_base)
    {
        using namespace spoof::helpers;
        std::vector<std::pair<std::uint64_t, std::uint32_t>> out;
        auto push = [&](std::uint64_t va, std::uint32_t af) {
            if (!set_looks_valid(va)) return;
            for (auto& o : out) if (o.first == va) return;
            out.emplace_back(va, af);
        };
        if (s_off.ipv4_global_rva) push(tcpip_base + s_off.ipv4_global_rva, 4);
        if (s_off.ipv6_global_rva) push(tcpip_base + s_off.ipv6_global_rva, 16);
        if (s_off.compartment_set_rva) {
            const std::uint64_t legacy = tcpip_base + s_off.compartment_set_rva;
            std::uint64_t va = legacy;
            const std::uint64_t deref = kread_val<std::uint64_t>(legacy);
            if (set_looks_valid(deref)) va = deref;
            if (set_looks_valid(va)) {
                const std::uint32_t af = probe_set_af_len(va);
                if (af == 4 || af == 16) push(va, af);
            }
        }
        return out;
    }

    // ------------------------------------------------------------------
    // FL_INTERFACE derivation
    //
    // tcpip's framing layer caches the NIC MAC inside per-module
    // FL_INTERFACE objects; Fl48pSendArpPacket stamps it as the ARP sender
    // address (Fl68 does the same for IPv6 ND). The objects are linked into
    // an interface set embedded in per-module provider statics in tcpip's
    // .data section.
    //
    // every offset below is derived from tcpip's own code at runtime:
    //   anchor A  Fl48pSendArpPacket      movzx r8d,[rcx+HLN]; movzx edx,[rcx+PLN]; lea r9,[rcx+MAC]
    //   anchor B  FlpInitializeInterfaceSet   and [rbx+8],0; lea rax,[rbx+LIST]; and [rbx+0x10],0;
    //                                     mov [rax+8],rax; mov [rax],rax
    //   anchor C  FlpInitializeProviderState lea rcx,[rbx+STATE]; call; xor eax,eax; mov byte [rbx],1
    //   anchor E  FlpCreateInterface      lea rax,[rbx+LINK]; mov [rbx+BACK],rsi; lea rcx,[rbx+..];
    //                                     mov [rax+8],rax; mov [rax],rax; mov [rbx+..],edi; mov [rbx+..],edi
    // ------------------------------------------------------------------
    struct fl_layout {
        std::uint32_t pln_off      = 0;  // byte: protocol address length (4 v4 / 16 v6)
        std::uint32_t hln_off      = 0;  // byte: hardware address length (6 ethernet)
        std::uint32_t mac_off      = 0;  // 6-byte cached NIC MAC
        std::uint32_t luid_off     = 0;  // qword: interface NET_LUID
        std::uint32_t link_off     = 0;  // intrusive list entry offset inside FL
        std::uint32_t prov_back_off = 0; // qword: back-pointer to the provider static
        std::uint32_t state_off    = 0;  // interface set embedded at provider+state_off
        std::uint32_t list_off     = 0;  // list head inside the interface set
    };

    // one section of an in-memory PE
    static bool get_module_section(std::uint64_t base, const char* name,
                                   std::uint32_t* out_rva, std::uint32_t* out_size) {
        using namespace spoof::helpers;
        const auto e_lfanew = kread_val<std::int32_t>(base + 0x3C);
        if (e_lfanew <= 0 || e_lfanew > 0x1000) return false;
        const std::uint64_t nt = base + static_cast<std::uint64_t>(e_lfanew);
        if (kread_val<std::uint32_t>(nt) != 0x4550) return false;
        const std::uint16_t nsec     = kread_val<std::uint16_t>(nt + 6);
        const std::uint16_t opt_size = kread_val<std::uint16_t>(nt + 20);
        const std::uint64_t sec = nt + 24 + opt_size;
        for (std::uint16_t i = 0; i < nsec && i < 96; ++i) {
            char sec_name[9] = {};
            kread(sec + i * 40, sec_name, 8);
            if (!strcmp(sec_name, name)) {
                // IMAGE_SECTION_HEADER: Name[8] VirtualSize VirtualAddress SizeOfRawData ...
                const std::uint32_t vsize = kread_val<std::uint32_t>(sec + i * 40 + 8);
                const std::uint32_t vaddr = kread_val<std::uint32_t>(sec + i * 40 + 12);
                if (!vaddr || !vsize) return false;
                *out_rva  = vaddr;
                *out_size = vsize;
                return true;
            }
        }
        return false;
    }

    // pattern scan with per-byte wildcard mask (0 = wildcard)
    static bool find_sig(const std::uint8_t* hay, std::size_t hay_len,
                         const std::uint8_t* pat, const std::uint8_t* mask,
                         std::size_t pat_len, std::size_t* out_at,
                         std::size_t from = 0) {
        if (pat_len == 0 || hay_len < pat_len) return false;
        for (std::size_t i = from; i + pat_len <= hay_len; ++i) {
            bool ok = true;
            for (std::size_t j = 0; j < pat_len; ++j) {
                if (mask[j] && hay[i + j] != pat[j]) { ok = false; break; }
            }
            if (ok) { *out_at = i; return true; }
        }
        return false;
    }

    // read a whole module section in chunks (max 4 MiB)
    static bool read_section(std::uint64_t base, std::uint32_t rva, std::uint32_t size,
                             std::vector<std::uint8_t>& out) {
        using namespace spoof::helpers;
        if (!is_kva(base) || !size || size > 4u * 1024 * 1024) return false;
        out.resize(size);
        constexpr std::uint32_t kChunk = 0x40000;
        for (std::uint32_t off = 0; off < size; off += kChunk) {
            const std::uint32_t n = (std::min)(kChunk, size - off);
            if (!kread(base + rva + off, out.data() + off, n)) return false;
        }
        return true;
    }

    // kernel modules live at 0xFFFFF8.. - a real FL link is a pool address
    static bool is_module_range(std::uint64_t va) {
        return (va >> 40) == 0xFFFFF8;
    }

    // FlpCreateInterface fallback: the init codegen drifts per build, the
    // object shape does not. every provider static keeps its interface-set
    // head at +state_off+list_off (anchors B+C) and the head's flink targets
    // an FL's embedded list entry. the true link offset is the one where the
    // object behind the flink reads hln==6 / pln 4-or-16 (anchor A offsets)
    // and holds a qword pointing back at the provider static - a back-pointer
    // no misaligned candidate can fake. first entry's blink must return to
    // the head, so only genuine list members are considered
    static bool derive_link_back_structural(std::uint64_t tcpip_base,
                                            std::uint32_t pln_off, std::uint32_t hln_off,
                                            std::uint32_t state_off, std::uint32_t list_off,
                                            std::uint32_t* link_off, std::uint32_t* back_off) {
        using namespace spoof::helpers;
        if (!pln_off || !hln_off || !state_off || !list_off) return false;
        std::uint32_t data_rva = 0, data_size = 0;
        if (!get_module_section(tcpip_base, ".data", &data_rva, &data_size)) return false;
        std::vector<std::uint8_t> data;
        if (!read_section(tcpip_base, data_rva, data_size, data)) return false;

        const std::uint32_t head_delta = state_off + list_off;
        for (std::uint32_t q = 0; q + head_delta + 8 <= data_size; q += 8) {
            std::uint64_t link = 0;
            memcpy(&link, &data[q + head_delta], 8);
            const std::uint64_t head_va = tcpip_base + data_rva + q + head_delta;
            if (!is_kva(link) || link == head_va || is_module_range(link)) continue;
            if (kread_val<std::uint64_t>(link + 8) != head_va) continue;

            const std::uint64_t provider = tcpip_base + data_rva + q;
            for (std::uint32_t cand = 8; cand < 0x100; cand += 8) {
                const std::uint64_t fl = link - cand;
                if (!is_kva(fl) || is_module_range(fl)) continue;
                const std::uint8_t hln = kread_val<std::uint8_t>(fl + hln_off);
                const std::uint8_t pln = kread_val<std::uint8_t>(fl + pln_off);
                if (hln != 6 || (pln != 4 && pln != 16)) continue;
                std::uint32_t found_back = 0;
                for (std::uint32_t o = 8; o < 0x200; o += 8) {
                    if (kread_val<std::uint64_t>(fl + o) == provider) { found_back = o; break; }
                }
                if (!found_back) continue;
                *link_off = cand;
                *back_off = found_back;
                return true;
            }
        }
        return false;
    }

    static bool derive_fl_layout(std::uint64_t tcpip_base, fl_layout* out) {
        std::uint32_t text_rva = 0, text_size = 0;
        if (!get_module_section(tcpip_base, ".text", &text_rva, &text_size)) {
            logging::print("spoof: arp - tcpip .text section not found");
            return false;
        }
        std::vector<std::uint8_t> text;
        if (!read_section(tcpip_base, text_rva, text_size, text)) {
            logging::print("spoof: arp - tcpip .text read failed");
            return false;
        }

        auto disp32_at = [&](std::size_t i) {
            return static_cast<std::uint32_t>(
                text[i] | (text[i + 1] << 8) | (text[i + 2] << 16) |
                (static_cast<std::uint32_t>(text[i + 3]) << 24));
        };

        // ---- anchor A: Fl48pSendArpPacket field reads ----
        // movzx r?, byte [rcx+disp32]   : 0F B6, modrm&0xC7 == 0x81
        // lea   r?, [rcx+disp32]        : 48/4C 8D, modrm&0xC7 == 0x81
        bool have_fl_fields = false;
        std::uint32_t pln = 0, hln = 0, mac = 0;
        for (std::size_t i = 0; i + 7 < text.size() && !have_fl_fields; ++i) {
            if (text[i] != 0x0F || text[i + 1] != 0xB6 || (text[i + 2] & 0xC7) != 0x81)
                continue;
            const std::uint32_t hln_cand = disp32_at(i + 3);
            if (hln_cand < 0x100 || hln_cand >= 0x2000) continue;

            // second movzx within 0x30 bytes
            for (std::size_t j = i + 7; j < i + 7 + 0x30 && j + 7 < text.size(); ++j) {
                if (text[j] != 0x0F || text[j + 1] != 0xB6 || (text[j + 2] & 0xC7) != 0x81)
                    continue;
                const std::uint32_t pln_cand = disp32_at(j + 3);
                if (pln_cand < 0x100 || pln_cand >= 0x2000) continue;

                // lea r?, [rcx+disp32] within another 0x30 bytes
                for (std::size_t k = j + 7; k < j + 7 + 0x30 && k + 7 < text.size(); ++k) {
                    const bool rex = text[k] == 0x48 || text[k] == 0x4C;
                    if (!rex || text[k + 1] != 0x8D || (text[k + 2] & 0xC7) != 0x81)
                        continue;
                    const std::uint32_t mac_cand = disp32_at(k + 3);
                    if (mac_cand <= hln_cand || mac_cand - pln_cand > 0x400 ||
                        mac_cand >= 0x2000)
                        continue;
                    pln = pln_cand; hln = hln_cand; mac = mac_cand;
                    have_fl_fields = true;
                    break;
                }
                break;
            }
        }
        if (!have_fl_fields) {
            logging::print("spoof: arp - Fl48pSendArpPacket anchor not found");
            return false;
        }

        // ---- anchor B: FlpInitializeInterfaceSet list-head init ----
        // 83 63 08 00 | 48 8D 43 LIST | 83 63 10 00 | 48 89 40 08 | 48 89 00
        static const std::uint8_t patB[] = {
            0x83,0x63,0x08,0x00,  0x48,0x8D,0x43,0x00,  0x83,0x63,0x10,0x00,
            0x48,0x89,0x40,0x08,  0x48,0x89,0x00
        };
        static const std::uint8_t maskB[] = {
            1,1,1,1,  1,1,1,0,  1,1,1,1,
            1,1,1,1,  1,1,1
        };
        std::size_t at = 0;
        std::uint32_t list_off = 0;
        if (!find_sig(text.data(), text.size(), patB, maskB, sizeof(patB), &at)) {
            logging::print("spoof: arp - FlpInitializeInterfaceSet anchor not found");
            return false;
        }
        list_off = text[at + 7];
        if (!list_off || list_off >= 0x100) {
            logging::print("spoof: arp - implausible interface-set list offset %u", list_off);
            return false;
        }

        // ---- anchor C: FlpInitializeProviderState embedded set ----
        // 48 8D 8B STATE(4) | E8 rel32 | xor eax,eax (31/33 C0) | C6 03 01
        static const std::uint8_t patC[] = {
            0x48,0x8D,0x8B,0,0,0,0,  0xE8,0,0,0,0,  0x00,0xC0,  0xC6,0x03,0x01
        };
        static const std::uint8_t maskC[] = {
            1,1,1,0,0,0,0,  1,0,0,0,0,  0,1,  1,1,1
        };
        if (!find_sig(text.data(), text.size(), patC, maskC, sizeof(patC), &at)) {
            logging::print("spoof: arp - FlpInitializeProviderState anchor not found");
            return false;
        }
        const std::uint32_t state_off = disp32_at(at + 3);
        if (!state_off || state_off >= 0x2000) {
            logging::print("spoof: arp - implausible provider state offset %u", state_off);
            return false;
        }

        // ---- anchor E: FlpCreateInterface init block ----
        // 48 8D 43 LINK | 48 89 73 BACK | 48 8D 4B .. | 48 89 40 08 |
        // 48 89 00 | 89 7B .. | 89 7B ..
        static const std::uint8_t patE[] = {
            0x48,0x8D,0x43,0x00,  0x48,0x89,0x73,0x00,  0x48,0x8D,0x4B,0x00,
            0x48,0x89,0x40,0x08,  0x48,0x89,0x00,  0x89,0x7B,0x00,  0x89,0x7B,0x00
        };
        static const std::uint8_t maskE[] = {
            1,1,1,0,  1,1,1,0,  1,1,1,0,
            1,1,1,1,  1,1,1,  1,1,0,  1,1,0
        };
        std::uint32_t link_off = 0, prov_back_off = 0;
        if (find_sig(text.data(), text.size(), patE, maskE, sizeof(patE), &at)) {
            link_off      = text[at + 3];
            prov_back_off = text[at + 7];
        } else {
            // codegen drifted (26200 tcpip): derive both offsets from the live
            // list topology instead of the init code - build-agnostic
            logging::print("spoof: arp - FlpCreateInterface anchor not found - structural fallback");
            if (!derive_link_back_structural(tcpip_base, pln, hln, state_off, list_off,
                                             &link_off, &prov_back_off)) {
                logging::print("spoof: arp - structural link/back derivation failed");
                return false;
            }
        }
        if (!link_off || link_off >= 0x100 || !prov_back_off || prov_back_off >= 0x100) {
            logging::print("spoof: arp - implausible FL link/back offsets %u/%u",
                link_off, prov_back_off);
            return false;
        }

        // ---- anchor F: FlpGetFirstInterface luid compare loop ----
        // the walk compares the NET_LUID of two FL objects through two
        // leas - one via the list link (lea r?,[link+d32]) and one direct
        // (lea r?,[fl+d32]) - each followed by mov r8d,8 (sizeof NET_LUID).
        // both displacements address the same field, so their delta is the
        // link offset; the direct one is the LUID. a following
        // lea fl,[link-link_off] confirms the link-to-object math.
        std::uint32_t luid_off = 0;
        {
            static const std::uint8_t patF1[] = {
                0x4C,0x8D,0xBF,0,0,0,0,  0x41,0xB8,0x08,0x00,0x00,0x00
            };
            static const std::uint8_t maskF1[] = {
                1,1,1,0,0,0,0,  1,1,1,1,1,1
            };
            static const std::uint8_t patF2[] = {
                0x48,0x8D,0x8B,0,0,0,0,  0x41,0xB8,0x08,0x00,0x00,0x00
            };
            static const std::uint8_t maskF2[] = {
                1,1,1,0,0,0,0,  1,1,1,1,1,1
            };
            static const std::uint8_t patF3[] = { 0x48,0x8D,0x5F,0 };
            static const std::uint8_t maskF3[] = { 1,1,1,0 };

            std::size_t f1 = 0;
            while (!luid_off &&
                   find_sig(text.data(), text.size(), patF1, maskF1,
                            sizeof(patF1), &f1, f1))
            {
                const std::uint32_t via_link = disp32_at(f1 + 3);
                std::size_t f2 = 0;
                if (via_link >= 0x100 && via_link < 0x1000 &&
                    find_sig(text.data(), text.size(), patF2, maskF2,
                             sizeof(patF2), &f2, f1 + 7) &&
                    f2 - f1 <= 0x40)
                {
                    const std::uint32_t via_fl = disp32_at(f2 + 3);
                    std::size_t f3 = 0;
                    if (via_fl == via_link + link_off &&
                        find_sig(text.data(), text.size(), patF3, maskF3,
                                 sizeof(patF3), &f3, f2) &&
                        f3 - f2 <= 0x40 &&
                        text[f3 + 3] == static_cast<std::uint8_t>(0x100 - link_off))
                    {
                        luid_off = via_fl;
                    }
                }
                ++f1;  // keep scanning past this candidate
            }
        }
        if (!luid_off)
            logging::print("spoof: arp - FlpGetFirstInterface anchor not found"
                " (luid fallback disabled)");

        out->pln_off       = pln;
        out->hln_off       = hln;
        out->mac_off       = mac;
        out->luid_off      = luid_off;
        out->link_off      = link_off;
        out->prov_back_off = prov_back_off;
        out->state_off     = state_off;
        out->list_off      = list_off;

        logging::print("spoof: arp - FL layout: pln@+%X hln@+%X mac@+%X luid@+%X"
            " link@+%X provider@+%X set@+%X list@+%X",
            pln, hln, mac, luid_off, link_off, prov_back_off, state_off, list_off);
        return true;
    }

    // validate one FL candidate: the provider back-pointer is the identity
    // anchor; the hw-address-length byte separates real ethernet framings
    // from loopback/tunnel (they carry 0)
    static bool fl_looks_valid(std::uint64_t fl, std::uint64_t provider,
                               const fl_layout& s_fl) {
        using namespace spoof::helpers;
        if (!is_kva(fl)) return false;
        if (kread_val<std::uint64_t>(fl + s_fl.prov_back_off) != provider) return false;
        const std::uint8_t hln = kread_val<std::uint8_t>(fl + s_fl.hln_off);
        return hln == 6;
    }

    struct fl_report {
        std::uint32_t providers = 0;   // candidates with a non-empty interface list
        std::uint32_t fls       = 0;   // validated FL_INTERFACES
        std::uint32_t patched   = 0;   // MACs written
    };

    // scan tcpip .data for framing-layer provider statics and process every
    // FL_INTERFACE on them. patch mode rewrites the cached sender MAC through
    // the NIC stage's override map so tcpip's copy matches the spoofed NDIS
    // MAC; diag mode is read-only and prints why candidates fail
    static fl_report process_fl_interfaces(std::uint64_t tcpip_base,
                                           const fl_layout& s_fl, bool patch)
    {
        using namespace spoof::helpers;
        fl_report report;

        std::uint32_t data_rva = 0, data_size = 0;
        if (!get_module_section(tcpip_base, ".data", &data_rva, &data_size)) {
            logging::print("spoof: arp - tcpip .data section not found");
            return report;
        }
        std::vector<std::uint8_t> data;
        if (!read_section(tcpip_base, data_rva, data_size, data)) {
            logging::print("spoof: arp - tcpip .data read failed");
            return report;
        }
        logging::print("spoof: arp - tcpip .data rva=0x%X size=0x%X", data_rva, data_size);

        const auto luid_map = s_fl.luid_off ? get_luid_mac_map()
                                           : std::vector<luid_mac>{};

        const std::uint32_t head_delta = s_fl.state_off + s_fl.list_off;
        std::uint32_t shown_candidates = 0;   // provider-static signature prints
        std::uint32_t shown_links = 0;        // per-walk first-link detail prints
        for (std::uint32_t q = 0; q + 8 <= data_size; q += 8) {
            const std::uint32_t head_off = q + head_delta;
            if (head_off + 8 > data_size) break;
            const std::uint64_t provider = tcpip_base + data_rva + q;
            const std::uint64_t head_va  = provider + head_delta;

            // cheap pre-filter: the embedded list head must hold a live
            // kernel link; garbage qwords in .data almost never look like one
            std::uint64_t link = 0;
            memcpy(&link, &data[head_off], 8);

            // provider-static signature (byte[0]=1): report in diag even
            // when the set is empty so real providers stay visible
            if (!patch && data[q] == 1 && shown_candidates < 128) {
                ++shown_candidates;
                logging::print("diag: arp - provider-static 0x%llX head=0x%llX%s",
                    (unsigned long long)provider, (unsigned long long)link,
                    link == head_va ? " (empty, self-linked)" : "");
            }

            if (!is_kva(link) || link == head_va || is_module_range(link)) continue;

            // full kernel-side walk of this provider's interface list
            std::uint32_t walked = 0, valid = 0, provider_patched = 0;
            for (std::uint64_t cur = link;
                 is_kva(cur) && cur != head_va && !is_module_range(cur) && walked < 64;
                 cur = kread_val<std::uint64_t>(cur), ++walked)
            {
                const std::uint64_t fl = cur - s_fl.link_off;

                if (!patch && data[q] == 1 && walked == 0 && shown_links < 32) {
                    // diag detail: first FL's fields for verification
                    const std::uint64_t back = kread_val<std::uint64_t>(fl + s_fl.prov_back_off);
                    const std::uint8_t pln = kread_val<std::uint8_t>(fl + s_fl.pln_off);
                    const std::uint8_t hln = kread_val<std::uint8_t>(fl + s_fl.hln_off);
                    const std::uint64_t luid = s_fl.luid_off
                        ? kread_val<std::uint64_t>(fl + s_fl.luid_off) : 0;
                    std::uint8_t mac[8] = {};
                    kread(fl + s_fl.mac_off, mac, 8);
                    std::uint8_t fl_head[0x40] = {};
                    kread(fl, fl_head, sizeof(fl_head));
                    logging::print("diag: arp - fl-walk 0x%llX fl0=0x%llX back=0x%llX"
                        " pln=%u hln=%u luid=0x%llX mac=%02X:%02X:%02X:%02X:%02X:%02X",
                        (unsigned long long)provider, (unsigned long long)fl,
                        (unsigned long long)back, pln, hln,
                        (unsigned long long)luid,
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    logging::print("diag: arp -   fl0[0x00..0x18]=%02X %02X %02X %02X %02X %02X"
                        " %02X %02X | %02X %02X %02X %02X %02X %02X %02X %02X"
                        " | %02X %02X %02X %02X %02X %02X %02X %02X",
                        fl_head[0], fl_head[1], fl_head[2], fl_head[3],
                        fl_head[4], fl_head[5], fl_head[6], fl_head[7],
                        fl_head[8], fl_head[9], fl_head[10], fl_head[11],
                        fl_head[12], fl_head[13], fl_head[14], fl_head[15],
                        fl_head[16], fl_head[17], fl_head[18], fl_head[19],
                        fl_head[20], fl_head[21], fl_head[22], fl_head[23]);
                    ++shown_links;
                }

                if (!fl_looks_valid(fl, provider, s_fl)) continue;
                ++valid;

                std::uint8_t mac[6] = {};
                kread(fl + s_fl.mac_off, mac, 6);
                if (!mac[0] && !mac[1] && !mac[2] && !mac[3] && !mac[4] && !mac[5])
                    continue;

                if (!patch) {
                    logging::print("diag: arp - FL provider 0x%llX: FL 0x%llX mac=%02X:%02X:%02X:%02X:%02X:%02X",
                        (unsigned long long)provider, (unsigned long long)fl,
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    if (s_fl.luid_off) {
                        const std::uint64_t luid =
                            kread_val<std::uint64_t>(fl + s_fl.luid_off);
                        const luid_mac* lm = nullptr;
                        for (const auto& m : luid_map)
                            if (m.luid == luid) { lm = &m; break; }
                        logging::print("diag: arp -   luid=0x%llX%s ndis=%02X:%02X:%02X:%02X:%02X:%02X",
                            (unsigned long long)luid,
                            lm ? "" : " (unmapped)",
                            lm ? lm->mac[0] : 0, lm ? lm->mac[1] : 0,
                            lm ? lm->mac[2] : 0, lm ? lm->mac[3] : 0,
                            lm ? lm->mac[4] : 0, lm ? lm->mac[5] : 0);
                    }
                    continue;
                }

                // the FL cache is the MAC tcpip stamps on outgoing frames -
                // it may only hold a MAC the hardware genuinely transmits
                // with (driver-adopted), otherwise frames desynchronize from
                // the NIC and traffic drops
                std::uint8_t new_mac[6]{};
                const auto* plan = spoof::nic::find_override(mac);
                if (plan && spoof::nic::is_adopted(plan->new_mac)) {
                    memcpy(new_mac, plan->new_mac, 6);
                } else if (s_fl.luid_off) {
                    // cached MAC unmapped in the plan (e.g. adopted in an
                    // earlier session): resolve through the interface LUID
                    // to the adapter's current NDIS MAC - valid only if that
                    // one is adopted too
                    const std::uint64_t luid =
                        kread_val<std::uint64_t>(fl + s_fl.luid_off);
                    for (const auto& lm : luid_map) {
                        if (lm.luid != luid) continue;
                        if (spoof::nic::is_adopted(lm.mac)) {
                            memcpy(new_mac, lm.mac, 6);
                            logging::print("spoof: arp - FL 0x%llX cached MAC"
                                " unmapped, using adopted ndis MAC via luid 0x%llX",
                                (unsigned long long)fl,
                                (unsigned long long)luid);
                        }
                        break;
                    }
                }
                if (!spoof::nic::mac_is_set(new_mac))
                    continue;  // nothing verified for this FL - leave it alone

                if (new_mac[0] == mac[0] && new_mac[1] == mac[1] &&
                    new_mac[2] == mac[2] && new_mac[3] == mac[3] &&
                    new_mac[4] == mac[4] && new_mac[5] == mac[5])
                    continue;  // already consistent with NDIS

                if (!kwrite_verified(fl + s_fl.mac_off, new_mac, 6, "arp: FL MAC"))
                    continue;
                ++provider_patched;
                logging::print("spoof: arp - FL 0x%llX MAC %02X:%02X:%02X:%02X:%02X:%02X"
                    " -> %02X:%02X:%02X:%02X:%02X:%02X",
                    (unsigned long long)fl,
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                    new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5]);
            }

            if (walked) {
                ++report.providers;
                report.fls += valid;
                report.patched += provider_patched;
            }
        }
        return report;
    }

    // walk one neighbor table and randomize the cached remote MACs
    // (network-environment fingerprint); OUI kept, gateway/multicast/empty
    // untouched. layout per IppGetNextNeighborOnInterface:
    //   table = [iface+nb_table], head at table+nb_table_list_head,
    //   nb = link-nb_table_entry_offset, network address inline at
    //   nb+nb_dl_address (af_len bytes) with the MAC right behind it
    static std::uint32_t spoof_neighbor_table(
        std::uint64_t table_va, std::uint32_t af_len,
        const std::vector<std::array<std::uint8_t, 6>>& protected_macs,
        std::vector<std::uint64_t>& seen)
    {
        using namespace spoof::helpers;
        if (!is_kva(table_va) || !s_off.nb_table_list_head || !s_off.nb_table_entry_offset)
            return 0;
        if (!s_off.nb_dl_address || (af_len != 4 && af_len != 16)) return 0;

        std::uint32_t count = 0;
        const std::uint64_t list_head = table_va + s_off.nb_table_list_head;
        std::uint64_t link = kread_val<std::uint64_t>(list_head);

        for (std::uint32_t i = 0;
             i < 512 && is_kva(link) && link != list_head;
             ++i, link = kread_val<std::uint64_t>(link))
        {
            const std::uint64_t nb = link - s_off.nb_table_entry_offset;

            bool visited = false;
            for (auto v : seen) if (v == nb) { visited = true; break; }
            if (visited) continue;
            seen.push_back(nb);

            // identity gate: an all-zero network address means the offsets
            // are wrong for this entry and the bytes behind it are not a MAC
            std::uint8_t addr[16] = {};
            if (!kread(nb + s_off.nb_dl_address, addr, af_len)) continue;
            bool addr_zero = true;
            for (std::uint32_t b = 0; b < af_len; ++b)
                if (addr[b]) { addr_zero = false; break; }
            if (addr_zero) continue;

            // MAC sits right behind the af_len-byte network address
            const std::uint64_t mac_va = nb + s_off.nb_dl_address + af_len;
            std::uint8_t mac[6];
            kread(mac_va, mac, 6);
            if (!mac[0] && !mac[1] && !mac[2] && !mac[3] && !mac[4] && !mac[5])
                continue;
            if (mac[0] & 1) continue;  // multicast/broadcast group

            bool skip = false;
            for (const auto& p : protected_macs) {
                if (p[0]==mac[0] && p[1]==mac[1] && p[2]==mac[2] &&
                    p[3]==mac[3] && p[4]==mac[4] && p[5]==mac[5]) {
                    skip = true; break;
                }
            }
            if (!skip) {
                mac[3] = static_cast<std::uint8_t>(rand_next());
                mac[4] = static_cast<std::uint8_t>(rand_next());
                mac[5] = static_cast<std::uint8_t>(rand_next());
                if (kwrite_verified(mac_va, mac, 6, "arp: neighbor MAC"))
                    ++count;
            }
        }
        return count;
    }

    inline void install() {
        using namespace spoof::helpers;

        if (!resolve_offsets()) return;

        const auto protected_macs = get_protected_macs();

        const std::uint64_t tcpip_base = get_kernel_module_base(L"tcpip.sys");
        if (!tcpip_base) {
            logging::print("spoof: arp - tcpip.sys not found in PsLoadedModuleList");
            return;
        }

        // ---- framing-layer sender MACs (ARP + ND own-MAC leak) ----
        fl_layout s_fl{};
        fl_report fl{};
        if (derive_fl_layout(tcpip_base, &s_fl))
            fl = process_fl_interfaces(tcpip_base, s_fl, true);

        // ---- compartment walk: neighbor tables ----
        const auto valid_sets = find_valid_sets(tcpip_base);
        if (valid_sets.empty())
            logging::print("spoof: arp - no valid compartment set found");

        std::uint32_t total_spoofed = 0;
        std::vector<std::uint64_t> nb_seen;
        for (const auto& set : valid_sets) {
            const std::uint32_t count     = kread_val<std::uint32_t>(set.first + s_off.cs_count);
            const std::uint64_t table_ptr = kread_val<std::uint64_t>(set.first + s_off.cs_table);
            if (!count || count > 4096 || !is_kva(table_ptr)) continue;

            for (std::uint32_t i = 0; i < count; ++i) {
                const std::uint64_t bucket = table_ptr + static_cast<std::uint64_t>(i) * s_off.cs_bucket_stride;
                std::uint64_t cur = kread_val<std::uint64_t>(bucket);

                for (std::uint32_t depth = 0;
                     depth < 64 && is_kva(cur) && cur != bucket;
                     ++depth)
                {
                    const std::uint64_t compartment = cur - s_off.cs_entry_offset;

                    if (s_off.compartment_if_list && s_off.if_compartment_link) {
                        const std::uint64_t if_list_va = compartment + s_off.compartment_if_list;
                        std::uint64_t if_flink = kread_val<std::uint64_t>(if_list_va);

                        for (std::uint32_t j = 0;
                             j < 128 && is_kva(if_flink) && if_flink != if_list_va;
                             ++j)
                        {
                            const std::uint64_t iface = if_flink - s_off.if_compartment_link;

                            for (auto nb_table_off : { s_off.if_nb_table, s_off.if_nb_table_alt }) {
                                if (!nb_table_off) continue;
                                const std::uint64_t nb_table =
                                    kread_val<std::uint64_t>(iface + nb_table_off);
                                total_spoofed += spoof_neighbor_table(
                                    nb_table, set.second, protected_macs, nb_seen);
                            }

                            if_flink = kread_val<std::uint64_t>(if_flink);
                        }
                    }

                    cur = kread_val<std::uint64_t>(cur);
                }
            }
        }

        logging::print("spoof: ARP - spoofed %u neighbor entries", total_spoofed);
        if (fl.providers)
            logging::print("spoof: ARP - %u framing provider(s), %u FL_INTERFACE(s),"
                " %u own-MAC patched", fl.providers, fl.fls, fl.patched);
        else
            logging::print("spoof: arp - no framing-layer interfaces found");
    }

    // read-only (--arptest): dump the FL layout, providers, cached MACs and
    // neighbor tables. never writes
    inline void diag(const std::vector<std::array<std::uint8_t, 6>>& extra_refs = {}) {
        using namespace spoof::helpers;

        if (!resolve_offsets()) return;

        const std::uint64_t tcpip_base = get_kernel_module_base(L"tcpip.sys");
        if (!tcpip_base) {
            logging::print("diag: arp - tcpip.sys not found in PsLoadedModuleList");
            return;
        }

        // reference table: live MACs from GetAdaptersInfo plus baselines
        // passed in (a kernel NDIS patch outlives its run, so live !=
        // hardware until reboot)
        struct ref_mac { std::string name; std::uint8_t mac[6]; };
        std::vector<ref_mac> refs;
        for (const auto& m : extra_refs) {
            ref_mac r{};
            r.name = "baseline";
            memcpy(r.mac, m.data(), 6);
            refs.push_back(r);
        }
        {
            const HMODULE iphlp = LoadLibraryW(L"iphlpapi.dll");
            if (iphlp) {
                const auto fn_gai = reinterpret_cast<fn_get_adapters_info_t>(
                    GetProcAddress(iphlp, "GetAdaptersInfo"));
                if (fn_gai) {
                    ULONG sz = 0;
                    fn_gai(nullptr, &sz);
                    if (sz) {
                        std::vector<std::uint8_t> buf(sz);
                        auto* info = reinterpret_cast<arp_adapter_info*>(buf.data());
                        if (fn_gai(info, &sz) == ERROR_SUCCESS) {
                            for (auto* a = info; a; a = a->Next) {
                                if (a->Type != 6 || a->AddressLength != 6) continue;
                                ref_mac r{};
                                r.name = a->AdapterName;
                                memcpy(r.mac, a->Address, 6);
                                refs.push_back(r);
                            }
                        }
                    }
                }
            }
        }
        logging::print("diag: arp - %u ref MACs (%u from --refmac)",
            (unsigned)refs.size(), (unsigned)extra_refs.size());
        for (const auto& r : refs)
            logging::print("diag: arp - ref '%s' = %02X:%02X:%02X:%02X:%02X:%02X",
                r.name.c_str(), r.mac[0], r.mac[1], r.mac[2],
                r.mac[3], r.mac[4], r.mac[5]);

        // ---- FL derivation + enumeration dump ----
        fl_layout s_fl{};
        if (!derive_fl_layout(tcpip_base, &s_fl)) return;

        const fl_report fl = process_fl_interfaces(tcpip_base, s_fl, false);
        logging::print("diag: arp - %u provider candidate(s) with interfaces,"
            " %u validated FL(s)", fl.providers, fl.fls);

        // ---- compartment + neighbor dump ----
        const auto sets = find_valid_sets(tcpip_base);
        logging::print("diag: arp - %u valid compartment set(s)", (unsigned)sets.size());

        std::vector<std::uint64_t> if_seen;
        for (const auto& set : sets) {
            logging::print("diag: arp - set 0x%llX af_len=%u",
                (unsigned long long)set.first, set.second);
            const std::uint32_t count     = kread_val<std::uint32_t>(set.first + s_off.cs_count);
            const std::uint64_t table_ptr = kread_val<std::uint64_t>(set.first + s_off.cs_table);

            for (std::uint32_t i = 0; i < count; ++i) {
                const std::uint64_t bucket = table_ptr + static_cast<std::uint64_t>(i) * s_off.cs_bucket_stride;
                std::uint64_t cur = kread_val<std::uint64_t>(bucket);

                for (std::uint32_t depth = 0;
                     depth < 64 && is_kva(cur) && cur != bucket;
                     ++depth)
                {
                    const std::uint64_t compartment = cur - s_off.cs_entry_offset;
                    if (!s_off.compartment_if_list || !s_off.if_compartment_link) break;
                    const std::uint64_t if_list_va = compartment + s_off.compartment_if_list;
                    std::uint64_t if_flink = kread_val<std::uint64_t>(if_list_va);

                    for (std::uint32_t j = 0;
                         j < 128 && is_kva(if_flink) && if_flink != if_list_va;
                         ++j)
                    {
                        const std::uint64_t iface = if_flink - s_off.if_compartment_link;

                        bool if_dup = false;
                        for (auto v : if_seen) if (v == iface) { if_dup = true; break; }
                        if (if_dup) { if_flink = kread_val<std::uint64_t>(if_flink); continue; }
                        if_seen.push_back(iface);

                        const std::uint64_t luid = kread_val<std::uint64_t>(iface + 0x10);
                        logging::print("diag: arp - iface 0x%llX luid=0x%llX",
                            (unsigned long long)iface, (unsigned long long)luid);

                        // live neighbor entries: dump the address + the MAC
                        // right behind it plus state/refcount for verification
                        const std::uint64_t nb_table = kread_val<std::uint64_t>(iface + s_off.if_nb_table);
                        if (is_kva(nb_table) && s_off.nb_table_list_head) {
                            const std::uint64_t head = nb_table + s_off.nb_table_list_head;
                            std::uint64_t link = kread_val<std::uint64_t>(head);
                            for (std::uint32_t n = 0;
                                 n < 6 && is_kva(link) && link != head &&
                                 link != nb_table + s_off.nb_table_list_head + 0x10;
                                 ++n, link = kread_val<std::uint64_t>(link))
                            {
                                const std::uint64_t nb = link - s_off.nb_table_entry_offset;
                                std::uint8_t dump[32] = {};
                                kread(nb + s_off.nb_dl_address, dump, 32);
                                const std::uint64_t nb_iface = kread_val<std::uint64_t>(nb + 8);
                                const std::uint32_t nb_state = kread_val<std::uint32_t>(nb + 0x1c);
                                const std::uint32_t nb_refs  = kread_val<std::uint32_t>(nb + 0x60);
                                logging::print("diag: arp -   nb 0x%llX iface@+8=0x%llX state@1c=%u refs@60=%u",
                                    (unsigned long long)nb, (unsigned long long)nb_iface,
                                    nb_state, nb_refs);
                                logging::print("diag: arp -   addr+0..3 = %02X %02X %02X %02X | "
                                    "mac@+4 = %02X:%02X:%02X:%02X:%02X:%02X | +0x10 = %02X:%02X:%02X:%02X:%02X:%02X",
                                    dump[0], dump[1], dump[2], dump[3],
                                    dump[4], dump[5], dump[6], dump[7], dump[8], dump[9],
                                    dump[16], dump[17], dump[18], dump[19], dump[20], dump[21]);
                            }
                        }

                        if_flink = kread_val<std::uint64_t>(if_flink);
                    }

                    cur = kread_val<std::uint64_t>(cur);
                }
            }
        }

        logging::print("diag: arp - %u interface(s) dumped", (unsigned)if_seen.size());
    }

}