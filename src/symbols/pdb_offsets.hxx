#pragma once

#define NOMINMAX
#include <Windows.h>
#include <Urlmon.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#pragma comment(lib, "urlmon.lib")

#define PDBLOG(fmt, ...) logging::print("pdb: " fmt, ##__VA_ARGS__)

namespace loader_offsets {

    struct disk_offsets {
        ULONG raid_unit_adapter;
        ULONG raid_unit_identity;
        ULONG raid_unit_vendor_id;
        ULONG raid_unit_product_id;
        ULONG raid_unit_serial_number;
        ULONG raid_unit_stor_async_notify;
        ULONG raid_unit_unit_extension;
        ULONG raid_unit_identify_namespace_data;
        ULONG stor_identity_serial_number;
        ULONG stor_identity_device_id;
        ULONG stor_identity_rich_device_description;
        ULONG rich_desc_vendor_id;
        ULONG rich_desc_model_number;
        ULONG rich_desc_firmware_revision;
        ULONG raid_adapter_miniport;
        ULONG raid_adapter_serial_number;
        ULONG raid_miniport_private_device_ext;
        ULONG raid_hw_device_extension;
        ULONG nvme_adapter_serial_number;
        ULONG nvme_adapter_controller;
        ULONG nvme_controller_identify_controller_data;
        ULONG nvme_namespace_controller;
        ULONG nvme_namespace_identify_data;
        ULONG nvme_namespace_identify_descriptor;
        ULONG nvme_identify_namespace_nguid;
        ULONG nvme_identify_namespace_eui64;
        ULONG nvme_identify_controller_serial;
        ULONG nvme_identify_controller_ieee;
        ULONG stornvme_internal_identify_controller;
        ULONG stornvme_namespace_count;
        ULONG stornvme_namespace_table;
        ULONG stornvme_namespace_serial_low;
        ULONG stornvme_namespace_serial_high;
        ULONG stornvme_namespace_nguid;
        ULONG stornvme_namespace_eui64;
        ULONG volmgr_volume_disk_number;
        ULONG volmgr_volume_partition_length;
        ULONG volmgr_volume_unique_guid;
        ULONG volmgr_volume_is_gpt;
        ULONG volmgr_volume_target_device;
        ULONG mountmgr_device_mounted_list;
        ULONG mountmgr_mounted_unique_id;
        ULONG partmgr_partition_info_ex;
        ULONG partmgr_partition_stable_guid;
        ULONG partmgr_partition_unique_id;
        ULONG partmgr_layout_cache;
        ULONG partmgr_layout_pointer;
        ULONG partmgr_layout_disk_id;
    };

    struct dxgkrnl_offsets {
        std::uint64_t edid_cache_rva;
        ULONG    entry_stride;
        ULONG    entry_timestamp;
        ULONG    entry_edid_data;
        ULONG    max_entries;
        std::uint64_t adapter_list_rva;  // RVA of the global LIST_ENTRY head (DxgkpAdapterList etc.)
    };

    struct usbstor_offsets {
        std::uint64_t get_serial_rva;
        ULONG    pdo_to_fdo;
        ULONG    fdo_inq_ptr;
        ULONG    inq_data_off;
        ULONG    inq_serial_desc;
        ULONG    fdo_serial_bytes;
        ULONG    fdo_serial_len;
    };

    struct tcpip_offsets {
        // compartment hash-set candidates: embedded statics on current builds,
        // TcpCompartmentSet kept as the legacy fallback (small InCS context
        // pointer there, the hash tables live in the two globals)
        std::uint64_t ipv4_global_rva;       // 0 = not found
        std::uint64_t ipv6_global_rva;       // 0 = not found
        std::uint64_t compartment_set_rva;   // legacy candidate
        ULONG    cs_count;                   // ULONG TableSize on the set object
        ULONG    cs_table;                   // POINTER to bucket array on the set object
        ULONG    cs_entry_offset;            // compartment = bucket_link - offset
        ULONG    cs_bucket_stride;           // bytes per bucket (16)
        // per-interface neighbor tables (hang off FL_INTERFACE on current
        // builds - the old compartment-relative table offset is gone)
        ULONG    if_nb_table;                // FL_INTERFACE -> NEIGHBOR_TABLE* (primary)
        ULONG    if_nb_table_alt;            // FL_INTERFACE -> NEIGHBOR_TABLE* (second family)
        ULONG    nb_table_list_head;         // all-neighbors LIST_ENTRY offset in table
        ULONG    nb_table_entry_offset;      // neighbor = list_link - offset
        ULONG    nb_interface;               // neighbor -> FL_INTERFACE* back-pointer
        ULONG    nb_state;
        ULONG    nb_refcount;
        ULONG    nb_dl_address;              // USHORT Length; UCHAR Address[] at +2
        // FL_INTERFACE walk for SendARP local-address patching; all three required, 0 = unavailable
        ULONG    compartment_if_list;       // interface LIST_ENTRY head in _TCP_COMPARTMENT
        ULONG    if_compartment_link;        // LIST_ENTRY CompartmentLink offset in _FL_INTERFACE
        // interface link-layer address: NOT inline in _FL_INTERFACE - it sits
        // behind iface->[0] -> +dl_p2 -> {dl_cur, dl_perm} address blocks of
        // shape {USHORT Length@dl_len; UCHAR Address@dl_len+2}
        ULONG    dl_p2_off;
        ULONG    dl_cur_off;                 // current DlPhysAddr block pointer
        ULONG    dl_perm_off;                // permanent copy (0 = not derived)
        ULONG    dl_len_off;                 // USHORT Length inside the block
    };

    // nvlddmkm has no public PDB - everything below is derived at runtime
    // from instruction patterns in the on-disk image; the rcdbDumpSystemInfo
    // UUID-extraction site anchors the whole layout
    struct nvlddmkm_offsets {
        std::uint64_t gpu_mgr_global_rva;  // .data pointer to the GPU-manager object
        ULONG    uuid_flag_off;            // OBJGPU gpuUuid cached-valid byte
        ULONG    uuid_data_off;            // OBJGPU cached 16-byte gpuUuid (flag+1)
        ULONG    mgr_inner_ptr_off;        // mgr -> GPU id/OBJGPU hash table
        ULONG    table_entries_off;        // table -> linear entry array
        ULONG    table_entry_stride;       // bytes per entry: {OBJGPU*, pad, id}
        ULONG    table_count_off;          // table -> ULONG entry count
        ULONG    max_gpus;                 // bitmap bound cross-check (32)
    };

    struct ndis_offsets {
        ULONG64 miniport_list_rva;
        ULONG64 wpp_main_cb_rva;
        ULONG mp_next_global;
        ULONG mp_eth_db;
        ULONG mp_adapter_ctx;
        ULONG mp_if_avail;
        ULONG mp_if_block;
        ULONG ifb_cur_phys_addr;
        ULONG ifb_perm_phys_addr;
        ULONG ifb_family_entry;
        ULONG pa_length;
        ULONG pa_address;
        ULONG ethdb_adapter_addr;
    };

}

namespace pdb_offsets {
namespace detail {

constexpr char pdb_magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53";
constexpr std::uint32_t tpi_stream = 2;
constexpr std::uint16_t s_ldata32  = 0x110C;
constexpr std::uint16_t s_gdata32  = 0x110D;
constexpr std::uint16_t s_pub32    = 0x110E;
constexpr std::uint16_t s_lproc32  = 0x110F;
constexpr std::uint16_t s_gproc32  = 0x1110;
constexpr std::uint16_t lf_fieldlist    = 0x1203;
constexpr std::uint16_t lf_bclass       = 0x1400;
constexpr std::uint16_t lf_vbclass      = 0x1401;
constexpr std::uint16_t lf_ivbclass     = 0x1402;
constexpr std::uint16_t lf_index        = 0x1404;
constexpr std::uint16_t lf_vfunctab     = 0x1409;
constexpr std::uint16_t lf_enumerate    = 0x1502;
constexpr std::uint16_t lf_member       = 0x150D;
constexpr std::uint16_t lf_static_member= 0x150E;
constexpr std::uint16_t lf_method       = 0x150F;
constexpr std::uint16_t lf_nesttype     = 0x1510;
constexpr std::uint16_t lf_onemethod    = 0x1511;
constexpr std::uint16_t lf_structure    = 0x1505;
constexpr std::uint16_t lf_class        = 0x1504;
constexpr std::uint16_t lf_char         = 0x8000;
constexpr std::uint16_t lf_short        = 0x8001;
constexpr std::uint16_t lf_ushort       = 0x8002;
constexpr std::uint16_t lf_long         = 0x8003;
constexpr std::uint16_t lf_ulong        = 0x8004;
constexpr std::uint16_t lf_quadword     = 0x8009;
constexpr std::uint16_t lf_uquadword    = 0x800A;

#pragma pack(push, 1)
struct msf_super_block {
    char magic[32];
    std::uint32_t block_size, free_block_map_block, num_blocks;
    std::uint32_t num_directory_bytes, unknown, block_map_addr;
};
struct tpi_header {
    std::uint32_t version, header_size, type_index_begin, type_index_end, type_record_bytes;
    std::uint16_t hash_stream_index, hash_aux_stream_index;
    std::uint32_t hash_key_size, num_hash_buckets;
    std::int32_t  hash_value_buffer_offset; std::uint32_t hash_value_buffer_length;
    std::int32_t  index_offset_buffer_offset; std::uint32_t index_offset_buffer_length;
    std::int32_t  hash_adj_buffer_offset; std::uint32_t hash_adj_buffer_length;
};
struct cv_info_pdb70 { std::uint32_t signature; GUID guid; std::uint32_t age; char pdb_file_name[1]; };
struct dbi_header {
    std::int32_t signature; std::uint32_t version_header, age;
    std::uint16_t global_stream_index, build_number, public_stream_index, pdb_dll_version;
    std::uint16_t sym_record_stream, pdb_dll_rbld;
    std::int32_t mod_info_size, section_contribution_size, section_map_size;
    std::int32_t source_info_size, type_server_size;
    std::uint32_t mfc_type_server_index;
    std::int32_t optional_dbg_header_size, ec_substream_size;
    std::uint16_t flags, machine; std::uint32_t padding;
};
struct pubsym32  { std::uint16_t record_len, record_type; std::uint32_t flags, offset; std::uint16_t segment; char name[1]; };
struct datasym32 { std::uint16_t record_len, record_type; std::uint32_t type_index, offset; std::uint16_t segment; char name[1]; };
struct procsym32_prefix {
    std::uint16_t record_len, record_type;
    std::uint32_t parent, end, next, length, debug_start, debug_end, type_index, offset;
    std::uint16_t segment; std::uint8_t flags; char name[1];
};
struct section_contribution {
    std::uint16_t section; char padding1[2]; std::int32_t offset, size;
    std::uint32_t characteristics; std::uint16_t module_index; char padding2[2];
    std::uint32_t data_crc, reloc_crc;
};
struct dbi_module_info {
    std::uint32_t opened; section_contribution contribution;
    std::uint16_t flags, module_symbol_stream;
    std::uint32_t symbol_bytes, c11_bytes, c13_bytes;
    std::uint16_t source_file_count; char padding[2];
    std::uint32_t unused, source_file_name_index, pdb_file_path_name_index;
    char module_name[1];
};
#pragma pack(pop)

struct stream_data  { std::uint32_t size = 0; std::vector<std::uint8_t> data; };
struct member_data  { std::string name; std::uint64_t offset = 0; std::uint32_t type_index = 0; };
struct base_data    { std::uint32_t type_index = 0; std::uint64_t offset = 0; };
struct type_data    { std::uint32_t index=0; std::uint16_t kind=0, properties=0; std::uint32_t field_list=0; std::string name; std::vector<member_data> members; std::vector<base_data> bases; };
struct public_symbol{ std::string name; std::uint32_t offset=0; std::uint16_t segment=0; };
struct pdb_context  { std::vector<std::uint8_t> raw; std::vector<stream_data> streams; std::uint32_t type_index_begin=0; std::vector<type_data> types; std::vector<public_symbol> public_symbols; };

static std::wstring get_system_module_path(const wchar_t* module_name) {
    wchar_t system_dir[MAX_PATH] = {};
    if (!GetSystemDirectoryW(system_dir, MAX_PATH)) return {};
    std::filesystem::path base(system_dir);
    auto full = base / module_name;
    if (std::filesystem::exists(full)) return full.wstring();
    auto drv = base / L"drivers" / module_name;
    if (std::filesystem::exists(drv)) return drv.wstring();
    return full.wstring();
}

static bool read_file_safe(const std::wstring& path, std::vector<std::uint8_t>* data) {

    {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (f) {
            auto sz = f.tellg();
            if (sz > 0) {
                f.seekg(0);
                data->resize((std::size_t)sz);
                if (f.read(reinterpret_cast<char*>(data->data()), sz)) return true;
            }
        }
    }

    wchar_t tmp_dir[MAX_PATH] = {}, tmp_file[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tmp_dir)) return false;
    if (!GetTempFileNameW(tmp_dir, L"pdb", 0, tmp_file)) return false;
    if (!CopyFileW(path.c_str(), tmp_file, FALSE)) { DeleteFileW(tmp_file); return false; }
    bool ok = false;
    {
        std::ifstream f(tmp_file, std::ios::binary | std::ios::ate);
        if (f) {
            auto sz = f.tellg();
            if (sz > 0) {
                f.seekg(0);
                data->resize((std::size_t)sz);
                ok = !!f.read(reinterpret_cast<char*>(data->data()), sz);
            }
        }
    }
    DeleteFileW(tmp_file);
    return ok;
}

static bool has_pdb_msf_magic(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    char magic[sizeof(pdb_magic) - 1] = {};
    return f.read(magic, sizeof(magic)) && memcmp(magic, pdb_magic, sizeof(magic)) == 0;
}

static void* rva_to_ptr(std::vector<std::uint8_t>& image, DWORD rva) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return nullptr;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD ss = sec[i].VirtualAddress;
        DWORD sz = (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
        if (rva >= ss && rva < ss + sz) {
            DWORD raw = sec[i].PointerToRawData + (rva - ss);
            if (raw < image.size()) return image.data() + raw;
        }
    }
    return nullptr;
}

static std::wstring widen_ascii(const char* v) {
    std::wstring out; while (*v) out.push_back((unsigned char)*v++); return out;
}

static std::wstring pdb_guid_age(const GUID& g, std::uint32_t age) {
    std::wstringstream ss;
    ss << std::uppercase << std::hex << std::setfill(L'0')
       << std::setw(8) << g.Data1 << std::setw(4) << g.Data2 << std::setw(4) << g.Data3;
    for (unsigned char b : g.Data4) ss << std::setw(2) << (unsigned)b;
    ss << std::hex << age;
    return ss.str();
}

static bool find_module_pdb(const wchar_t* module_name, std::wstring* pdb_path) {
    const auto module_path = get_system_module_path(module_name);
    if (module_path.empty()) return false;
    std::vector<std::uint8_t> image;
    if (!read_file_safe(module_path, &image)) {
        PDBLOG("[-] Failed to read %ls", module_name);
        return false;
    }
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    auto dbg = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(rva_to_ptr(image, dd.VirtualAddress));
    if (!dbg) return false;
    std::uint32_t cnt = dd.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (std::uint32_t i = 0; i < cnt; ++i) {
        if (dbg[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
        if (dbg[i].PointerToRawData + sizeof(cv_info_pdb70) > image.size()) continue;
        auto cv = reinterpret_cast<cv_info_pdb70*>(image.data() + dbg[i].PointerToRawData);
        if (cv->signature != 'SDSR') continue;
        const auto pdb_file = std::filesystem::path(cv->pdb_file_name).filename();
        const auto pdb_name = widen_ascii(pdb_file.string().c_str());
        const auto guid_age = pdb_guid_age(cv->guid, cv->age);
        wchar_t temp_path[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp_path);
        std::filesystem::path cache = std::filesystem::path(temp_path) / L"physmem_symbols" / pdb_name / guid_age;
        std::filesystem::create_directories(cache);
        auto local = cache / pdb_name;
        if (std::filesystem::exists(local)) {
            if (has_pdb_msf_magic(local)) { *pdb_path = local.wstring(); PDBLOG("[+] Using cached PDB for %ls", module_name); return true; }
            std::error_code ec; std::filesystem::remove(local, ec);
        }
        const auto url = L"https://msdl.microsoft.com/download/symbols/" + pdb_name + L"/" + guid_age + L"/" + pdb_name;
        PDBLOG("[+] Downloading PDB for %ls", module_name);
        if (FAILED(URLDownloadToFileW(nullptr, url.c_str(), local.wstring().c_str(), 0, nullptr))) {
            PDBLOG("[-] Download failed for %ls", module_name); return false;
        }
        if (!has_pdb_msf_magic(local)) {
            std::error_code ec; std::filesystem::remove(local, ec); return false;
        }
        *pdb_path = local.wstring();
        return true;
    }
    return false;
}

static bool get_section_rva(const wchar_t* module_name, std::uint16_t segment, std::uint32_t* section_rva) {
    if (!segment) return false;
    std::vector<std::uint8_t> image;
    if (!read_file_safe(get_system_module_path(module_name), &image)) return false;
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (segment > nt->FileHeader.NumberOfSections) return false;
    *section_rva = IMAGE_FIRST_SECTION(nt)[segment - 1].VirtualAddress;
    return true;
}

static bool parse_streams(pdb_context* ctx) {
    if (ctx->raw.size() < sizeof(msf_super_block)) return false;
    auto sb = reinterpret_cast<const msf_super_block*>(ctx->raw.data());
    if (memcmp(sb->magic, pdb_magic, sizeof(pdb_magic) - 1) != 0) return false;
    const std::uint32_t bs = sb->block_size;
    const std::uint32_t dir_blocks = (sb->num_directory_bytes + bs - 1) / bs;
    const std::uint64_t bm_off = (std::uint64_t)sb->block_map_addr * bs;
    if (bm_off + (std::uint64_t)dir_blocks * 4 > ctx->raw.size()) return false;
    auto bm = reinterpret_cast<const std::uint32_t*>(ctx->raw.data() + bm_off);
    std::vector<std::uint8_t> dir((std::size_t)dir_blocks * bs);
    for (std::uint32_t i = 0; i < dir_blocks; ++i) {
        std::uint64_t src = (std::uint64_t)bm[i] * bs;
        if (src + bs > ctx->raw.size()) return false;
        memcpy(dir.data() + (std::size_t)i * bs, ctx->raw.data() + src, bs);
    }
    const std::uint32_t* cur = reinterpret_cast<const std::uint32_t*>(dir.data());
    std::uint32_t sc = *cur++;
    ctx->streams.resize(sc);
    for (std::uint32_t i = 0; i < sc; ++i) ctx->streams[i].size = *cur++;
    for (std::uint32_t i = 0; i < sc; ++i) {
        if (!ctx->streams[i].size || ctx->streams[i].size == 0xFFFFFFFF) continue;
        std::uint32_t nb = (ctx->streams[i].size + bs - 1) / bs;
        ctx->streams[i].data.resize((std::size_t)nb * bs);
        for (std::uint32_t b = 0; b < nb; ++b) {
            std::uint64_t src = (std::uint64_t)(*cur++) * bs;
            if (src + bs > ctx->raw.size()) return false;
            memcpy(ctx->streams[i].data.data() + (std::size_t)b * bs, ctx->raw.data() + src, bs);
        }
    }
    return true;
}

static void add_symbol(pdb_context* ctx, const char* name, std::size_t max_len, std::uint32_t off, std::uint16_t seg) {
    ctx->public_symbols.push_back({ std::string(name, strnlen(name, max_len)), off, seg });
}

static void parse_symbol_records(pdb_context* ctx, const std::uint8_t* ptr, const std::uint8_t* end) {
    while (ptr + 4 <= end) {
        std::uint16_t rlen = *reinterpret_cast<const std::uint16_t*>(ptr);
        if (!rlen || ptr + 2 + rlen > end) break;
        std::uint16_t rtype = *reinterpret_cast<const std::uint16_t*>(ptr + 2);
        if (rtype == s_pub32 && rlen >= sizeof(pubsym32) - 2) {
            auto p = reinterpret_cast<const pubsym32*>(ptr);
            add_symbol(ctx, p->name, rlen - (offsetof(pubsym32, name) - 2), p->offset, p->segment);
        } else if ((rtype == s_gdata32 || rtype == s_ldata32) && rlen >= sizeof(datasym32) - 2) {
            auto p = reinterpret_cast<const datasym32*>(ptr);
            add_symbol(ctx, p->name, rlen - (offsetof(datasym32, name) - 2), p->offset, p->segment);
        } else if ((rtype == s_gproc32 || rtype == s_lproc32) && rlen >= sizeof(procsym32_prefix) - 2) {
            auto p = reinterpret_cast<const procsym32_prefix*>(ptr);
            add_symbol(ctx, p->name, rlen - (offsetof(procsym32_prefix, name) - 2), p->offset, p->segment);
        }
        ptr += 2 + rlen;
    }
}

static bool parse_module_symbols(pdb_context* ctx, const dbi_header* dbi) {
    const std::uint8_t* ptr = reinterpret_cast<const std::uint8_t*>(dbi + 1);
    const std::uint8_t* end = ptr + dbi->mod_info_size;
    while (ptr + sizeof(dbi_module_info) <= end) {
        auto mod = reinterpret_cast<const dbi_module_info*>(ptr);
        if (mod->module_symbol_stream != 0xFFFF &&
            ctx->streams.size() > mod->module_symbol_stream &&
            ctx->streams[mod->module_symbol_stream].data.size() >= 4) {
            const auto& st = ctx->streams[mod->module_symbol_stream];
            const std::uint8_t* sp = st.data.data();
            std::uint32_t sig = *reinterpret_cast<const std::uint32_t*>(sp);
            if (sig == 4 || sig == 0xeffe0000) sp += 4;
            parse_symbol_records(ctx, sp, sp + st.size);
        }
        const std::uint8_t* names = reinterpret_cast<const std::uint8_t*>(mod->module_name);
        auto mn_end = static_cast<const std::uint8_t*>(memchr(names, 0, end - names));
        if (!mn_end) return false;
        auto on_end = static_cast<const std::uint8_t*>(memchr(mn_end + 1, 0, end - mn_end - 1));
        if (!on_end) return false;
        ptr = on_end + 1;
        ptr += (4 - (reinterpret_cast<uintptr_t>(ptr) & 3)) & 3;
    }
    return true;
}

static bool parse_public_symbols(pdb_context* ctx) {
    if (ctx->streams.size() <= 3 || ctx->streams[3].data.size() < sizeof(dbi_header)) return false;
    auto dbi = reinterpret_cast<const dbi_header*>(ctx->streams[3].data.data());
    if (ctx->streams.size() <= dbi->sym_record_stream) return false;
    const auto& st = ctx->streams[dbi->sym_record_stream];
    parse_symbol_records(ctx, st.data.data(), st.data.data() + st.size);
    return parse_module_symbols(ctx, dbi);
}

static bool parse_cv_integer(const std::uint8_t*& ptr, std::uint32_t& rem, std::uint64_t* val) {
    if (rem < 2) return false;
    std::uint16_t leaf = *reinterpret_cast<const std::uint16_t*>(ptr);
    ptr += 2; rem -= 2;
    if (leaf < 0x8000) { *val = leaf; return true; }
    std::uint32_t bytes = 0;
    switch (leaf) {
    case lf_char: bytes=1; break; case lf_short: bytes=2; break;
    case lf_ushort: bytes=2; break; case lf_long: bytes=4; break;
    case lf_ulong: bytes=4; break; case lf_quadword: bytes=8; break;
    case lf_uquadword: bytes=8; break; default: return false;
    }
    if (rem < bytes) return false;
    switch (leaf) {
    case lf_char:      *val = *reinterpret_cast<const std::int8_t*>(ptr);   break;
    case lf_short:     *val = *reinterpret_cast<const std::int16_t*>(ptr);  break;
    case lf_ushort:    *val = *reinterpret_cast<const std::uint16_t*>(ptr); break;
    case lf_long:      *val = *reinterpret_cast<const std::int32_t*>(ptr);  break;
    case lf_ulong:     *val = *reinterpret_cast<const std::uint32_t*>(ptr); break;
    case lf_quadword:  *val = *reinterpret_cast<const std::int64_t*>(ptr);  break;
    case lf_uquadword: *val = *reinterpret_cast<const std::uint64_t*>(ptr); break;
    }
    ptr += bytes; rem -= bytes; return true;
}

static bool read_c_string(const std::uint8_t*& ptr, std::uint32_t& rem, std::string* val) {
    const void* z = memchr(ptr, 0, rem);
    if (!z) return false;
    std::size_t n = static_cast<const std::uint8_t*>(z) - ptr;
    val->assign(reinterpret_cast<const char*>(ptr), n);
    ptr += n + 1; rem -= (std::uint32_t)(n + 1); return true;
}

static bool skip_c_string(const std::uint8_t*& ptr, std::uint32_t& rem) {
    std::string s; return read_c_string(ptr, rem, &s);
}

static void skip_padding(const std::uint8_t*& ptr, std::uint32_t& rem) {
    while (rem && *ptr >= 0xF0) {
        std::uint32_t a = (*ptr & 0x0F) < 1 ? 1u : (unsigned)(*ptr & 0x0F);
        if (a > rem) a = rem;
        ptr += a; rem -= a;
    }
}

static type_data* find_type(pdb_context* ctx, std::uint32_t index) {
    if (index < ctx->type_index_begin) return nullptr;
    std::uint32_t vi = index - ctx->type_index_begin;
    if (vi >= ctx->types.size()) return nullptr;
    return &ctx->types[vi];
}

static bool parse_fieldlist(const std::uint8_t* data, std::uint32_t size, type_data* type) {
    const std::uint8_t* ptr = data;
    std::uint32_t rem = size;
    while (rem >= 2) {
        skip_padding(ptr, rem);
        if (rem < 2) break;
        std::uint16_t leaf = *reinterpret_cast<const std::uint16_t*>(ptr);
        ptr += 2; rem -= 2;
        if (leaf == lf_member) {
            if (rem < 6) return false;
            ptr += 2; rem -= 2;                       // attrs
            std::uint32_t member_type = *reinterpret_cast<const std::uint32_t*>(ptr);
            ptr += 4; rem -= 4;
            std::uint64_t offset = 0;
            if (!parse_cv_integer(ptr, rem, &offset)) return false;
            std::string name;
            if (!read_c_string(ptr, rem, &name)) return false;
            type->members.push_back({name, offset, member_type});
        } else if (leaf == lf_enumerate) {
            if (rem < 2) return false;
            ptr += 2; rem -= 2;
            std::uint64_t v = 0;
            if (!parse_cv_integer(ptr, rem, &v) || !skip_c_string(ptr, rem)) return false;
        } else if (leaf == lf_bclass) {
            if (rem < 6) return false;
            ptr += 2; rem -= 2;                       // attrs
            std::uint32_t base_type = *reinterpret_cast<const std::uint32_t*>(ptr);
            ptr += 4; rem -= 4;
            std::uint64_t base_off = 0;
            if (!parse_cv_integer(ptr, rem, &base_off)) return false;
            type->bases.push_back({base_type, base_off});
        } else if (leaf == lf_vbclass || leaf == lf_ivbclass) {
            if (rem < 8) return false;
            ptr += 2; ptr += 4; ptr += 4; rem -= 10;
            std::uint64_t a = 0, b = 0;
            if (!parse_cv_integer(ptr, rem, &a) || !parse_cv_integer(ptr, rem, &b)) return false;
        } else if (leaf == lf_static_member || leaf == lf_nesttype) {
            if (rem < 6) return false;
            ptr += 2; ptr += 4; rem -= 6;
            if (!skip_c_string(ptr, rem)) return false;
        } else if (leaf == lf_method) {
            if (rem < 6) return false;
            ptr += 2; ptr += 4; rem -= 6;
            if (!skip_c_string(ptr, rem)) return false;
        } else if (leaf == lf_onemethod) {
            if (rem < 6) return false;
            std::uint16_t attr = *reinterpret_cast<const std::uint16_t*>(ptr);
            ptr += 2; ptr += 4; rem -= 6;
            std::uint8_t mp = (attr >> 2) & 0x07;
            if (mp == 4 || mp == 5 || mp == 6) {
                if (rem < 4) return false;
                ptr += 4; rem -= 4;
            }
            if (!skip_c_string(ptr, rem)) return false;
        } else if (leaf == lf_vfunctab) {
            if (rem < 4) return false;
            ptr += 4; rem -= 4;
        } else if (leaf == lf_index) {
            if (rem < 4) return false;
            ptr += 4; rem -= 4;
        } else { break; }
    }
    return true;
}

static bool parse_structure(const std::uint8_t* data, std::uint32_t size, std::uint16_t leaf, type_data* type) {
    const std::uint8_t* ptr = data;
    std::uint32_t rem = size;
    if (rem < sizeof(std::uint16_t)*2 + sizeof(std::uint32_t)*3) return false;
    type->kind = leaf;
    ptr += 2;
    type->properties = *reinterpret_cast<const std::uint16_t*>(ptr); ptr += 2;
    type->field_list  = *reinterpret_cast<const std::uint32_t*>(ptr); ptr += 12;
    rem -= 4 + 12;
    std::uint64_t sz = 0;
    if (!parse_cv_integer(ptr, rem, &sz)) return false;
    return read_c_string(ptr, rem, &type->name);
}

static bool parse_tpi(pdb_context* ctx) {
    if (ctx->streams.size() <= tpi_stream || ctx->streams[tpi_stream].data.size() < sizeof(tpi_header)) return false;
    const auto& st = ctx->streams[tpi_stream];
    auto hdr = reinterpret_cast<const tpi_header*>(st.data.data());
    if (hdr->header_size < sizeof(tpi_header) ||
        hdr->type_index_end <= hdr->type_index_begin ||
        hdr->header_size + hdr->type_record_bytes > st.data.size()) return false;
    ctx->type_index_begin = hdr->type_index_begin;
    ctx->types.reserve(hdr->type_index_end - hdr->type_index_begin);
    const std::uint8_t* ptr = st.data.data() + hdr->header_size;
    std::uint32_t rem = hdr->type_record_bytes;
    std::uint32_t idx = hdr->type_index_begin;
    while (rem >= 2 && idx < hdr->type_index_end) {
        std::uint16_t rlen = *reinterpret_cast<const std::uint16_t*>(ptr);
        if (rlen < 2 || rlen + 2 > rem) return false;
        const std::uint8_t* rec = ptr + 2;
        std::uint16_t leaf = *reinterpret_cast<const std::uint16_t*>(rec);
        const std::uint8_t* data = rec + 2;
        std::uint32_t dsz = rlen - 2;
        type_data type = {}; type.index = idx; type.kind = leaf;
        if (leaf == lf_structure || leaf == lf_class)
            parse_structure(data, dsz, leaf, &type);
        else if (leaf == lf_fieldlist)
            parse_fieldlist(data, dsz, &type);
        ctx->types.push_back(std::move(type));
        ptr += rlen + 2; rem -= rlen + 2; ++idx;
    }
    return true;
}

static type_data* find_struct(pdb_context* ctx, const char* name) {
    type_data* fwd = nullptr;
    for (auto& t : ctx->types) {
        if ((t.kind != lf_structure && t.kind != lf_class) || t.name != name) continue;
        if (t.properties & 0x80) { if (!fwd) fwd = &t; continue; }
        return &t;
    }
    return fwd;
}

// a struct's fieldlist only lists its OWN members - inherited ones sit in
// lf_bclass bases (26100 _NDIS_IF_BLOCK keeps ifPhysAddress in the inherited
// _NDIS_NSI_INTERFACE_ENUM_ROD base), so resolve direct members first, then
// walk the bases with their offsets. bases appear as forward declarations -
// find_struct prefers the real definition carrying the fieldlist.
static type_data* resolve_base_def(pdb_context* ctx, type_data* bt) {
    if (bt && (bt->properties & 0x80) && !bt->name.empty())
        if (type_data* real = find_struct(ctx, bt->name.c_str())) return real;
    return bt;
}

static bool resolve_member_in_type(pdb_context* ctx, type_data* s, const char* field_name,
                                   std::uint64_t base, int depth, ULONG* out) {
    if (!s || depth > 4) return false;
    type_data* fl = find_type(ctx, s->field_list);
    if (!fl || fl->kind != lf_fieldlist) return false;
    for (const auto& m : fl->members)
        if (m.name == field_name) { *out = (ULONG)(base + m.offset); return true; }
    for (const auto& b : fl->bases)
        if (resolve_member_in_type(ctx, resolve_base_def(ctx, find_type(ctx, b.type_index)),
                                   field_name, base + b.offset, depth + 1, out))
            return true;
    return false;
}

// flattened member walk: every member including inherited ones, base
// offsets folded in, member type indices preserved
static bool collect_members(pdb_context* ctx, type_data* s, std::uint64_t base, int depth,
                            std::vector<member_data>* out) {
    if (!s || depth > 4) return false;
    type_data* fl = find_type(ctx, s->field_list);
    if (!fl || fl->kind != lf_fieldlist) return false;
    for (const auto& m : fl->members)
        out->push_back({m.name, base + m.offset, m.type_index});
    for (const auto& b : fl->bases)
        collect_members(ctx, resolve_base_def(ctx, find_type(ctx, b.type_index)),
                        base + b.offset, depth + 1, out);
    return true;
}

static bool resolve_field(pdb_context* ctx, const char* struct_name, const char* field_name, ULONG* out) {
    type_data* s = find_struct(ctx, struct_name);
    if (!s) return false;
    if (resolve_member_in_type(ctx, s, field_name, 0, 0, out)) {
        PDBLOG("[+] %s::%s = 0x%lx", struct_name, field_name, *out);
        return true;
    }
    PDBLOG("[-] %s::%s not found", struct_name, field_name);
    return false;
}

static bool resolve_public_symbol_rva(const wchar_t* module_name, pdb_context* ctx,
                                       const char* symbol_name, std::uint64_t* rva,
                                       bool quiet = false) {
    if (!parse_public_symbols(ctx)) return false;
    for (const auto& sym : ctx->public_symbols) {
        if (sym.name != symbol_name) continue;
        std::uint32_t sec_rva = 0;
        if (!get_section_rva(module_name, sym.segment, &sec_rva)) return false;
        *rva = (std::uint64_t)sec_rva + sym.offset;
        PDBLOG("[+] %ls!%s = rva 0x%llx", module_name, symbol_name, (unsigned long long)*rva);
        return true;
    }
    if (!quiet) PDBLOG("[-] %ls!%s not found", module_name, symbol_name);
    return false;
}

static bool read_module_image(const wchar_t* module_name, std::vector<std::uint8_t>* image) {
    const auto path = get_system_module_path(module_name);
    if (path.empty()) return false;
    return read_file_safe(path, image);
}

static const std::uint8_t* module_rva_to_ptr(std::vector<std::uint8_t>& image, std::uint64_t rva) {
    if (rva > MAXDWORD) return nullptr;
    return static_cast<const std::uint8_t*>(rva_to_ptr(image, (DWORD)rva));
}

static bool load_pdb_context(const wchar_t* module_name, pdb_context* ctx, bool parse_types) {
    std::wstring pdb_path;
    if (!find_module_pdb(module_name, &pdb_path)) return false;
    if (!read_file_safe(pdb_path, &ctx->raw)) return false;
    PDBLOG("[+] Parsing PDB for %ls", module_name);
    if (!parse_streams(ctx)) return false;
    return !parse_types || parse_tpi(ctx);
}

static bool extract_disp32(const std::uint8_t* code, std::size_t size, const std::vector<int>& pat, ULONG* out) {
    for (std::size_t i = 0; i + pat.size() <= size; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] >= 0 && code[i+j] != (std::uint8_t)pat[j]) { match = false; break; }
        if (!match) continue;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] == -2 && i+j+4 <= size) { *out = *reinterpret_cast<const ULONG*>(code+i+j); return true; }
    }
    return false;
}

static bool extract_disp8(const std::uint8_t* code, std::size_t size, const std::vector<int>& pat, ULONG* out) {
    for (std::size_t i = 0; i + pat.size() <= size; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] >= 0 && code[i+j] != (std::uint8_t)pat[j]) { match = false; break; }
        if (!match) continue;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] == -2) { *out = code[i+j]; return true; }
    }
    return false;
}

static bool extract_disp8_nth(const std::uint8_t* code, std::size_t size, const std::vector<int>& pat, std::size_t occ, ULONG* out) {
    std::size_t seen = 0;
    for (std::size_t i = 0; i + pat.size() <= size; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] >= 0 && code[i+j] != (std::uint8_t)pat[j]) { match = false; break; }
        if (!match) continue;
        for (std::size_t j = 0; j < pat.size(); ++j)
            if (pat[j] == -2) { if (seen++ == occ) { *out = code[i+j]; return true; } break; }
    }
    return false;
}

static bool resolve_stornvme_layout(pdb_context* ctx, loader_offsets::disk_offsets* d) {
    std::vector<std::uint8_t> image;
    if (!read_module_image(L"stornvme.sys", &image)) return false;
    std::uint64_t serial_rva = 0;
    if (!resolve_public_symbol_rva(L"stornvme.sys", ctx, "FormInquirySerialNumberData", &serial_rva)) return false;
    const std::uint8_t* code = module_rva_to_ptr(image, serial_rva);
    if (!code) return false;
    if (!extract_disp32(code, 0x300, {0x4C,0x8B,0xA9,-2,-1,-1,-1}, &d->stornvme_internal_identify_controller) ||
        !extract_disp32(code, 0x300, {0x4A,0x8B,0x84,0xE6,-2,-1,-1,-1}, &d->stornvme_namespace_table) ||
        !extract_disp8 (code, 0x300, {0x4C,0x8D,0x50,-2}, &d->stornvme_namespace_nguid) ||
        !extract_disp8 (code, 0x300, {0x4C,0x8D,0x78,-2}, &d->stornvme_namespace_eui64) ||
        !extract_disp8_nth(code, 0x300, {0x0F,0xB7,0x48,-2}, 0, &d->stornvme_namespace_serial_high) ||
        !extract_disp8_nth(code, 0x300, {0x0F,0xB7,0x48,-2}, 1, &d->stornvme_namespace_serial_low)) {
        PDBLOG("[-] stornvme FormInquirySerialNumberData pattern scan failed");
        return false;
    }
    std::uint64_t idents_rva = 0;
    if (!resolve_public_symbol_rva(L"stornvme.sys", ctx, "FormInquiryDeviceIdentifiersData", &idents_rva)) return false;
    const std::uint8_t* icode = module_rva_to_ptr(image, idents_rva);
    if (!icode) return false;
    if (!extract_disp32(icode, 0x400, {0x44,0x3B,0xA6,-2,-1,-1,-1}, &d->stornvme_namespace_count)) {
        PDBLOG("[-] stornvme FormInquiryDeviceIdentifiersData pattern scan failed");
        return false;
    }
    PDBLOG("[+] stornvme: ident_ctrl=0x%lx ns_count=0x%lx ns_table=0x%lx nguid=0x%lx eui64=0x%lx",
        d->stornvme_internal_identify_controller, d->stornvme_namespace_count,
        d->stornvme_namespace_table, d->stornvme_namespace_nguid, d->stornvme_namespace_eui64);
    return true;
}

static bool resolve_volmgr_layout(pdb_context* ctx, loader_offsets::disk_offsets* d) {
    std::vector<std::uint8_t> image;
    if (!read_module_image(L"volmgr.sys", &image)) return false;
    std::uint64_t rva = 0;
    if (!resolve_public_symbol_rva(L"volmgr.sys", ctx,
        "?VmpSetPartitionInformation@@YAXPEAVVM_VOLUME_EXTENSION@@PEAU_PARTITION_INFORMATION_EX@@@Z", &rva))
        return false;
    const std::uint8_t* code = module_rva_to_ptr(image, rva);
    if (!code) return false;

    bool ok = extract_disp32(code,0x300,{0x40,0x38,0xA9,-2,-1,-1,-1},&d->volmgr_volume_is_gpt) &&
              extract_disp32(code,0x300,{0x0F,0x10,0x87,-2,-1,-1,-1},&d->volmgr_volume_unique_guid) &&
              extract_disp32(code,0x300,{0x8B,0x87,-2,-1,-1,-1,0x89,0x44},&d->volmgr_volume_disk_number) &&
              extract_disp32(code,0x300,{0x48,0x39,0x91,-2,-1,-1,-1,0x74},&d->volmgr_volume_partition_length);
    if (!ok) {
        ok = extract_disp32(code,0x300,{0x44,0x38,0xA3,-2,-1,-1,-1},&d->volmgr_volume_is_gpt) &&
             extract_disp32(code,0x300,{0x0F,0x10,0x83,-2,-1,-1,-1},&d->volmgr_volume_unique_guid) &&
             extract_disp32(code,0x300,{0x8B,0x83,-2,-1,-1,-1,0x89,0x45},&d->volmgr_volume_disk_number) &&
             extract_disp32(code,0x300,{0x48,0x39,0x83,-2,-1,-1,-1,0x75},&d->volmgr_volume_partition_length);
    }
    if (!ok) { PDBLOG("[-] volmgr VmpSetPartitionInformation pattern scan failed"); return false; }
    std::uint64_t qrva = 0;
    if (!resolve_public_symbol_rva(L"volmgr.sys", ctx,
        "?VmpQueryUniqueIdInternal@@YAJPEAVVM_VOLUME_EXTENSION@@PEAGPEAE@Z", &qrva))
        return false;
    const std::uint8_t* qcode = module_rva_to_ptr(image, qrva);
    if (!qcode) return false;
    if (!extract_disp32(qcode,0x120,{0x49,0x8B,0x82,-2,-1,-1,-1},&d->volmgr_volume_target_device) &&
        !extract_disp32(qcode,0x120,{0x49,0x8B,0x81,-2,-1,-1,-1},&d->volmgr_volume_target_device)) {
        PDBLOG("[-] volmgr VmpQueryUniqueIdInternal pattern scan failed"); return false;
    }
    PDBLOG("[+] volmgr: disk_num=0x%lx guid=0x%lx is_gpt=0x%lx target=0x%lx",
        d->volmgr_volume_disk_number, d->volmgr_volume_unique_guid,
        d->volmgr_volume_is_gpt, d->volmgr_volume_target_device);
    return true;
}

static bool resolve_mountmgr_layout(pdb_context* ctx, loader_offsets::disk_offsets* d) {
    std::vector<std::uint8_t> image;
    if (!read_module_image(L"mountmgr.sys", &image)) return false;
    std::uint64_t rva = 0;
    if (!resolve_public_symbol_rva(L"mountmgr.sys", ctx, "QueryPointsFromMemory", &rva)) return false;
    const std::uint8_t* code = module_rva_to_ptr(image, rva);
    if (!code) return false;
    bool ok = extract_disp8(code,0x700,{0x48,0x8B,0x7E,-2,0x4C,0x8D,0x76},&d->mountmgr_device_mounted_list) &&
              extract_disp8(code,0x700,{0x48,0x8B,0x57,-2,0x41,0x0F,0xB7,0x07},&d->mountmgr_mounted_unique_id);
    if (!ok) {
        bool uid_ok = extract_disp8(code,0x700,{0x49,0x8B,0x46,-2,0x4D,0x8D,0x7E},&d->mountmgr_mounted_unique_id) ||
                      extract_disp8(code,0x700,{0x48,0x8B,0x56,-2,0x0F,0xB7,0x5E},&d->mountmgr_mounted_unique_id);
        ok = extract_disp8(code,0x700,{0x4D,0x8B,0x75,-2,0x49,0x83,0xC5},&d->mountmgr_device_mounted_list) && uid_ok;
    }
    if (!ok) { PDBLOG("[-] mountmgr QueryPointsFromMemory pattern scan failed"); return false; }
    PDBLOG("[+] mountmgr: mounted_list=0x%lx unique_id=0x%lx",
        d->mountmgr_device_mounted_list, d->mountmgr_mounted_unique_id);
    return true;
}

static bool resolve_partmgr_layout(pdb_context* ctx, loader_offsets::disk_offsets* d) {
    std::vector<std::uint8_t> image;
    if (!read_module_image(L"partmgr.sys", &image)) return false;
    std::uint64_t rva = 0;
    if (!resolve_public_symbol_rva(L"partmgr.sys", ctx,
        "?PmBuildUniqueId@@YAJPEAU_DEVICE_EXTENSION@@PEAU_PARTITION_EXTENSION@@@Z", &rva))
        return false;
    const std::uint8_t* code = module_rva_to_ptr(image, rva);
    if (!code) return false;
    if (!extract_disp32(code,0x180,{0x83,0xBA,-2,-1,-1,-1,0x01},&d->partmgr_partition_info_ex) ||
        !extract_disp8 (code,0x180,{0x48,0x8B,0x6F,-2},&d->partmgr_partition_unique_id)) {
        PDBLOG("[-] partmgr PmBuildUniqueId pattern scan failed"); return false;
    }
    std::uint64_t sg_rva = 0;
    if (!resolve_public_symbol_rva(L"partmgr.sys", ctx,
        "?PmBuildStableGuid@@YAJPEAU_DEVICE_EXTENSION@@PEAU_PARTITION_EXTENSION@@@Z", &sg_rva))
        return false;
    const std::uint8_t* sgcode = module_rva_to_ptr(image, sg_rva);
    if (!sgcode) return false;
    if (!extract_disp8(sgcode,0x100,{0x48,0x8D,0x4A,-2},&d->partmgr_partition_stable_guid) &&
        !extract_disp8(sgcode,0x100,{0xF3,0x0F,0x7F,0x42,-2},&d->partmgr_partition_stable_guid)) {
        PDBLOG("[-] partmgr PmBuildStableGuid pattern scan failed"); return false;
    }
    std::uint64_t gl_rva = 0;
    if (!resolve_public_symbol_rva(L"partmgr.sys", ctx, "PmGetDriveLayoutEx", &gl_rva)) return false;
    const std::uint8_t* glcode = module_rva_to_ptr(image, gl_rva);
    if (!glcode) return false;
    bool layout_ok =
        (extract_disp32(glcode,0x500,{0x48,0x8B,0x86,-2,-1,-1,-1},&d->partmgr_layout_pointer) ||
         extract_disp32(glcode,0x500,{0x48,0x8B,0xB5,-2,-1,-1,-1},&d->partmgr_layout_pointer)) &&
        (extract_disp32(glcode,0x500,{0x48,0x8D,0x8E,-2,-1,-1,-1},&d->partmgr_layout_cache) ||
         extract_disp32(glcode,0x500,{0x48,0x8D,0x8D,-2,-1,-1,-1},&d->partmgr_layout_cache));
    if (!layout_ok) { PDBLOG("[-] partmgr PmGetDriveLayoutEx pattern scan failed"); return false; }
    d->partmgr_layout_disk_id = 0x8;
    PDBLOG("[+] partmgr: info_ex=0x%lx stable_guid=0x%lx unique_id=0x%lx layout_cache=0x%lx layout_ptr=0x%lx",
        d->partmgr_partition_info_ex, d->partmgr_partition_stable_guid,
        d->partmgr_partition_unique_id, d->partmgr_layout_cache, d->partmgr_layout_pointer);
    return true;
}

}

inline bool resolve_disk(loader_offsets::disk_offsets* out) {
    if (!out) return false;
    *out = {};


    detail::pdb_context stor_ctx;
    if (!detail::load_pdb_context(L"storport.sys", &stor_ctx, true)) {
        PDBLOG("[-] storport.sys PDB load failed"); return false;
    }


    const char* id_struct = detail::find_struct(&stor_ctx, "_STOR_IDENTITY") ? "_STOR_IDENTITY" : "_STOR_SCSI_IDENTITY";

    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "Adapter",               &out->raid_unit_adapter);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "Identity",              &out->raid_unit_identity);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "VendorId",              &out->raid_unit_vendor_id);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "ProductId",             &out->raid_unit_product_id);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "SerialNumber",          &out->raid_unit_serial_number);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "StorAsyncNotify",       &out->raid_unit_stor_async_notify);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "UnitExtension",         &out->raid_unit_unit_extension);
    detail::resolve_field(&stor_ctx, "_RAID_UNIT_EXTENSION", "IdentifyNamespaceData", &out->raid_unit_identify_namespace_data);

    detail::resolve_field(&stor_ctx, id_struct, "SerialNumber",          &out->stor_identity_serial_number);
    detail::resolve_field(&stor_ctx, id_struct, "DeviceId",              &out->stor_identity_device_id);
    detail::resolve_field(&stor_ctx, id_struct, "RichDeviceDescription", &out->stor_identity_rich_device_description);

    detail::resolve_field(&stor_ctx, "_STOR_RICH_DEVICE_DESCRIPTION", "VendorId",          &out->rich_desc_vendor_id);
    detail::resolve_field(&stor_ctx, "_STOR_RICH_DEVICE_DESCRIPTION", "ModelNumber",       &out->rich_desc_model_number);
    detail::resolve_field(&stor_ctx, "_STOR_RICH_DEVICE_DESCRIPTION", "FirmwareRevision",  &out->rich_desc_firmware_revision);

    detail::resolve_field(&stor_ctx, "_RAID_ADAPTER_EXTENSION", "Miniport",           &out->raid_adapter_miniport);
    detail::resolve_field(&stor_ctx, "_RAID_ADAPTER_EXTENSION", "AdapterSerialNumber",&out->raid_adapter_serial_number);
    detail::resolve_field(&stor_ctx, "_RAID_MINIPORT",          "PrivateDeviceExt",   &out->raid_miniport_private_device_ext);
    detail::resolve_field(&stor_ctx, "_RAID_HW_DEVICE_EXT",     "HwDeviceExtension",  &out->raid_hw_device_extension);


    detail::resolve_field(&stor_ctx, "NVME_IDENTIFY_NAMESPACE_DATA",   "NGUID", &out->nvme_identify_namespace_nguid);
    detail::resolve_field(&stor_ctx, "NVME_IDENTIFY_NAMESPACE_DATA",   "EUI64", &out->nvme_identify_namespace_eui64);
    detail::resolve_field(&stor_ctx, "NVME_IDENTIFY_CONTROLLER_DATA",  "SN",    &out->nvme_identify_controller_serial);
    detail::resolve_field(&stor_ctx, "NVME_IDENTIFY_CONTROLLER_DATA",  "IEEE",  &out->nvme_identify_controller_ieee);


    detail::resolve_field(&stor_ctx, "_NVME_ADAPTER_EXTENSION",    "AdapterSerialNumber",       &out->nvme_adapter_serial_number);
    detail::resolve_field(&stor_ctx, "_NVME_ADAPTER_EXTENSION",    "NVMeController",            &out->nvme_adapter_controller);
    detail::resolve_field(&stor_ctx, "_NVME_CONTROLLER",           "IdentifyControllerData",    &out->nvme_controller_identify_controller_data);
    detail::resolve_field(&stor_ctx, "_NVME_NAMESPACE_EXTENSION",  "NvmeController",            &out->nvme_namespace_controller);
    detail::resolve_field(&stor_ctx, "_NVME_NAMESPACE_EXTENSION",  "IdentifyNamespaceData",     &out->nvme_namespace_identify_data);
    detail::resolve_field(&stor_ctx, "_NVME_NAMESPACE_EXTENSION",  "IdentifyNamespaceDescriptor",&out->nvme_namespace_identify_descriptor);

    if (!out->raid_unit_identity || !out->raid_unit_adapter || !out->stor_identity_serial_number) {
        PDBLOG("[-] Critical storport fields not resolved"); return false;
    }


    detail::pdb_context stornvme_ctx;
    if (!detail::load_pdb_context(L"stornvme.sys", &stornvme_ctx, false))
        PDBLOG("[!] stornvme.sys PDB load failed - private namespace patching disabled");
    else if (!detail::resolve_stornvme_layout(&stornvme_ctx, out))
        PDBLOG("[!] stornvme layout scan failed - private namespace patching disabled");


    detail::pdb_context volmgr_ctx;
    if (!detail::load_pdb_context(L"volmgr.sys", &volmgr_ctx, false)) {
        PDBLOG("[-] volmgr.sys PDB load failed"); return false;
    }
    if (!detail::resolve_volmgr_layout(&volmgr_ctx, out)) {
        PDBLOG("[-] volmgr layout scan failed"); return false;
    }


    detail::pdb_context mountmgr_ctx;
    if (!detail::load_pdb_context(L"mountmgr.sys", &mountmgr_ctx, false)) {
        PDBLOG("[-] mountmgr.sys PDB load failed"); return false;
    }
    if (!detail::resolve_mountmgr_layout(&mountmgr_ctx, out)) {
        PDBLOG("[-] mountmgr layout scan failed"); return false;
    }


    detail::pdb_context partmgr_ctx;
    if (!detail::load_pdb_context(L"partmgr.sys", &partmgr_ctx, false)) {
        PDBLOG("[-] partmgr.sys PDB load failed"); return false;
    }
    if (!detail::resolve_partmgr_layout(&partmgr_ctx, out)) {
        PDBLOG("[-] partmgr layout scan failed"); return false;
    }

    return true;
}

inline bool resolve_dxgkrnl(loader_offsets::dxgkrnl_offsets* out) {
    if (!out) return false;
    *out = {};

    detail::pdb_context ctx;
    if (!detail::load_pdb_context(L"dxgkrnl.sys", &ctx, false)) {
        PDBLOG("[-] dxgkrnl.sys PDB load failed"); return false;
    }

    // EDID cache global
    if (!detail::resolve_public_symbol_rva(L"dxgkrnl.sys", &ctx,
            "?s_pEdidCache@EDIDCACHE@DxgMonitor@@0PEAV12@EA", &out->edid_cache_rva) &&
        !detail::resolve_public_symbol_rva(L"dxgkrnl.sys", &ctx,
            "s_pEdidCache", &out->edid_cache_rva)) {
        PDBLOG("[-] dxgkrnl s_pEdidCache not found in PDB");
        return false;
    }

    // derive the cache layout from the ctor + AddEdid anchors - no hardcoded
    // constants; dxgkrnl PDBs are publics-only
    std::vector<std::uint8_t> image;
    if (!detail::read_module_image(L"dxgkrnl.sys", &image)) {
        PDBLOG("[-] dxgkrnl.sys image read failed"); return false;
    }
    auto sym_code = [&](const char* sym) -> const std::uint8_t* {
        std::uint64_t rva = 0;
        if (!detail::resolve_public_symbol_rva(L"dxgkrnl.sys", &ctx, sym, &rva, true)) {
            PDBLOG("[-] dxgkrnl!%s not found in PDB", sym); return nullptr;
        }
        return detail::module_rva_to_ptr(image, rva);
    };

    const auto ctor = sym_code("??0EDIDCACHE@DxgMonitor@@QEAA@XZ");
    const auto add  = sym_code("?AddEdid@EDIDCACHE@DxgMonitor@@UEAAXU_LUID@@IEPEBEW4_D3DKMDT_MONITOR_CAPABILITIES_ORIGIN@@@Z");
    if (!ctor || !add) return false;

    ULONG entries_base = 0, region_size = 0, stride = 0, ts_disp = 0, edid_disp = 0, max_ent = 0;
    // ctor: add rcx,<entries_base>; ... mov r8d,<region_size> (memset span)
    if (!detail::extract_disp8(ctor, 0x60, {0x48,0x83,0xC1,-2}, &entries_base) ||
        !detail::extract_disp32(ctor, 0x60, {0x41,0xB8,-2,-1,-1,-1}, &region_size)) {
        PDBLOG("[-] EDIDCACHE ctor pattern scan failed"); return false;
    }
    // AddEdid: imul rcx,rax,<stride>; mov [rcx+rax+<ts>],rax (tick store);
    // movups [rcx+rax+<disp>],xmm0 (first EDID store); cmp reg,4; jae
    if (!detail::extract_disp32(add, 0x200, {0x48,0x69,0xC8,-2,-1,-1,-1}, &stride) ||
        !detail::extract_disp8 (add, 0x200, {0x48,0x89,0x44,0x39,-2}, &ts_disp) ||
        !detail::extract_disp8 (add, 0x200, {0x0F,0x11,0x44,0x39,-2}, &edid_disp) ||
        !detail::extract_disp8 (add, 0x200, {0x83,0xF,-1,-2,0x73}, &max_ent)) {
        // max-entries cmp register varies; fall back to region_size/stride
        if (!detail::extract_disp32(add, 0x200, {0x48,0x69,0xC8,-2,-1,-1,-1}, &stride) ||
            !detail::extract_disp8 (add, 0x200, {0x48,0x89,0x44,0x39,-2}, &ts_disp) ||
            !detail::extract_disp8 (add, 0x200, {0x0F,0x11,0x44,0x39,-2}, &edid_disp) ||
            !stride || region_size % stride) {
            PDBLOG("[-] EDIDCACHE AddEdid pattern scan failed"); return false;
        }
        max_ent = region_size / stride;
    }

    // consistency gate: ctor memset region must equal max_entries * stride
    if (!max_ent || !stride || region_size != max_ent * stride) {
        PDBLOG("[-] EDIDCACHE layout consistency gate failed (region 0x%lx stride 0x%lx max %lu)",
            region_size, stride, max_ent);
        return false;
    }

    // tool addressing: entry = obj + i*stride; ctor bumps the base by
    // entries_base before memset, so AddEdid's this-relative disps already
    // include it - they map 1:1 onto the tool's offsets
    out->entry_stride    = stride;
    out->entry_timestamp = ts_disp;
    out->entry_edid_data = edid_disp;
    out->max_entries     = max_ent;
    PDBLOG("[+] EDIDCACHE: stride=0x%lx ts=0x%lx edid=0x%lx max=%lu (region 0x%lx)",
        stride, ts_disp, edid_disp, max_ent, region_size);

    static const char* k_list_syms[] = {
        "DxgkpAdapterList", "gpDxgAdapterList", "DxgkAdapterList", "DxgAdapterList",
        "DxgpAdapterList", "g_DxgAdapterList", "DxgkpAdapterListHead",
        "DxgpAdapterListHead", "g_pAdapterList", "DxgAdapterListHead", nullptr
    };
    for (int i = 0; k_list_syms[i]; ++i) {
        if (detail::resolve_public_symbol_rva(L"dxgkrnl.sys", &ctx,
                k_list_syms[i], &out->adapter_list_rva, true)) break;
    }
    if (!out->adapter_list_rva)
        PDBLOG("[!] dxgkrnl adapter list symbol not found");

    return true;
}

inline bool resolve_usbstor(loader_offsets::usbstor_offsets* out) {
    if (!out) return false;
    *out = {};

    detail::pdb_context ctx;
    if (!detail::load_pdb_context(L"USBSTOR.SYS", &ctx, false)) {
        PDBLOG("[-] USBSTOR.SYS PDB load failed"); return false;
    }


    if (!detail::resolve_public_symbol_rva(L"USBSTOR.SYS", &ctx,
            "USBSTOR_GetDeviceSerialNumber", &out->get_serial_rva)) {
        PDBLOG("[-] USBSTOR_GetDeviceSerialNumber not found"); return false;
    }

    std::vector<std::uint8_t> image;
    if (!detail::read_module_image(L"USBSTOR.SYS", &image)) {
        PDBLOG("[-] USBSTOR.SYS image read failed"); return false;
    }

    const std::uint8_t* code = detail::module_rva_to_ptr(image, out->get_serial_rva);
    if (!code) { PDBLOG("[-] USBSTOR_GetDeviceSerialNumber not in image"); return false; }

    constexpr std::size_t scan_sz = 0x180;


    if (!detail::extract_disp8(code, scan_sz, {0x48, 0x8B, 0x7D, -2}, &out->pdo_to_fdo))
        { out->pdo_to_fdo = 0x40u; PDBLOG("[~] USBSTOR pdo_to_fdo fallback 0x40"); }


    if (!detail::extract_disp8(code, scan_sz, {0x48, 0x8B, 0x47, -2}, &out->fdo_inq_ptr))
        { out->fdo_inq_ptr = 0x10u; PDBLOG("[~] USBSTOR fdo_inq_ptr fallback 0x10"); }


    if (!detail::extract_disp8(code, scan_sz, {0x48, 0x8B, 0x70, -2}, &out->inq_data_off))
        { out->inq_data_off = 0x40u; PDBLOG("[~] USBSTOR inq_data_off fallback 0x40"); }


    if (!detail::extract_disp8(code, scan_sz, {0x48, 0x8B, 0x46, -2}, &out->inq_serial_desc))
        { out->inq_serial_desc = 0x48u; PDBLOG("[~] USBSTOR inq_serial_desc fallback 0x48"); }


    if (!detail::extract_disp8(code, scan_sz, {0x4C, 0x8D, 0x47, -2}, &out->fdo_serial_bytes))
        { out->fdo_serial_bytes = 0x6Cu; PDBLOG("[~] USBSTOR fdo_serial_bytes fallback 0x6C"); }


    if (!detail::extract_disp8(code, scan_sz, {0x89, 0x47, -2}, &out->fdo_serial_len))
        { out->fdo_serial_len = 0x40u; PDBLOG("[~] USBSTOR fdo_serial_len fallback 0x40"); }

    PDBLOG("[+] USBSTOR: pdo_to_fdo=0x%lx inq_ptr=0x%lx inq_data=0x%lx desc=0x%lx serial=0x%lx len=0x%lx",
        out->pdo_to_fdo, out->fdo_inq_ptr, out->inq_data_off,
        out->inq_serial_desc, out->fdo_serial_bytes, out->fdo_serial_len);
    return true;
}

inline bool resolve_ndis(loader_offsets::ndis_offsets* out) {
    if (!out) return false;
    *out = {};

    detail::pdb_context ctx;
    if (!detail::load_pdb_context(L"ndis.sys", &ctx, true)) {
        PDBLOG("[-] ndis.sys PDB load failed"); return false;
    }


    if (!detail::resolve_public_symbol_rva(L"ndis.sys", &ctx,
            "?ndisMiniportList@@3PEAU_NDIS_MINIPORT_BLOCK@@EA", &out->miniport_list_rva))
        detail::resolve_public_symbol_rva(L"ndis.sys", &ctx, "ndisMiniportList", &out->miniport_list_rva);

    detail::resolve_public_symbol_rva(L"ndis.sys", &ctx, "WPP_MAIN_CB", &out->wpp_main_cb_rva);

    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "NextGlobalMiniport",       &out->mp_next_global);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "EthDB",                    &out->mp_eth_db);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "MiniportAdapterContext",   &out->mp_adapter_ctx);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "IfBlockAvailable",         &out->mp_if_avail);
    detail::resolve_field(&ctx, "_NDIS_MINIPORT_BLOCK", "IfBlock",                  &out->mp_if_block);

    // the phys-addr pair keeps its classic names but 26100 moved them into
    // the inherited _NDIS_NSI_INTERFACE_ENUM_ROD base - the base-class walk
    // finds them; name candidates cover builds where the names drifted. on
    // total name failure identify the pair BY TYPE: the two members typed as
    // IF_PHYSICAL_ADDRESS_LH, first = current, second = permanent. unresolved
    // means offset 0 and the stage SKIPS - a stale hardcoded offset wrote 6
    // MAC bytes into wrong fields of live IF_BLOCKs and bricked NDIS (code
    // 31); skipping is always cheaper than corrupting.
    if (!detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "ifPhysAddress",       &out->ifb_cur_phys_addr) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "ifPhyAddress",        &out->ifb_cur_phys_addr) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "CurrentPhysAddress",  &out->ifb_cur_phys_addr))
        out->ifb_cur_phys_addr = 0;
    if (!detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "PermanentPhysAddress", &out->ifb_perm_phys_addr) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "PermPhysAddress",      &out->ifb_perm_phys_addr))
        out->ifb_perm_phys_addr = 0;
    if (!out->ifb_cur_phys_addr || !out->ifb_perm_phys_addr) {
        detail::type_data* pa = detail::find_struct(&ctx, "_IF_PHYSICAL_ADDRESS_LH");
        std::vector<detail::member_data> all;
        if (pa && detail::collect_members(&ctx, detail::find_struct(&ctx, "_NDIS_IF_BLOCK"),
                                          0, 0, &all)) {
            std::vector<ULONG> hits;
            for (const auto& m : all) {
                detail::type_data* mt = detail::find_type(&ctx, m.type_index);
                if (mt && (mt->kind == detail::lf_structure || mt->kind == detail::lf_class) &&
                    mt->name == pa->name)
                    hits.push_back((ULONG)m.offset);
            }
            if (!out->ifb_cur_phys_addr && !hits.empty()) {
                out->ifb_cur_phys_addr = hits[0];
                PDBLOG("[+] _NDIS_IF_BLOCK current phys addr by type = 0x%lx", out->ifb_cur_phys_addr);
            }
            if (!out->ifb_perm_phys_addr && hits.size() > 1) {
                out->ifb_perm_phys_addr = hits[1];
                PDBLOG("[+] _NDIS_IF_BLOCK permanent phys addr by type = 0x%lx", out->ifb_perm_phys_addr);
            }
        }
    }
    if (!out->ifb_cur_phys_addr)
        PDBLOG("[!] ifPhysAddress unresolved - IF_BLOCK cur patch disabled");
    if (!out->ifb_perm_phys_addr)
        PDBLOG("[!] PermanentPhysAddress unresolved - IF_BLOCK perm patch disabled");

    if (!detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "Link",              &out->ifb_family_entry) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "IfFamilyListEntry", &out->ifb_family_entry) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "ndisIfBlockList",   &out->ifb_family_entry) &&
        !detail::resolve_field(&ctx, "_NDIS_IF_BLOCK", "FamilyListEntry",   &out->ifb_family_entry))
        { out->ifb_family_entry = 0; PDBLOG("[!] IF_BLOCK family entry unresolved - family walk disabled"); }

    if (!detail::resolve_field(&ctx, "_IF_PHYSICAL_ADDRESS_LH", "Length",  &out->pa_length) ||
        !detail::resolve_field(&ctx, "_IF_PHYSICAL_ADDRESS_LH", "Address", &out->pa_address))
        { out->pa_length = 0; out->pa_address = 2; }

    if (!detail::resolve_field(&ctx, "_X_FILTER",   "AdapterAddress", &out->ethdb_adapter_addr) &&
        !detail::resolve_field(&ctx, "_ETH_FILTER", "AdapterAddress", &out->ethdb_adapter_addr))
        { out->ethdb_adapter_addr = 0; PDBLOG("[!] eth filter AdapterAddress unresolved - miniport MAC read disabled"); }

    return out->mp_next_global && out->mp_eth_db && out->miniport_list_rva;
}

inline bool resolve_tcpip(loader_offsets::tcpip_offsets* out) {
    if (!out) return false;
    *out = {};

    detail::pdb_context ctx;
    if (!detail::load_pdb_context(L"tcpip.sys", &ctx, false)) {
        PDBLOG("[-] tcpip.sys PDB load failed"); return false;
    }

    // embedded statics on current builds; TcpCompartmentSet is only a small
    // InCS context pointer there - legacy candidate for older builds.
    detail::resolve_public_symbol_rva(L"tcpip.sys", &ctx, "TcpCompartmentSet",
        &out->compartment_set_rva, true);
    const bool have_v4 = detail::resolve_public_symbol_rva(L"tcpip.sys", &ctx,
        "Ipv4Global", &out->ipv4_global_rva, true);
    const bool have_v6 = detail::resolve_public_symbol_rva(L"tcpip.sys", &ctx,
        "Ipv6Global", &out->ipv6_global_rva, true);
    if (!have_v4 && !have_v6 && !out->compartment_set_rva) {
        PDBLOG("[-] no compartment set symbol in tcpip.sys PDB"); return false;
    }

    // ---- anchored pattern derivation (tcpip PDBs are publics-only) --------
    std::vector<std::uint8_t> image;
    if (!detail::read_module_image(L"tcpip.sys", &image)) {
        PDBLOG("[-] tcpip.sys image read failed"); return false;
    }

    auto scan = [&](const char* fn) -> const std::uint8_t* {
        std::uint64_t rva = 0;
        if (!detail::resolve_public_symbol_rva(L"tcpip.sys", &ctx, fn, &rva, true)) {
            PDBLOG("[-] tcpip!%s not found in PDB", fn); return nullptr;
        }
        const auto p = detail::module_rva_to_ptr(image, rva);
        if (!p) { PDBLOG("[-] tcpip!%s rva 0x%llx outside image", fn, (unsigned long long)rva); return nullptr; }
        return p;
    };

    // build-triage aid: on a pattern miss, hexdump the anchor function into
    // the log so an exact fallback pattern can be written for that tcpip
    // build without another round trip. dump first, fail after.
    auto dump = [&](const char* fn, unsigned len) {
        std::uint64_t rva = 0;
        if (!detail::resolve_public_symbol_rva(L"tcpip.sys", &ctx, fn, &rva, true)) {
            PDBLOG("[dump] %s: unresolved", fn); return;
        }
        const auto p = detail::module_rva_to_ptr(image, rva);
        if (!p) { PDBLOG("[dump] %s: outside image", fn); return; }
        PDBLOG("[dump] %s rva=0x%llx len=0x%x:", fn, (unsigned long long)rva, len);
        for (unsigned i = 0; i < len; i += 16) {
            char line[96] = {};
            int n = snprintf(line, sizeof(line), "%04x: ", i);
            for (unsigned j = 0; j < 16 && i + j < len; ++j)
                n += snprintf(line + n, sizeof(line) - n, "%02x ", p[i + j]);
            PDBLOG("%s", line);
        }
    };

    // set layout from IppFindCompartmentById, cross-checked against
    // IppGetNextCompartment (register encodings differ between the two)
    const auto find_code = scan("IppFindCompartmentById");
    const auto next_code = scan("IppGetNextCompartment");
    if (!find_code) return false;

    ULONG count_a = 0, table_a = 0, entry_a = 0, shift = 0;
    const bool w11 =
        detail::extract_disp32(find_code, 0x140, {0x8B,0x86,-2,-1,-1,-1,0xFF,0xC8,0x8B,0xCF}, &count_a) &&
        detail::extract_disp32(find_code, 0x140, {0x48,0x03,0x86,-2,-1,-1,-1}, &table_a) &&
        detail::extract_disp8 (find_code, 0x140, {0x48,0x8D,0x59,-2}, &entry_a) &&
        detail::extract_disp8 (find_code, 0x140, {0x48,0xC1,0xE0,-2}, &shift);
    bool w10 = false;
    if (!w11) {
        // Windows 10 19045 codegen: compact bucket helper inside the same
        // function (mov r8d,[rcx+cnt]; dec r8d / shl r8,imm;
        // add r8,[rcx+tbl]; lea rax,[rcx-30h]; cmp [rax],edx). trailing
        // bytes pin each hit to the Id-compare sequence, not a random lea.
        w10 =
            detail::extract_disp8(find_code, 0x140, {0x44,0x8B,0x41,-2,0x41,0xFF,0xC8}, &count_a) &&
            detail::extract_disp8(find_code, 0x140, {0x4C,0x03,0x41,-2,0x49,0x8B,0x08}, &table_a) &&
            detail::extract_disp8(find_code, 0x140, {0x48,0x8D,0x41,-2,0x39,0x10}, &entry_a) &&
            detail::extract_disp8(find_code, 0x140, {0x49,0xC1,0xE0,-2}, &shift);
        if (w10) {
            // foreign-build sanity gates: small sane offsets only, or abort
            // exactly as before (a wrong offset here would BSOD the walk).
            if (count_a > 0x100 || table_a > 0x100 || shift > 6 ||
                (ULONG)-(std::int8_t)entry_a > 0x100)
                w10 = false;
            else
                PDBLOG("[+] tcpip set layout via Win10-19045 fallback");
        }
    }
    const bool a_ok = w11 || w10;
    // mov eax,[rsi+d]; neg eax - TableSize doubles as the hash mask, the
    // negated form still identifies the field unambiguously
    if (!a_ok) { PDBLOG("[-] IppFindCompartmentById pattern scan failed"); dump("IppFindCompartmentById", 0x200); dump("IppGetNextCompartment", 0x200); return false; }
    if (w11 && next_code) {
        ULONG count_b = 0, table_b = 0, entry_b = 0;
        const bool b_ok =
            (detail::extract_disp32(next_code, 0x1f0, {0x39,0xB7,-2,-1,-1,-1}, &count_b) ||
             detail::extract_disp32(next_code, 0x1f0, {0x8B,0xBE,-2,-1,-1,-1}, &count_b)) &&
            (detail::extract_disp32(next_code, 0x1f0, {0x4C,0x03,0xB7,-2,-1,-1,-1}, &table_b) ||
             detail::extract_disp32(next_code, 0x1f0, {0x48,0x03,0xB7,-2,-1,-1,-1}, &table_b)) &&
            (detail::extract_disp8 (next_code, 0x1f0, {0x41,0x39,0x47,-2}, &entry_b) ||
             detail::extract_disp8 (next_code, 0x1f0, {0x49,0x8D,0x77,-2}, &entry_b));
        // both lea forms are "entry = link - disp" - same convention, so a
        // straight byte comparison is the correct agreement test
        if (b_ok && (count_b != count_a || table_b != table_a ||
                     (std::int8_t)entry_b != (std::int8_t)entry_a)) {
            PDBLOG("[-] compartment set layout cross-check failed (find vs next disagree)");
            return false;
        }
        if (b_ok) PDBLOG("[+] tcpip set layout cross-checked against IppGetNextCompartment");
    }

    out->cs_count         = count_a;
    out->cs_table         = table_a;
    out->cs_entry_offset  = (ULONG)-(std::int8_t)entry_a;  // lea reg,[link-0x30]
    out->cs_bucket_stride = 1u << (shift ? shift : 4);
    if (!out->cs_bucket_stride || out->cs_bucket_stride > 64) out->cs_bucket_stride = 16;

    // interface list on the compartment: head + back-offset.
    // primary anchor (Win11) with 19045 fallback anchors probed in order.
    ULONG if_list = 0, if_link_raw = 0;
    bool if_layout_ok = false;

    // LEA patterns shared across all three anchor functions.
    // head-LEA: lea rXX,[compartment_reg+head_off]  REX.R=4C/4D, mod=10b.
    static const std::vector<int> k_if_head_pats[] = {
        {0x4C,0x8D,0x8B,-2,-1,-1,-1,0x4D,0x8B},  // lea r9,[rbx+d32]  Win11 primary (pinned)
        {0x4C,0x8D,0xB3,-2,-1,-1,-1},              // lea r14,[rbx+d32]
        {0x4C,0x8D,0x87,-2,-1,-1,-1},              // lea r8,[rdi+d32]
        {0x4C,0x8D,0x8F,-2,-1,-1,-1},              // lea r9,[rdi+d32]
        {0x4C,0x8D,0x97,-2,-1,-1,-1},              // lea r10,[rdi+d32]
        {0x4C,0x8D,0x9F,-2,-1,-1,-1},              // lea r11,[rdi+d32]
        {0x4C,0x8D,0xA7,-2,-1,-1,-1},              // lea r12,[rdi+d32]
        {0x4C,0x8D,0xAF,-2,-1,-1,-1},              // lea r13,[rdi+d32]
        {0x4C,0x8D,0xB7,-2,-1,-1,-1},              // lea r14,[rdi+d32]
        {0x4C,0x8D,0xBF,-2,-1,-1,-1},              // lea r15,[rdi+d32]
        {0x4C,0x8D,0x81,-2,-1,-1,-1},              // lea r8,[rcx+d32]
        {0x4C,0x8D,0x89,-2,-1,-1,-1},              // lea r9,[rcx+d32]
        {0x4C,0x8D,0x91,-2,-1,-1,-1},              // lea r10,[rcx+d32]
        {0x4C,0x8D,0x99,-2,-1,-1,-1},              // lea r11,[rcx+d32]
        {0x4C,0x8D,0xA1,-2,-1,-1,-1},              // lea r12,[rcx+d32]
        {0x4C,0x8D,0xA9,-2,-1,-1,-1},              // lea r13,[rcx+d32]
        {0x4C,0x8D,0xB1,-2,-1,-1,-1},              // lea r14,[rcx+d32]  19045 hypothesis
        {0x4C,0x8D,0xB9,-2,-1,-1,-1},              // lea r15,[rcx+d32]
        {0x4D,0x8D,0x80,-2,-1,-1,-1},              // lea r8,[r8+d32]
        {0x4D,0x8D,0x88,-2,-1,-1,-1},              // lea r9,[r8+d32]
        {0x4D,0x8D,0xB0,-2,-1,-1,-1},              // lea r14,[r8+d32]
        {0x4D,0x8D,0xB8,-2,-1,-1,-1},              // lea r15,[r8+d32]
    };
    // link-back LEA: lea reg,[entry_reg+link_raw]  where link_raw is negative disp32.
    static const std::vector<int> k_if_link_pats[] = {
        {0x49,0x8D,0x98,-2,-1,-1,-1},  // lea rbx,[r8+d32]
        {0x49,0x8D,0xB8,-2,-1,-1,-1},  // lea rdi,[r8+d32]
        {0x48,0x8D,0x9F,-2,-1,-1,-1},  // lea rbx,[rdi+d32]
        {0x48,0x8D,0x9E,-2,-1,-1,-1},  // lea rbx,[rsi+d32]
        {0x48,0x8D,0x9B,-2,-1,-1,-1},  // lea rbx,[rbx+d32]
        {0x48,0x8D,0x98,-2,-1,-1,-1},  // lea rbx,[rax+d32]
        {0x48,0x8D,0x99,-2,-1,-1,-1},  // lea rbx,[rcx+d32]
        {0x48,0x8D,0x9A,-2,-1,-1,-1},  // lea rbx,[rdx+d32]
        {0x4C,0x8D,0xB3,-2,-1,-1,-1},  // lea r14,[rbx+d32]
        {0x4C,0x8D,0xB7,-2,-1,-1,-1},  // lea r14,[rdi+d32]
        {0x4D,0x8D,0xB0,-2,-1,-1,-1},  // lea r14,[r8+d32]
        {0x4D,0x8D,0xB8,-2,-1,-1,-1},  // lea r15,[r8+d32]
    };

    if (const auto luid_code = scan("IppFindInterfaceInCompartmentByLuid")) {
        for (const auto& hp : k_if_head_pats) {
            if (detail::extract_disp32(luid_code, 0x100, hp, &if_list)) break;
        }
        for (const auto& lp : k_if_link_pats) {
            if (detail::extract_disp32(luid_code, 0x100, lp, &if_link_raw)) break;
        }
        if_layout_ok = if_list && if_link_raw;
        if (!if_layout_ok) {
            PDBLOG("[-] IppFindInterfaceInCompartmentByLuid pattern scan failed");
            dump("IppFindInterfaceInCompartmentByLuid", 0x200);
        }
    } else {
        PDBLOG("[~] IppFindInterfaceInCompartmentByLuid absent, trying fallbacks");
    }
    if (!if_layout_ok) {
        // 19045 fallback: IppGetNextInterfaceOnCompartment does an inline
        // LIST_ENTRY walk of the compartment's interface list.
        // The function loads the list head as:  lea rXX,[compartment+head]
        // then walks: lea rYY,[entry_ptr-link_off]
        // Compartment arrives in rcx (first arg); head >= 0x80 so always disp32.
        // link_off = distance from LIST_ENTRY link to the start of FL_INTERFACE;
        // on 19045 this is typically 0xA0 (head) and 0xB0 (link).
        if (const auto nextif_code = scan("IppGetNextInterfaceOnCompartment")) {
            ULONG w10_list = 0, w10_link_raw = 0;
            // Try every plausible head-LEA encoding.
            for (const auto& hp : k_if_head_pats) {
                if (detail::extract_disp32(nextif_code, 0x140, hp, &w10_list)) break;
            }
            // Try every plausible link-LEA encoding.
            for (const auto& lp : k_if_link_pats) {
                if (detail::extract_disp32(nextif_code, 0x140, lp, &w10_link_raw)) break;
            }
            if (w10_list && w10_link_raw) {
                const ULONG w10_link = (ULONG)-(std::int32_t)w10_link_raw;
                // plausibility: both offsets < 0x2000, link > 0 after negation
                if (w10_list <= 0x2000 && w10_link <= 0x2000) {
                    if_list = w10_list;
                    if_link_raw = w10_link_raw;
                    if_layout_ok = true;
                    PDBLOG("[+] tcpip if-list via IppGetNextInterfaceOnCompartment (19045)");
                } else {
                    PDBLOG("[-] IppGetNextInterfaceOnCompartment values implausible (list=0x%lx link=0x%lx)",
                        w10_list, w10_link);
                }
            }
            if (!if_layout_ok) {
                PDBLOG("[~] IppGetNextInterfaceOnCompartment: pattern miss - need dump");
                dump("IppGetNextInterfaceOnCompartment", 0x200);
                dump("IppFindInterfaceByLuid", 0x200);
                dump("IppGetNextInterface", 0x200);
            }
        }
    }
    // tertiary: IppFindInterfaceByLuid (NOT ByLuid-in-compartment) -
    // present on 19045, walks a global interface table, but the head/link
    // offsets in the FL_INTERFACE struct are the same ones we need.
    if (!if_layout_ok) {
        if (const auto ifl_code = scan("IppFindInterfaceByLuid")) {
            ULONG t_list = 0, t_link_raw = 0;
            for (const auto& hp : k_if_head_pats) {
                if (detail::extract_disp32(ifl_code, 0x140, hp, &t_list)) break;
            }
            for (const auto& lp : k_if_link_pats) {
                if (detail::extract_disp32(ifl_code, 0x140, lp, &t_link_raw)) break;
            }
            if (t_list && t_link_raw) {
                const ULONG t_link = (ULONG)-(std::int32_t)t_link_raw;
                if (t_list <= 0x2000 && t_link <= 0x2000) {
                    // NOTE: IppFindInterfaceByLuid uses a *global* interface
                    // list, not the per-compartment one. The list head and link
                    // offsets in FL_INTERFACE itself are the same, so
                    // if_compartment_link is valid.  if_list here points into
                    // the global, NOT the compartment — caller must be aware.
                    if_list = t_list;
                    if_link_raw = t_link_raw;
                    if_layout_ok = true;
                    PDBLOG("[+] tcpip if-list via IppFindInterfaceByLuid (tertiary, global-list offsets)");
                } else {
                    PDBLOG("[-] IppFindInterfaceByLuid values implausible (list=0x%lx link=0x%lx)",
                        t_list, t_link);
                    dump("IppFindInterfaceByLuid", 0x200);
                }
            } else {
                dump("IppFindInterfaceByLuid", 0x200);
            }
        }
    }
    if (!if_layout_ok) {
        PDBLOG("[-] interface-list layout unresolved"); return false;
    }
    out->compartment_if_list = if_list;
    out->if_compartment_link = (ULONG)-(std::int32_t)if_link_raw;  // lea rXX,[entry-link_off]

    // interface own MAC + per-interface neighbor tables
    const auto nbnext_code = scan("IppGetNextNeighborOnInterface");
    const auto ins_code   = scan("IppInsertNeighbor");
    if (!nbnext_code) return false;
    ULONG nb_table = 0, nb_list = 0, nb_entry = 0;
    // Win11 primary: mov rdi,[rcx+nb_table] = 48 8B B9; list head = 4C 8D 71 (disp8);
    // entry back-offset = 48 8D 70 (disp8, negative -> entry = link - off)
    // 19045 fallback: the neighbor table pointer may be in a different
    // src register (rax/rdx/rbx/rsi/rdi/r8-r15).  Try the most common MOV
    // encodings. list-head and entry LEAs are disp8 forms on all observed
    // 19045 builds (offsets < 0x80 from base reg).
    const bool nbnext_w11 =
        detail::extract_disp32(nbnext_code, 0x1d0, {0x48,0x8B,0xB9,-2,-1,-1,-1}, &nb_table) &&
        detail::extract_disp8 (nbnext_code, 0x1d0, {0x4C,0x8D,0x71,-2}, &nb_list) &&
        detail::extract_disp8 (nbnext_code, 0x1d0, {0x48,0x8D,0x70,-2}, &nb_entry);
    if (!nbnext_w11) {
        // 19045: nb_table pointer is a disp32 MOV off whichever reg holds
        // the FL_INTERFACE*; try all 64-bit MOV [reg+disp32] encodings
        // (REX.W=1, opcode 8B, ModRM mod=10b).  For each source register:
        //   rcx=0x89, rdx=0x8A, rbx=0x8B, rsp=skip, rbp=0x8D(with SIB),
        //   rsi=0x8E, rdi=0x8F,
        //   REX.B: r8=49 8B 80..  r9=49 8B 88..  r13=49 8B A8..  r15=49 8B B8..
        static const std::vector<int> k_nbtbl[] = {
            {0x48,0x8B,0x81,-2,-1,-1,-1},  // mov rax,[rcx+d32]
            {0x48,0x8B,0x82,-2,-1,-1,-1},  // mov rax,[rdx+d32]
            {0x48,0x8B,0x83,-2,-1,-1,-1},  // mov rax,[rbx+d32]
            {0x48,0x8B,0x86,-2,-1,-1,-1},  // mov rax,[rsi+d32]
            {0x48,0x8B,0x87,-2,-1,-1,-1},  // mov rax,[rdi+d32]
            {0x48,0x8B,0xB1,-2,-1,-1,-1},  // mov rsi,[rcx+d32]
            {0x48,0x8B,0xB2,-2,-1,-1,-1},  // mov rsi,[rdx+d32]
            {0x48,0x8B,0xB3,-2,-1,-1,-1},  // mov rsi,[rbx+d32]
            {0x48,0x8B,0xB6,-2,-1,-1,-1},  // mov rsi,[rsi+d32]
            {0x48,0x8B,0xB7,-2,-1,-1,-1},  // mov rsi,[rdi+d32]
            {0x48,0x8B,0xBF,-2,-1,-1,-1},  // mov rdi,[rdi+d32]
            {0x48,0x8B,0xBE,-2,-1,-1,-1},  // mov rdi,[rsi+d32]
            {0x49,0x8B,0x80,-2,-1,-1,-1},  // mov rax,[r8+d32]
            {0x49,0x8B,0x81,-2,-1,-1,-1},  // mov rax,[r9+d32]
            {0x49,0x8B,0xB8,-2,-1,-1,-1},  // mov rdi,[r8+d32]
            {0x49,0x8B,0xB9,-2,-1,-1,-1},  // mov rdi,[r9+d32]
            {0x4C,0x8B,0xB9,-2,-1,-1,-1},  // mov r15,[rcx+d32]
            {0x4C,0x8B,0xBF,-2,-1,-1,-1},  // mov r15,[rdi+d32]
            {0x4C,0x8B,0xBE,-2,-1,-1,-1},  // mov r15,[rsi+d32]
        };
        for (const auto& p : k_nbtbl) {
            if (detail::extract_disp32(nbnext_code, 0x1d0, p, &nb_table)) break;
        }
        // list head LEA: lea r8/r9.../rax/rbx,[nb_table_base+disp8]
        // All disp8 forms: REX.R=4C or 4D (ext dst), opcode 8D, mod=01b
        static const std::vector<int> k_nblist[] = {
            {0x4C,0x8D,0x71,-2},   // lea r14,[rcx+d8]  Win11
            {0x4C,0x8D,0x70,-2},   // lea r14,[rax+d8]
            {0x4C,0x8D,0x72,-2},   // lea r14,[rdx+d8]
            {0x4C,0x8D,0x73,-2},   // lea r14,[rbx+d8]
            {0x4C,0x8D,0x76,-2},   // lea r14,[rsi+d8]
            {0x4C,0x8D,0x77,-2},   // lea r14,[rdi+d8]
            {0x4C,0x8D,0x61,-2},   // lea r12,[rcx+d8]
            {0x4C,0x8D,0x67,-2},   // lea r12,[rdi+d8]
            {0x4C,0x8D,0x41,-2},   // lea r8,[rcx+d8]
            {0x4C,0x8D,0x47,-2},   // lea r8,[rdi+d8]
            {0x4D,0x8D,0x40,-2},   // lea r8,[r8+d8]
            {0x4D,0x8D,0x48,-2},   // lea r9,[r8+d8]
            {0x48,0x8D,0x70,-2},   // lea rsi,[rax+d8]
            {0x48,0x8D,0x71,-2},   // lea rsi,[rcx+d8]
            {0x48,0x8D,0x77,-2},   // lea rsi,[rdi+d8]
        };
        static const std::vector<int> k_nbentry[] = {
            {0x48,0x8D,0x70,-2},   // lea rsi,[rax+d8]  Win11
            {0x48,0x8D,0x71,-2},   // lea rsi,[rcx+d8]
            {0x48,0x8D,0x77,-2},   // lea rsi,[rdi+d8]
            {0x48,0x8D,0x78,-2},   // lea rdi,[rax+d8]
            {0x48,0x8D,0x79,-2},   // lea rdi,[rcx+d8]
            {0x48,0x8D,0x7F,-2},   // lea rdi,[rdi+d8]
            {0x48,0x8D,0x5F,-2},   // lea rbx,[rdi+d8]
            {0x48,0x8D,0x58,-2},   // lea rbx,[rax+d8]
            {0x48,0x8D,0x59,-2},   // lea rbx,[rcx+d8]
            {0x4C,0x8D,0x70,-2},   // lea r14,[rax+d8]
            {0x4C,0x8D,0x77,-2},   // lea r14,[rdi+d8]
            {0x4D,0x8D,0x70,-2},   // lea r14,[r8+d8]
        };
        if (!nb_table) {
            PDBLOG("[-] IppGetNextNeighborOnInterface nb_table pattern scan failed");
            dump("IppGetNextNeighborOnInterface", 0x280);
            return false;
        }
        for (const auto& p : k_nblist)  { if (detail::extract_disp8(nbnext_code, 0x1d0, p, &nb_list))  break; }
        for (const auto& p : k_nbentry) { if (detail::extract_disp8(nbnext_code, 0x1d0, p, &nb_entry)) break; }
        if (!nb_list || !nb_entry) {
            PDBLOG("[-] IppGetNextNeighborOnInterface list/entry pattern scan failed (nb_list=0x%lx nb_entry=0x%lx)",
                nb_list, nb_entry);
            dump("IppGetNextNeighborOnInterface", 0x280);
            return false;
        }
        PDBLOG("[+] IppGetNextNeighborOnInterface via 19045 fallback patterns");
    }
    // plausibility gates:
    // nb_table: intra-struct pointer offset — must be < 0x4000
    // nb_list:  list head offset WITHIN the neighbor table — disp8, must be < 0x80
    // nb_entry: raw signed disp8 — value >= 0x80 means a NEGATIVE displacement
    //           (e.g. 0xD8 = -0x28, back-offset = 0x28). Gate on the negated value.
    const ULONG nb_entry_back = (ULONG)-(std::int8_t)(std::uint8_t)nb_entry;
    if (nb_table > 0x4000 || nb_list >= 0x80 || nb_entry_back == 0 || nb_entry_back > 0x200) {
        PDBLOG("[-] IppGetNextNeighborOnInterface implausible values (tbl=0x%lx list=0x%x entry_raw=0x%x back=0x%lx)",
            nb_table, nb_list, nb_entry, nb_entry_back);
        dump("IppGetNextNeighborOnInterface", 0x280);
        return false;
    }
    out->if_nb_table           = nb_table;
    out->nb_table_list_head    = nb_list;
    out->nb_table_entry_offset = nb_entry_back;  // -(int8_t)raw → positive back-offset

    // interface link-layer address chain - the neighbor walk and the
    // neighbor-parameter fill read the same chain with different register
    // allocations, a free cross-check:
    //   p1 = [iface+0];  p2 = [p1+X];  blk = [p2+Y];  len = blk+Z (USHORT)
    // (an earlier revision mistook a spinlock lea for an inline DlPhysAddr -
    // the guard caught it)
    {
        ULONG p2 = 0, cur = 0, len = 0;
        // Win11 primary
        const bool dl_w11 =
            detail::extract_disp8(nbnext_code, 0x1d0, {0x4C,0x8B,0x48,-2}, &p2) &&
            detail::extract_disp8(nbnext_code, 0x1d0, {0x49,0x8B,0x41,-2}, &cur) &&
            detail::extract_disp8(nbnext_code, 0x1d0, {0x0F,0xB7,0x40,-2}, &len);
        if (!dl_w11) {
            // 19045: p2 load uses a different source/dest register pair.
            // Shape: mov rXX,[iface_reg+p2_off] where iface is at [neighbor+nb_if]
            // and p2_off is a disp8 (< 0x80).  Try all plausible combos.
            static const std::vector<int> k_p2[] = {
                {0x4C,0x8B,0x48,-2},  // mov r9,[rax+d8]    Win11
                {0x4C,0x8B,0x41,-2},  // mov r8,[rcx+d8]
                {0x4C,0x8B,0x43,-2},  // mov r8,[rbx+d8]
                {0x4C,0x8B,0x46,-2},  // mov r8,[rsi+d8]
                {0x4C,0x8B,0x47,-2},  // mov r8,[rdi+d8]
                {0x4C,0x8B,0x50,-2},  // mov r10,[rax+d8]
                {0x4C,0x8B,0x51,-2},  // mov r10,[rcx+d8]
                {0x4C,0x8B,0x57,-2},  // mov r10,[rdi+d8]
                {0x48,0x8B,0x40,-2},  // mov rax,[rax+d8]
                {0x48,0x8B,0x41,-2},  // mov rax,[rcx+d8]
                {0x48,0x8B,0x43,-2},  // mov rax,[rbx+d8]
                {0x48,0x8B,0x46,-2},  // mov rax,[rsi+d8]
                {0x48,0x8B,0x47,-2},  // mov rax,[rdi+d8]
            };
            static const std::vector<int> k_cur[] = {
                {0x49,0x8B,0x41,-2},  // mov rax,[r9+d8]    Win11
                {0x49,0x8B,0x40,-2},  // mov rax,[r8+d8]
                {0x49,0x8B,0x42,-2},  // mov rax,[r10+d8]
                {0x48,0x8B,0x40,-2},  // mov rax,[rax+d8]
                {0x48,0x8B,0x41,-2},  // mov rax,[rcx+d8]
                {0x48,0x8B,0x46,-2},  // mov rax,[rsi+d8]
                {0x48,0x8B,0x47,-2},  // mov rax,[rdi+d8]
            };
            static const std::vector<int> k_len[] = {
                {0x0F,0xB7,0x40,-2},  // movzx eax,word[rax+d8]  Win11
                {0x0F,0xB7,0x41,-2},  // movzx eax,word[rcx+d8]
                {0x0F,0xB7,0x43,-2},  // movzx eax,word[rbx+d8]
                {0x0F,0xB7,0x46,-2},  // movzx eax,word[rsi+d8]
                {0x0F,0xB7,0x47,-2},  // movzx eax,word[rdi+d8]
                {0x44,0x0F,0xB7,0x40,-2},  // movzx r8d,word[rax+d8]
                {0x44,0x0F,0xB7,0x41,-2},  // movzx r8d,word[rcx+d8]
                {0x44,0x0F,0xB7,0x47,-2},  // movzx r8d,word[rdi+d8]
            };
            for (const auto& pp : k_p2)  { if (detail::extract_disp8(nbnext_code, 0x1d0, pp, &p2))  break; }
            for (const auto& pp : k_cur) { if (detail::extract_disp8(nbnext_code, 0x1d0, pp, &cur)) break; }
            for (const auto& pp : k_len) { if (detail::extract_disp8(nbnext_code, 0x1d0, pp, &len)) break; }
            if (!p2 || !cur) {
                PDBLOG("[-] FL_INTERFACE DlPhysAddr chain derivation failed (p2=0x%x cur=0x%x len=0x%x)",
                    p2, cur, len);
                dump("IppGetNextNeighborOnInterface", 0x280);
                dump("IppFillNeighborParametersUnderLock", 0x200);
                return false;
            }
            PDBLOG("[+] DlPhysAddr chain via 19045 fallback patterns");
        }
        if (const auto fill_code = scan("IppFillNeighborParametersUnderLock")) {
            ULONG p2b = 0, curb = 0, lenb = 0;
            // Win11 primary cross-check + 19045 alternatives
            const bool b_p2  = detail::extract_disp8(fill_code, 0x140, {0x4C,0x8B,0x50,-2}, &p2b) ||
                               detail::extract_disp8(fill_code, 0x140, {0x4C,0x8B,0x48,-2}, &p2b) ||
                               detail::extract_disp8(fill_code, 0x140, {0x4C,0x8B,0x41,-2}, &p2b) ||
                               detail::extract_disp8(fill_code, 0x140, {0x4C,0x8B,0x47,-2}, &p2b) ||
                               detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x40,-2}, &p2b) ||
                               detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x41,-2}, &p2b) ||
                               detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x47,-2}, &p2b);
            const bool b_cur = detail::extract_disp8(fill_code, 0x140, {0x49,0x8B,0x42,-2}, &curb) ||
                               detail::extract_disp8(fill_code, 0x140, {0x49,0x8B,0x40,-2}, &curb) ||
                               detail::extract_disp8(fill_code, 0x140, {0x49,0x8B,0x41,-2}, &curb) ||
                               detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x40,-2}, &curb) ||
                               detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x41,-2}, &curb);
            const bool b_len = detail::extract_disp8(fill_code, 0x140, {0x44,0x0F,0xB7,0x50,-2}, &lenb) ||
                               detail::extract_disp8(fill_code, 0x140, {0x44,0x0F,0xB7,0x40,-2}, &lenb) ||
                               detail::extract_disp8(fill_code, 0x140, {0x0F,0xB7,0x40,-2}, &lenb)   ||
                               detail::extract_disp8(fill_code, 0x140, {0x0F,0xB7,0x41,-2}, &lenb)   ||
                               detail::extract_disp8(fill_code, 0x140, {0x0F,0xB7,0x47,-2}, &lenb);
            const bool b_ok = b_p2 && b_cur && b_len;
            if (b_ok && (p2b != p2 || curb != cur || lenb != len)) {
                PDBLOG("[-] DlPhysAddr chain cross-check failed (walk vs fill disagree: p2=%x/%x cur=%x/%x len=%x/%x)",
                    p2, p2b, cur, curb, len, lenb);
                return false;
            }
            if (b_ok) PDBLOG("[+] DlPhysAddr chain cross-checked against IppFillNeighborParametersUnderLock");
        }
        out->dl_p2_off = p2;
        out->dl_cur_off = cur;
        out->dl_len_off = len;
    }
    // permanent-address twin: IppRegenerateLinkLayerSuffixAddresses prefetches
    // the second address block off the same p2 - optional, 0 when unresolvable
    if (const auto regen_code = scan("IppRegenerateLinkLayerSuffixAddresses")) {
        ULONG perm = 0;
        if ((detail::extract_disp8(regen_code, 0x200, {0x48,0x8B,0x42,-2}, &perm) ||
             detail::extract_disp8(regen_code, 0x200, {0x48,0x8B,0x40,-2}, &perm) ||
             detail::extract_disp8(regen_code, 0x200, {0x48,0x8B,0x41,-2}, &perm) ||
             detail::extract_disp8(regen_code, 0x200, {0x48,0x8B,0x47,-2}, &perm)) &&
            perm != out->dl_cur_off)
            out->dl_perm_off = perm;
    }
    if (ins_code) {
        ULONG nb_table2 = 0;
        if (detail::extract_disp32(ins_code, 0x1d0, {0x49,0x8D,0xBE,-2,-1,-1,-1}, &nb_table2) ||
            detail::extract_disp32(ins_code, 0x1d0, {0x48,0x8D,0xBE,-2,-1,-1,-1}, &nb_table2) ||
            detail::extract_disp32(ins_code, 0x1d0, {0x48,0x8D,0xB9,-2,-1,-1,-1}, &nb_table2) ||
            detail::extract_disp32(ins_code, 0x1d0, {0x49,0x8D,0xB9,-2,-1,-1,-1}, &nb_table2) ||
            detail::extract_disp32(ins_code, 0x1d0, {0x48,0x8D,0xB7,-2,-1,-1,-1}, &nb_table2))
            out->if_nb_table_alt = nb_table2;
    }

    // neighbor entry fields
    const auto fill_code = scan("IppFillNeighborParametersUnderLock");
    if (!fill_code) return false;
    // nb_interface: back-ptr to FL_INTERFACE in the neighbor object.
    // Win11: mov rbx,[rax+nb_if]  = 48 8B 59
    // 19045: same field, different register for both source and destination.
    if (!detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x59,-2}, &out->nb_interface) &&
        !detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x57,-2}, &out->nb_interface) &&
        !detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x58,-2}, &out->nb_interface) &&
        !detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x50,-2}, &out->nb_interface) &&
        !detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x51,-2}, &out->nb_interface) &&
        !detail::extract_disp8(fill_code, 0x140, {0x48,0x8B,0x52,-2}, &out->nb_interface) &&
        !detail::extract_disp8(fill_code, 0x140, {0x4C,0x8B,0x59,-2}, &out->nb_interface) &&
        !detail::extract_disp8(fill_code, 0x140, {0x4C,0x8B,0x57,-2}, &out->nb_interface)) {
        PDBLOG("[-] IppFillNeighborParametersUnderLock nb_interface scan failed");
        dump("IppFillNeighborParametersUnderLock", 0x200);
        return false;
    }
    // nb_dl_address: ptr to DL address block inside the neighbor.
    // Win11: lea r10,[rcx+d32]  = 49 8D 93
    // 19045: lea rXX,[rYY+d32] — try all REX.R/REX.B combinations with mod=10b.
    if (!detail::extract_disp32(fill_code, 0x140, {0x49,0x8D,0x93,-2,-1,-1,-1}, &out->nb_dl_address) &&
        !detail::extract_disp32(fill_code, 0x140, {0x48,0x8D,0x91,-2,-1,-1,-1}, &out->nb_dl_address) &&
        !detail::extract_disp32(fill_code, 0x140, {0x48,0x8D,0x90,-2,-1,-1,-1}, &out->nb_dl_address) &&
        !detail::extract_disp32(fill_code, 0x140, {0x48,0x8D,0x97,-2,-1,-1,-1}, &out->nb_dl_address) &&
        !detail::extract_disp32(fill_code, 0x140, {0x49,0x8D,0x90,-2,-1,-1,-1}, &out->nb_dl_address) &&
        !detail::extract_disp32(fill_code, 0x140, {0x49,0x8D,0x91,-2,-1,-1,-1}, &out->nb_dl_address) &&
        !detail::extract_disp32(fill_code, 0x140, {0x49,0x8D,0x92,-2,-1,-1,-1}, &out->nb_dl_address) &&
        !detail::extract_disp32(fill_code, 0x140, {0x4C,0x8D,0x81,-2,-1,-1,-1}, &out->nb_dl_address) &&
        !detail::extract_disp32(fill_code, 0x140, {0x4C,0x8D,0x91,-2,-1,-1,-1}, &out->nb_dl_address)) {
        PDBLOG("[-] IppFillNeighborParametersUnderLock nb_dl_address scan failed");
        dump("IppFillNeighborParametersUnderLock", 0x200);
        return false;
    }
    // plausibility: nb_interface < 0x80 (disp8 field), nb_dl_address in [0x10, 0x4000)
    if (out->nb_interface >= 0x80 || out->nb_dl_address < 0x10 || out->nb_dl_address > 0x4000) {
        PDBLOG("[-] IppFillNeighborParametersUnderLock implausible (if=0x%x dl=0x%x)",
            out->nb_interface, out->nb_dl_address);
        dump("IppFillNeighborParametersUnderLock", 0x200);
        return false;
    }

    // nb_state: the state ULONG written by the neighbor state update function.
    // IppUpdateNeighborState exists on Win11 but is absent / merged on Win10 19045.
    // Cascade: primary symbol → Win10 alternative names → state-read pattern in
    // fill_code → soft-fail with nb_state=0 (state write skipped in spoof stage).
    {
        // All known public names across Win10/Win11 builds that write the
        // NL_NEIGHBOR_STATE field.  Short functions (< 0x80 bytes), the state
        // write is the first dword store on the neighbor object arg.
        static const char* const k_state_syms[] = {
            "IppUpdateNeighborState",         // Win11 primary
            "IppSetNeighborUnreachable",       // Win10 alternative
            "IppSetNeighborReachable",         // Win10 alternative
            "IppConfirmNeighborReachability",  // Win10 reachability confirm path
            "IppHandleReachabilityTimeout",    // Win10 NUD timeout handler
            "IppSetNudState",                  // internal NUD helper (some builds)
            nullptr
        };
        // All plausible MOV [reg+d8],r32 encodings for a state write < 0x80 bytes in.
        auto try_state_syms = [&]() -> bool {
            for (int si = 0; k_state_syms[si]; ++si) {
                const auto st_code = scan(k_state_syms[si]);
                if (!st_code) continue;
                PDBLOG("[+] trying nb_state from %s", k_state_syms[si]);
                const bool hit =
                    detail::extract_disp8(st_code, 0x80, {0x89,0x5F,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x47,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x57,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x4F,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x41,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x42,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x43,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x46,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x4E,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x89,0x5E,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x44,0x89,0x47,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x44,0x89,0x41,-2}, &out->nb_state) ||
                    detail::extract_disp8(st_code, 0x80, {0x44,0x89,0x46,-2}, &out->nb_state);
                if (hit && out->nb_state < 0x80) return true;
                out->nb_state = 0;
            }
            return false;
        };

        if (!try_state_syms()) {
            // Fallback: derive the state offset from IppFillNeighborParametersUnderLock.
            // That function reads the state DWORD near the top to choose which DL
            // address block to copy.  The neighbor is passed in rcx (first arg);
            // state is loaded as mov eax,[rcx+state_off] and immediately compared
            // against a small enum constant (1-8 on all observed builds).
            // Pattern: 8B 41 XX  83 F8 NN  where XX < 0x80 and NN <= 8.
            ULONG st_from_fill = 0;
            bool fill_state_ok = false;
            if (fill_code) {
                for (std::size_t i = 0; i + 5 < 0x140; ++i) {
                    // mov eax,[rcx+d8]  = 8B 41 XX (XX < 0x80, positive offset)
                    if (fill_code[i] != 0x8B || fill_code[i+1] != 0x41) continue;
                    const std::uint8_t d8 = fill_code[i+2];
                    if (d8 >= 0x80) continue;  // negative disp — not a forward field
                    // must be followed by cmp eax, small_const  = 83 F8 NN (NN <= 8)
                    if (i + 5 >= 0x140) break;
                    if (fill_code[i+3] != 0x83 || fill_code[i+4] != 0xF8) continue;
                    const std::uint8_t cst = fill_code[i+5];
                    if (cst < 1 || cst > 8) continue;
                    st_from_fill = d8;
                    fill_state_ok = true;
                    PDBLOG("[+] nb_state derived from IppFillNeighborParametersUnderLock read pattern (off=0x%lx cmp=%u)",
                        st_from_fill, (unsigned)cst);
                    break;
                }
            }
            if (fill_state_ok) {
                out->nb_state = st_from_fill;
            } else {
                // nb_state not resolvable on this build (inlined / stripped).
                // State write is skipped during the spoof — neighbor re-probes
                // naturally via ARP/NDP after MAC is overwritten.  Non-fatal.
                out->nb_state = 0;
                PDBLOG("[!] nb_state unresolved — neighbor state write will be skipped");
            }
        }
        if (out->nb_state) PDBLOG("[+] tcpip nb_state=0x%x", out->nb_state);
    }

    // nb_refcount: the LONG field decremented atomically by IppDereferenceNeighbor.
    // Win11: lock xadd [rcx+d8],rax  = F0 48 0F C1 41
    // 19045: same sequence, base register may differ (rcx/rdx/rbx/rsi/rdi/r8-r15).
    {
        const auto deref_code = scan("IppDereferenceNeighbor");
        if (!deref_code) {
            PDBLOG("[-] IppDereferenceNeighbor not found in PDB");
            dump("IppDereferenceNeighbor", 0xA0);
            return false;
        }
        // LOCK XADD [reg+d8], rax/rbx/rcx...
        // F0 REX.W(48) 0F C1 ModRM(mod=01,rm=reg) disp8
        // ModRM for [rcx+d8]=0x41 [rdx+d8]=0x42 [rbx+d8]=0x43 [rsi+d8]=0x46 [rdi+d8]=0x47
        // REX.B extended base: F0 49 0F C1 [r8+d8]=0x40  [r9+d8]=0x41  [r15+d8]=0x47
        const bool ref_ok =
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x48,0x0F,0xC1,0x41,-2}, &out->nb_refcount) ||  // [rcx]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x48,0x0F,0xC1,0x42,-2}, &out->nb_refcount) ||  // [rdx]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x48,0x0F,0xC1,0x43,-2}, &out->nb_refcount) ||  // [rbx]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x48,0x0F,0xC1,0x46,-2}, &out->nb_refcount) ||  // [rsi]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x48,0x0F,0xC1,0x47,-2}, &out->nb_refcount) ||  // [rdi]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x49,0x0F,0xC1,0x40,-2}, &out->nb_refcount) ||  // [r8]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x49,0x0F,0xC1,0x41,-2}, &out->nb_refcount) ||  // [r9]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x49,0x0F,0xC1,0x42,-2}, &out->nb_refcount) ||  // [r10]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x49,0x0F,0xC1,0x43,-2}, &out->nb_refcount) ||  // [r11]
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x49,0x0F,0xC1,0x44,-2}, &out->nb_refcount) ||  // [r12] SIB follows
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x49,0x0F,0xC1,0x47,-2}, &out->nb_refcount) ||  // [r15]
            // 32-bit XADD (refcount is LONG not LONGLONG) — no REX prefix.
            // 19045 IppDereferenceNeighbor: mov rdx,rcx then lock xadd [rdx+0x04],eax
            // → F0 0F C1 42 04.  Enumerate all non-SIB, non-REX rm encodings.
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x0F,0xC1,0x40,-2}, &out->nb_refcount) ||  // [rax] no REX
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x0F,0xC1,0x41,-2}, &out->nb_refcount) ||  // [rcx] no REX
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x0F,0xC1,0x42,-2}, &out->nb_refcount) ||  // [rdx] no REX ← 19045
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x0F,0xC1,0x43,-2}, &out->nb_refcount) ||  // [rbx] no REX
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x0F,0xC1,0x46,-2}, &out->nb_refcount) ||  // [rsi] no REX
            detail::extract_disp8(deref_code, 0xA0, {0xF0,0x0F,0xC1,0x47,-2}, &out->nb_refcount);    // [rdi] no REX
        if (!ref_ok || out->nb_refcount >= 0x80) {
            PDBLOG("[-] IppDereferenceNeighbor pattern scan failed (ref=0x%x)", out->nb_refcount);
            dump("IppDereferenceNeighbor", 0xA0);
            return false;
        }
    }

    PDBLOG("[+] tcpip: cs_count=0x%lx cs_table=0x%lx cs_entry=0x%lx stride=%lu if_list=0x%lx if_link=0x%lx",
        out->cs_count, out->cs_table, out->cs_entry_offset, out->cs_bucket_stride,
        out->compartment_if_list, out->if_compartment_link);
    PDBLOG("[+] tcpip: dl_p2=0x%lx dl_cur=0x%lx dl_perm=0x%lx dl_len=0x%lx nb_table=0x%lx/0x%lx nb_list=0x%lx nb_entry=0x%lx nb_if=0x%lx nb_state=0x%lx nb_ref=0x%lx nb_dl=0x%lx",
        out->dl_p2_off, out->dl_cur_off, out->dl_perm_off, out->dl_len_off,
        out->if_nb_table, out->if_nb_table_alt,
        out->nb_table_list_head, out->nb_table_entry_offset,
        out->nb_interface, out->nb_state, out->nb_refcount, out->nb_dl_address);

    return true;
}

inline bool resolve_nvlddmkm(loader_offsets::nvlddmkm_offsets* out) {
    // DCH drivers keep nvlddmkm.sys in the DriverStore FileRepository, not in
    // system32\drivers - the on-disk path comes from the service ImagePath
    std::wstring drv_path;
    {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\nvlddmkm",
                0, KEY_READ, &hk) == ERROR_SUCCESS) {
            wchar_t buf[MAX_PATH] = {};
            DWORD sz = sizeof(buf), type = 0;
            // service ImagePath is REG_EXPAND_SZ on most builds, REG_SZ on old ones
            if (RegQueryValueExW(hk, L"ImagePath", nullptr, &type,
                    reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS
                    && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                drv_path = buf;
                if (_wcsnicmp(drv_path.c_str(), L"\\??\\", 4) == 0)
                    drv_path = drv_path.substr(4);
                if (_wcsnicmp(drv_path.c_str(), L"\\SystemRoot", 11) == 0) {
                    wchar_t windir[MAX_PATH] = {};
                    if (GetWindowsDirectoryW(windir, MAX_PATH))
                        drv_path = std::wstring(windir) + drv_path.substr(11);
                }
            }
            RegCloseKey(hk);
        }
    }
    if (drv_path.empty())
        drv_path = detail::get_system_module_path(L"nvlddmkm.sys");
    if (drv_path.empty()) {
        PDBLOG("[-] nvlddmkm: image path not found (no NVIDIA driver)");
        return false;
    }

    std::vector<std::uint8_t> image;
    if (!detail::read_file_safe(drv_path, &image)) {
        PDBLOG("[-] nvlddmkm: failed to read %ls", drv_path.c_str());
        return false;
    }
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto secs = IMAGE_FIRST_SECTION(nt);

    auto off_to_rva = [&](std::size_t off) -> std::uint64_t {
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& s = secs[i];
            if (s.PointerToRawData <= off && off < (std::uint64_t)s.PointerToRawData + s.SizeOfRawData)
                return (std::uint64_t)s.VirtualAddress + (off - s.PointerToRawData);
        }
        return 0;
    };

    // anchor: the rcdbDumpSystemInfo GPU dump site. it is unique and both
    // leads hang off it: GpuMgrGetGpuFromId is the called function, and the
    // real uuid getter is called a few instructions later:
    //   call  GpuMgrGetGpuFromId           e8 <rel32>
    //   mov   rbx, rax                     48 8b d8
    //   test  rax, rax                     48 85 c0
    //   jz    ..                            0f 84 <rel32>
    //   mov   r8d, [rax+<print arg>]        44 8b 80 <disp32>   (NOT the uuid)
    //   lea   rdx, [rip+..]                 48 8d 15
    //   ...
    //   mov   r9d, 2                       41 b9 02 00 00 00
    //   lea   r8, [rsp+..] ; lea rdx, [rsp+..] ; mov rcx, rbx
    //   call  <uuid getter>
    // must be unique across executable sections
    static const int anchor[] = {
        0xE8,-1,-1,-1,-1,  0x48,0x8B,0xD8,  0x48,0x85,0xC0,
        0x0F,0x84,-1,-1,-1,-1,  0x44,0x8B,0x80,-2,-1,-1,-1,
        0x48,0x8D,0x15
    };
    constexpr std::size_t kAnchorLen = sizeof(anchor) / sizeof(anchor[0]);

    std::size_t anchor_off = 0, hits = 0;
    for (WORD si = 0; si < nt->FileHeader.NumberOfSections && hits <= 1; ++si) {
        const auto& s = secs[si];
        if (!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE) || !s.SizeOfRawData) continue;
        const std::size_t base = s.PointerToRawData;
        const std::size_t end  = base + (std::size_t)s.SizeOfRawData;
        for (std::size_t i = base; i + kAnchorLen <= end && hits <= 1; ++i) {
            bool match = true;
            for (std::size_t j = 0; j < kAnchorLen; ++j) {
                if (anchor[j] >= 0 && image[i + j] != (std::uint8_t)anchor[j]) { match = false; break; }
            }
            if (!match) continue;
            ++hits;
            anchor_off = i;
        }
    }
    if (hits != 1) {
        PDBLOG("[-] nvlddmkm: uuid anchor %s (%zu hit(s))", hits ? "not unique" : "not found", hits);
        return false;
    }

    const std::uint64_t anchor_rva = off_to_rva(anchor_off);
    if (!anchor_rva) return false;
    const std::int32_t rel = *reinterpret_cast<const std::int32_t*>(image.data() + anchor_off + 1);
    const std::uint64_t fn1_rva = anchor_rva + 5 + rel;   // GpuMgrGetGpuFromId
    const auto fn1 = detail::module_rva_to_ptr(image, fn1_rva);
    if (!fn1) {
        PDBLOG("[-] nvlddmkm: GpuMgrGetGpuFromId (rva 0x%llx) outside image",
            (unsigned long long)fn1_rva);
        return false;
    }

    // GpuMgrGetGpuFromId (rax = mgr, pre-loaded by the caller):
    //   mov  r8, [rax+<inner>]            -> id/OBJGPU* table pointer
    //   mov  r9d, [r8+<count>]            -> entry count
    //   add  rcx, <half> ; add rcx,rcx ; mov rdx,[r8+rcx*8]
    //     -> entry i at table + half*16 + i*16, {OBJGPU*, pad, id at +8}
    ULONG inner_a = 0, count_off = 0, entries_half = 0;
    if (!detail::extract_disp32(fn1, 0x20,  {0x4C,0x8B,0x80,-2,-1,-1,-1}, &inner_a) ||
        !detail::extract_disp32(fn1, 0x20,  {0x45,0x8B,0x88,-2,-1,-1,-1}, &count_off) ||
        !detail::extract_disp32(fn1, 0x100, {0x48,0x81,0xC1,-2,-1,-1,-1}, &entries_half)) {
        PDBLOG("[-] nvlddmkm: GpuMgrGetGpuFromId pattern scan failed");
        return false;
    }
    if (inner_a < 8 || inner_a > 0x10000 || entries_half < 0x10 ||
        entries_half > 0x100000 || count_off <= entries_half * 16) {
        PDBLOG("[-] nvlddmkm: implausible table layout (inner=0x%lx entries=0x%lx count=0x%lx)",
            inner_a, entries_half, count_off);
        return false;
    }

    // the enumeration twin after fn1 loads the GPU-manager global itself -
    // everything fn1 derives is cross-checked here
    const std::size_t fn1_off = (std::size_t)(fn1 - image.data());
    std::size_t fn2_off = 0;
    for (std::size_t i = fn1_off + 0x20; i + 0x120 <= image.size(); ++i) {
        if (image[i] != 0x48 || image[i+1] != 0x89 || image[i+2] != 0x5C ||
            image[i+3] != 0x24 || image[i+4] != 0x08) continue;
        fn2_off = i;
        break;
    }
    if (!fn2_off) {
        PDBLOG("[-] nvlddmkm: enumeration twin (prologue) not found after GpuMgrGetGpuFromId");
        return false;
    }
    const auto fn2 = image.data() + fn2_off;
    const std::uint64_t fn2_rva = off_to_rva(fn2_off);
    if (!fn2_rva) return false;

    // mov rax, [rip+<global>] ; xor esi,esi ; xor edi,edi
    ULONG global_rva32 = 0;
    for (std::size_t j = 0; j + 11 < 0x100; ++j) {
        if (fn2[j] != 0x48 || fn2[j+1] != 0x8B || fn2[j+2] != 0x05) continue;
        if (fn2[j+7] != 0x33 || fn2[j+8] != 0xF6 || fn2[j+9] != 0x33 || fn2[j+10] != 0xFF) continue;
        global_rva32 = (ULONG)(fn2_rva + j + 7 +
            *reinterpret_cast<const std::int32_t*>(fn2 + j + 3));
        break;
    }
    if (!global_rva32) {
        PDBLOG("[-] nvlddmkm: GPU-manager global load not found in enumeration twin");
        return false;
    }

    // twin cross-checks: same inner-pointer offset, same table layout
    ULONG inner_b = 0, count_b = 0, half_b = 0, max_gpus = 0;
    const bool twin_ok =
        detail::extract_disp32(fn2, 0x100, {0x4C,0x8B,0x98,-2,-1,-1,-1}, &inner_b) &&
        detail::extract_disp32(fn2, 0x100, {0x45,0x8B,0x93,-2,-1,-1,-1}, &count_b) &&
        (detail::extract_disp32(fn2, 0x100, {0x48,0x8D,0x8A,-2,-1,-1,-1}, &half_b) ||
         detail::extract_disp32(fn2, 0x100, {0x48,0x81,0xC1,-2,-1,-1,-1}, &half_b)) &&
        detail::extract_disp8 (fn2, 0x100, {0x41,0x83,0xF8,-2}, &max_gpus);
    if (!twin_ok || inner_b != inner_a || count_b != count_off || half_b != entries_half) {
        PDBLOG("[-] nvlddmkm: enumeration twin disagrees with GpuMgrGetGpuFromId layout");
        return false;
    }
    if (!max_gpus || max_gpus > 256) {
        PDBLOG("[-] nvlddmkm: implausible max-gpu bound %lu", max_gpus);
        return false;
    }

    // the global must live in a writable data section
    bool writable = false;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& s = secs[i];
        if (s.VirtualAddress <= global_rva32 &&
            global_rva32 < (std::uint64_t)s.VirtualAddress + (std::max)(s.Misc.VirtualSize, s.SizeOfRawData)) {
            writable = (s.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            break;
        }
    }
    if (!writable) {
        PDBLOG("[-] nvlddmkm: GPU-manager global rva 0x%lx not in a writable section", global_rva32);
        return false;
    }

    // ---- uuid getter: flag byte + 16-byte cache offsets -------------------
    // the getter's register allocation varies (gpu in rcx or rdi), but its
    // shape is fixed and gives four independent extraction sites:
    //   cmp  byte [gpu+<flag>], bl        38 99 / 38 bf  <d32>
    //   lea  r8, [gpu+<uuid>]              4c 8d 81 / 4c 8d 87  <d32>  (cache read)
    //   lea  rcx, [gpu+<uuid>]             48 8d 8f / 48 8d 89  <d32>  (cache store)
    //   mov  byte [gpu+<flag>], 1          c6 87 / c6 81  <d32> 01
    // the flag byte always sits immediately before the 16-byte cache.
    const auto find_uuid_getter = [&]() -> const std::uint8_t* {
        // after the anchor: find mov r9d,2, then mov rcx,rbx, then call rel32
        const std::size_t after = anchor_off + 31;   // end of lea rdx,[rip+..]
        const std::size_t limit = (std::min)(image.size(), after + 0x100);
        for (std::size_t i = after; i + 6 <= limit; ++i) {
            if (image[i] != 0x41 || image[i+1] != 0xB9 ||
                image[i+2] != 0x02 || image[i+3] || image[i+4] || image[i+5])
                continue;
            const std::size_t m2 = (std::min)(image.size(), i + 0x40);
            for (std::size_t j = i + 6; j + 3 <= m2; ++j) {
                if (image[j] != 0x48 || image[j+1] != 0x8B || image[j+2] != 0xCB) continue;
                const std::size_t m3 = (std::min)(image.size(), j + 0x20);
                for (std::size_t k = j + 3; k + 5 <= m3; ++k) {
                    if (image[k] != 0xE8) continue;
                    const std::uint64_t call_rva = off_to_rva(k);
                    if (!call_rva) return nullptr;
                    const std::int32_t rel =
                        *reinterpret_cast<const std::int32_t*>(image.data() + k + 1);
                    return detail::module_rva_to_ptr(image, call_rva + 5 + rel);
                }
                break;
            }
            break;
        }
        return nullptr;
    };

    const auto getter = find_uuid_getter();
    if (!getter) {
        PDBLOG("[-] nvlddmkm: uuid getter call not found after anchor");
        return false;
    }
    ULONG flag_a = 0, flag_b = 0, uuid_a = 0, uuid_b = 0;
    const bool g_ok =
        (detail::extract_disp32(getter, 0x100, {0x38,0x99,-2,-1,-1,-1}, &flag_a) ||
         detail::extract_disp32(getter, 0x100, {0x38,0xBF,-2,-1,-1,-1}, &flag_a)) &&
        (detail::extract_disp32(getter, 0x140, {0x4C,0x8D,0x81,-2,-1,-1,-1}, &uuid_a) ||
         detail::extract_disp32(getter, 0x140, {0x4C,0x8D,0x87,-2,-1,-1,-1}, &uuid_a)) &&
        (detail::extract_disp32(getter, 0x140, {0x48,0x8D,0x8F,-2,-1,-1,-1}, &uuid_b) ||
         detail::extract_disp32(getter, 0x140, {0x48,0x8D,0x89,-2,-1,-1,-1}, &uuid_b)) &&
        (detail::extract_disp32(getter, 0x140, {0xC6,0x87,-2,-1,-1,-1,0x01}, &flag_b) ||
         detail::extract_disp32(getter, 0x140, {0xC6,0x81,-2,-1,-1,-1,0x01}, &flag_b));
    if (!g_ok || flag_a != flag_b || uuid_a != uuid_b ||
        uuid_a != flag_a + 1 || flag_a >= 0x200000) {
        PDBLOG("[-] nvlddmkm: uuid getter layout disagrees (flag=%lu/%lu uuid=%lu/%lu)",
            flag_a, flag_b, uuid_a, uuid_b);
        return false;
    }

    out->gpu_mgr_global_rva = global_rva32;
    out->uuid_flag_off      = flag_a;
    out->uuid_data_off      = uuid_a;
    out->mgr_inner_ptr_off   = inner_a;
    out->table_entries_off   = entries_half * 16;
    out->table_entry_stride  = 16;
    out->table_count_off     = count_off;
    out->max_gpus            = max_gpus;

    PDBLOG("[+] nvlddmkm: mgr_global=rva 0x%lx uuid_flag=0x%lx uuid_data=0x%lx inner=0x%lx entries=0x%lx count=0x%lx max=%lu",
        global_rva32, flag_a, uuid_a, inner_a, out->table_entries_off, count_off, max_gpus);
    return true;
}

}
