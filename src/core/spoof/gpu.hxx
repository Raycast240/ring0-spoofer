#pragma once
#include "helpers.hxx"
#include "../../symbols/pdb_offsets.hxx"
#include <algorithm>
#include <vector>

namespace gpu {

    static void format_uuid(const std::uint8_t* u, char* out, std::size_t out_len) {
        snprintf(out, out_len,
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
            u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
    }

    // run a hidden console child and wait briefly - nvml init forces nvlddmkm
    // to populate the OBJGPU uuid cache (DCH drivers ship nvidia-smi in System32)
    static bool spawn_hidden(const wchar_t* exe, const wchar_t* args, DWORD wait_ms) {
        std::wstring cmd = std::wstring(exe) + L" " + args;
        std::vector<wchar_t> buf(cmd.begin(), cmd.end());
        buf.push_back(0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(exe, buf.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return false;
        WaitForSingleObject(pi.hProcess, wait_ms);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

    // nvapi warm-up: NvAPI_Initialize + NvAPI_EnumPhysicalGPUs walk the same
    // RM physical-GPU enumeration nvml does. interface ids are stable public
    // constants of nvapi64.dll (queried through nvapi_QueryInterface)
    static void nvapi_warmup() {
        const HMODULE nvapi = LoadLibraryW(L"nvapi64.dll");
        if (!nvapi) return;
        using query_interface_t = void* (*)(unsigned);
        const auto query_interface = reinterpret_cast<query_interface_t>(
            GetProcAddress(nvapi, "nvapi_QueryInterface"));
        if (!query_interface) return;

        constexpr unsigned k_id_initialize   = 0x01518E1B;
        constexpr unsigned k_id_enum_physical = 0xE5AC921F;
        const auto init = reinterpret_cast<int (*)()>(
            query_interface(k_id_initialize));
        const auto enum_phys = reinterpret_cast<int (*)(void**, int*)>(
            query_interface(k_id_enum_physical));
        if (!init || !enum_phys || init() != 0) return;
        void* gpus[64] = {};
        int count = 0;
        enum_phys(gpus, &count);
    }

    inline void install() {
        using namespace spoof::helpers;

        const std::uint64_t nv_base = get_kernel_module_base(L"nvlddmkm.sys");
        if (!nv_base) {
            logging::print("spoof: gpu - nvlddmkm.sys not loaded (no NVIDIA driver)");
            return;
        }

        loader_offsets::nvlddmkm_offsets off{};
        if (!pdb_offsets::resolve_nvlddmkm(&off)) {
            logging::print("spoof: gpu - nvlddmkm offset derivation failed");
            return;
        }

        // mgr global -> manager object -> id/OBJGPU* hash table
        const std::uint64_t mgr = kread_val<std::uint64_t>(nv_base + off.gpu_mgr_global_rva);
        if (!is_kva(mgr)) {
            logging::print("spoof: gpu - GPU manager not initialised (ptr=0x%llX)",
                (unsigned long long)mgr);
            return;
        }
        const std::uint64_t table = kread_val<std::uint64_t>(mgr + off.mgr_inner_ptr_off);
        if (!is_kva(table)) {
            logging::print("spoof: gpu - GPU table pointer not valid (0x%llX)",
                (unsigned long long)table);
            return;
        }
        const std::uint32_t count = kread_val<std::uint32_t>(table + off.table_count_off);
        if (!count || count > off.max_gpus * 4) {
            logging::print("spoof: gpu - implausible GPU table count %u", count);
            return;
        }

        std::vector<std::uint64_t> seen;
        std::uint32_t scanned = 0, patched = 0;

        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint64_t entry =
                table + off.table_entries_off + (std::uint64_t)i * off.table_entry_stride;
            const std::uint64_t gpu = kread_val<std::uint64_t>(entry);
            const std::uint32_t id  = kread_val<std::uint32_t>(entry + 8);
            if (!is_kva(gpu) || id >= off.max_gpus) continue;
            if (std::find(seen.begin(), seen.end(), gpu) != seen.end()) continue;
            seen.push_back(gpu);
            ++scanned;

            // the getter serves the 16-byte OBJGPU cache whenever the flag
            // byte is set, so we overwrite the cache AND set the flag  -
            // no warm-up needed, the first RM client query (nvapi/nvml/
            // cuda) reads our value directly
            const std::uint8_t old_flag = kread_val<std::uint8_t>(gpu + off.uuid_flag_off);
            std::uint8_t old_uuid[16] = {};
            kread(gpu + off.uuid_data_off, old_uuid, 16);

            // identity gate on the PDB-derived slot pair: the flag byte is
            // 0 (cold cache) or 1 (cache served), and a populated cache
            // holds a non-zero uuid - anything else means the offset is
            // wrong for this driver build and a write could hit a neighbour
            bool old_uuid_zero = true;
            for (auto b : old_uuid) if (b) { old_uuid_zero = false; break; }
            if (old_flag > 1 || (old_flag == 1 && old_uuid_zero)) {
                logging::print("spoof: gpu - GPU id %u: uuid slot shape implausible"
                               " (flag=%u, uuid %s) - write skipped",
                               id, old_flag, old_uuid_zero ? "zero" : "set");
                continue;
            }

            std::uint8_t new_uuid[16] = {};
            for (auto& b : new_uuid) b = static_cast<std::uint8_t>(rand_next());
            // the real value is SHA-1 derived - keep the version/variant shape
            new_uuid[6] = (new_uuid[6] & 0x0F) | 0x50;
            new_uuid[8] = (new_uuid[8] & 0x3F) | 0x80;

            if (!kwrite_verified(gpu + off.uuid_data_off, new_uuid, 16, "gpu: uuid cache")) {
                logging::print("spoof: gpu - GPU id %u: kernel write failed", id);
                continue;
            }
            if (old_flag != 1) {
                const std::uint8_t one = 1;
                if (!kwrite_verified(gpu + off.uuid_flag_off, &one, 1, "gpu: uuid flag")) {
                    logging::print("spoof: gpu - GPU id %u: flag write failed", id);
                    continue;
                }
            }
            ++patched;

            char old_s[40] = {}, new_s[40] = {};
            format_uuid(old_uuid, old_s, sizeof(old_s));
            format_uuid(new_uuid, new_s, sizeof(new_s));
            logging::print("spoof: gpu - GPU id %u UUID %s -> %s (flag %u -> 1)%s",
                id, old_s, new_s, old_flag, old_flag ? "" : " [cache was cold]");

            char name[56] = {};
            snprintf(name, sizeof(name), "OBJGPU UUID (GPU id %u)", id);
            logging::change("GPU", name, old_s, new_s, true);
        }

        logging::print("spoof: gpu - %u/%u OBJGPU UUID(s) patched (nvlddmkm 0x%llX)",
            patched, scanned, (unsigned long long)nv_base);
    }

    // read-only (--gputest): dump the derived offsets and each GPU's uuid
    // cache before and after the warm-up - never writes
    static void dump_uuid_cache(const char* tag, std::uint64_t gpu,
                                const loader_offsets::nvlddmkm_offsets& off) {
        using namespace spoof::helpers;
        const std::uint8_t flag = kread_val<std::uint8_t>(gpu + off.uuid_flag_off);
        std::uint8_t uuid[16] = {};
        kread(gpu + off.uuid_data_off, uuid, 16);
        char s[40] = {};
        format_uuid(uuid, s, sizeof(s));
        logging::print("diag: gpu - [%s] gpu=0x%llX flag=%u uuid=%s",
            tag, (unsigned long long)gpu, flag, s);
    }

    inline void diag() {
        using namespace spoof::helpers;

        const std::uint64_t nv_base = get_kernel_module_base(L"nvlddmkm.sys");
        if (!nv_base) {
            logging::print("diag: gpu - nvlddmkm.sys not loaded (no NVIDIA driver)");
            return;
        }
        loader_offsets::nvlddmkm_offsets off{};
        if (!pdb_offsets::resolve_nvlddmkm(&off)) {
            logging::print("diag: gpu - nvlddmkm offset derivation failed");
            return;
        }
        logging::print("diag: gpu - flag=0x%lx uuid=0x%lx inner=0x%lx entries=0x%lx count=0x%lx max=%lu",
            off.uuid_flag_off, off.uuid_data_off, off.mgr_inner_ptr_off,
            off.table_entries_off, off.table_count_off, off.max_gpus);

        const std::uint64_t mgr = kread_val<std::uint64_t>(nv_base + off.gpu_mgr_global_rva);
        logging::print("diag: gpu - mgr=0x%llX", (unsigned long long)mgr);
        if (!is_kva(mgr)) return;
        const std::uint64_t table = kread_val<std::uint64_t>(mgr + off.mgr_inner_ptr_off);
        if (!is_kva(table)) {
            logging::print("diag: gpu - table ptr not valid (0x%llX)", (unsigned long long)table);
            return;
        }
        const std::uint32_t count = kread_val<std::uint32_t>(table + off.table_count_off);
        logging::print("diag: gpu - table=0x%llX count=%u", (unsigned long long)table, count);
        if (!count || count > off.max_gpus * 4) return;

        std::vector<std::uint64_t> seen;
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint64_t entry =
                table + off.table_entries_off + (std::uint64_t)i * off.table_entry_stride;
            const std::uint64_t gpu = kread_val<std::uint64_t>(entry);
            const std::uint32_t id  = kread_val<std::uint32_t>(entry + 8);
            if (!is_kva(gpu) || id >= off.max_gpus) continue;
            if (std::find(seen.begin(), seen.end(), gpu) != seen.end()) continue;
            seen.push_back(gpu);
            logging::print("diag: gpu - entry %u id=%u", i, id);
            dump_uuid_cache("pre-warmup", gpu, off);
        }

        // force the lazy uuid computation the same way install() used to
        wchar_t smi_path[MAX_PATH] = {};
        GetSystemDirectoryW(smi_path, MAX_PATH);
        wcscat_s(smi_path, L"\\nvidia-smi.exe");
        if (GetFileAttributesW(smi_path) != INVALID_FILE_ATTRIBUTES)
            spawn_hidden(smi_path, L"-L", 4000);
        nvapi_warmup();
        logging::print("diag: gpu - warm-up done, re-reading");

        for (auto gpu : seen)
            dump_uuid_cache("post-warmup", gpu, off);
    }

}