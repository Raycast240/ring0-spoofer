#pragma once
#include "shared.hxx"
#include <winioctl.h>

namespace spoof::disk::disk_class {
    using namespace helpers;

    struct StorDescHdr {
        std::uint32_t Version;
        std::uint32_t Size;
        std::uint8_t  DeviceType;
        std::uint8_t  DeviceTypeModifier;
        std::uint8_t  RemovableMedia;
        std::uint8_t  CommandQueueing;
        std::uint32_t VendorIdOffset;
        std::uint32_t ProductIdOffset;
        std::uint32_t ProductRevisionOffset;
        std::uint32_t SerialNumberOffset;
        std::uint32_t BusType;
        std::uint32_t RawPropertiesLength;
    };

    static bool looks_like_stor_desc(const StorDescHdr& h) {
        return h.Version >= 0x20 && h.Version <= 0x400
            && h.Size >= h.Version && h.Size <= 0x2000
            && h.BusType >= 1 && h.BusType <= 0x20
            && h.SerialNumberOffset != 0
            && h.SerialNumberOffset < h.Size;
    }


    struct StorIdDescHdr {
        std::uint32_t Version;
        std::uint32_t Size;
        std::uint32_t NumberOfIdentifiers;
    };

    static bool looks_like_stor_id_desc(const StorIdDescHdr& h) {
        return h.Version >= sizeof(StorIdDescHdr)
            && h.Version <= 0x200
            && h.Size >= h.Version
            && h.Size <= 0x1000
            && h.NumberOfIdentifiers >= 1
            && h.NumberOfIdentifiers <= 16;
    }


    struct StorIdent {
        std::uint8_t  CodeSet;
        std::uint8_t  Type;
        std::uint16_t IdentifierSize;
        std::uint16_t NextOffset;
        std::uint8_t  Association;
        std::uint8_t  Reserved;

    };
    static constexpr std::uint32_t kStorIdentHeaderSize = sizeof(StorIdent);
    static constexpr std::uint8_t  kCodeSetBinary = 1;

    static void record_id_change(const char* name, const std::uint8_t* old_bytes,
                                 const std::uint8_t* new_bytes, std::uint32_t length) {
        if (!name || !length || memcmp(old_bytes, new_bytes, length) == 0) return;
        char old_txt[80] = {};
        char new_txt[80] = {};
        format_hex_bytes(old_txt, sizeof(old_txt), old_bytes, length);
        format_hex_bytes(new_txt, sizeof(new_txt), new_bytes, length);
        logging::change("Disk", name, old_txt, new_txt, true);
    }


    static std::uint32_t patch_disk_class_device(std::uint64_t dev_va) {
        if (dev_type(dev_va) != kDevTypeDisk) return 0;
        std::uint64_t ext_va = dev_extension(dev_va);
        if (!is_kva(ext_va)) return 0;


        static constexpr std::uint32_t kScanBytes = 0x1000;
        std::vector<std::uint8_t> ext(kScanBytes);
        if (!kread(ext_va, ext.data(), kScanBytes)) return 0;

        std::uint32_t patched = 0;
        bool found_serial = false;



        for (std::uint32_t off = 0; off + 8 <= kScanBytes; off += 8) {
            std::uint64_t candidate = *reinterpret_cast<const std::uint64_t*>(ext.data() + off);
            if (candidate < 0xFFFF000000000000ULL || candidate == ~0ULL) continue;


            if (!found_serial) {
                StorDescHdr desc_hdr{};
                if (kread(candidate, &desc_hdr, sizeof(desc_hdr)) && looks_like_stor_desc(desc_hdr)) {
                    std::uint64_t ser_va = candidate + desc_hdr.SerialNumberOffset;
                    char ser_buf[128] = {};
                    if (kread(ser_va, ser_buf, sizeof(ser_buf)-1)) {
                        std::size_t ser_len = strnlen(ser_buf, sizeof(ser_buf)-1);
                        if (ser_len >= 2 && ascii_printable(ser_buf, ser_len)) {
                            ensure_canonical(ser_buf, ser_len);
                            if (s_serial_len) {
                                char chg_name[56] = {};
                                snprintf(chg_name, sizeof(chg_name), "serial (FDO 0x%llx)", dev_va);
                                char new_ser[96] = {};
                                std::size_t copy = (std::size_t)s_serial_len < ser_len ? (std::size_t)s_serial_len : ser_len;
                                snprintf(new_ser, sizeof(new_ser), "%.*s", (int)copy, s_serial);
                                if (s_trailing && copy < ser_len) {
                                    std::size_t tail = strlen(new_ser);
                                    snprintf(new_ser + tail, sizeof(new_ser) - tail, "%c", s_trailing);
                                }
                                write_canonical(ser_va, ser_len + 1, 0);
                                logging::change("Disk", chg_name, ser_buf, new_ser, true);
                                logging::print("disk: disk_class device 0x%llx FDO serial patched", dev_va);
                                found_serial = true;
                                ++patched;
                            }
                        }
                    }
                }
            }


            if (s_serial_len) {
                StorIdDescHdr id_hdr{};
                if (kread(candidate, &id_hdr, sizeof(id_hdr)) && looks_like_stor_id_desc(id_hdr)) {

                    std::vector<std::uint8_t> id_buf(id_hdr.Size);
                    if (kread(candidate, id_buf.data(), id_hdr.Size)) {
                        std::uint32_t id_off = sizeof(StorIdDescHdr);
                        std::uint32_t count = id_hdr.NumberOfIdentifiers;
                        std::uint32_t id_patched = 0;
                        for (std::uint32_t i = 0; i < count && id_off + kStorIdentHeaderSize <= id_hdr.Size; ++i) {
                            const StorIdent* ident = reinterpret_cast<const StorIdent*>(id_buf.data() + id_off);
                            if (!ident->IdentifierSize || ident->IdentifierSize > 0x100) break;
                            if (id_off + kStorIdentHeaderSize + ident->IdentifierSize > id_hdr.Size) break;
                            if (ident->CodeSet == kCodeSetBinary &&
                                (ident->IdentifierSize==8||ident->IdentifierSize==16||ident->IdentifierSize==20)) {
                                std::uint64_t ident_data_va = candidate + id_off + kStorIdentHeaderSize;
                                std::uint8_t old_ident[20] = {};
                                bool have_old = kread(ident_data_va, old_ident, ident->IdentifierSize);
                                fill_identity_bytes(ident_data_va, ident->IdentifierSize);
                                std::uint8_t new_ident[20] = {};
                                bool have_new = kread(ident_data_va, new_ident, ident->IdentifierSize);
                                if (have_old && have_new) {
                                    char chg_name[56] = {};
                                    snprintf(chg_name, sizeof(chg_name), "device ID (FDO 0x%llx)", dev_va);
                                    record_id_change(chg_name, old_ident, new_ident, ident->IdentifierSize);
                                }
                                ++id_patched;
                            }
                            if (!ident->NextOffset) break;
                            if (id_off + ident->NextOffset <= id_off) break;
                            id_off += ident->NextOffset;
                        }
                        if (id_patched) {
                            logging::print("disk: disk_class device 0x%llx ID descriptor patched (%u idents)", dev_va, id_patched);
                            patched += id_patched;
                        }
                    }
                }
            }
        }

        return patched;
    }

    inline void install() {
        std::uint32_t patched = 0;
        enum_driver_devices(L"\\Driver\\disk", [&](std::uint64_t dev_va) {
            patched += patch_disk_class_device(dev_va);
        });
        logging::print("disk: disk_class patched %u FDO serials/identifiers", patched);
    }

}
