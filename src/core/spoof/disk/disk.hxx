#pragma once
#include "shared.hxx"
#include "disk_offsets.hxx"
#include "storport.hxx"
#include "stornvme.hxx"
#include "storahci.hxx"
#include "disk_class.hxx"
#include "volume_serial.hxx"
#include "partmgr.hxx"
#include "mountmgr.hxx"
#include "registry.hxx"

namespace spoof::disk {

    struct DiskLayer {
        const char* name;
        void(*fn)();
    };


    static void stornvme_install() {
        storport::spoof_raid_units(L"\\Driver\\stornvme", true);
    }

    static constexpr DiskLayer kLayers[] = {
        { "stornvme",      stornvme_install         },
        { "storahci",      storahci::install        },
        { "disk_class",    disk_class::install      },
        { "volume_serial", volume_serial::install   },
        { "partmgr",       partmgr::install         },
        { "mountmgr",      mountmgr::install        },
        { "registry",      registry::install        },
    };

    inline void install() {
        resolve_disk_offsets();
        for (const auto& layer : kLayers) {
            logging::print("disk: running layer [%s]", layer.name);
            layer.fn();
        }
    }

}
