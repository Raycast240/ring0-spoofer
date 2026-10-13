#pragma once
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <mutex>
#include <vector>
#include <Windows.h>
#include <fstream>
#include <winternl.h>
#include <cstdint>
#include <functional>
#include <dia2.h>
#include <diacreate.h>
#include <atlbase.h>
#include <string>
#include <memory>
#include <utility>

#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "ntdll.lib")

#include <third_party/ia32/include.h>
#include <third_party/oxorany/include.h>

#include <src/utility/logger.hxx>
#include <src/utility/utility.hxx>

#include <src/symbols/pdb/pdb.hxx>

#include <src/core/service/bytes.h>
#include <src/core/service/service.hxx>
#include <src/core/service/startup.hxx>

#include <src/core/service/driver/driver.hxx>

#include <src/core/memory/paging/paging.hxx>
#include <src/core/memory/syscall/syscall.hxx>

#include <src/utility/exit.hxx>

#include <src/core/spoof/spoof.hxx>
