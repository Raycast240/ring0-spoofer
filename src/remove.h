#pragma once
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <dwmapi.h>
#include <codecvt>
#include <iomanip>
#include <src/ui.hxx>

extern HWND hwnd;
extern RECT rc;
extern float WIDTH;
extern float HEIGHT;
extern ImVec2 menu_size;

namespace ui { void move_window(); }
inline void move_window() { ui::move_window(); }
