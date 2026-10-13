#pragma once
#include <Windows.h>
#include <d3d11.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

#include <third_party/imgui/imgui.h>
#include <third_party/imgui/imgui_impl_win32.h>
#include <third_party/imgui/imgui_impl_dx11.h>

#include <src/symbols/includes.h>

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace ui {

    static HWND g_hwnd = nullptr;

    inline void move_window() {
        if (g_hwnd && ImGui::IsWindowHovered() && ImGui::IsMouseDown(0)) {
            RECT rc;
            GetWindowRect(g_hwnd, &rc);
            ImVec2 delta = ImGui::GetMouseDragDelta(0);
            if (delta.x != 0 || delta.y != 0) {
                MoveWindow(g_hwnd, rc.left + (int)delta.x, rc.top + (int)delta.y, rc.right - rc.left, rc.bottom - rc.top, TRUE);
                ImGui::ResetMouseDragDelta(0);
            }
        }
    }

    static ID3D11Device*            g_pd3dDevice = nullptr;
    static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
    static IDXGISwapChain*          g_pSwapChain = nullptr;
    static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

    static bool g_cleanTraces = false;
    static bool g_spoofNetwork = true;
    static bool g_showCleanConfirmPopup = false;
    static std::atomic<bool> g_isExecuting(false);
    static std::atomic<bool> g_executionDone(false);
    static std::string g_statusMessage = "Ready";

    static std::mutex g_logMutex;
    static std::vector<std::string> g_logLines;

    inline void add_log(const std::string& line) {
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_logLines.push_back(line);
        if (g_logLines.size() > 500) g_logLines.erase(g_logLines.begin());
    }

    inline void create_render_target() {
        ID3D11Texture2D* pBackBuffer = nullptr;
        g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
        if (pBackBuffer) {
            g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
            pBackBuffer->Release();
        }
    }

    inline void cleanup_render_target() {
        if (g_mainRenderTargetView) {
            g_mainRenderTargetView->Release();
            g_mainRenderTargetView = nullptr;
        }
    }

    inline bool create_device_d3d(HWND hWnd) {
        DXGI_SWAP_CHAIN_DESC sd{};
        sd.BufferCount = 2;
        sd.BufferDesc.Width = 0;
        sd.BufferDesc.Height = 0;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = hWnd;
        sd.SampleDesc.Count = 1;
        sd.SampleDesc.Quality = 0;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        UINT createDeviceFlags = 0;
        D3D_FEATURE_LEVEL featureLevel;
        const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
        HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
                                                   featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
                                                   &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
        if (res != S_OK) return false;
        create_render_target();
        return true;
    }

    inline void cleanup_device_d3d() {
        cleanup_render_target();
        if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
        if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
        if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    }

    inline LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

        switch (msg) {
        case WM_SIZE:
            if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
                cleanup_render_target();
                g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
                create_render_target();
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    inline void apply_style() {
        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = 8.0f;
        style.FrameRounding = 5.0f;
        style.PopupRounding = 5.0f;
        style.ScrollbarRounding = 5.0f;
        style.GrabRounding = 5.0f;
        style.WindowPadding = ImVec2(15, 15);
        style.FramePadding = ImVec2(8, 6);
        style.ItemSpacing = ImVec2(10, 10);

        ImVec4* colors = style.Colors;
        colors[ImGuiCol_WindowBg]           = ImVec4(0.09f, 0.10f, 0.14f, 0.98f);
        colors[ImGuiCol_Header]             = ImVec4(0.18f, 0.20f, 0.28f, 1.00f);
        colors[ImGuiCol_HeaderHovered]      = ImVec4(0.24f, 0.27f, 0.38f, 1.00f);
        colors[ImGuiCol_HeaderActive]       = ImVec4(0.30f, 0.34f, 0.48f, 1.00f);
        colors[ImGuiCol_Button]             = ImVec4(0.32f, 0.24f, 0.58f, 1.00f);
        colors[ImGuiCol_ButtonHovered]      = ImVec4(0.42f, 0.32f, 0.74f, 1.00f);
        colors[ImGuiCol_ButtonActive]       = ImVec4(0.50f, 0.38f, 0.86f, 1.00f);
        colors[ImGuiCol_FrameBg]            = ImVec4(0.14f, 0.16f, 0.22f, 1.00f);
        colors[ImGuiCol_FrameBgHovered]     = ImVec4(0.20f, 0.22f, 0.30f, 1.00f);
        colors[ImGuiCol_FrameBgActive]      = ImVec4(0.26f, 0.28f, 0.38f, 1.00f);
        colors[ImGuiCol_CheckMark]          = ImVec4(0.70f, 0.45f, 1.00f, 1.00f);
        colors[ImGuiCol_SliderGrab]         = ImVec4(0.60f, 0.40f, 0.90f, 1.00f);
        colors[ImGuiCol_SliderGrabActive]   = ImVec4(0.70f, 0.45f, 1.00f, 1.00f);
        colors[ImGuiCol_Text]               = ImVec4(0.92f, 0.94f, 0.98f, 1.00f);
        colors[ImGuiCol_TextDisabled]       = ImVec4(0.50f, 0.52f, 0.60f, 1.00f);
        colors[ImGuiCol_TitleBg]            = ImVec4(0.12f, 0.14f, 0.18f, 1.00f);
        colors[ImGuiCol_TitleBgActive]      = ImVec4(0.16f, 0.18f, 0.24f, 1.00f);
        colors[ImGuiCol_Border]             = ImVec4(0.24f, 0.26f, 0.34f, 0.60f);
    }

    inline void render_gui() {
        WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"SpooferGUI", nullptr };
        RegisterClassExW(&wc);
        HWND hwnd = CreateWindowW(wc.lpszClassName, L"Cracked-2m96 Spoofer", WS_OVERLAPPEDWINDOW, 100, 100, 720, 520, nullptr, nullptr, wc.hInstance, nullptr);

        if (!create_device_d3d(hwnd)) {
            cleanup_device_d3d();
            UnregisterClassW(wc.lpszClassName, wc.hInstance);
            return;
        }

        ShowWindow(hwnd, SW_SHOWDEFAULT);
        UpdateWindow(hwnd);

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

        apply_style();

        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

        ImVec4 clear_color = ImVec4(0.07f, 0.08f, 0.11f, 1.00f);

        bool running = true;
        while (running) {
            MSG msg;
            while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
                if (msg.message == WM_QUIT)
                    running = false;
            }
            if (!running) break;

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::Begin("MainControl", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

            ImGui::TextColored(ImVec4(0.70f, 0.45f, 1.00f, 1.00f), "CRACKED-2M96 HARDWARE SPOOFER");
            ImGui::Separator();
            ImGui::Spacing();

            bool is_busy = g_isExecuting.load();

            if (is_busy) ImGui::BeginDisabled();

            if (ImGui::Button("SPOOF HARDWARE", ImVec2(220, 45))) {
                g_isExecuting = true;
                g_statusMessage = "Spoofing Hardware...";
                add_log("[+] Starting hardware spoof operation...");
                bool clean_opt = g_cleanTraces;
                bool net_opt = g_spoofNetwork;
                struct thread_params { bool clean; bool net; };
                thread_params* p = new thread_params{ clean_opt, net_opt };
                CreateThread(nullptr, 0, [](LPVOID lpParam) -> DWORD {
                    thread_params* params = (thread_params*)lpParam;
                    bool do_clean = params->clean;
                    bool do_net = params->net;
                    delete params;
                    if (!spoof::preflight::run()) {
                        ui::add_log("[-] Preflight failed - operation aborted.");
                        g_statusMessage = "Preflight Failed!";
                    } else {
                        spoof::install(do_clean, do_net);
                        ui::add_log("[+] Hardware spoof completed!");
                        g_statusMessage = "Spoof Complete!";
                    }
                    g_isExecuting = false;
                    return 0;
                }, p, 0, nullptr);
            }

            ImGui::SameLine();
            if (ImGui::Button("CLEAN TRACES ONLY", ImVec2(220, 45))) {
                ImGui::OpenPopup("Confirm Trace Cleanup");
            }

            // Custom ImGui Confirmation Modal
            ImVec2 center = ImGui::GetMainViewport()->GetCenter();
            ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            ImGui::SetNextWindowSize(ImVec2(400, 190));
            if (ImGui::BeginPopupModal("Confirm Trace Cleanup", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove)) {
                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "WARNING: CONFIRM TRACE CLEANUP");
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::TextWrapped("Are you sure you want to clean Windows traces (Prefetch, Event Logs, ETW)?");
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Note: Your saved login credentials are kept safe.");
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                if (ImGui::Button("YES, CLEAN TRACES", ImVec2(170, 32))) {
                    ImGui::CloseCurrentPopup();
                    g_isExecuting = true;
                    g_statusMessage = "Cleaning Traces...";
                    add_log("[+] Starting standalone trace cleanup...");
                    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
                        spoof::clean_only();
                        ui::add_log("[+] Trace cleanup completed!");
                        g_statusMessage = "Clean Complete!";
                        g_isExecuting = false;
                        return 0;
                    }, nullptr, 0, nullptr);
                }
                ImGui::SetItemDefaultFocus();
                ImGui::SameLine();
                if (ImGui::Button("CANCEL", ImVec2(100, 32))) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }

            if (is_busy) ImGui::EndDisabled();

            ImGui::Spacing();
            ImGui::Checkbox("Spoof Network Adapters (Ethernet & Wi-Fi MACs)", &g_spoofNetwork);
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Uncheck this if MAC / adapter spoofing disrupts your internet connection.\nDisabling this leaves your physical Network Cards untouched.");
            }

            ImGui::Checkbox("Clean Trace Artifacts (Prefetch, Logs, ETW)", &g_cleanTraces);
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("When checked, clears Windows Prefetch, Event Logs, and ETW traces during spoofing.\nNote: User login credentials (Chrome, Discord, Steam) are ALWAYS preserved.");
            }

            ImGui::Spacing();
            ImGui::Text("Status: ");
            ImGui::SameLine();
            ImGui::TextColored(is_busy ? ImVec4(1.0f, 0.8f, 0.2f, 1.0f) : ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "%s", g_statusMessage.c_str());

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Text("Execution Log:");

            ImGui::BeginChild("LogRegion", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
            {
                std::lock_guard<std::mutex> lock(g_logMutex);
                for (const auto& line : g_logLines) {
                    if (line.find("[-]") != std::string::npos || line.find("ERR") != std::string::npos) {
                        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", line.c_str());
                    } else if (line.find("[+]") != std::string::npos || line.find("OK") != std::string::npos) {
                        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "%s", line.c_str());
                    } else if (line.find("STEP") != std::string::npos) {
                        ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "%s", line.c_str());
                    } else {
                        ImGui::Text("%s", line.c_str());
                    }
                }
                if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                    ImGui::SetScrollHereY(1.0f);
            }
            ImGui::EndChild();

            ImGui::End();

            ImGui::Render();
            const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            g_pSwapChain->Present(1, 0);
        }

        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        cleanup_device_d3d();
        DestroyWindow(hwnd);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
    }
}
