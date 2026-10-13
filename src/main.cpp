// Dear ImGui: standalone example application for DirectX 11

// Learn about Dear ImGui:
// - FAQ                  https://dearimgui.com/faq
// - Getting Started      https://dearimgui.com/getting-started
// - Documentation        https://dearimgui.com/docs (same as your local docs/ folder).
// - Introduction, links and more at the top of imgui.cpp
#include <iostream>
#include <fstream>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include "menu.h"
#include <vector>
#include <string>
#include <time.h>
#include <dwmapi.h>
#include <codecvt>
#include <iomanip>
#include "remove.h"
#include "xor.hpp"
#include "lazy_importer.hpp"
#include <filesystem>
#pragma comment(lib, "dwmapi.lib")
#include <D3DX11tex.h>
#pragma comment(lib, "D3DX11.lib")
// Data
static bool                     g_SwapChainOccluded = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

//                                                                             PROTECTION LOADER
/*
void DetectWindow() {
    HWND Window;
    Window = FindWindowW(0, L"IDA: Quick start");
    if (Window)
        li(exit)(0);
    Window = FindWindowW(0, L"Scylla x86 v0.9.6");
    if (Window)
        li(exit)(0);
    Window = FindWindowW(0, L"x64dbg");
    if (Window)
        li(exit)(0);
    Window = FindWindowW(0, L"x32dbg");
    if (Window)
        li(exit)(0);
    Window = FindWindowW(0, L"x32dbg [Elevated]");
    if (Window)
        li(exit)(0);
}


                                                                                (OPTIONAL) This is an additional protection against the processes of the game, in this example cs:go

HANDLE CsgoProcess(char* TargetProc) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)

        pe32.dwSize = sizeof(PROCESSENTRY32);
    int i = 0;
    while (Process32Next(hProcessSnap, &pe32)) {

        if (0 == strcmp(pe32.szExeFile, TargetProc))
        {
            CSGO = true;
            ProcID = pe32.th32ProcessID;
            return(0);
        }
        else  CSGO = false;
    }
    CloseHandle(hProcessSnap);
}

void killProcess(const char* name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(pEntry);
    BOOL hRes = Process32First(hSnapshot, &pEntry);
    while (hRes)
    {
        if (strcmp(pEntry.szExeFile, name) == 0)
        {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
                (DWORD)pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
                li(exit)(-1);
            }
        }

        hRes = Process32Next(hSnapshot, &pEntry);
    }
    CloseHandle(hSnapshot);
}




                                    ITS KILL PROCESS

 std::thread([&] {

        while (true) {
            //	system(xorstr("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
            killProcess(xorstr("x64dbg.exe"));
            killProcess(xorstr("ida64.exe"));
            killProcess(xorstr("MLSvc.exe"));
            killProcess(xorstr("OLLYDBG.exe"));
            killProcess(xorstr("ExtrimeInjector.exe"));
            killProcess(xorstr("extrimeinjector.exe"));
            killProcess(xorstr("extrime.exe"));
            killProcess(xorstr("windbg.exe"));
            killProcess(xorstr("idaq.exe"));
            killProcess(xorstr("dumper.exe"));
            killProcess(xorstr("ImmunityDebugger.exe"));
            killProcess(xorstr("HTTPAnalyzerStdV7.exe"));
            killProcess(xorstr("HTTPAnalyzerStdV5.exe"));
            killProcess(xorstr("die.exe"));
            killProcess(xorstr("netdump.exe"));
            killProcess(xorstr("PETools.exe"));
            killProcess(xorstr("cheatengine-x86_64.exe"));
            killProcess(xorstr("LordPE.exe"));
            killProcess(xorstr("x32dbg.exe"));
            killProcess(xorstr("cmd.exe"));
            killProcess(xorstr("dumpcap.exe"));
            killProcess(xorstr("anydesk.exe"));
            killProcess(xorstr("AnyDesk.exe"));
            killProcess(xorstr("tcpview.exe"));
            killProcess(xorstr("Wiershark.exe"));
            killProcess(xorstr("x32dbg.exe"));
            killProcess(xorstr("ProcessHacker2.exe"));
            killProcess(xorstr("ProcessHacker.exe"));
            //	system(xorstr("taskkill /FI \"IMAGENAME" eq processhacker * \" /IM * /F /T >nul 2>&1"));
        }

        }).detach();


*/

//                      KEYAUTH
/*

CURL* curl_handle;
                                            curl_handle = curl_easy_init();

                                            key_n2 = HWID;
                                            std::string url = (xorstr("https://amazingbots.ru/dadadzikkkkkkkk/?activate=")) + key_n2 + "&hwid=" + serial();
                                            std::string content;

                                            if (curl_handle)
                                            {
                                                curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
                                                curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
                                                curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
                                                curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writer);
                                                curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &content);
                                                CURLcode res = curl_easy_perform(curl_handle);
                                                curl_easy_cleanup(curl_handle);
                                                if (content.find("key_success") != std::string::npos)
                                                {

                                                    SubRudokop = true;

                                                }

*/

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

//                Attention! in order for all the protections to work, you need to move the menu to the folder with the hooks of the game and then all
//                the elements will be initialized, if you want to connect keyauth, there is a code on top, here is the full tutorial - https://github.com/KeyAuth/KeyAuth-CPP-Example?ysclid=m8qc7wsn7e566059205


HWND hwnd; 
RECT rc;

float WIDTH = 1000;
float HEIGHT = 560;

ImVec2 menu_size = { WIDTH, HEIGHT };

void move_window()
{
    ImGui::SetCursorPos({ 0, 0 });

    if (ImGui::InvisibleButton("Move_detector", ImVec2(menu_size)) || ImGui::IsItemActive())
    {
        GetWindowRect(hwnd, &rc);
        MoveWindow(hwnd, rc.left + ImGui::GetMouseDragDelta().x, rc.top + ImGui::GetMouseDragDelta().y, menu_size.x, menu_size.y, TRUE);
    }
}

int main(int, char**)
{
    WNDCLASSEXW wc;
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = NULL;
    wc.cbWndExtra = NULL;
    wc.hInstance = nullptr;
    wc.hIcon = LoadIcon(0, IDI_APPLICATION);
    wc.hCursor = LoadCursor(0, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszMenuName = L"ImGui";
    wc.lpszClassName = L"Example";
    wc.hIconSm = LoadIcon(0, IDI_APPLICATION);

    RegisterClassExW(&wc);
    hwnd = CreateWindowExW(NULL, wc.lpszClassName, L"Loader", WS_POPUP, (GetSystemMetrics(SM_CXSCREEN) / 2) - (WIDTH / 2), (GetSystemMetrics(SM_CYSCREEN) / 2) - (HEIGHT / 2), WIDTH, HEIGHT, 0, 0, 0, 0);

    SetWindowLongA(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);

    MARGINS margins = { -1 };
    DwmExtendFrameIntoClientArea(hwnd, &margins);

    POINT mouse;
    rc = { 0 };
    GetWindowRect(hwnd, &rc);

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOW);
    ::UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    //ImGui::StyleColorsLight();

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_menu.g_pd3dDevice, g_menu.g_pd3dDeviceContext);
    g_menu.setup();
    // Our state
    bool show_another_window = false;
    ImVec4 clear_color = ImVec4(0.f, 0.f, 0.f, 0.f);



    // Main loop
    bool done = false;
    while (!done)
    {
        // Poll and handle messages (inputs, window resize, etc.)
        // See the WndProc() function below for our to dispatch events to the Win32 backend.
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        // Handle window being minimized or screen locked
        if (g_SwapChainOccluded && g_menu.g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
        {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        // Handle window resize (we don't resize directly in the WM_SIZE handler)
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_menu.g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        g_menu.draw();
       
        // Rendering
        ImGui::Render();
        const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_menu.g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_menu.g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // Present
        HRESULT hr = g_menu.g_pSwapChain->Present(1, 0);   // Present with vsync
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

// Helper functions

bool CreateDeviceD3D(HWND hWnd)
{
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
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
    //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_menu.g_pSwapChain, &g_menu.g_pd3dDevice, &featureLevel, &g_menu.g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_menu.g_pSwapChain, &g_menu.g_pd3dDevice, &featureLevel, &g_menu.g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_menu.g_pSwapChain) { g_menu.g_pSwapChain->Release(); g_menu.g_pSwapChain = nullptr; }
    if (g_menu.g_pd3dDeviceContext) { g_menu.g_pd3dDeviceContext->Release(); g_menu.g_pd3dDeviceContext = nullptr; }
    if (g_menu.g_pd3dDevice) { g_menu.g_pd3dDevice->Release(); g_menu.g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_menu.g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_menu.g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
INLINE void toggle_key(int key, bool& flip, WPARAM wparam, UINT msg)
{
    if (wparam == key)
    {
        if (msg == WM_KEYUP)
            flip = !flip;
    }
}
// Win32 message handler
// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    toggle_key(VK_INSERT, g_menu.opened, wParam, msg);
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
