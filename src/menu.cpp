#include "menu.h"
#include "helpers.h"
#include <algorithm>
#include <time.h>
#include <imgui.h>
#include "color.h"
#include "bytes.h"
#include "games_bytes.h"
#include "games_bytesA.h"
#include <imgui_internal.h>
#include "descriptions.h"



void c_menu::setup()
{
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig cfg;
    cfg.OversampleH = 3;
    cfg.OversampleV = 3;
    font_600 = io.Fonts->AddFontFromMemoryTTF(font_600_ttf, sizeof(font_600_ttf), 30.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
    font_500 = io.Fonts->AddFontFromMemoryTTF(font_500_ttf, sizeof(font_500_ttf), 28.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
    font_400 = io.Fonts->AddFontFromMemoryTTF(font_400_ttf, sizeof(font_400_ttf), 28.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
    font_300 = io.Fonts->AddFontFromMemoryTTF(font_300_ttf, sizeof(font_300_ttf), 19.f, &cfg, io.Fonts->GetGlyphRangesCyrillic());
    D3DX11_IMAGE_LOAD_INFO iInfo;
    ID3DX11ThreadPump* threadPump{ nullptr };
    if (logo_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, logo_png, sizeof(logo_png), &iInfo, threadPump, &logo_t, 0);
    }
    if (setting_another_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, setting_another_png, sizeof(setting_another_png), &iInfo, threadPump, &setting_another_t, 0);
    }
    if (setting_mac_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, setting_mac_png, sizeof(setting_mac_png), &iInfo, threadPump, &setting_mac_t, 0);
    }
    if (user_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, user_png, sizeof(user_png), &iInfo, threadPump, &user_t, 0);
    }
    if (logout_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, logout_png, sizeof(logout_png), &iInfo, threadPump, &logout_t, 0);
    }
    if (enter_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, enter_png, sizeof(enter_png), &iInfo, threadPump, &enter_t, 0);
    }
    if (login_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, login_png, sizeof(login_png), &iInfo, threadPump, &login_t, 0);
    }
    if (password_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, password_png, sizeof(password_png), &iInfo, threadPump, &password_t, 0);
    }
    if (download_t == nullptr)
    {
        D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, download_png, sizeof(download_png), &iInfo, threadPump, &download_t, 0);
    }

    ID3D11ShaderResourceView* dota_t[2]{ nullptr, nullptr };
    ID3D11ShaderResourceView* gta_t[2]{ nullptr, nullptr };
    ID3D11ShaderResourceView* cs2_t[2]{ nullptr, nullptr };
    ID3D11ShaderResourceView* pubg_t[2]{ nullptr, nullptr };
    ID3D11ShaderResourceView* valorant_t[2]{ nullptr, nullptr };
    ID3D11ShaderResourceView* mine_t[2]{ nullptr, nullptr };
    ID3D11ShaderResourceView* fifa_t[2]{ nullptr, nullptr };

    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, dota2_pngA, sizeof(dota2_pngA), &iInfo, threadPump, &dota_t[1], 0);
    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, dota2_pngD, sizeof(dota2_pngD), &iInfo, threadPump, &dota_t[0], 0);

    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, gta_pngA, sizeof(gta_pngA), &iInfo, threadPump, &gta_t[1], 0);
    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, gta_pngD, sizeof(gta_pngD), &iInfo, threadPump, &gta_t[0], 0);

    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, cs2_pngA, sizeof(cs2_pngA), &iInfo, threadPump, &cs2_t[1], 0);
    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, cs2_pngD, sizeof(cs2_pngD), &iInfo, threadPump, &cs2_t[0], 0);

    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, pubg_pngA, sizeof(pubg_pngA), &iInfo, threadPump, &pubg_t[1], 0);
    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, pubg_pngD, sizeof(pubg_pngD), &iInfo, threadPump, &pubg_t[0], 0);

    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, valorant_pngA, sizeof(valorant_pngA), &iInfo, threadPump, &valorant_t[1], 0);
    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, valorant_pngD, sizeof(valorant_pngD), &iInfo, threadPump, &valorant_t[0], 0);

    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, mine_pngA, sizeof(mine_pngA), &iInfo, threadPump, &mine_t[1], 0);
    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, mine_pngD, sizeof(mine_pngD), &iInfo, threadPump, &mine_t[0], 0);

    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, fifa_pngA, sizeof(fifa_pngA), &iInfo, threadPump, &fifa_t[1], 0);
    D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, fifa_pngD, sizeof(fifa_pngD), &iInfo, threadPump, &fifa_t[0], 0);

    container.push_back(element_t("Fortnite", 3, mine_t[0], mine_t[1], -384.f));
    container.push_back(element_t("Dead By Daylight", 3, pubg_t[0], pubg_t[1], -119.f));

    container.push_back(element_t("Rust", 3, gta_t[0], gta_t[1], 146.f));
    container.push_back(element_t("Call Of Duty", 3, dota_t[0], dota_t[1], 411.f));//active is container[3]
    container.push_back(element_t("Universal Spoof", 3, cs2_t[0], cs2_t[1], 676.f));

  
}

void c_menu::draw()
{
    static auto reset = false;
    update_animation_speed();
    update_animation(alpha, opened, 0.1f);
    if (alpha <= 0.0f)
    {
        if (reset)
        {
            for (auto& a : item_animations)
            {
                a.second.reset();
            }
            reset = false;
        }

        //if (!opened) // you can use this in release project
        //    ((void(*)())uintptr_t(0x0))();//crash is more safety then exit();

        return;
    }
    reset = true;
    begin();
    {
        bg();
        user();
        main();
    }
    end();
}

void c_menu::begin()
{
    ImGui::SetNextWindowSize(ImVec2(1100.f, 800.f));
    ImGui::SetNextWindowPos({ 0, 0 });
    ImGui::Begin("Temporary Spoofer", nullptr, ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground);
}

int rotation_start_index;
void ImRotateStart() {
    rotation_start_index = ImGui::GetWindowDrawList()->VtxBuffer.Size;
}

ImVec2 ImRotationCenter() {
    ImVec2 l(FLT_MAX, FLT_MAX), u(-FLT_MAX, -FLT_MAX);

    const auto& buf = ImGui::GetWindowDrawList()->VtxBuffer;
    for (int i = rotation_start_index; i < buf.Size; i++) {
        l = ImMin(l, buf[i].pos);
        u = ImMax(u, buf[i].pos);
    }

    return ImVec2((l.x + u.x) / 2, (l.y + u.y) / 2); // _ClipRectStack
}

ImVec2 ImRotates(const ImVec2& v, float s, float c) {
    return ImVec2(v.x * c - v.y * s, v.x * s + v.y * c);
}

void ImRotateEnd(float rad, ImVec2 center = ImRotationCenter()) {
    float s = sinf(rad), c = cosf(rad);
    center = ImRotates(center, s, c) - center;

    auto& buf = ImGui::GetWindowDrawList()->VtxBuffer;
    for (int i = rotation_start_index; i < buf.Size; i++) {
        buf[i].pos = ImRotates(buf[i].pos, s, c) - center;
    }
}

void c_menu::bg()
{
    GImGui->Style.WindowRounding = 24.f;

    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 pos_window = ImGui::GetWindowPos();
    ImVec2 size_window = ImGui::GetWindowSize();

    list->AddRectFilled(pos_window, pos_window + size_window, c_color(10, 10, 10).new_alpha(alpha * 255).u32(), 25.f);

    anim_t* anim_bg = animation("logo_bg", { clamp_out | lerp_anim, 0.1f });
    anim_t* anim_rot = animation("logo_bg_rot", { clamp_out, 0.015f });
    anim_t* anim_main = animation("logo_main", { clamp_out | lerp_anim, 0.09f });

    float offset_bg = 52.f - (52.f * anim_bg->extra(i_bz4));

    ImRotateStart();
   
    list->AddImage(ImTextureID(logo_t), pos_window + ImVec2(105.f, 400.f + offset_bg),
        pos_window + ImVec2(105.f, 400.f + offset_bg) + ImVec2(923.f, 437.f), ImVec2(0, 0), ImVec2(1, 1), c_color(255, 255, 255).new_alpha((alpha * 0.02f) * 255).u32());

    float rot = anim_rot->extra(i_bz4 | i_clamp);

    if (login_screen)
    {
        ImRotateEnd(helpers::deg2rad(max(rot - anim_main->val, 0.f) * 1.5f));
    }
    else
    {
        ImRotateEnd(helpers::deg2rad(max(rot, 0.f) * 1.5f));
    }
    if (anim_rot->val >= 0.99f)
    {
        anim_rot->active = false;
    }
    else if (anim_rot->val <= 0.01f)
    {
        anim_rot->active = true;
    }

    if (anim_main->val >= 0.7f)
    {
        if (login_screen)
        {
            anim_rot->val = 0.f;
        }
        login_screen = false;
    }
    list->AddShadowCircle(pos_window + ImVec2(550.f, 915.f + 70.f), 380.f, c_color(200, 91, 242, 0.57f * alpha * 255).u32(), 562.f + 190.f, ImVec2(0.f, 0.f));
    float offset_main_a = anim_main->extra(i_elastic);
    ImVec2 offset_main = ImVec2(462.f * offset_main_a, (login_screen ? 70.f * helpers::bz4(1.f - alpha) : 0.f) + 193.f * offset_main_a);

    list->AddImage(ImTextureID(logo_t), pos_window + ImVec2(502.f - offset_main.x, 233.f - offset_main.y),
        pos_window + ImVec2(502.f - offset_main.x, 233.f - offset_main.y) + ImVec2(95.f, 44.f), ImVec2(0, 0), ImVec2(1, 1), c_color(255, 255, 255, alpha * 255).u32());
}

void c_menu::user()
{
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 pos_window = ImGui::GetWindowPos();
    ImVec2 size_window = ImGui::GetWindowSize();

    anim_t* anim_user = animation("user_main", { clamp_out | lerp_anim, 0.1f });

    if (!login_screen)
    {
        if (alpha >= 0.45f)
        {
            anim_user->active = true;
            float size_x = 15.f + 400.f * anim_user->extra(i_bounce);

            list->AddRectFilledMultiColor(pos_window + ImVec2(size_window.x - 40.f - size_x - 0.75f, 30.f - 0.75f),
                pos_window + ImVec2(size_window.x - 40.f + 0.75f, 110.f + 0.75f),
                c_color(32, 12, 19, 0).u32(), c_color(126, 26, 182, alpha * 255 * anim_user->val).u32(),
                c_color(126, 26, 182, alpha * 255 * anim_user->val).u32(), c_color(32, 12, 19, 0).u32(), 51.f, ImDrawFlags_RoundCornersAll
            );

            if (alpha >= 0.9f)
                list->AddRectFilled(pos_window + ImVec2(size_window.x - 40.f - size_x, 30.f), pos_window + ImVec2(size_window.x - 40.f, 110.f),
                    c_color(10, 10, 10, alpha * 255 * anim_user->val).u32(), 51.f);

            list->AddRectFilledMultiColor(pos_window + ImVec2(size_window.x - 40.f - size_x, 30.f), pos_window + ImVec2(size_window.x - 40.f, 110.f),
                c_color(17, 17, 17, 0).u32(), c_color(126, 26, 182, alpha * 255 * anim_user->val).u32(),
                c_color(126, 26, 182, alpha * 255 * anim_user->val).u32(), c_color(17, 17, 17, 0).u32(), 51.f, ImDrawFlags_RoundCornersAll
            );

            float size_x2 = 15.f + 400.f * anim_user->extra(i_bz4);
            list->PushClipRect(pos_window + ImVec2(size_window.x - 40.f - 400.f, 30.f), pos_window + ImVec2(size_window.x - 80.f, 110.f));
            list->AddText(font_600, 24.f,
                pos_window + ImVec2(size_window.x - 40.f - size_x2 + 226.f, 48.f),
                c_color(255, 255, 255, alpha * 255 * anim_user->extra(i_bz4)).u32(), "Claudziaa");

            list->AddText(font_300, 16.f,
                pos_window + ImVec2(size_window.x - 40.f - size_x2 + 286.f, 71.f),
                c_color(97, 97, 97, alpha * 255 * anim_user->extra(i_bz4)).u32(), "logout");

            ImVec2 logout_t_pos = pos_window + ImVec2(size_window.x - 40.f - size_x2 + 272.f, 76.f);
            list->AddImage(ImTextureID(logout_t), logout_t_pos, logout_t_pos + ImVec2(10.f, 11.f));
            if (anim_user->val >= 0.7f)
            {
                ImGui::SetCursorPos(ImVec2(size_window.x - 40.f - size_x2 + 272.f, 76.f));
                if (ImGui::InvisibleButton("logout", ImVec2(60.f, 11.f)))
                {
                    get_anim_obj(CONST_HASH("logo_main"))->reset();
                    get_anim_obj(CONST_HASH("subscribetab"))->reset();
                    get_anim_obj(CONST_HASH("settingstab"))->reset();
                    get_anim_obj(CONST_HASH("helptab"))->reset();
                    get_anim_obj(CONST_HASH("injtab"))->reset();
                    switch_screen = false;
                    login_screen = true;
                    anim_user->active = false;
                    if (screen_numb == 3)
                    {
                        screen_numb = 0;
                    }
                }

            }

            list->AddText(font_300, 18.f,
                pos_window + ImVec2(size_window.x - 40.f - size_x2 + 61.f, 51.f),
                c_color(97, 97, 97, alpha * 255 * anim_user->extra(i_bz4)).u32(), "Subscribe until:");

            list->AddText(font_600, 19.f,
                pos_window + ImVec2(size_window.x - 40.f - size_x2 + 85.f, 71.f),
                c_color(255, 255, 255, alpha * 255 * anim_user->extra(i_bz4)).u32(), "22/06/25");
            list->PopClipRect();
            ImRotateStart();
            //render circle img
            list->PushTextureID(ImTextureID(user_t));
            int vert_start_idx = list->VtxBuffer.Size;
            list->AddCircleFilled(pos_window + ImVec2(size_window.x - 50.f - 30.f, 40.f + 30.f), 30.f * anim_user->extra(i_elastic),
                c_color(255, 255, 255, std::clamp(int(alpha * 255 * anim_user->val * 1.5f), 0, 255)).u32());
            int vert_end_idx = list->VtxBuffer.Size;
            ImGui::ShadeVertsLinearUV(list, vert_start_idx, vert_end_idx,
                pos_window + ImVec2(size_window.x - 35.f - 91.f, 38.f),
                pos_window + ImVec2(size_window.x - 35.f, 38.f + 64.f), ImVec2(0, 0), ImVec2(1, 1), true);
            list->PopTextureID();
            //
            ImRotateEnd(helpers::deg2rad(360.f * anim_user->extra(i_bounce)));
        }
    }
}

void c_menu::tabs()
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();

    anim_t* anim_global = animation("tabs_main", { clamp_out , 0.04f });
    anim_global->active = true;

    ImRotateStart();
    float y_pos = 55.f - 100.f * anim_global->extra(i_inverse | i_inv_bounce);
    int old_screen_numb = screen_numb;

    if (tab("subscribe", screen_numb == 0, ImVec2(207.f, y_pos), 97.f) && screen_numb != 3)
        screen_numb = 0;
    if (tab("help", screen_numb == 1, ImVec2(207.f, y_pos) + ImVec2(147.f, 0.f), 45.f) && screen_numb != 3)
        screen_numb = 1;
    if (tab("settings", screen_numb == 2, ImVec2(207.f, y_pos) + ImVec2(242.f, 0.f), 81.f) && screen_numb != 3)
        screen_numb = 2;
    if (switch_to_inject)
    {
        screen_numb = 3;
        switch_to_inject = false;
    }

    anim_t* anim_line = animation("tabs_line", { clamp_out , 0.04f });
    if (anim_global->val >= 0.7f)
    {
        anim_line->active = true;
        float yline_pos = 81.f - 130.f * anim_global->extra(i_inverse | i_inv_bounce);
        float xline_pos = 207.f;
        float xline_size = 52.f;
        static float old_xline_pos = 207.f;
        static float old_xline_size = 52.f;
        if (screen_numb == 1)
        {
            xline_pos = 207.f + 147.f;
            xline_size = 24.f;
        }
        else if (screen_numb == 2)
        {
            xline_pos = 207.f + 242.f;
            xline_size = 43.f;
        }
        else if (screen_numb == 3)
        {
            xline_pos = 207.f + 242.f + 81.f + 50.f;
            xline_size = 0.f;
        }
        anim_t* anim_old_line = animation("tabs_old_line", { clamp_out , 0.04f });
        if (old_screen_numb != screen_numb)
        {
            anim_old_line->active = true;
            anim_old_line->val = 0.f;
            if (old_xline_pos == xline_pos)
            {
                old_xline_pos = 207.f;
                old_xline_size = 52.f;
                if (old_screen_numb == 1)
                {
                    old_xline_pos = 207.f + 147.f;
                    old_xline_size = 24.f;
                }
                else if (old_screen_numb == 2)
                {
                    old_xline_pos = 207.f + 242.f;
                    old_xline_size = 43.f;
                }
                else if (old_screen_numb == 3)
                {
                    old_xline_pos = 207.f + 242.f + 81.f + 50.f;
                    old_xline_size = 0.f;
                }
            }
        }
        if (anim_old_line->val >= 0.99f)
        {
            old_xline_pos = xline_pos;
            old_xline_size = xline_size;
            anim_old_line->active = false;
            anim_old_line->val = 0.f;
        }
        ImVec2 line_pos = window->Pos + ImVec2(helpers::lerp(old_xline_pos, xline_pos, anim_old_line->extra(i_elastic)), yline_pos);
        int alpha_ex = alpha * 255 * anim_line->val;
        float sz_x = helpers::lerp(old_xline_size, xline_size, anim_old_line->extra(i_elastic));
        if (screen_numb == 3)
        {
            alpha_ex = alpha * 255 * anim_line->val * sz_x;
            alpha_ex = std::clamp(alpha_ex, 0, 255);
        }
        window->DrawList->AddRectFilledMultiColor(line_pos, line_pos +
            ImVec2(sz_x, 2.f),
            c_color(42, 9, 19, alpha_ex).u32(),
            c_color(200, 91, 242, alpha_ex).u32(),
            c_color(200, 91, 242, alpha_ex).u32(),
            c_color(42, 9, 19, alpha_ex).u32(),
            10.f, ImDrawFlags_RoundCornersAll);
    }

    ImRotateEnd(helpers::deg2rad(-90.f * anim_global->extra(i_inverse | i_inv_elastic)));
}

bool c_menu::tab(const char* label, bool selected, ImVec2 pos, float sz_x)
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    
    anim_t* anim_main = animation((std::string(label) + "tab").c_str(), { clamp_out, 0.1f });
    anim_t* anim_global = get_anim_obj(CONST_HASH("tabs_main"));
    c_color active = c_color(200, 91, 242, 255);
    c_color disable = c_color(97, 97, 97, 255);
    ImVec2 main_pos = window->Pos + pos;
    window->DrawList->AddText(font_400, 24.f,
        main_pos,
        disable.multiply(active, anim_main->val * anim_global->val).new_alpha(alpha * 255 * anim_global->val).u32(),
        label);

    anim_main->active = selected;

    ImGui::SetCursorPos(pos);
    bool ret = ImGui::InvisibleButton((std::string(label) + "tab").c_str(), ImVec2(sz_x, 23.f));

    return ret;
}

void c_menu::setting_screen()
{
    anim_t* anim_settings = get_anim_obj(CONST_HASH("settingstab"));
    if (anim_settings->val > 0.1f)
    {
        ImGuiWindow* window = ImGui::GetCurrentWindow();
        ImVec2 pos_ch = ImVec2();
        if (anim_settings->active)
        {
            pos_ch = ImVec2(0.f, 500.f * anim_settings->extra(i_inverse | i_inv_bounce));
            ImRotateStart();
        }
        else
        {
            pos_ch = ImVec2(1000.f * anim_settings->extra(i_inverse), 0.f);
        }
        
        setting_left(pos_ch);
        setting_right(pos_ch);

        if (anim_settings->active)
        {
            ImRotateEnd(helpers::deg2rad(90.f * anim_settings->extra(i_inverse | i_inv_elastic)));
        }

        //�������� � 2 ����� ��-�� ImRotateEnd
        setting_left_active_section(pos_ch);
    }
}

void c_menu::setting_left(ImVec2 pos_ch)
{
    anim_t* anim_settings = get_anim_obj(CONST_HASH("settingstab"));
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    ImVec2 pos = window->Pos + pos_ch;
    window->DrawList->AddText(font_600, 30.f, pos + ImVec2(177.f, 230.f),
        c_color(255, 255, 255, alpha * 255 * anim_settings->val).u32(), "Settings");
    ImVec2 main_posL = pos + ImVec2(80.f, 305.f);
    ImVec2 end_posL = main_posL + ImVec2(463.f, 431.f);

    window->DrawList->AddShadowRectBBB(main_posL, end_posL, c_color(0, 0, 0, alpha * 255 * anim_settings->val).u32(),
        20.f, ImVec2(0.f, 0.f), 0, 20.f
    );
    window->DrawList->AddRectFilledMultiColor(main_posL, end_posL,
        c_color(10, 10, 10, alpha * 255 * anim_settings->val).u32(),
        c_color(12, 9, 10, alpha * 255 * anim_settings->val).u32(),
        c_color(35, 14, 21, alpha * 255 * anim_settings->val).u32(),
        c_color(17, 11, 13, alpha * 255 * anim_settings->val).u32(),
        20.f, ImDrawFlags_RoundCornersAll
    );
    window->DrawList->AddShadowRectBBB(ImVec2(main_posL.x - 1.f, pos.y + 405.f),
        ImVec2(main_posL.x + 1.f, pos.y + 455.f), c_color(200, 91, 242, alpha * 255 * anim_settings->val).u32(),
        30.f, ImVec2(0.f, 0.f), 0, 3.f
    );

    window->DrawList->AddRectFilled(ImVec2(main_posL.x - 1.f, pos.y + 405.f),
        ImVec2(main_posL.x + 1.f, pos.y + 455.f),
        c_color(200, 91, 242, alpha * 255 * anim_settings->val).u32(), 3.f, ImDrawFlags_RoundCornersAll);
}

void c_menu::setting_left_active_section(ImVec2 pos_ch)
{
    anim_t* anim_settings = get_anim_obj(CONST_HASH("settingstab"));
    //active section
    ImGui::SetCursorPos(ImVec2(80.f + pos_ch.x, 355.f + pos_ch.y));
    ImGui::BeginChild("setting_left", ImVec2(460.f, 380.f), 0, ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground);
    {
        if (anim_settings->active)
            ImRotateStart();

        const char* desc_mac[3] = {
            "Allows you to spoof network adapters",
            "(Ethernet & Wi-Fi MAC addresses).",
            "Uncheck if it disrupts your internet."
        };
        const char* desc_clean[3] = {
            "Clears Windows Prefetch, Event Logs,",
            "and ETW traces during spoofing.",
            "Saved login tokens are kept safe."
        };

        checkbox("Spoof Network MAC", desc_mac, 3, &ui::g_spoofNetwork, setting_mac_t, ImVec2(31.f, 22.f));
        checkbox("Clean Trace Artifacts", desc_clean, 3, &ui::g_cleanTraces, setting_another_t, ImVec2(22.f, 22.f));
        
        if (anim_settings->active)
            ImRotateEnd(helpers::deg2rad(90.f * anim_settings->extra(i_inverse | i_inv_elastic)));
    }
    ImGui::EndChild();
}

void c_menu::setting_right(ImVec2 pos_ch)
{
    anim_t* anim_settings = get_anim_obj(CONST_HASH("settingstab"));
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    ImVec2 pos = window->Pos + pos_ch;
    ImVec2 main_posR = pos + ImVec2(557.f, 305.f);
    ImVec2 end_posR = main_posR + ImVec2(463.f, 250.f);
    window->DrawList->AddShadowRectBBB(main_posR, end_posR, c_color(0, 0, 0, alpha * 255 * anim_settings->val).u32(),
        20.f, ImVec2(0.f, 0.f), 0, 20.f
    );
    window->DrawList->AddRectFilledMultiColor(main_posR, end_posR,
        c_color(10, 9, 9, alpha * 255 * anim_settings->val).u32(),
        c_color(9, 9, 9, alpha * 255 * anim_settings->val).u32(),
        c_color(14, 10, 11, alpha * 255 * anim_settings->val).u32(),
        c_color(21, 11, 14, alpha * 255 * anim_settings->val).u32(),
        20.f, ImDrawFlags_RoundCornersAll
    );

    window->DrawList->AddShadowRectBBB(main_posR + ImVec2(-1.f, 100.f),
        main_posR + ImVec2(1.f, 150.f), c_color(200, 91, 242, alpha * 255 * anim_settings->val).u32(),
        30.f, ImVec2(0.f, 0.f), 0, 3.f
    );

    window->DrawList->AddRectFilled(main_posR + ImVec2(-1.f, 100.f),
        main_posR + ImVec2(1.f, 150.f),
        c_color(200, 91, 242, alpha * 255 * anim_settings->val).u32(), 3.f, ImDrawFlags_RoundCornersAll);

    window->DrawList->AddText(font_300, 18.f,
        main_posR + ImVec2(101.f, 30.f),
        c_color(97, 97, 97, alpha * 255 * anim_settings->val).u32(), "To work, you need to turn off");
    window->DrawList->AddText(font_300, 18.f,
        main_posR + ImVec2(101.f, 50.f),
        c_color(97, 97, 97, alpha * 255 * anim_settings->val).u32(), "the following:");

    //active section
    float off_y = 0.f;
    setting_right_disablers("TMP", "is disabled", main_posR, off_y, true);
    setting_right_disablers("WI-FI", "is disabled", main_posR, off_y, false, 159.f);
    setting_right_disablers("USB", "is disconnected", main_posR, off_y, true);
}

void c_menu::setting_right_disablers(const char* main, const char* sec, ImVec2 pos, float &off_y, bool active, float off_x)
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    anim_t* anim_settings = get_anim_obj(CONST_HASH("settingstab"));

    window->DrawList->AddText(font_500, 24.f,
        pos + ImVec2(100.f, 100.f + off_y),
        c_color(200, 91, 242, alpha * 255 * anim_settings->val).u32(), main);
    window->DrawList->AddText(font_500, 24.f,
        pos + ImVec2(off_x, 100.f + off_y),
        c_color(255, 255, 255, alpha * 255 * anim_settings->val).u32(), sec);

    c_color act = c_color(97, 97, 97, 0.25f * alpha * 255 * anim_settings->val);
    if (active)
    {
        act = c_color(200, 91, 242, alpha * 255 * anim_settings->val);
        window->DrawList->AddShadowCircle(pos + ImVec2(50.f + 10.f, 100.f + 12.5f + off_y),
            10.f, c_color(200, 91, 242, 0.75f * alpha * 255 * anim_settings->val).u32(), 20.f, ImVec2(0.f, 0.f));
        ImGui::RenderCheckMark(window->DrawList, pos + ImVec2(50.f + 5.f, 100.f + 7.f + off_y), act.u32(), 10.f);
    }
    window->DrawList->AddCircle(pos + ImVec2(50.f + 10.f, 100.f + 12.5f + off_y),
        10.f, act.u32());

    off_y += 40.f;
}

void c_menu::subscribe_screen()
{
    subscribe_games();
    subscribe_inject();
}

void c_menu::subscribe_games()
{
    anim_t* anim_subscribe = get_anim_obj(CONST_HASH("subscribetab"));
    anim_t* anim_inj = animation("injtab", { clamp_out, 0.2f }); anim_inj->active = screen_numb == 3;
    anim_t* anim_games = animation("games", { clamp_out, 0.08f });
    anim_t* anim_desc = animation("games_desc", { clamp_out, 0.08f });
    if (anim_subscribe->val > 0.1f)
    {
        ImGuiWindow* window = ImGui::GetCurrentWindow();

        static bool right_s = false;
        static bool left_s = false;
        static bool move_mouse = false;
        static bool move_mouse_old = false;
        static float mouse_x = ImGui::GetIO().MousePos.x;
        static float fix_bug_pos = 0.f;
        static float fix_pos = 0.f;
        static float rot = 0.f;
        static int side = 1;
        float active_x = 550.f;
        float x{};
        float old_x{};
        float add_x = 0.f;
        float inv_add_x = 0.f;
        bool set_false = false;
        bool best_scale = 0.f;
        float gen2 = 0.f;
        float act_sect = 139.f - 15.f;

        if (left_s || right_s)
        {
            anim_games->active = true;
        }

        const ImRect bb(window->Pos + ImVec2(0.f, 164.f), window->Pos + ImVec2(0.f, 164.f) + ImVec2(1100.f, 390.f));
        const ImGuiID id = window->GetID("games_mouse");
        ImGui::SetCursorPos(ImVec2(400.f, 643.f + 60.f * extra_alpha));
        if (button("Start", false, anim_subscribe->val))
        {
            switch_to_inject = true;
            if (!ui::g_isExecuting.load()) {
                ui::g_isExecuting = true;
                ui::g_statusMessage = "Spoofing Hardware...";
                ui::add_log("[+] Starting hardware spoof operation...");
                bool clean_opt = ui::g_cleanTraces;
                bool net_opt = ui::g_spoofNetwork;
                struct thread_params { bool clean; bool net; };
                thread_params* p = new thread_params{ clean_opt, net_opt };
                CreateThread(nullptr, 0, [](LPVOID lpParam) -> DWORD {
                    thread_params* params = (thread_params*)lpParam;
                    bool do_clean = params->clean;
                    bool do_net = params->net;
                    delete params;
                    if (!spoof::preflight::run()) {
                        ui::add_log("[-] Preflight failed - operation aborted.");
                        ui::g_statusMessage = "Preflight Failed!";
                    } else {
                        spoof::install(do_clean, do_net);
                        ui::add_log("[+] Hardware spoof completed!");
                        ui::g_statusMessage = "Spoof Complete!";
                    }
                    ui::g_isExecuting = false;
                    return 0;
                }, p, 0, nullptr);
            }
        }
        if (!anim_games->active)
        {
            if (ImGui::GetIO().MouseDown[0] &&
                ImGui::IsMouseHoveringRect(window->Pos + ImVec2(0.f, 164.f), window->Pos + ImVec2(1100.f, 164.f + 390.f)))
            {
                move_mouse = true;
            }
            if (!ImGui::GetIO().MouseDown[0])
            {
                move_mouse = false;
            }
            if (move_mouse)
            {
                add_x = -(mouse_x - ImGui::GetIO().MousePos.x);
                inv_add_x = -(add_x / 2.f);
                if (active_game == 0 && add_x > 0.f)
                {
                    add_x = 0.f;
                }
                else if (active_game == int(container.size()) - 1 && add_x < 0.f)
                {
                    add_x = 0.f;
                }
                else
                {
                    inv_add_x = 0.f;
                }
            }
        }
        else
        {
            move_mouse = false;
            move_mouse_old = false;
            fix_pos = 0.f;
        }
        mouse_x = ImGui::GetIO().MousePos.x;


        int i = 0;
        for (auto& element : container)
        {
            anim_t* anim_update = animation((std::string(element.name) + "update").c_str(), { clamp_out, 0.1f });
            float offset = 0.f;
            if (i < active_game)
            {
                offset = -15.f;
            }
            else if (i > active_game)
            {
                offset = 15.f;
            }

            float element_buff = element.x + add_x;
            if (anim_games->active)
            {
                element_buff += float(265.f * side) * anim_games->extra(i_elastic);
                if (anim_games->val >= 1.0f)
                {
                    element.x += float(265.f * side);
                    set_false = true;
                }
            }

            if (i == 0)
            {
                rot = element_buff - element.old_x;
            }

            if (move_mouse)
            {
                element.x = element_buff;
                move_mouse_old = true;
            }
            else
            {
                element.x += fix_pos + fix_bug_pos;
            }
            float gen = fabsf((element_buff + act_sect) - active_x);
            float scale = 0.f;
            if (gen < act_sect - 1.f)
            {
                scale = (act_sect - gen) / act_sect;
            }

            float extra_size = 0.1f * rot;
            if (scale > 0.f)
            {
                extra_size = 1.2f * rot * scale;
            }
            ImVec2 pos = window->Pos +
                ImVec2(element_buff - 14.f * scale + offset - extra_size / 2.f - inv_add_x,
                    204.f - 40.f * scale - extra_size / 2.f);

            ImVec2 size = ImVec2(250.f + 28.f * scale + extra_size / 2.f, 350.f + 40.f * scale + extra_size / 2.f);
            if (scale > best_scale)
            {
                element.active = true;
                best_scale = scale;
                gen2 = -((element_buff + act_sect) - active_x);
            }
            else
            {
                element.active = false;
            }
            if (element.active)
            {
                active_game = i;
            }

            if (fabsf(rot) > 0.f)
                ImRotateStart();
            if ((1.f - scale) > 0.f)
            {
                window->DrawList->AddImageRounded(ImTextureID(element.game_t),
                    pos, pos + size, ImVec2(0, 0), ImVec2(1, 1),
                    c_color(255, 255, 255, 255 * alpha * anim_subscribe->val * (1.f - scale)).u32(), 20.f);
            }
            if (scale > 0.f)
            {
                c_color act_text = c_color(200, 91, 242);
                ImVec2 text_size = font_600->CalcTextSizeA(24.f + 6.f * scale, FLT_MAX, -1.f, element.name);
                float glob_a = alpha * anim_subscribe->val * scale;

                if (anim_inj->active && i == active_game)
                {
                    rot = 0.f;
                    glob_a = alpha * anim_subscribe->val * scale * anim_inj->inverse();
                    ImVec2 pos2 = window->Pos + ImVec2(411.f + (278.f / 2.f) * anim_inj->val, 164.f + (390.f / 2.f) * anim_inj->val);
                    window->DrawList->AddImageRounded(ImTextureID(element.Agame_t),
                        pos2, pos2 + ImVec2(278.f * anim_inj->inverse(), 390.f * anim_inj->inverse()), ImVec2(0, 0), ImVec2(1, 1),
                        c_color(255, 255, 255, 255 * anim_inj->inverse()).u32(), 20.f);
                }
                else
                {
                    window->DrawList->AddImageRounded(ImTextureID(element.Agame_t),
                        pos, pos + size, ImVec2(0, 0), ImVec2(1, 1),
                        c_color(255, 255, 255, 255 * glob_a).u32(), 20.f);
                }
                window->DrawList->AddText(font_600, 24.f + 6.f * scale,
                    pos + ImVec2(size.x / 2.f - text_size.x / 2.f, size.y + 24.f * scale),
                    act_text.grayscale().multiply(act_text, glob_a).new_alpha(255 * glob_a).u32(), element.name);

                if (anim_subscribe->val > 0.22f)
                {
                    anim_update->active = element.has_update;
                    if (anim_update->val > 0.1f)
                    {
                        //update
                        if (anim_inj->active && i == active_game)
                        {
                            pos = window->Pos + ImVec2(411.f + (278.f / 2.f) * anim_inj->val, 164.f + (390.f / 2.f) * anim_inj->val);
                        }
                        glob_a *= anim_update->val;
                        window->DrawList->AddText(font_600, 3.f + 12.f * anim_inj->inverse(),
                            pos + ImVec2(20.f, -21.f),
                            c_color(255, 255, 255).grayscale().multiply(c_color(255, 255, 255), glob_a).new_alpha(255 * glob_a).u32(), "Update!");
                        window->DrawList->AddShadowCircle(pos - ImVec2(-7.5f, 6.f + 7.5f), 3.f + 4.5f * anim_inj->inverse(),
                            act_text.grayscale().multiply(act_text, glob_a).new_alpha(255 * glob_a).u32(),
                            3.f + 27.f * anim_inj->inverse(), ImVec2(0.f, 0.f));
                        window->DrawList->AddCircleFilled(pos - ImVec2(-7.5f, 6.f + 7.5f), 3.f + 4.5f * anim_inj->inverse(),
                            act_text.grayscale().multiply(act_text, glob_a).new_alpha(255 * glob_a).u32(), 30);

                        //bot
                        window->DrawList->AddCircleFilled(pos + ImVec2(30.f, 30.f), 3.f + 12.f * anim_inj->inverse(),
                            act_text.grayscale().multiply(act_text, glob_a).new_alpha(255 * glob_a).u32(), 30);
                        window->DrawList->AddImage(ImTextureID(download_t),
                            pos + ImVec2(25.f, 24.f), pos + ImVec2(25.f, 24.f) + ImVec2(10.f, 12.f), ImVec2(0, 0), ImVec2(1, 1),
                            c_color(255, 255, 255, 255 * glob_a).u32());

                        if (element.has_update)
                        {
                            if (ImGui::GetIO().MouseClicked[0] &&
                                ImGui::IsMouseHoveringRect(pos + ImVec2(15.f, 15.f), pos + ImVec2(45.f, 45.f)) && scale > 0.9f)
                            {
                                element.has_update = false;
                            }
                        }
                    }
                }
                else
                {
                    anim_update->reset();
                }
            }
            if (fabsf(rot) > 0.f)
            {
                if (scale > 0.f)
                {
                    ImRotateEnd(helpers::deg2rad(0.41f * rot * scale));
                }
                else
                {
                    ImRotateEnd(helpers::deg2rad(-0.07f * rot));
                }
            }
            element.old_x = element_buff;
            i++;
        }

        static int act_ex = active_game;
        anim_desc->active = !anim_games->active;
        if (!anim_games->active && int(gen2) == 0)
        {
            act_ex = active_game;
        }

        if (anim_desc->val > 0.0f && fabsf(fix_bug_pos) == 0.f)
        {
            window->DrawList->PushClipRect(window->Pos, window->Pos + ImVec2(1100.f, 643.f + 60.f * extra_alpha));
            c_color act_text = c_color(255, 219, 230);
            float ex_scale = 0.f;
            //weird bc msvc compl
            if (anim_desc->active && !(int(gen2) == 0))
            {
                if (fabsf(gen2) < act_sect - 1.f)
                {
                    ex_scale = (act_sect - fabsf(gen2)) / act_sect;
                    anim_desc->val = ex_scale;
                }
                else
                {
                    anim_desc->active = false;
                    anim_desc->val = 0.f;
                }
            }
            else
            {
                ex_scale = 0.f;
                if (act_ex != active_game)
                {
                    ex_scale = anim_desc->val;
                }
                else if (fabsf(gen2) < act_sect - 1.f)
                {
                    ex_scale = anim_desc->val;
                }
            }
            float glob_a = alpha * anim_subscribe->val * ex_scale;

            float ex_y = 90.f * (1.f - (anim_subscribe->val * ex_scale));

            if (container[act_ex].desc_ > 0)
            {
                int act_ex_ex = act_ex;
                if (!anim_games->active)
                {
                    act_ex_ex = active_game;
                }
                float off_y = -5.f;
                for (int j = 0; j < container[act_ex_ex].desc_; j++)
                {
                    ImVec2 text_size = font_600->CalcTextSizeA(15.f + 4.f * ex_scale, FLT_MAX, -1.f, desc_G[act_ex_ex][j]);
                    window->DrawList->AddText(font_600, 15.f + 4.f * ex_scale,
                        window->Pos + ImVec2(active_x - text_size.x / 2.f, 579.f + 73.f - 25.f + ex_y + off_y),
                        act_text.grayscale().multiply(act_text, glob_a).new_alpha(0.7f * 255 * glob_a).u32(),
                        desc_G[act_ex_ex][j]);
                    off_y += 23.f;
                }
            }

            window->DrawList->PopClipRect();
        }


        if (!move_mouse && move_mouse_old)
        {
            fix_pos = gen2 * 0.1f;
            move_mouse_old = false;
        }
        else if (!anim_games->active)
        {
            fix_pos = gen2 * 0.1f;
            if (int(gen2) == 0)
            {
                fix_pos = 0.f;
            }
            if (gen2 == 0.f)
            {
                fix_bug_pos = -(container[active_game].x + act_sect - active_x) * 0.1f;
            }
            else
            {
                fix_bug_pos = 0.f;
            }
        }
        else
        {
            fix_pos = 0.f;
        }
        if (set_false)
        {
            anim_games->active = false;
            anim_games->val = 0.f;
        }
        right_s = false;
        left_s = false;

        if (active_game != 0)
        {
            ImGui::SetCursorPos(ImVec2(30.f, 387.f));
            if (arrow_button("right", true) && !anim_games->active)
            {
                side = 1;
                right_s = true;
            }
        }

        if (active_game != int(container.size()) - 1)
        {
            ImGui::SetCursorPos(ImVec2(1045.f, 387.f));
            if (arrow_button("left") && !anim_games->active)
            {
                side = -1;
                left_s = true;
            }
        }
        bool hovered = false, held = false;
        ImGui::ButtonBehavior(bb, id, &hovered, &held);

    }
    else
    {
        anim_games->reset();
        anim_desc->reset();
    }
}

void c_menu::subscribe_inject()
{
    anim_t* anim_inj = get_anim_obj(CONST_HASH("injtab"));
    anim_t* anim_inj_sec = animation("injsectab", { clamp_out, 0.2f }); anim_inj_sec->active = anim_inj->val >= 0.99f;
    anim_t* anim_inj_tri = animation("injtritab", { clamp_out, 0.1f }); anim_inj_tri->active = anim_inj_sec->val >= 0.99f;
    anim_t* anim_inj_triROT = animation("injtriROTtab", { clamp_out | lerp_anim, 0.1f }); anim_inj_triROT->active = anim_inj_tri->val >= 0.25f;
    anim_t* anim_inj_final = animation("injfinaltab", { clamp_out, 0.004f }); anim_inj_final->active = anim_inj_triROT->val >= 0.99f;
    anim_t* anim_inj_final_ex = animation("injfinalextab", { clamp_out, 0.02f });
    anim_t* anim_inj_notify = animation("injnotify", { clamp_out | lerp_anim, 0.1f });
    static int timer = 0;
    if (anim_inj_sec->val > 0.1f)
    {
        ImGui::SetCursorPos(ImVec2(400.f, 627.f + 43.f * extra_alpha + 150.f * anim_inj_tri->extra(i_inverse | i_inv_bounce)));
        if (button("Back", false, anim_inj_tri->val * anim_inj->val) || (timer > 2 && anim_inj_notify->val < 0.3f))
        {
            screen_numb = 0; timer = 0;
            anim_inj_notify->reset();
        }
        ImGuiWindow* window = ImGui::GetCurrentWindow();
        auto& element = container[active_game];
        float r = 182.f * anim_inj_sec->extra(i_elastic);
        ImVec2 pos2 = window->Pos + ImVec2(368.f + 182.f, 253.f + 182.f);

        //prog circle
        float lc = 45.f - 270.f * anim_inj_tri->extra(i_inverse | i_bz4) - 270.f * anim_inj_final->val;
        float rc = 225.f;
        c_color line = c_color(200, 91, 242, alpha * 255 * anim_inj_sec->val * anim_inj_tri->val * anim_inj->val);
        if (lc == -225.f && anim_inj_final->active)
        {
            line.change_alpha(100 * anim_inj->val + 155 * anim_inj_final_ex->val * anim_inj->val);
            window->DrawList->AddShadowCircle(pos2, 184.f,
                line.u32(), 50.f + 150.f * anim_inj_final_ex->val, ImVec2(0.f, 0.f));
            if (anim_inj_final_ex->val >= 0.9f)
            {
                anim_inj_final_ex->active = false;
                timer++;
            }
            else if (anim_inj_final_ex->val <= 0.1f)
            {
                anim_inj_final_ex->active = true;
            }
        }
        else
        {
            window->DrawList->PathArcTo(pos2, 189.f, helpers::deg2rad(lc), -helpers::deg2rad(rc), 128);
            window->DrawList->AddPolyline(window->DrawList->_Path.Data, window->DrawList->_Path.Size,
                line.u32(), false, 19.0f);
            // Draw the shadow using the convex shape code
            window->DrawList->AddShadowConvexPoly(window->DrawList->_Path.Data, window->DrawList->_Path.Size,
                c_color(200, 91, 242, alpha * 255 * anim_inj_sec->val * anim_inj_tri->val * anim_inj->val).u32(), 200.f, ImVec2(0.f, 0.f));
            window->DrawList->_Path.Size = 0;
        }


        //text
        ImVec2 text_size = font_600->CalcTextSizeA(24.f, FLT_MAX, -1.f, (std::string("Injected game: ") + element.name).c_str());
        ImVec2 text_sizeS = font_600->CalcTextSizeA(24.f, FLT_MAX, -1.f, "Injected game: ");
        ImVec2 text_sizeP = font_600->CalcTextSizeA(24.f, FLT_MAX, -1.f, "Processing...");
        static float text_ex = 0.f;
        static float text_ex2 = 0.f;
        if (anim_inj_final->val >= 0.99f)
        {
            text_ex += 9.f;
            if (text_ex >= 90.f)
            {
                text_ex = 90.f;
                text_ex2 += 10.f;
                if (text_ex2 >= 180.f)
                {
                    text_ex2 = 180.f;
                }
            }
        }
        else
        {
            text_ex2 = 0.f;
            text_ex = 0.f;
        }
        ImVec2 pos_ts = ImVec2(439.f + 112.f - text_size.x / 2.f, 253.f + 182.f - 288.f * anim_inj_triROT->extra(i_elastic) + text_ex2);
        if (text_ex2 < 180.f)
        {
            window->DrawList->AddText(font_500, 24.f,
                window->Pos + pos_ts,
                c_color(255, 255, 255, alpha * 255 * anim_inj_sec->val * anim_inj_triROT->val * anim_inj->val).u32(), "Injected game:");
            window->DrawList->AddText(font_500, 24.f,
                window->Pos + pos_ts + ImVec2(text_sizeS.x, 0.f),
                c_color(200, 91, 242, alpha * 255 * anim_inj_sec->val * anim_inj_triROT->val * anim_inj->val).u32(), element.name);
            anim_inj_notify->active = false;
        }
        else
        {
            anim_inj_notify->active = true;
        }
        if (timer > 2)
        {
            anim_inj_notify->active = false;
        }
        if (text_ex < 90.f)
        {
            window->DrawList->AddText(font_500, 24.f,
                window->Pos + ImVec2(439.f + 112.f - text_sizeP.x / 2.f, pos_ts.y + 24.f + 15.f + text_ex),
                c_color(255, 255, 255, alpha * 255 * anim_inj_sec->val * anim_inj_triROT->val * anim_inj->val).u32(), "Processing...");
        }
        if (anim_inj_notify->val > 0.1f)
        {
            float a_np = anim_inj_notify->extra(i_inverse | i_inv_elastic);
            if (!anim_inj_notify->active)
                a_np = anim_inj_notify->extra(i_inverse | i_bz4);
            ImVec2 n_p = ImVec2(438.f + 37.f, 150.f - 250.f * a_np);
            window->DrawList->AddShadowRectBBB(window->Pos + n_p,
                window->Pos + n_p + ImVec2(150.f, 50.f), c_color(200, 91, 242, 125).multiplier(alpha * anim_inj_notify->val * anim_inj->val * anim_inj_sec->val).u32(),
                25.f, ImVec2(0.f, 0.f), 0, 20.f
            );
            window->DrawList->AddRectFilledMultiColor(window->Pos + n_p,
                window->Pos + n_p + ImVec2(150.f, 50.f),
                c_color(200, 91, 242, 125 * anim_inj_notify->val).multiplier(alpha * anim_inj_notify->val * anim_inj->val * anim_inj_sec->val).u32(),
                c_color(126, 26, 182, 0).multiplier(alpha * anim_inj_notify->val * anim_inj->val * anim_inj_sec->val).u32(),
                c_color(126, 26, 182, 0).multiplier(alpha * anim_inj_notify->val * anim_inj->val * anim_inj_sec->val).u32(),
                c_color(200, 91, 242, 125 * anim_inj_notify->val).multiplier(alpha * anim_inj_notify->val * anim_inj->val * anim_inj_sec->val).u32(),
                20.f, ImDrawFlags_RoundCornersAll);
            if ((alpha * anim_inj_notify->val * anim_inj->val) >= 0.25f)
            {
                window->DrawList->AddRectFilled(window->Pos + ImVec2(n_p.x + 1.f, n_p.y + 1.f),
                    window->Pos + ImVec2(n_p.x - 1.f, n_p.y - 1.f) + ImVec2(150.f, 50.f),
                    c_color(18, 11, 13, 255).multiplier(alpha * anim_inj_notify->val * anim_inj->val * anim_inj_sec->val).u32(),
                    20.f, ImDrawFlags_RoundCornersAll);
            }

            c_color act = c_color(200, 91, 242, alpha * 255 * anim_inj_notify->val * anim_inj->val);
            ImVec2 p = window->Pos + ImVec2(n_p.x + 12.f, n_p.y + 12.f);
            window->DrawList->AddShadowCircle(p + ImVec2(10.f, 12.5f),
                10.f, c_color(200, 91, 242, 0.75f * alpha * 255 * anim_inj_notify->val * anim_inj->val).u32(), 20.f, ImVec2(0.f, 0.f));
            ImGui::RenderCheckMark(window->DrawList, p + ImVec2(5.f, 7.f), act.u32(), 10.f);
            window->DrawList->AddCircle(p + ImVec2(10.f, 12.5f),
                10.f, act.u32());

            window->DrawList->AddText(font_500, 24.f,
                p + ImVec2(30.f, 0.f),
                c_color(255, 255, 255, alpha * 255 * anim_inj_sec->val * anim_inj_notify->val * anim_inj->val).u32(), "Spoofed");
        }

        //game img
        ImRotateStart();
        float alp = alpha * 255 * anim_inj_sec->val * anim_inj_tri->inverse();
        if (anim_inj_final->active)
        {
            alp = alpha * 255 * anim_inj_sec->val;
        }

        window->DrawList->PushTextureID(ImTextureID(element.game_t));
        int vert_start_idx = window->DrawList->VtxBuffer.Size;
        window->DrawList->AddCircleFilled(pos2, r,
            c_color(255, 255, 255, alpha * 255 * anim_inj_sec->val * anim_inj_tri->val * anim_inj->val).u32());
        int vert_end_idx = window->DrawList->VtxBuffer.Size;
        ImGui::ShadeVertsLinearUV(window->DrawList, vert_start_idx, vert_end_idx,
            pos2 + ImVec2(-182.f, -182.f),
            pos2 + ImVec2(182.f, 182.f), ImVec2(0, 0), ImVec2(1, 1), true);
        window->DrawList->PopTextureID();

        window->DrawList->PushClipRect(window->Pos + ImVec2(367.f, 252.f + 365.f * anim_inj_final->inverse()),
            window->Pos + ImVec2(368.f, 252.f) + ImVec2(365.f, 365.f));
        window->DrawList->PushTextureID(ImTextureID(element.Agame_t));
        vert_start_idx = window->DrawList->VtxBuffer.Size;
        window->DrawList->AddCircleFilled(pos2, r,
            c_color(255, 255, 255, alp * anim_inj->val).u32());
        vert_end_idx = window->DrawList->VtxBuffer.Size;
        ImGui::ShadeVertsLinearUV(window->DrawList, vert_start_idx, vert_end_idx,
            pos2 + ImVec2(-182.f, -182.f),
            pos2 + ImVec2(182.f, 182.f), ImVec2(0, 0), ImVec2(1, 1), true);
        window->DrawList->PopTextureID();
        window->DrawList->PopClipRect();
        ImRotateEnd(helpers::deg2rad(360.f * anim_inj_triROT->extra(i_bounce)));

    }
    else
    {
        timer = 0;
        anim_inj_tri->reset();
        anim_inj_triROT->reset();
        anim_inj_final->reset();
        anim_inj_final_ex->reset();
        anim_inj_notify->reset();
    }
}

void c_menu::main()
{
    anim_t* anim_bg = get_anim_obj(CONST_HASH("logo_bg"));
    anim_t* anim_main = get_anim_obj(CONST_HASH("logo_main"));
    if (hide_button())
    {
    }
    if (close_button())
    {
        opened = false;
    }
    anim_bg->active = switch_screen && opened && alpha >= 0.1f;
    anim_main->active = switch_screen;
    if (opened)
    {
        extra_alpha = helpers::bounce(alpha);
    }
    else
    {
        extra_alpha = helpers::bz4(alpha);
    }
    if (login_screen)
    {
        login_input();
        password_input();
        if (text_button())
        {
            ShellExecuteA(NULL, "open", "https://youtu.be/beoNy4MMHTc?si=JV97KjZkRhWRpFOx", NULL, NULL, SW_SHOWNORMAL);
        }
        ImGui::SetCursorPos(ImVec2(400.f, 600.f + 70.f * extra_alpha + 743.f * anim_main->val));
        if (button("Enter", true, (1.f - anim_main->val)))
        {
            switch_screen = true;
        }
    }
    else
    {
        /*anim_t* anim_help = get_anim_obj(CONST_HASH("helptab"));*/
        tabs();
        setting_screen();
        subscribe_screen();
    }
}

bool c_menu::hide_button()
{
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 pos_window = ImGui::GetWindowPos();
    ImVec2 size_window = ImGui::GetWindowSize();
    ImVec2 size = ImVec2(15.f, 11.f);
    ImVec2 pos_b = ImVec2(size_window.x - 17.f - size.x - 25.f, 15.f);
    ImGui::SetCursorPos(pos_b);
    bool ret = ImGui::InvisibleButton("hide", size);

   
    return ret;
}

bool c_menu::close_button()
{
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 pos_window = ImGui::GetWindowPos();
    ImVec2 size_window = ImGui::GetWindowSize();
    ImVec2 size = ImVec2(11.f, 11.f);
    ImVec2 pos_b = ImVec2(size_window.x - 17.f - size.x, 15.f);
    ImGui::SetCursorPos(pos_b);
    bool ret = ImGui::InvisibleButton("close", size);
    list->AddLine(pos_window + pos_b, pos_window + pos_b + size, c_color(200, 91, 242).new_alpha(alpha * 255).u32());
    list->AddLine(pos_window + ImVec2(pos_b.x, pos_b.y + size.y), pos_window + ImVec2(pos_b.x + size.x, pos_b.y), c_color(200,91,242).new_alpha(alpha * 255).u32());
    return ret;
}

bool c_menu::text_button()
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    anim_t* anim_main = get_anim_obj(CONST_HASH("logo_main"));

    ImVec2 size = ImVec2(437.f, 30.f);
    ImVec2 pos_b = ImVec2(331.f, 486.f + 70.f * extra_alpha + 743.f * anim_main->val);
    ImGui::SetCursorPos(pos_b);
    bool ret = ImGui::InvisibleButton("join_us", size);

    window->DrawList->AddText(font_500, 28.f, window->Pos + ImVec2(331.f, 486.f + 70.f * extra_alpha + 743.f * anim_main->val), c_color(255, 255, 255, alpha * (1.f - anim_main->val) * 255).u32(), "Don't you have an account?");
    window->DrawList->AddText(font_500, 28.f, window->Pos + ImVec2(331.f + 331.f, 486.f + 70.f * extra_alpha + 743.f * anim_main->val), c_color(200, 91, 242, alpha * (1.f - anim_main->val) * 255).u32(), "Join us!");

    return ret;
}

bool c_menu::login_input()
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    anim_t* anim_main = get_anim_obj(CONST_HASH("logo_main"));

    window->DrawList->AddRectFilledMultiColor(window->Pos + ImVec2(300.f - 0.5f, 257.f + 70.f * extra_alpha + 743.f * anim_main->val - 0.5f),
        window->Pos + ImVec2(300.f + 0.5f, 257.f + 70.f * extra_alpha + 743.f * anim_main->val + 0.5f) + ImVec2(500.f, 70.f),
        c_color(200, 91, 242, 255).multiplier(alpha).u32(),
        c_color(126, 26, 182, 0).multiplier(alpha).u32(),
        c_color(126, 26, 182, 0).multiplier(alpha).u32(),
        c_color(200, 91, 242, 255).multiplier(alpha).u32(),
        20.f, ImDrawFlags_RoundCornersAll);

    if (alpha >= 0.25f)
    {
        window->DrawList->AddRectFilled(window->Pos + ImVec2(300.f, 257.f + 70.f * extra_alpha + 743.f * anim_main->val),
            window->Pos + ImVec2(300.f, 257.f + 70.f * extra_alpha + 743.f * anim_main->val) + ImVec2(500.f, 70.f),
            c_color(11, 9, 10, 255).multiplier(alpha).u32(),
            20.f, ImDrawFlags_RoundCornersAll);
    }
    ImGui::SetCursorPos(ImVec2(306.f, 274.f + 70.f * extra_alpha + 743.f * anim_main->val));
    ImGui::SetNextItemWidth(435.f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(255.f / 255.f, 255.f / 255.f, 255.f / 255.f, 0.f));
    ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, ImVec4(255.f / 255.f, 55.f / 255.f, 119.f / 255.f, 1.f));
    ImGui::InputText("##logini", login, sizeof login);
    ImGui::PopStyleColor(2);
    window->DrawList->AddText(font_300, 19.f,
        window->Pos + ImVec2(320.f, 232.f + 70.f * extra_alpha + 768.f * anim_main->val),
        c_color(97, 97, 97, alpha * 255).u32(), "Login");

  
    return false;
}

bool c_menu::password_input()
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    anim_t* anim_main = get_anim_obj(CONST_HASH("logo_main"));

    window->DrawList->AddRectFilledMultiColor(window->Pos + ImVec2(300.f - 0.5f, 370.f + 70.f * extra_alpha + 750.f * anim_main->val - 0.5f),
        window->Pos + ImVec2(300.f + 0.5f, 370.f + 70.f * extra_alpha + 750.f * anim_main->val + 0.5f) + ImVec2(500.f, 70.f),
        c_color(200, 91, 242, 255).multiplier(alpha).u32(),
        c_color(126, 26, 182, 0).multiplier(alpha).u32(),
        c_color(126, 26, 182, 0).multiplier(alpha).u32(),
        c_color(200, 91, 242, 255).multiplier(alpha).u32(),
        20.f, ImDrawFlags_RoundCornersAll);

    if (alpha >= 0.25f)
    {
        window->DrawList->AddRectFilled(window->Pos + ImVec2(300.f, 370.f + 70.f * extra_alpha + 750.f * anim_main->val),
            window->Pos + ImVec2(300.f, 370.f + 70.f * extra_alpha + 750.f * anim_main->val) + ImVec2(500.f, 70.f),
            c_color(11, 9, 10, 255).multiplier(alpha).u32(),
            20.f, ImDrawFlags_RoundCornersAll);
    }
    ImGui::SetCursorPos(ImVec2(306.f, 387.f + 70.f * extra_alpha + 775.f * anim_main->val));
    ImGui::SetNextItemWidth(435.f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(255.f / 255.f, 255.f / 255.f, 255.f / 255.f, 0.f));
    ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, ImVec4(255.f / 255.f, 55.f / 255.f, 119.f / 255.f, 1.f));
    ImGui::InputText("##passwordi", password, sizeof password);
    ImGui::PopStyleColor(2);
    window->DrawList->AddText(font_300, 19.f,
        window->Pos + ImVec2(320.f, 345.f + 70.f * extra_alpha + 775.f * anim_main->val),
        c_color(97, 97, 97, alpha * 255).u32(), "Password");

    return false;
}

bool c_menu::button(const char* label, bool icon, float extra_alpha)
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems)
        return false;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(300.f, 70.f);

    const ImRect bb(pos, pos + size);
    ImGui::ItemSize(size, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, id))
        return false;

    bool hovered, held;
    bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);

    window->DrawList->AddShadowRectBBB(bb.Min, bb.Max, c_color(200, 91, 242, 0.6f * alpha * extra_alpha * 255).u32(),
        159.f, ImVec2(0.f,0.f), 0, 20.f
        );

    window->DrawList->AddRectFilledMultiColor(bb.Min, bb.Max,
        c_color(200, 91, 242, alpha * extra_alpha * 255).u32(), c_color(200, 91, 242, alpha * extra_alpha * 255).u32(), c_color(200, 91, 242, alpha * extra_alpha * 255).u32(), c_color(126, 26, 182, alpha * extra_alpha * 255).u32(),
        20.f, ImDrawFlags_RoundCornersAll);
    float space = 24.f;
    if (icon)
    {
        space = 0.f;
        window->DrawList->AddImage(ImTextureID(enter_t), bb.Min + ImVec2(181.f, 23.f),
            bb.Min + ImVec2(181.f, 23.f) + ImVec2(25.f, 25.f), ImVec2(0, 0), ImVec2(1, 1),
            c_color(255, 255, 255, alpha * extra_alpha * 255).u32());
    }
    window->DrawList->AddText(font_600, 30.f, bb.Min + ImVec2(95.f + space, 20.f), c_color(10, 10, 10, alpha * extra_alpha * 255).u32(), label);
    // Render
    /*const ImU32 col = ImGui::GetColorU32((held && hovered) ? ImGuiCol_ButtonActive : hovered ? ImGuiCol_ButtonHovered : ImGuiCol_Button);
    ImGui::RenderNavCursor(bb, id);
    ImGui::RenderFrame(bb.Min, bb.Max, col, true, style.FrameRounding);
    ImGui::RenderTextClipped(bb.Min + style.FramePadding, bb.Max - style.FramePadding, label, NULL, &label_size, style.ButtonTextAlign, &bb);*/

    return pressed;
}

bool c_menu::arrow_button(const char* label, bool right)
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems)
        return false;
    anim_t* anim_arrow = animation(label, { clamp_out, 0.08f });
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(25.f, 25.f);

    const ImRect bb(pos, pos + size);
    ImGui::ItemSize(size, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, id))
        return false;
    anim_t* anim_subscribe = get_anim_obj(CONST_HASH("subscribetab"));
    bool hovered, held;
    bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);

    c_color main = c_color(126, 26, 182, alpha * 255 * anim_subscribe->val);
    c_color main_border = c_color(200, 91, 242, alpha * 255 * anim_subscribe->val);
    c_color second = c_color(22, 22, 22, alpha * 255 * anim_subscribe->val);
    c_color second_border = c_color(22, 22, 22, alpha * 255 * anim_subscribe->val);
    ImRotateStart();
    if (!right)
    {
        main = c_color(22, 22, 22, alpha * 255 * anim_subscribe->val);
        main_border = c_color(22, 22, 22, alpha * 255 * anim_subscribe->val);
        second = c_color(126, 26, 182, alpha * 255 * anim_subscribe->val);
        second_border = c_color(200, 91, 242, alpha * 255 * anim_subscribe->val);
    }

    window->DrawList->AddShadowCircle(bb.Min + ImVec2(12.5f, 12.5f), 12.f,
        c_color(200, 91, 242, 0.5f * alpha * 255).u32(), 50.f, ImVec2(0.f, 0.f));

    int vert_start_idx = window->DrawList->VtxBuffer.Size;
    window->DrawList->AddCircleFilled(bb.Min + ImVec2(12.5f, 12.5f), 13.5f, c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(),25.f);
    int vert_end_idx = window->DrawList->VtxBuffer.Size;
    ImGui::ShadeVertsLinearColorGradientKeepAlpha(window->DrawList, vert_start_idx, vert_end_idx, bb.Min, bb.Max,
        main_border.u32(), second_border.u32());

    vert_start_idx = window->DrawList->VtxBuffer.Size;
    window->DrawList->AddCircleFilled(bb.Min + ImVec2(12.5f, 12.5f), 12.5f, c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 25.f);
    vert_end_idx = window->DrawList->VtxBuffer.Size;
    ImGui::ShadeVertsLinearColorGradientKeepAlpha(window->DrawList, vert_start_idx, vert_end_idx, bb.Min, bb.Max,
        main.u32(), second.u32());
    ImRotateEnd(helpers::deg2rad(-45.f));
    if(pressed)
    {
        anim_arrow->active = true;
    }
    if(anim_arrow->val == 1.f)
    {
        anim_arrow->val = 0.f;
        anim_arrow->active = false;
    }
    window->DrawList->PushClipRect(bb.Min, bb.Max);
    float offset = 25.f * anim_arrow->extra(i_bounce);
    if (right)
    {
        window->DrawList->AddLine(bb.Min + ImVec2(7.f - offset, 12.5f), bb.Min + ImVec2(17.f - offset, 12.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
        window->DrawList->AddLine(bb.Min + ImVec2(6.f - offset, 12.5f), bb.Min + ImVec2(12.f - offset, 16.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
        window->DrawList->AddLine(bb.Min + ImVec2(6.f - offset, 12.5f), bb.Min + ImVec2(12.f - offset, 8.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);

        window->DrawList->AddLine(bb.Min + ImVec2(7.f + (25.f - offset), 12.5f), bb.Min + ImVec2(17.f + (25.f - offset), 12.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
        window->DrawList->AddLine(bb.Min + ImVec2(6.f + (25.f - offset), 12.5f), bb.Min + ImVec2(12.f + (25.f - offset), 16.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
        window->DrawList->AddLine(bb.Min + ImVec2(6.f + (25.f - offset), 12.5f), bb.Min + ImVec2(12.f + (25.f - offset), 8.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
    }
    else
    {
        window->DrawList->AddLine(bb.Max - ImVec2(17.f - offset, 12.5f), bb.Max - ImVec2(7.f - offset, 12.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
        window->DrawList->AddLine(bb.Max - ImVec2(12.f - offset, 16.5f), bb.Max - ImVec2(6.f - offset, 12.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
        window->DrawList->AddLine(bb.Max - ImVec2(12.f - offset, 8.5f), bb.Max - ImVec2(6.f - offset, 12.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);

        window->DrawList->AddLine(bb.Max - ImVec2(17.f + (25.f - offset), 12.5f), bb.Max - ImVec2(7.f + (25.f - offset), 12.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
        window->DrawList->AddLine(bb.Max - ImVec2(12.f + (25.f - offset), 16.5f), bb.Max - ImVec2(6.f + (25.f - offset), 12.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
        window->DrawList->AddLine(bb.Max - ImVec2(12.f + (25.f - offset), 8.5f), bb.Max - ImVec2(6.f + (25.f - offset), 12.5f), c_color(255, 255, 255, alpha * 255 * anim_subscribe->val).u32(), 1.25f);
    }
    window->DrawList->PopClipRect();
    return pressed;
}

bool c_menu::checkbox(const char* label, const char** desc, int desc_, bool* v, ID3D11ShaderResourceView* icon_t, ImVec2 icon_sz)
{
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems)
        return false;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);

    const float square_sz = ImGui::GetFrameHeight();
    const ImVec2 pos = window->DC.CursorPos;
    const ImVec2 size = ImVec2(318.f, 22.f);
    const ImRect total_bb(pos + ImVec2(97.f, 0.f), pos + size + ImVec2(97.f, 0.f));
    const ImRect item_bb(total_bb.Min, total_bb.Max + ImVec2(0.f, 15.f + 21.f * desc_));
    const ImRect button_bb(item_bb.Min, item_bb.Max - ImVec2(0.f, 15.f));
    ImGui::ItemSize(item_bb, style.FramePadding.y);
    const bool is_visible = ImGui::ItemAdd(item_bb, id);
    
    if (!is_visible)
        return false;
    anim_t* anim_settings = get_anim_obj(CONST_HASH("settingstab"));
    // Range-Selection/Multi-selection support (header)
    bool checked = *v;
   

    bool hovered, held;
    bool pressed = ImGui::ButtonBehavior(button_bb, id, &hovered, &held);

    if (pressed)
        checked = !checked;

    if (*v != checked)
    {
        *v = checked;
        pressed = true; // return value
        ImGui::MarkItemEdited(id);
    }
    anim_t* anim_main = animation((std::string(label) + "settings").c_str(), { clamp_out, 0.08f });
    anim_main->active = (*v) && anim_settings->val >= 0.9f;
    const ImRect check_bb(total_bb.Max - ImVec2(35.f, 17.f), total_bb.Max - ImVec2(0.f, 2.f));
    window->DrawList->AddRectFilled(check_bb.Min, check_bb.Max, c_color(14, 14, 14, 255 * alpha * anim_settings->val).u32(), 15.f);
    c_color sel = c_color(255, 255, 255).multiply(c_color(200, 91, 242), anim_main->val).new_alpha(alpha * 255 * anim_settings->val);
    float off_x = 20.f * anim_main->extra(anim_main->active ? i_elastic : i_inv_elastic);
    window->DrawList->AddShadowCircle(check_bb.Min + ImVec2(7.5f + off_x, 7.5f), 7.5f, sel.new_alpha(0.4f * alpha * 255 * anim_settings->val * anim_main->val).u32(), 26.f, ImVec2(0.f, 0.f));
    window->DrawList->AddCircleFilled(check_bb.Min + ImVec2(7.5f + off_x, 7.5f), 7.5f, sel.u32(), 35);
   
    const ImVec2 label_pos = total_bb.Min;

    // Hide anything after a '##' string
    const char* text_display_end = ImGui::FindRenderedTextEnd(label, 0);
    if (label != text_display_end)
    {
        window->DrawList->AddText(font_500, 24.f, label_pos, c_color(255, 255, 255, 255 * alpha * anim_settings->val).u32(), label, text_display_end);
    }
    if (icon_t != nullptr)
    {
        const ImVec2 min_icon = total_bb.Min + ImVec2(-(31.f + icon_sz.x/2.f), 0.f);
        window->DrawList->AddImage(ImTextureID(icon_t), min_icon, min_icon + icon_sz, ImVec2(0, 0), ImVec2(1, 1),
            c_color(255, 255, 255, 255 * alpha * anim_settings->val).u32());
    }
    if (desc_ > 0)
    {
        float off_y = 30.f;
        for (int i = 0; i < desc_; i++)
        {
            window->DrawList->AddText(font_300, 17.f, label_pos + ImVec2(0.f, off_y),
                c_color(97, 97, 97, 255 * alpha * anim_settings->val).u32(), desc[i]);
            off_y += 21.f;
        }
    }
    return pressed;
}

void c_menu::end()
{
    move_window();
    ImGui::End();
}

c_menu::anim_t* c_menu::animation(std::string id_name, anim_t data)
{
    return animation(CONST_HASH(id_name.c_str()), data);
}

c_menu::anim_t* c_menu::animation(std::uint32_t id, anim_t data)
{
    anim_t* anim = create_animation(id, data);
    update_animation(anim->val, anim->active, anim->speed, anim->flags, anim->min, anim->max);
    return anim;
}

c_menu::anim_t* c_menu::create_animation(std::uint32_t id, anim_t data)
{
    auto item_data = item_animations.find(id);

    if (item_data == item_animations.end())
    {
        item_animations.insert({ id, data });
        item_data = item_animations.find(id);
    }
    return &item_data->second;
}

c_menu::anim_t* c_menu::get_anim_obj(std::uint32_t id)
{
    return &item_animations[id];
}

void c_menu::update_animation(float& mod, bool& cond, float speed_multiplier, unsigned int animation_flags, float min, float max)
{
    float time = (get_animation_speed() * 5.f) * speed_multiplier;

    if ((animation_flags & skip_enable) && cond)
        mod = max;
    else if ((animation_flags & skip_disable) && !cond)
        mod = min;

    if (animation_flags & lerp_anim)
        mod = helpers::lerp(mod, cond ? max : min, time);
    else
    {
        if (cond && mod <= max)
            mod += time;
        else if (!cond && mod >= min)
            mod -= time;
    }

    if (animation_flags & clamp_out)
        mod = std::clamp(mod, min, max);
}

float c_menu::get_animation_speed()
{
    return animation_speed;
}

void c_menu::update_animation_speed()
{
    if (last_time_updated == -1.f)
        last_time_updated = system_time();

    animation_speed = fabsf(last_time_updated - system_time()) * 5.f;
    last_time_updated = system_time();
}

float c_menu::system_time()
{
    return (float)(clock() / (float)1000.f);
}
