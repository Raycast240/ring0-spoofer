#pragma once
#include <map>
#include <algorithm>
#include "hash.hpp"
#include "helpers.h"
#include "imgui.h"
#include <D3DX11tex.h>
#include <vector>
#include "remove.h"
enum animation_flags_t
{
    clamp_out = (1 << 0),
    skip_enable = (1 << 1),
    skip_disable = (1 << 2),
    lerp_anim = (1 << 3),
};

enum improve_anim_flags_t
{
    i_bz4 = (1 << 0),
    i_bounce = (1 << 1),
    i_inv_bounce = (1 << 2),
    i_elastic = (1 << 3),
    i_inv_elastic = (1 << 4),
    i_clamp = (1 << 5),
    i_inverse = (1 << 6),
};

class c_menu
{
public:
    
    struct anim_t
    {
        anim_t() {};
        anim_t(unsigned int def_flags, float def_speed, float def_min = 0.f, float def_max = 1.f)
        {
            flags = def_flags; speed = def_speed; min = def_min; max = def_max;
        };

        bool active{ false };
        float val{ 0.f };

        unsigned int flags{ animation_flags_t::clamp_out };
        float speed{ 1.f };
        float min{ 0.f };
        float max{ 1.f };

        INLINE float extra(unsigned int flags = improve_anim_flags_t::i_bz4 | improve_anim_flags_t::i_clamp)
        {
            float mod = fabsf(val);
            if (flags & i_inverse)
            {
                mod = fabsf(inverse());
            }
            //we clamp always bc bounce & bz4 work only with [0.f - 1.f]
            mod = std::clamp(mod, 0.f, 1.f);

            if (flags & i_bz4)
            {
                mod = helpers::bz4(mod);
            }
            if (flags & i_bounce)
            {
                mod = helpers::bounce(mod);
            }
            if (flags & i_inv_bounce)
            {
                mod = helpers::inverse_bounce(mod);
            }
            if (flags & i_elastic)
            {
                mod = helpers::elastic(mod);
            }
            if (flags & i_inv_elastic)
            {
                mod = helpers::inverse_elastic(mod);
            }
            if (flags & i_clamp)
                mod = std::clamp(mod, 0.f, 1.f);

            return mod;
        }

        INLINE float inverse() {
            return 1.f - val;
        }

        INLINE void reset()
        {
            active = false;
            val = 0.f;
        }
    };
    struct element_t
    {
        element_t(const char* game_name, int game_desc_, ID3D11ShaderResourceView* game, ID3D11ShaderResourceView* Agame, float off, bool upd = true)
        {
            name = game_name; desc_ = game_desc_; game_t = game; Agame_t = Agame; x = off; old_x = off; has_update = upd;
        };
        float x{};
        bool active{};
        bool has_update{};
        float old_x{};
        const char* name{};
        int desc_{};
        ID3D11ShaderResourceView* game_t{ nullptr };
        ID3D11ShaderResourceView* Agame_t{ nullptr };
    };
    
    void setup();
    void draw();

    void begin();
    void bg();
    void user();
    void tabs();
    bool tab(const char* label, bool selected, ImVec2 pos, float sz_x = 50.f);
    void setting_screen();
    void setting_left(ImVec2 pos_ch);
    void setting_left_active_section(ImVec2 pos_ch);
    void setting_right(ImVec2 pos_ch);
    void setting_right_disablers(const char* main, const char* sec, ImVec2 pos, float &off_y, bool active, float off_x = 149.f);
    void subscribe_screen();
    void subscribe_games();
    void subscribe_inject();
    void main();
    bool hide_button();
    bool close_button();
    bool text_button();
    bool login_input();
    bool password_input();
    bool button(const char* label, bool icon = false, float extra_alpha = 1.f);
    bool arrow_button(const char* label, bool right = false);
    bool checkbox(const char* label, const char** desc, int desc_, bool* v, ID3D11ShaderResourceView* icon_t, ImVec2 icon_sz);
    void end();

    anim_t* animation(std::string id_name, anim_t data = anim_t());
    anim_t* animation(std::uint32_t id, anim_t data = anim_t());
    anim_t* create_animation(std::uint32_t id, anim_t data = anim_t());
    void update_animation(float& mod, bool& cond, float speed_multiplier = 1.f, unsigned int animation_flags = animation_flags_t::clamp_out, float min = 0.f, float max = 1.f);
    anim_t* get_anim_obj(std::uint32_t id);
    float get_animation_speed();

    //call one time every frame update
    void update_animation_speed();
    bool opened{ true };
    ID3D11Device* g_pd3dDevice{ nullptr };
    ID3D11DeviceContext* g_pd3dDeviceContext{ nullptr };
    IDXGISwapChain* g_pSwapChain{ nullptr };
    ImFont* font_600{ };
    ImFont* font_500{ };
    ImFont* font_400{ };
    ImFont* font_300{ };
    int screen_numb{ 0 };
    int active_game{ 3 };
    char login[64]{};
    char password[64]{};
private:
    float system_time();
    std::map< std::uint32_t, anim_t > item_animations{};
    std::vector<element_t> container{};
    float last_time_updated{ -1.0f };
    float animation_speed{ 0.16f };
    float alpha{ 0.f };
    float extra_alpha{ 0.f };
    bool login_screen{ true };
    bool switch_to_inject{ false };
    bool switch_screen{ false };
    ID3D11ShaderResourceView* logo_t{ nullptr };
    ID3D11ShaderResourceView* user_t{ nullptr };
    ID3D11ShaderResourceView* logout_t{ nullptr };
    ID3D11ShaderResourceView* enter_t{ nullptr };
    ID3D11ShaderResourceView* login_t{ nullptr };
    ID3D11ShaderResourceView* password_t{ nullptr };
    ID3D11ShaderResourceView* download_t{ nullptr };

    ID3D11ShaderResourceView* setting_another_t{ nullptr };
    ID3D11ShaderResourceView* setting_mac_t{ nullptr };
};

inline c_menu g_menu{};

