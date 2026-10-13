#pragma once

#ifndef PI
#define PI 3.1415926545
#endif

namespace helpers
{
    template<typename T> static inline T lerp(T a, T b, float t) { return (T)(a + (b - a) * t); };
    inline float bz4(float x) { return x * x * (3.0f - 2.0f * x); };

    inline float bounce(float x) {
        const float n1 = 7.5625f;
        const float d1 = 2.75f;

        if (x < 1.f / d1) {
            return n1 * x * x;
        }
        else if (x < 2.f / d1) {
            return n1 * (x -= 1.5f / d1) * x + 0.75f;
        }
        else if (x < 2.5f / d1) {
            return n1 * (x -= 2.25f / d1) * x + 0.9375f;
        }
        else {
            return n1 * (x -= 2.625f / d1) * x + 0.984375f;
        }
    };
    inline float inverse_bounce(float x) { return 1.f - bounce(1.f - x); };
    inline float get_side(float x)
    {
        if (x >= 0.f)
        {
            return 1.f;
        }
        return -1.f;
    }
    inline float elastic(float t) {
        float t2 = (t - 1.f) * (t - 1.f);
        return 1.f - t2 * t2 * cosf(t * PI * 4.5f);
    }
    inline float inverse_elastic(float x) { return 1.f - elastic(1.f - x); };
    inline float deg2rad(float degrees) {
        return degrees * (3.14159265358979323846f / 180.0f);
    }
};
