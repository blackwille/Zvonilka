#version 300 es

#ifdef GL_ES
precision mediump float;
#endif

in vec2 uv;
out vec4 fragColor;

uniform float u_level;
uniform float u_time;
uniform float u_aspect;

vec4 ColorOrbWave(vec4 col1, vec4 col2, float coef) {
    vec2 curPos = vec2(uv.x * u_aspect, uv.y);
    float sine1 = sin(2.f * coef * atan(curPos.y / curPos.x) + u_time * coef);
    float sine2 = sin(4.f * coef * atan(curPos.y / curPos.x) + u_time * coef);
    float wave = 0.4f + 0.1f * pow(u_level, 0.6f) * coef * (1.f + sine1 * sine2);

    float thickness = 0.01f;
    float bloor = 0.05f;
    float colorStart = wave - thickness / 2.f - bloor / 2.f;
    float colorEnd = wave + thickness / 2.f + bloor / 2.f;

    float r = length(curPos);
    float diff = r - wave;

    float outerEdge = smoothstep(colorEnd, wave + thickness / 2.f, r);
    float innerEdge = smoothstep(colorStart, wave - thickness / 2.f, r);

    float mixCoef = diff < 0.0f ? innerEdge : outerEdge;
    return mix(col1, col2, mixCoef);
}

void main() {
    vec4 col1 = vec4(0.824f, 0.847f, 0.89f, 1.f); // #d2d8e3
    vec4 col2 = vec4(0.137f, 0.263f, 0.53f, 1.f); // #234388

    vec4 result = vec4(0);
    int count = 4;
    for(int i = 0; i < count; ++i) {
        result += ColorOrbWave(col1, col2, float(i)) / float(count);
    }

    fragColor = result;
}
