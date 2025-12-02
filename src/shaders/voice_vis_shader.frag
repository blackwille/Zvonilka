#version 300 es

#ifdef GL_ES
precision mediump float;
#endif

in vec2 uv;
out vec4 fragColor;

uniform float u_level;
uniform float u_time;

vec4 ColorOrbWave(vec4 col1, vec4 col2, float coef) {
    float sine1 = sin(2. * coef * atan(uv.y / uv.x) + u_time * coef);
    float sine2 = sin(4. * coef * atan(uv.y / uv.x) + u_time * coef);
    float wave = 0.4 + 0.2 * (coef * u_level + coef * u_level * sine1 * sine2);

    float thickness = 0.01;
    float bloor = 0.1;
    float colorStart = wave - thickness / 2. - bloor / 2.;
    float colorEnd = wave + thickness / 2. + bloor / 2.;

    float r = length(uv);
    float diff = r - wave;

    float outerEdge = smoothstep(colorEnd, wave + thickness / 2., r);
    float innerEdge = smoothstep(colorStart, wave - thickness / 2., r);

    float mixCoef = diff < 0.0 ? innerEdge : outerEdge;
    return mix(col1, col2, mixCoef);
}

void main() {
    vec4 col1 = vec4(0.824, 0.847, 0.89, 1.); // #d2d8e3
    vec4 col2 = vec4(0.137, 0.263, 0.53, 1.); // #234388

    vec4 result = vec4(0);
    int count = 4;
    for(int i = 0; i < count; ++i) {
        result += ColorOrbWave(col1, col2, float(i)) / float(count);
    }

    fragColor = result;
}