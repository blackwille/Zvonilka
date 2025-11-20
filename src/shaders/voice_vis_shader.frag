#version 330 core
in vec2 uv;
out vec4 fragColor;

uniform float level; // 0..1
uniform int time; 

void main() {
    vec3 col1 = vec3(0.824, 0.847, 0.89); // #d2d8e3
    vec3 col2 = vec3(0.137, 0.263, 0.53); // #234388
    // радиус шара зависит от level
    float radius = 0.6 + level * 3;
    float r = length(uv);

    float sine1 = radius + 0.1 * sin(18 * atan(uv.y / uv.x) + time * 0.1);
    float edge01 = sine1 - 0.02;
    float edge11 = sine1 + 0.02;
    float diff1 = r - sine1;
    float outerEdge1 = smoothstep(edge11, sine1, r);
    float innerEdge1 = smoothstep(edge01, sine1, r);
    float mixValue1 = diff1 < 0.0 ? innerEdge1 : outerEdge1;
    vec3 colOrb1 = mix(col1, col2, mixValue1);

    float sine2 = radius + 0.03 * sin(12 * atan(uv.y / uv.x) + time * 0.2);
    float edge02 = sine2 - 0.02;
    float edge12 = sine2 + 0.02;
    float diff2 = r - sine2;
    float outerEdge2 = smoothstep(edge12, sine2, r);
    float innerEdge2 = smoothstep(edge02, sine2, r);
    float mixValue2 = diff2 < 0.0 ? innerEdge2 : outerEdge2;
    vec3 colOrb2 = mix(col1, col2, mixValue2);
    
    fragColor = vec4((colOrb1 + colOrb2) / 2, 1.0);
}