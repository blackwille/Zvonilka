// Zvonilka demo (SDL3 + ImGui): mic -> AES-256-GCM -> decrypt -> speakers
#include <SDL3/SDL_init.h>
#include <SDL3/SDL_video.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "imgui.h"
#include "imgui_bindings/imgui_impl_sdl3.h"
#include "imgui_bindings/imgui_impl_opengl3.h"
#include <SDL3/SDL.h>
#include <SDL3/SDL_opengl.h>

// ---------- AEAD (AES-256-GCM) ----------
struct AeadCtx {
    std::array<uint8_t, 32> key{};   // 256-bit
    std::array<uint8_t, 12> salt{};  // 96-bit IV prefix (we use first 4 bytes)
    std::atomic<uint64_t> seq{0};    // per-frame counter (nonce suffix)
};

static bool rand_bytes(uint8_t *dst, size_t n) {
    return RAND_bytes(dst, (int)n) == 1;
}

static inline uint64_t host_to_be64(uint64_t x) {
    return ((x & 0x00000000000000FFULL) << 56) |
           ((x & 0x000000000000FF00ULL) << 40) |
           ((x & 0x0000000000FF0000ULL) << 24) |
           ((x & 0x00000000FF000000ULL) << 8) |
           ((x & 0x000000FF00000000ULL) >> 8) |
           ((x & 0x0000FF0000000000ULL) >> 24) |
           ((x & 0x00FF000000000000ULL) >> 40) |
           ((x & 0xFF00000000000000ULL) >> 56);
}

static void make_iv(const std::array<uint8_t, 12> &salt, uint64_t seq,
                    uint8_t iv[12]) {
    // 96-bit IV = 32-bit salt prefix + 64-bit counter (BE)
    std::memcpy(iv, salt.data(), 4); // важная правка: только 4 байта префикса
    uint64_t be = host_to_be64(seq);
    std::memcpy(iv + 4, &be, 8);
}

static bool aead_seal(AeadCtx &ctx, // non-const: seq++
                      std::span<const uint8_t> aad,
                      std::span<const uint8_t> plain,
                      std::vector<uint8_t> &outCipher) {
    uint8_t iv[12];
    const uint64_t seq = ctx.seq.fetch_add(1, std::memory_order_relaxed);
    make_iv(ctx.salt, seq, iv);

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return false;

    int ok = 1, len = 0, outLen = 0;
    ok &= EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    ok &= EVP_EncryptInit_ex(c, nullptr, nullptr, ctx.key.data(), iv);

    if (!aad.empty())
        ok &= EVP_EncryptUpdate(c, nullptr, &len, aad.data(), (int)aad.size());

    outCipher.resize(plain.size() + 16); // + tag
    ok &= EVP_EncryptUpdate(c, outCipher.data(), &len, plain.data(),
                            (int)plain.size());
    outLen = len;
    ok &= EVP_EncryptFinal_ex(c, outCipher.data() + outLen, &len);
    outLen += len;

    uint8_t tag[16];
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(c);
    if (!ok) return false;

    std::memcpy(outCipher.data() + outLen, tag, 16);
    return true;
}

static bool aead_open(const AeadCtx &ctx, uint64_t seq,
                      std::span<const uint8_t> aad,
                      std::span<const uint8_t> cipherWithTag,
                      std::vector<uint8_t> &outPlain) {
    if (cipherWithTag.size() < 16) return false;
    const size_t clen = cipherWithTag.size() - 16;
    const uint8_t *tag = cipherWithTag.data() + clen;

    uint8_t iv[12];
    make_iv(ctx.salt, seq, iv);

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return false;

    int ok = 1, len = 0, outLen = 0;
    ok &= EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    ok &= EVP_DecryptInit_ex(c, nullptr, nullptr, ctx.key.data(), iv);

    if (!aad.empty())
        ok &= EVP_DecryptUpdate(c, nullptr, &len, aad.data(), (int)aad.size());

    outPlain.resize(clen);
    ok &= EVP_DecryptUpdate(c, outPlain.data(), &len, cipherWithTag.data(),
                            (int)clen);
    outLen = len;
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    ok &= EVP_DecryptFinal_ex(c, outPlain.data() + outLen, &len);
    outLen += len;

    EVP_CIPHER_CTX_free(c);
    return ok != 0;
}

// ---------- Miniaudio: один duplex девайс ----------
#define MINIAUDIO_IMPLEMENTATION
// Без ручного выбора бэкенда — miniaudio сам подберёт лучшее для OS.
#include "miniaudio.h"

struct AudioConfig {
    int sampleRate = 48000;
    int channels = 1;
    int frameMs = 20; // 960 frames @48k
    int framesPerBuffer() const { return (sampleRate / 1000) * frameMs; }
};

struct App {
    AudioConfig cfg{};
    AeadCtx aead{};
    std::mutex crypto_mtx; // простой guard на смену ключей

    ma_context ctx{};
    ma_device dev{};

    std::atomic<bool> running{false};    // устройство открыто
    std::atomic<bool> capturing{false};  // поток запущен

    static void print_hex(const char* label, const std::span<const uint8_t> bytes) {
        std::stringstream ss;
        ss << "0x";
        for (uint8_t b : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << int(b);
        }
        std::cout << label << " " << ss.str() << "\n";
    }

    bool generateCrypto() {
        std::lock_guard<std::mutex> lg(crypto_mtx);

        if (!rand_bytes(aead.key.data(), aead.key.size())) {
            std::cerr << "RAND key failed\n"; return false;
        }
        if (!rand_bytes(aead.salt.data(), aead.salt.size())) {
            std::cerr << "RAND salt failed\n"; return false;
        }
        aead.seq.store(0, std::memory_order_relaxed);

        print_hex("Generated session key:",
                  std::span<const uint8_t>(aead.key.data(),
                                           aead.key.size()));
        print_hex("Generated session salt:",
                  std::span<const uint8_t>(aead.salt.data(),
                                           aead.salt.size()));

        return true;
    }

    static void on_duplex(ma_device *pDevice, void *pOutput, const void *pInput,
                          ma_uint32 frameCount) {
        App *self = (App *)pDevice->pUserData;
        if (!self || !pOutput) return;

        const ma_uint32 ch = (ma_uint32)self->cfg.channels;
        const size_t bytesPCM = frameCount * ma_get_bytes_per_frame(ma_format_s16, ch);

        if (!self->capturing.load(std::memory_order_relaxed)) {
            std::memset(pOutput, 0, bytesPCM);
            return;
        }
        if (pInput == nullptr) {
            std::memset(pOutput, 0, bytesPCM);
            return;
        }

        // Копируем входной PCM (s16) в байтовый буфер
        std::vector<uint8_t> plain(bytesPCM);
        std::memcpy(plain.data(), pInput, bytesPCM);

        // AAD = seq в BE (8 байт) — фиксируем порядок
        const uint64_t sealSeq = self->aead.seq.load(std::memory_order_relaxed);
        uint64_t aad_be = host_to_be64(sealSeq);
        uint8_t aad[8];
        std::memcpy(aad, &aad_be, 8);

        // Снимок ключа/соли для декрипта (простая синхронизация)
        AeadCtx decodeSnap;
        {
            std::lock_guard<std::mutex> lg(self->crypto_mtx);
            decodeSnap.key = self->aead.key;
            decodeSnap.salt = self->aead.salt;
            decodeSnap.seq.store(sealSeq, std::memory_order_relaxed);
        }

        std::vector<uint8_t> cipher;
        if (!aead_seal(self->aead, std::span<const uint8_t>(aad, 8),
                       std::span<const uint8_t>(plain.data(), plain.size()),
                       cipher)) {
            std::memset(pOutput, 0, bytesPCM);
            return;
        }

        std::vector<uint8_t> decrypted;
        if (!aead_open(decodeSnap, sealSeq, std::span<const uint8_t>(aad, 8),
                       cipher, decrypted)) {
            std::memset(pOutput, 0, bytesPCM);
            std::cerr << "wrong decode..." << std::endl;
            return;
        }

        // Воспроизведение
        std::memcpy(pOutput, decrypted.data(), std::min(decrypted.size(), bytesPCM));
        if (decrypted.size() < bytesPCM) {
            std::memset((uint8_t *)pOutput + decrypted.size(), 0, bytesPCM - decrypted.size());
        }
    }

    // открыть/закрыть устройство один раз
    bool open() {
        if (running.load()) return true;
        if (!generateCrypto()) return false;

        if (ma_context_init(NULL, 0, NULL, &ctx) != MA_SUCCESS) {
            std::cerr << "context init failed\n"; return false;
        }
        ma_device_config cfgd = ma_device_config_init(ma_device_type_duplex);
        cfgd.sampleRate = (ma_uint32)cfg.sampleRate;
        cfgd.capture.format = ma_format_s16;
        cfgd.capture.channels = (ma_uint32)cfg.channels;
        cfgd.playback.format = ma_format_s16;
        cfgd.playback.channels = (ma_uint32)cfg.channels;
        cfgd.periodSizeInFrames = (ma_uint32)cfg.framesPerBuffer();
        cfgd.periods = 3;
        cfgd.dataCallback = on_duplex;
        cfgd.pUserData = this;

        if (ma_device_init(&ctx, &cfgd, &dev) != MA_SUCCESS) {
            std::cerr << "device init failed\n";
            ma_context_uninit(&ctx);
            return false;
        }
        running.store(true);
        std::cout << "Audio open OK: " << cfg.sampleRate << " Hz, "
                  << cfg.channels << " ch, frame " << cfg.framesPerBuffer() << "\n";
        return true;
    }

    void close() {
        if (!running.load()) return;
        stop_capture();
        ma_device_uninit(&dev);
        ma_context_uninit(&ctx);
        running.store(false);
        std::cout << "Audio closed.\n";
    }

    bool start_capture() {
        if (!running.load()) return false;
        if (capturing.load()) return true;
        if (ma_device_start(&dev) != MA_SUCCESS) {
            std::cerr << "device start failed\n"; return false;
        }
        capturing.store(true);
        return true;
    }

    void stop_capture() {
        if (!running.load()) return;
        if (!capturing.load()) return;
        ma_device_stop(&dev);
        capturing.store(false);
    }
};

bool MicButton(const char* id, bool active)
{
    ImGuiStyle& style = ImGui::GetStyle();
    float size = 40.0f; // диаметр кнопки
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 center = ImVec2(p.x + size * 0.5f, p.y + size * 0.5f);

    // Невидимая кнопка для ввода мыши
    ImGui::InvisibleButton(id, ImVec2(size, size), ImGuiButtonFlags_None);

    bool hovered = ImGui::IsItemHovered();
    bool pressed = ImGui::IsItemClicked();

    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddCircleFilled(center,
                          size * 0.5f,
                          active ? IM_COL32(255, 60, 60, 255) : // красная если записываем
                                   IM_COL32(200, 200, 200, 255),
                          32);

    draw->AddText(
        ImVec2(center.x - 10, center.y - 8),
        IM_COL32(0,0,0,255),
        "mic"
    );

    return pressed;
}

int main() {
    std::cout << "Zvonilka demo (SDL3 + ImGui): mic -> AES-GCM -> decrypt -> speakers\n";

    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMEPAD | SDL_INIT_EVENTS)) {
        std::cerr << "SDL_Init failed: " << SDL_GetError() << "\n";
        return 1;
    }

    const char* glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);

    SDL_Window* window = SDL_CreateWindow("Zvonilka", 800, 480,
                                          SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE);
    if (!window) {
        std::cerr << "SDL_CreateWindow failed: " << SDL_GetError() << "\n";
        SDL_Quit();
        return 1;
    }

    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui_ImplSDL3_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    App app;
    (void)app.open(); // пробуем открыть аудио; если не вышло — GUI всё равно покажем

    bool done = false;
    while (!done) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            ImGui_ImplSDL3_ProcessEvent(&e);
            if (e.type == SDL_EVENT_QUIT) done = true;
            if (e.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED &&
                e.window.windowID == SDL_GetWindowID(window)) done = true;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL3_NewFrame();
        ImGui::NewFrame();

        int w = 0, h = 0;
        SDL_GetWindowSizeInPixels(window, &w, &h);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(static_cast<float>(w), static_cast<float>(h)));
        // clang-format off
        ImGui::Begin("Control", nullptr,
            ImGuiWindowFlags_NoTitleBar | 
            ImGuiWindowFlags_NoResize   |
            ImGuiWindowFlags_NoMove     | 
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);
        // clang-format on

        ImGui::Text("Sample Rate: %d, Channels: %d, Frame: %d ms",
                    app.cfg.sampleRate, app.cfg.channels, app.cfg.frameMs);

        
        if (!app.capturing.load()) {
            if (MicButton("mic_record", false)) {
                if (!app.start_capture())
                    ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "Start failed");
            }
        } else {
            if (MicButton("mic_record", true)) {
                app.stop_capture();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Rotate Key")) {
            if (!app.generateCrypto())
                ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "Rotate failed");
            else
                ImGui::TextColored(ImVec4(0.3f,1,0.3f,1), "Key rotated");
        }

        ImGui::Separator();
        ImGui::Text("Device: %s", app.running.load() ? "open" : "not open");
        ImGui::Text("Capturing: %s", app.capturing.load() ? "yes" : "no");
        ImGui::Text("Hint: Start = begin duplex stream; Stop = pause stream.");
        ImGui::End();

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    app.close();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DestroyContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
