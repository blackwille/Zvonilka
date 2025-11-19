// Zvonilka RTP demo (SDL3 + ImGui + miniaudio + OpenSSL + Opus)
// mic -> Opus -> AES-256-GCM -> RTP/UDP -> AES-256-GCM -> Opus -> speakers

#include <SDL3/SDL_init.h>
#include <SDL3/SDL_video.h>
#include <SDL3/SDL.h>
#include <SDL3/SDL_opengl.h>

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
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <opus/opus.h>

#include "imgui.h"
#include "imgui_bindings/imgui_impl_sdl3.h"
#include "imgui_bindings/imgui_impl_opengl3.h"

#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"

// --- POSIX UDP (Linux/macOS). Для Windows нужно будет отдельно тащить winsock2 ---
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// ---------- AEAD (AES-256-GCM) ----------

struct AeadCtx {
    std::array<uint8_t, 32> key{};   // 256-bit
    std::array<uint8_t, 12> salt{};  // 96-bit IV prefix
    std::atomic<uint64_t> seq{0};    // per-packet sequence (на отправку)
};

static uint64_t host_to_be64(uint64_t x) {
    return ((x & 0x00000000000000FFULL) << 56) |
           ((x & 0x000000000000FF00ULL) << 40) |
           ((x & 0x0000000000FF0000ULL) << 24) |
           ((x & 0x00000000FF000000ULL) << 8)  |
           ((x & 0x000000FF00000000ULL) >> 8)  |
           ((x & 0x0000FF0000000000ULL) >> 24) |
           ((x & 0x00FF000000000000ULL) >> 40) |
           ((x & 0xFF00000000000000ULL) >> 56);
}

static void make_iv(const std::array<uint8_t,12>& salt,
                    uint64_t seq,
                    uint8_t out[12])
{
    std::memcpy(out, salt.data(), 12);
    uint64_t be = host_to_be64(seq);
    // первые 4 байта соли + 8 байт счётчика
    std::memcpy(out + 4, &be, 8);
}

static bool rand_bytes(uint8_t* dst, size_t n) {
    return RAND_bytes(dst, (int)n) == 1;
}

static bool aead_seal_pkt(const AeadCtx& ctx,
                          uint64_t seq,
                          std::span<const uint8_t> aad,
                          std::span<const uint8_t> plain,
                          std::vector<uint8_t>& outCipher)
{
    uint8_t iv[12];
    make_iv(ctx.salt, seq, iv);

    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;

    int ok = 1, len = 0, outLen = 0;
    ok &= EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    ok &= EVP_EncryptInit_ex(c, nullptr, nullptr, ctx.key.data(), iv);

    if (!aad.empty())
        ok &= EVP_EncryptUpdate(c, nullptr, &len,
                                aad.data(), (int)aad.size());

    outCipher.resize(plain.size() + 16);
    ok &= EVP_EncryptUpdate(c, outCipher.data(), &len,
                            plain.data(), (int)plain.size());
    outLen = len;

    ok &= EVP_EncryptFinal_ex(c, outCipher.data() + outLen, &len);
    outLen += len;

    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16,
                              outCipher.data() + outLen);
    outLen += 16;
    outCipher.resize(outLen);

    EVP_CIPHER_CTX_free(c);
    return ok != 0;
}

static bool aead_open_pkt(const AeadCtx& ctx,
                          uint64_t seq,
                          std::span<const uint8_t> aad,
                          std::span<const uint8_t> cipherWithTag,
                          std::vector<uint8_t>& outPlain)
{
    if (cipherWithTag.size() < 16) return false;
    const size_t clen = cipherWithTag.size() - 16;
    const uint8_t* tag = cipherWithTag.data() + clen;

    uint8_t iv[12];
    make_iv(ctx.salt, seq, iv);

    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;

    int ok = 1, len = 0, outLen = 0;
    ok &= EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    ok &= EVP_DecryptInit_ex(c, nullptr, nullptr, ctx.key.data(), iv);

    if (!aad.empty())
        ok &= EVP_DecryptUpdate(c, nullptr, &len,
                                aad.data(), (int)aad.size());

    outPlain.resize(clen);
    ok &= EVP_DecryptUpdate(c, outPlain.data(), &len,
                            cipherWithTag.data(), (int)clen);
    outLen = len;

    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    ok &= EVP_DecryptFinal_ex(c, outPlain.data() + outLen, &len);
    outLen += len;

    EVP_CIPHER_CTX_free(c);
    return ok != 0;
}

// ---------- RTP (минималистичный заголовок) ----------

#pragma pack(push, 1)
struct RtpHeader {
    uint8_t  vpxcc;
    uint8_t  mpt;
    uint16_t seq;
    uint32_t timestamp;
    uint32_t ssrc;
};
#pragma pack(pop)

static constexpr uint8_t RTP_VERSION = 2;
static constexpr uint8_t RTP_PAYLOAD_TYPE_OPUS = 111; // стандартный динамический PT для Opus

// ---------- Аудиоконфиг и состояние приложения ----------

struct AudioConfig {
    int sampleRate = 48000;
    int channels   = 1;
    int frameMs    = 20; // 20 ms
    int framesPerBuffer() const { return (sampleRate / 1000) * frameMs; }
};

struct App {
    // --- Core audio config & crypto ---
    AudioConfig cfg{};
    AeadCtx     aead{};
    std::mutex  crypto_mtx;

    // --- miniaudio device ---
    ma_context ctx{};
    ma_device  dev{};

    // Ring buffer для принятых PCM из сети
    ma_pcm_rb      rb{};
    bool           rbInitialized{false};
    ma_uint32      rbCapacityFrames{48000}; // 1 сек буфер на 48k

    std::atomic<bool> running{false};    // device open
    std::atomic<bool> capturing{false};  // started

    // --- Opus ---
    OpusEncoder* encoder{nullptr};
    OpusDecoder* decoder{nullptr};

    // --- Network / RTP ---
    int          sockfd{-1};
    sockaddr_in  localAddr{};
    sockaddr_in  remoteAddr{};
    std::atomic<bool> netRunning{false};
    std::thread recvThread;

    uint16_t rtpSeq{0};
    uint32_t rtpTimestamp{0};
    uint32_t rtpSSRC{0};

    // UI helpers
    bool           keyValid{false};
    std::string    lastError;

    // ---- Utility ----
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
        // if (!rand_bytes(aead.key.data(), aead.key.size())) {
        //     lastError = "RAND key failed";
        //     return false;
        // }
        // if (!rand_bytes(aead.salt.data(), aead.salt.size())) {
        //     lastError = "RAND salt failed";
        //     return false;
        // }
        for (uint8_t& byte : aead.key) {
            byte = '\x11';
        }
        for (uint8_t& byte : aead.salt) {
            byte = '\x11';
        }
        aead.seq.store(0, std::memory_order_relaxed);
        keyValid = true;

        print_hex("Session key:",
                  std::span<const uint8_t>(aead.key.data(), aead.key.size()));
        print_hex("Session salt:",
                  std::span<const uint8_t>(aead.salt.data(), aead.salt.size()));

        return true;
    }

    // --- Opus init/destroy ---
    bool initOpus() {
        int err = 0;
        encoder = opus_encoder_create(cfg.sampleRate, cfg.channels,
                                      OPUS_APPLICATION_VOIP, &err);
        if (err != OPUS_OK || !encoder) {
            lastError = "Opus encoder init failed: " + std::string(opus_strerror(err));
            return false;
        }

        decoder = opus_decoder_create(cfg.sampleRate, cfg.channels, &err);
        if (err != OPUS_OK || !decoder) {
            lastError = "Opus decoder init failed: " + std::string(opus_strerror(err));
            opus_encoder_destroy(encoder);
            encoder = nullptr;
            return false;
        }
        return true;
    }

    void destroyOpus() {
        if (encoder) {
            opus_encoder_destroy(encoder);
            encoder = nullptr;
        }
        if (decoder) {
            opus_decoder_destroy(decoder);
            decoder = nullptr;
        }
    }

    // --- Network init/destroy ---
    bool startNetwork(const std::string& localIp,
                      uint16_t          localPort,
                      const std::string& remoteIp,
                      uint16_t          remotePort)
    {
        if (netRunning.load()) return true;

        sockfd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            lastError = "socket() failed";
            return false;
        }

        std::memset(&localAddr, 0, sizeof(localAddr));
        localAddr.sin_family = AF_INET;
        localAddr.sin_port   = htons(localPort);
        localAddr.sin_addr.s_addr = localIp.empty()
                                  ? INADDR_ANY
                                  : ::inet_addr(localIp.c_str());

        if (::bind(sockfd, (sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
            lastError = "bind() failed";
            ::close(sockfd);
            sockfd = -1;
            return false;
        }

        std::memset(&remoteAddr, 0, sizeof(remoteAddr));
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_port   = htons(remotePort);
        remoteAddr.sin_addr.s_addr = ::inet_addr(remoteIp.c_str());

        // RTP params
        rtpSeq       = (uint16_t)std::rand();
        rtpTimestamp = 0;
        rtpSSRC      = (uint32_t)std::rand();

        netRunning.store(true);
        recvThread   = std::thread(&App::recvLoop, this);

        return true;
    }

    void stopNetwork() {
        if (!netRunning.load()) return;
        netRunning.store(false);
        if (sockfd >= 0) {
            ::shutdown(sockfd, SHUT_RDWR);
            ::close(sockfd);
            sockfd = -1;
        }
        if (recvThread.joinable())
            recvThread.join();
    }

    void recvLoop() {
        // Принимаем RTP пакеты, расшифровываем, декодируем Opus и складываем PCM в ring buffer
        std::vector<uint8_t> buf(1500);
        while (netRunning.load()) {
            sockaddr_in src{};
            socklen_t   slen = sizeof(src);
            ssize_t n = ::recvfrom(sockfd, buf.data(), (int)buf.size(), 0,
                                   (sockaddr*)&src, &slen);
            if (n <= 0) {
                // сокет закрыт или ошибка; выходим
                break;
            }
            if (n < (ssize_t)(sizeof(RtpHeader) + 8 + 16)) {
                continue; // мало для RTP+seq+tag
            }

            auto* hdr = reinterpret_cast<RtpHeader*>(buf.data());
            uint8_t* p = buf.data() + sizeof(RtpHeader);

            uint64_t seq_be = 0;
            std::memcpy(&seq_be, p, 8);
            uint64_t seq = host_to_be64(seq_be);

            size_t cipherLen = (size_t)n - sizeof(RtpHeader) - 8;
            std::span<const uint8_t> cipher(p + 8, cipherLen);

            // AAD = RTP header (можно и без, но давай прилично)
            std::span<const uint8_t> aad(reinterpret_cast<uint8_t*>(hdr),
                                         sizeof(RtpHeader));

            // снимем снапшот ключа
            AeadCtx snap;
            {
                std::lock_guard<std::mutex> lg(crypto_mtx);
                snap.key  = aead.key;
                snap.salt = aead.salt;
            }

            std::vector<uint8_t> plain;
            if (!aead_open_pkt(snap, seq, aad, cipher, plain)) {
                std::cerr << "Decrypt failed\n";
                continue;
            }

            if (!decoder) continue;

            const int maxFrames = cfg.framesPerBuffer();
            std::vector<int16_t> pcm(maxFrames * cfg.channels);

            int decoded = opus_decode(decoder,
                                      plain.data(), (opus_int32)plain.size(),
                                      pcm.data(), maxFrames,
                                      0);
            if (decoded <= 0) {
                std::cerr << "Opus decode error: " << decoded << "\n";
                continue;
            }

            if (!rbInitialized) continue;

            ma_uint32 framesToWrite = (ma_uint32)decoded;
            void*     pWrite = nullptr;
            if (ma_pcm_rb_acquire_write(&rb, &framesToWrite, &pWrite) == MA_SUCCESS &&
                framesToWrite >= (ma_uint32)decoded)
            {
                std::memcpy(pWrite, pcm.data(),
                            decoded * cfg.channels * sizeof(int16_t));
                ma_pcm_rb_commit_write(&rb, (ma_uint32)decoded);
            }
            // если места не хватило — просто дропаем
        }
    }

    // --- Audio open/close ---
    bool open() {
        if (running.load()) return true;

        if (ma_context_init(nullptr, 0, nullptr, &ctx) != MA_SUCCESS) {
            lastError = "ma_context_init failed";
            return false;
        }

        if (!initOpus()) {
            ma_context_uninit(&ctx);
            return false;
        }

        ma_device_config cfgd = ma_device_config_init(ma_device_type_duplex);
        cfgd.sampleRate          = (ma_uint32)cfg.sampleRate;
        cfgd.capture.format      = ma_format_s16;
        cfgd.capture.channels    = (ma_uint32)cfg.channels;
        cfgd.playback.format     = ma_format_s16;
        cfgd.playback.channels   = (ma_uint32)cfg.channels;
        cfgd.periodSizeInFrames  = (ma_uint32)cfg.framesPerBuffer();
        cfgd.periods             = 3;
        cfgd.dataCallback        = &App::on_duplex;
        cfgd.pUserData           = this;

        if (ma_device_init(&ctx, &cfgd, &dev) != MA_SUCCESS) {
            lastError = "ma_device_init failed";
            destroyOpus();
            ma_context_uninit(&ctx);
            return false;
        }

        // ring buffer
        if (ma_pcm_rb_init(ma_format_s16,
                           (ma_uint32)cfg.channels,
                           rbCapacityFrames,
                           nullptr,
                           nullptr,
                           &rb) != MA_SUCCESS) {
            lastError = "ma_pcm_rb_init failed";
            ma_device_uninit(&dev);
            destroyOpus();
            ma_context_uninit(&ctx);
            return false;
        }
        rbInitialized = true;

        running.store(true);
        return true;
    }

    void close() {
        stop_capture();
        stopNetwork();

        if (rbInitialized) {
            ma_pcm_rb_uninit(&rb);
            rbInitialized = false;
        }

        if (running.load()) {
            ma_device_uninit(&dev);
            ma_context_uninit(&ctx);
            destroyOpus();
            running.store(false);
        }
    }

    bool start_capture() {
        if (!running.load()) {
            lastError = "Device not open";
            return false;
        }
        if (capturing.load()) return true;

        if (ma_device_start(&dev) != MA_SUCCESS) {
            lastError = "ma_device_start failed";
            return false;
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

    // --- Audio callback ---
    static void on_duplex(ma_device* pDevice,
                          void*      pOutput,
                          const void* pInput,
                          ma_uint32  frameCount)
    {
        App* self = static_cast<App*>(pDevice->pUserData);
        if (!self || !pOutput) return;

        const ma_uint32 ch = (ma_uint32)self->cfg.channels;
        const size_t bytesPCM = frameCount * ma_get_bytes_per_frame(ma_format_s16, ch);

        auto* out = static_cast<int16_t*>(pOutput);

        // Playback: читаем из ring buffer
        if (self->rbInitialized) {
            ma_uint32 framesToRead = frameCount;
            void*     pRead = nullptr;
            if (ma_pcm_rb_acquire_read(&self->rb, &framesToRead, &pRead) == MA_SUCCESS &&
                framesToRead > 0)
            {
                size_t copyFrames = std::min<ma_uint32>(framesToRead, frameCount);
                size_t copyBytes = copyFrames * ch * sizeof(int16_t);
                std::memcpy(out, pRead, copyBytes);
                ma_pcm_rb_commit_read(&self->rb, copyFrames);

                if (copyFrames < frameCount) {
                    std::memset(reinterpret_cast<uint8_t*>(out) + copyBytes,
                                0,
                                bytesPCM - copyBytes);
                }
            } else {
                std::memset(out, 0, bytesPCM);
            }
        } else {
            std::memset(out, 0, bytesPCM);
        }

        // Capture + send
        if (!self->capturing.load(std::memory_order_relaxed)) {
            return;
        }
        if (!pInput) {
            return;
        }
        if (!self->encoder) return;
        if (!self->keyValid) return; // нет ключа — не шифруем, не шлём

        auto* in = static_cast<const int16_t*>(pInput);
        const int frameSize = (int)frameCount;

        // 1) Opus encode
        std::vector<uint8_t> opusPacket(4000);
        int nbBytes = opus_encode(self->encoder,
                                  in,
                                  frameSize,
                                  opusPacket.data(),
                                  (opus_int32)opusPacket.size());
        if (nbBytes <= 0) {
            std::cerr << "Opus encode error: " << nbBytes << "\n";
            return;
        }
        opusPacket.resize(nbBytes);

        if (self->sockfd < 0 || !self->netRunning.load()) {
            // сеть не включена — можно было бы сделать локальный loopback, но для MVP шлём только по сети
            return;
        }

        // 2) Снапшот ключа и seq
        AeadCtx snap;
        uint64_t seq = 0;
        {
            std::lock_guard<std::mutex> lg(self->crypto_mtx);
            snap.key  = self->aead.key;
            snap.salt = self->aead.salt;
            seq = self->aead.seq.fetch_add(1, std::memory_order_relaxed);
        }

        // 3) RTP header
        RtpHeader hdr{};
        hdr.vpxcc    = (uint8_t)((RTP_VERSION << 6) | 0); // V=2, P=0, X=0, CC=0
        hdr.mpt      = (uint8_t)(0x00 | (RTP_PAYLOAD_TYPE_OPUS & 0x7F)); // M=0, PT=111
        hdr.seq      = htons(self->rtpSeq++);
        hdr.timestamp = htonl(self->rtpTimestamp);
        hdr.ssrc     = htonl(self->rtpSSRC);
        self->rtpTimestamp += frameSize; // 1 sample per tick

        // AAD = RTP header
        std::span<const uint8_t> aad(reinterpret_cast<uint8_t*>(&hdr),
                                     sizeof(RtpHeader));

        // 4) Encrypt Opus payload, seq в отдельном поле
        uint64_t seq_be = host_to_be64(seq);
        std::vector<uint8_t> cipher;
        if (!aead_seal_pkt(snap, seq,
                           aad,
                           std::span<const uint8_t>(opusPacket.data(), opusPacket.size()),
                           cipher))
        {
            std::cerr << "Encrypt failed\n";
            return;
        }

        std::vector<uint8_t> packet;
        packet.resize(sizeof(RtpHeader) + 8 + cipher.size());
        std::memcpy(packet.data(), &hdr, sizeof(RtpHeader));
        std::memcpy(packet.data() + sizeof(RtpHeader), &seq_be, 8);
        std::memcpy(packet.data() + sizeof(RtpHeader) + 8,
                    cipher.data(), cipher.size());

        ::sendto(self->sockfd,
                 packet.data(), (int)packet.size(),
                 0,
                 (sockaddr*)&self->remoteAddr, sizeof(self->remoteAddr));
    }
};

// ---------- UI helpers ----------

static bool MicButton(const char* id, bool active) {
    ImVec2 size = ImVec2(48, 48);
    ImVec2 pos  = ImGui::GetCursorScreenPos();
    ImVec2 center = ImVec2(pos.x + size.x * 0.5f, pos.y + size.y * 0.5f);

    ImGui::InvisibleButton(id, size);
    bool hovered = ImGui::IsItemHovered();
    bool pressed = ImGui::IsItemClicked();

    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddCircleFilled(center,
                          size.x * 0.5f,
                          active ? IM_COL32(255, 60, 60, 255)
                                 : IM_COL32(200, 200, 200, 255),
                          32);

    float innerRadius = size.x * 0.2f;
    draw->AddCircleFilled(center,
                          innerRadius,
                          IM_COL32(255, 255, 255, 255),
                          16);

    if (hovered) {
        draw->AddCircle(center,
                        size.x * 0.5f - 1,
                        IM_COL32(255, 255, 255, 120),
                        32,
                        2.0f);
    }

    return pressed;
}

// ---------- main ----------

int main(int, char**) {
    if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMEPAD | SDL_INIT_EVENTS)) {
        std::cerr << "SDL_Init failed: " << SDL_GetError() << "\n";
        return -1;
    }

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK,
                        SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);

    SDL_Window* window = SDL_CreateWindow("Zvonilka RTP Demo",
                                          1280, 720,
                                          SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE);
    if (!window) {
        std::cerr << "SDL_CreateWindow failed: " << SDL_GetError() << "\n";
        SDL_Quit();
        return -1;
    }

    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    if (!gl_context) {
        std::cerr << "SDL_GL_CreateContext failed: " << SDL_GetError() << "\n";
        SDL_DestroyWindow(window);
        SDL_Quit();
        return -1;
    }
    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();

    ImGui_ImplSDL3_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init("#version 330");

    App app;

    bool quit = false;
    bool showDemo = false;

    // network UI state
    static char localIpBuf[64]  = "";           // пусто = INADDR_ANY
    static char remoteIpBuf[64] = "127.0.0.1";  // по умолчанию localhost
    static int  localPort       = 5004;
    static int  remotePort      = 5005;

    while (!quit) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            ImGui_ImplSDL3_ProcessEvent(&e);
            if (e.type == SDL_EVENT_QUIT)
                quit = true;
            if (e.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED &&
                e.window.windowID == SDL_GetWindowID(window))
                quit = true;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL3_NewFrame();
        ImGui::NewFrame();

        if (showDemo)
            ImGui::ShowDemoWindow(&showDemo);

        int w = 0, h = 0;
        SDL_GetWindowSizeInPixels(window, &w, &h);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(static_cast<float>(w), static_cast<float>(h)));
        // clang-format off
        ImGui::Begin("Zvonilka RTP", nullptr,
            ImGuiWindowFlags_NoTitleBar | 
            ImGuiWindowFlags_NoResize   |
            ImGuiWindowFlags_NoMove     | 
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);
        // clang-format on

        ImGui::Text("Audio: %d Hz, %d ch, %d ms",
                    app.cfg.sampleRate,
                    app.cfg.channels,
                    app.cfg.frameMs);
        ImGui::Separator();

        // Mic button
        ImGui::Text("Mic:");
        ImGui::SameLine();
        if (MicButton("mic_btn", app.capturing.load())) {
            if (!app.capturing.load()) {
                if (!app.start_capture()) {
                    ImGui::TextColored(ImVec4(1,0.3f,0.3f,1),
                                       "Start capture failed");
                }
            } else {
                app.stop_capture();
            }
        }

        ImGui::SameLine();
        ImGui::Text("%s", app.capturing.load() ? "ON" : "OFF");

        // Device open/close
        if (!app.running.load()) {
            if (ImGui::Button("Open device")) {
                if (!app.open()) {
                    ImGui::TextColored(ImVec4(1,0.3f,0.3f,1),
                                       "Open failed");
                }
            }
        } else {
            if (ImGui::Button("Close device")) {
                app.close();
            }
        }

        // Crypto
        if (ImGui::Button("Rotate session key")) {
            if (!app.generateCrypto()) {
                ImGui::TextColored(ImVec4(1,0.3f,0.3f,1),
                                   "Key rotation failed");
            }
        }
        ImGui::SameLine();
        ImGui::Text("%s", app.keyValid ? "Key: OK" : "Key: not set");

        ImGui::Separator();
        ImGui::Text("Network (RTP over UDP + Opus)");

        ImGui::InputText("Local IP (empty = 0.0.0.0)", localIpBuf,
                         sizeof(localIpBuf));
        ImGui::InputInt("Local port", &localPort);
        ImGui::InputText("Remote IP", remoteIpBuf, sizeof(remoteIpBuf));
        ImGui::InputInt("Remote port", &remotePort);

        if (!app.netRunning.load()) {
            if (ImGui::Button("Start network")) {
                std::string localIp  = localIpBuf;
                std::string remoteIp = remoteIpBuf;
                if (!app.startNetwork(localIp,
                                      (uint16_t)localPort,
                                      remoteIp,
                                      (uint16_t)remotePort))
                {
                    ImGui::TextColored(ImVec4(1,0.3f,0.3f,1),
                                       "Network start failed");
                }
            }
        } else {
            if (ImGui::Button("Stop network")) {
                app.stopNetwork();
            }
        }

        ImGui::Text("Device: %s", app.running.load()   ? "open" : "closed");
        ImGui::Text("Capture: %s", app.capturing.load() ? "on"   : "off");
        ImGui::Text("Network: %s", app.netRunning.load() ? "on"   : "off");

        if (!app.lastError.empty()) {
            ImGui::Separator();
            ImGui::TextColored(ImVec4(1,0.5f,0.5f,1),
                               "Last error: %s", app.lastError.c_str());
        }

        ImGui::Checkbox("Show ImGui demo", &showDemo);

        ImGui::End();

        ImGui::Render();
        SDL_GL_MakeCurrent(window, gl_context);
        glViewport(0, 0,
                   (int)ImGui::GetIO().DisplaySize.x,
                   (int)ImGui::GetIO().DisplaySize.y);
        glClearColor(0.1f, 0.12f, 0.15f, 1.0f);
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
