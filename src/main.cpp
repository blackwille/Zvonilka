// main.cpp
//
// Zvonilka: ICE + TURN + Opus + AES-256-GCM demo.
// -------------------------------------------------------
// Архитектура (кратко):
//
//  * Аудио:
//      - miniaudio duplex: захват и воспроизведение моно 48 kHz.
//      - Opus (voip) кодек.
//
//  * Сеть:
//      - libnice (ICE) как единственный транспорт медиа.
//      - STUN/TURN на coturn.
//      - Кнопка "Force TURN only": при включении используем
//        только RELAY-кандидат (через TURN).
//
//  * Шифрование медиа:
//      - AES-256-GCM (блочное шифрование).
//      - Раздельные ключи TX и RX.
//      - Обмен ключами по RSA (pubkey собеседника).
//      - Смена TX-ключа по кнопке -> отправка зашифрованного
//        ключа собеседнику (он забирает его через сигн. сервер).
//      - Можно отключить шифрование кнопкой.
//
//  * Сигналинг (signaling_server.py):
//      - GETPUB: получить RSA pub сервера.
//      - AUTH: RSA-авторизация по login/pass, токен.
//      - PUBKEY: получить публичный ключ другого пользователя.
//      - KEY_PUSH / KEY_POLL: обмен зашифрованными AES-ключами.
//      - ICE_OFFER / ICE_POLL_OFFER / ICE_ANSWER / ICE_POLL_ANSWER:
//        обмен зашифрованными ICE-параметрами.
//
//    Все данные, которые содержат ключи (AES/ICE), шифруются RSA
//    (client<->client через сервер). Сервер видит только RSA-шифротекст.
//
//  * UI (ImGui):
//      - Авторизация на сигналинге.
//      - Настройки STUN/TURN, флаг Force TURN only.
//      - Кнопки:
//          * Мут микрофона.
//          * Вкл/выкл шифрование аудио.
//          * Смена TX-ключа и отправка собеседнику.
//          * Получение нового RX-ключа.
//          * ICE: Caller / Callee, отправка offer/answer,
//            получение offer/answer.
//      - Простая визуализация через внешние шейдеры:
//          shaders/voice_vis_shader.vert
//          shaders/voice_vis_shader.frag
//
// -------------------------------------------------------

#include <GL/glew.h>
#include <SDL3/SDL.h>
#include <SDL3/SDL_error.h>
#include <SDL3/SDL_init.h>
#include <SDL3/SDL_opengl.h>
#include <SDL3/SDL_video.h>
#include <nice/candidate.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <opus_defines.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <list>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#undef min
#undef max
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

// spdlog
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"

// ImGui
#include "imgui.h"
#include "imgui_bindings/imgui_impl_opengl3.h"
#include "imgui_bindings/imgui_impl_sdl3.h"

// Opus
#include <opus/opus.h>

// miniaudio
#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"

// libnice / GLib
#include <glib-object.h>
#include <glib.h>
#include <nice/agent.h>

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

#ifdef _WIN32
struct WsaInit {
    WsaInit() {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            spdlog::critical("WSAStartup failed");
        }
    }
    ~WsaInit() { WSACleanup(); }
};
#endif

static std::string Trim(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace((unsigned char)s[b])) b++;
    size_t e = s.size();
    while (e > b && std::isspace((unsigned char)s[e - 1])) e--;
    return s.substr(b, e - b);
}

static std::string LoadFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) throw std::runtime_error("Failed to open file: " + path);
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

// Base64 (через OpenSSL EVP_Encode/DecodeBlock)

static std::string B64Encode(const std::vector<uint8_t>& in) {
    if (in.empty()) return {};
    int outLen = 4 * ((int)in.size() / 3 + 1);
    std::string out;
    out.resize(outLen);
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), in.data(), (int)in.size());
    if (n < 0) return {};
    out.resize(n);
    return out;
}

static bool B64Decode(const std::string& in, std::vector<uint8_t>& out) {
    if (in.empty()) return false;
    int outLen = 3 * ((int)in.size() / 4 + 1);
    out.resize(outLen);
    int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(in.data()), (int)in.size());
    if (n < 0) return false;
    // EVP_DecodeBlock может добить нулями — подрежем
    while (n > 0 && out[(size_t)n - 1] == 0) --n;
    out.resize((size_t)n);
    return true;
}

// ------------------------------------------------------------
// RSA / AES
// ------------------------------------------------------------

class RsaKeyPair {
public:
    RsaKeyPair() = default;
    ~RsaKeyPair() {
        if (pkey_) EVP_PKEY_free(pkey_);
    }

    RsaKeyPair(const RsaKeyPair&) = delete;
    RsaKeyPair& operator=(const RsaKeyPair&) = delete;

    EVP_PKEY* get() const { return pkey_; }

    bool generate(int bits = 4096) {
        if (pkey_) {
            EVP_PKEY_free(pkey_);
            pkey_ = nullptr;
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return false;

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        BIGNUM* e = BN_new();
        if (!e || !BN_set_word(e, RSA_F4)) {
            if (e) BN_free(e);
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) <= 0) {
            BN_free(e);
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        BN_free(e);  // ctx держит свою копию

        if (EVP_PKEY_keygen(ctx, &pkey_) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        EVP_PKEY_CTX_free(ctx);
        return true;
    }

    std::string publicDerB64() const {
        if (!pkey_) return {};
        int len = i2d_PUBKEY(pkey_, nullptr);
        if (len <= 0) return {};
        std::vector<uint8_t> buf((size_t)len);
        unsigned char* p = buf.data();
        if (i2d_PUBKEY(pkey_, &p) != len) return {};
        return B64Encode(buf);
    }

    // RSA-OAEP + SHA512
    bool decrypt(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain) const {
        if (!pkey_) return false;

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        if (!ctx) return false;

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha512()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha512()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, cipher.data(), cipher.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        plain.resize(outlen);
        if (EVP_PKEY_decrypt(ctx, plain.data(), &outlen, cipher.data(), cipher.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        plain.resize(outlen);
        EVP_PKEY_CTX_free(ctx);
        return true;
    }

private:
    EVP_PKEY* pkey_{nullptr};
};

class RsaPublicKey {
public:
    RsaPublicKey() = default;
    ~RsaPublicKey() {
        if (pkey_) EVP_PKEY_free(pkey_);
    }

    RsaPublicKey(const RsaPublicKey&) = delete;
    RsaPublicKey& operator=(const RsaPublicKey&) = delete;

    RsaPublicKey(RsaPublicKey&& other) noexcept : pkey_(std::exchange(other.pkey_, nullptr)) {}
    RsaPublicKey& operator=(RsaPublicKey&& other) noexcept {
        if (this != &other) {
            if (pkey_) EVP_PKEY_free(pkey_);
            pkey_ = std::exchange(other.pkey_, nullptr);
        }
        return *this;
    }

    bool loadDer(const std::vector<uint8_t>& der) {
        if (pkey_) {
            EVP_PKEY_free(pkey_);
            pkey_ = nullptr;
        }
        const unsigned char* p = der.data();
        pkey_ = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
        return pkey_ != nullptr;
    }

    bool encrypt(const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher) const {
        if (!pkey_) return false;

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        if (!ctx) return false;

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha512()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha512()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plain.data(), plain.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }

        cipher.resize(outlen);
        if (EVP_PKEY_encrypt(ctx, cipher.data(), &outlen, plain.data(), plain.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        cipher.resize(outlen);
        EVP_PKEY_CTX_free(ctx);
        return true;
    }

    bool valid() const { return pkey_ != nullptr; }

private:
    EVP_PKEY* pkey_{nullptr};
};

struct AesGcmKey {
    std::array<uint8_t, 32> key{};
};

class AesGcm {
public:
    AesGcm() {
        ctx_ = EVP_CIPHER_CTX_new();
        if (!ctx_) {
            spdlog::critical("EVP_CIPHER_CTX_new failed");
        }
    }
    ~AesGcm() { EVP_CIPHER_CTX_free(ctx_); }

    void setKey(const AesGcmKey& k) { key_ = k; }

    bool encrypt(const uint8_t* plain, size_t plainLen, const uint8_t* aad, size_t aadLen, const uint8_t iv[12],
                 std::vector<uint8_t>& outCipher, std::array<uint8_t, 16>& tag) {
        const EVP_CIPHER* cipher = EVP_aes_256_gcm();
        int rc = EVP_EncryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr);
        if (rc != 1) return false;
        rc = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        if (rc != 1) return false;
        rc = EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key_.key.data(), iv);
        if (rc != 1) return false;

        int len = 0;
        if (aad && aadLen > 0) {
            rc = EVP_EncryptUpdate(ctx_, nullptr, &len, aad, (int)aadLen);
            if (rc != 1) return false;
        }

        outCipher.resize(plainLen);
        rc = EVP_EncryptUpdate(ctx_, outCipher.data(), &len, plain, (int)plainLen);
        if (rc != 1) return false;
        int cipherLen = len;

        rc = EVP_EncryptFinal_ex(ctx_, outCipher.data() + cipherLen, &len);
        if (rc != 1) return false;
        cipherLen += len;
        outCipher.resize(cipherLen);

        rc = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        return rc == 1;
    }

    bool decrypt(const uint8_t* cipherText, size_t cipherLen, const uint8_t* aad, size_t aadLen, const uint8_t iv[12],
                 const uint8_t tag[16], std::vector<uint8_t>& plain) {
        const EVP_CIPHER* cipher = EVP_aes_256_gcm();
        int rc = EVP_DecryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr);
        if (rc != 1) return false;
        rc = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        if (rc != 1) return false;
        rc = EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key_.key.data(), iv);
        if (rc != 1) return false;

        int len = 0;
        if (aad && aadLen > 0) {
            rc = EVP_DecryptUpdate(ctx_, nullptr, &len, aad, (int)aadLen);
            if (rc != 1) return false;
        }

        plain.resize(cipherLen);
        rc = EVP_DecryptUpdate(ctx_, plain.data(), &len, cipherText, (int)cipherLen);
        if (rc != 1) return false;
        int plainLen = len;

        rc = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
        if (rc != 1) return false;
        rc = EVP_DecryptFinal_ex(ctx_, plain.data() + plainLen, &len);
        if (rc != 1) return false;
        plainLen += len;
        plain.resize(plainLen);
        return true;
    }

private:
    EVP_CIPHER_CTX* ctx_{};
    AesGcmKey key_{};
};

static void randomKey(AesGcmKey& k) { RAND_bytes(k.key.data(), (int)k.key.size()); }

// ------------------------------------------------------------
// Audio (miniaudio + Opus)
// ------------------------------------------------------------

struct AudioFrame {
    std::vector<float> samples;
};

class AudioEngine {
public:
    bool init() {
        ma_device_config cfg = ma_device_config_init(ma_device_type_duplex);
        cfg.capture.format = ma_format_f32;
        cfg.capture.channels = 1;
        cfg.playback.format = ma_format_f32;
        cfg.playback.channels = 1;
        cfg.sampleRate = 48000;
        cfg.dataCallback = &AudioEngine::dataCallback;
        cfg.pUserData = this;

        ma_result res = ma_device_init(nullptr, &cfg, &device_);
        if (res != MA_SUCCESS) {
            std::cerr << "miniaudio init failed: " << (int)res << "\n";
            return false;
        }
        res = ma_device_start(&device_);
        if (res != MA_SUCCESS) {
            std::cerr << "miniaudio start failed\n";
            return false;
        }
        // размер jitter-буфера, напр. 80 мс
        rbCapacityFrames_ = cfg.sampleRate / 1000 * 200;  // 80ms
        if (ma_pcm_rb_init(ma_format_f32, cfg.capture.channels, rbCapacityFrames_, nullptr, nullptr, &playbackRb_) !=
            MA_SUCCESS) {
            return false;
        }
        rbInitialized_ = true;
        return true;
    }

    ~AudioEngine() {
        ma_device_uninit(&device_);
        if (rbInitialized_) {
            ma_pcm_rb_uninit(&playbackRb_);
            rbInitialized_ = false;
        }
    }

    void setMuted(bool m) { muted_.store(m); }

    bool popCaptured(AudioFrame& frame) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (captureQueue_.empty()) return false;
        frame = std::move(captureQueue_.front());
        captureQueue_.pop_front();
        return true;
    }

    void pushPlayback(const AudioFrame& frame) {
        if (!rbInitialized_) return;
        if (frame.samples.empty()) return;

        const float* data = frame.samples.data();
        auto framesToWrite = static_cast<ma_uint32>(frame.samples.size());

        std::lock_guard<std::mutex> lock(mutex_);  // если у тебя уже есть mutex_

        while (framesToWrite > 0) {
            // Сколько свободного места есть сейчас?
            ma_uint32 freeFrames = ma_pcm_rb_available_write(&playbackRb_);
            if (freeFrames == 0) {
                // Буфер забит -> выбрасываем кусок старых данных
                ma_uint32 discard = framesToWrite;  // можно и поменьше, но так проще
                void* pDiscard = nullptr;
                if (ma_pcm_rb_acquire_read(&playbackRb_, &discard, &pDiscard) == MA_SUCCESS && discard > 0) {
                    ma_pcm_rb_commit_read(&playbackRb_, discard);
                } else {
                    // не получилось прочитать — выходим, чтобы не зациклиться
                    break;
                }
            }

            ma_uint32 chunk = framesToWrite;
            void* pWrite = nullptr;
            if (ma_pcm_rb_acquire_write(&playbackRb_, &chunk, &pWrite) != MA_SUCCESS || chunk == 0) {
                break;
            }

            // копируем chunk фреймов в буфер
            std::memcpy(pWrite, data,
                        chunk * sizeof(float));  // mono; если стерео — *channels

            ma_pcm_rb_commit_write(&playbackRb_, chunk);

            data += chunk;
            framesToWrite -= chunk;
        }
    }

private:
    static void dataCallback(ma_device* device, void* output, const void* input, ma_uint32 frameCount) {
        auto* self = (AudioEngine*)device->pUserData;
        self->onData((float*)output, (const float*)input, (size_t)frameCount);
    }

    void onData(float* out, const float* in, size_t frames) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Захват
        if (!muted_.load()) {
            // Добавляем свежие сэмплы в аккумулятор
            captureAccum_.insert(captureAccum_.end(), in, in + frames);

            // Нарезаем на кадры по 960 сэмплов
            const size_t frameSize = 960;  // 20 ms @ 48 kHz
            while (captureAccum_.size() >= frameSize) {
                AudioFrame f;
                f.samples.assign(captureAccum_.begin(), captureAccum_.begin() + frameSize);
                captureQueue_.emplace_back(std::move(f));
                captureAccum_.erase(captureAccum_.begin(), captureAccum_.begin() + frameSize);
            }
        }

        const ma_uint32 framesRequested = (ma_uint32)frames;
        const size_t bytesTotal = framesRequested * sizeof(float);  // mono

        if (!rbInitialized_) {
            // буфер ещё не готов — тишина
            std::memset(out, 0, bytesTotal);
            return;
        }

        ma_uint32 framesToRead = framesRequested;
        void* pRead = nullptr;

        ma_result res = ma_pcm_rb_acquire_read(&playbackRb_, &framesToRead, &pRead);
        if (res == MA_SUCCESS && framesToRead > 0) {
            const size_t bytesRead = framesToRead * sizeof(float);
            std::memcpy(out, pRead, bytesRead);
            ma_pcm_rb_commit_read(&playbackRb_, framesToRead);

            if (framesToRead < framesRequested) {
                // остальное — тишина
                std::memset(reinterpret_cast<uint8_t*>(out) + bytesRead, 0, bytesTotal - bytesRead);
            }
        } else {
            // нечего играть — полная тишина
            std::memset(out, 0, bytesTotal);
        }
    }

    ma_device device_{};
    std::atomic<bool> muted_{false};
    std::mutex mutex_;
    std::deque<float> captureAccum_;
    std::deque<AudioFrame> captureQueue_;

    // PLAYBACK jitter-buffer:
    ma_pcm_rb playbackRb_{};
    ma_uint32 rbCapacityFrames_{0};
    bool rbInitialized_{false};
};

class OpusCodec {
public:
    bool init() {
        int err = 0;
        enc_ = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &err);
        if (err != OPUS_OK) {
            std::cerr << "opus_encoder_create: " << opus_strerror(err) << "\n";
            return false;
        }
        dec_ = opus_decoder_create(48000, 1, &err);
        if (err != OPUS_OK) {
            std::cerr << "opus_decoder_create: " << opus_strerror(err) << "\n";
            return false;
        }
        return true;
    }
    ~OpusCodec() {
        if (enc_) opus_encoder_destroy(enc_);
        if (dec_) opus_decoder_destroy(dec_);
    }

    bool encode(const AudioFrame& f, std::vector<uint8_t>& packet) {
        packet.resize(960 * 10);
        int n = opus_encode_float(enc_, f.samples.data(), (int)f.samples.size(), packet.data(), (int)packet.size());
        if (n < 0) {
            std::cerr << "opus encode error: " << opus_strerror(n) << "\n";
            return false;
        }
        packet.resize((size_t)n);
        return true;
    }

    bool decode(const std::vector<uint8_t>& packet, AudioFrame& out) {
        out.samples.resize(960 * 6);
        int n =
            opus_decode_float(dec_, packet.data(), (int)packet.size(), out.samples.data(), (int)out.samples.size(), 0);
        if (n < 0) {
            std::cerr << "opus decode error: " << opus_strerror(n) << "\n";
            return false;
        }
        out.samples.resize((size_t)n);
        return true;
    }

private:
    OpusEncoder* enc_{};
    OpusDecoder* dec_{};
};

// ------------------------------------------------------------
// ICE (libnice) – полноценный транспорт медиа
// ------------------------------------------------------------

static const char* candidate_type_str(NiceCandidateType t) {
    switch (t) {
        case NICE_CANDIDATE_TYPE_HOST:
            return "host";
        case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
            return "srflx";
        case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
            return "prflx";
        case NICE_CANDIDATE_TYPE_RELAYED:
            return "relay";
        default:
            return "unknown";
    }
}

static NiceCandidateType parse_candidate_type(const std::string& s) {
    if (s == "host") return NICE_CANDIDATE_TYPE_HOST;
    if (s == "srflx") return NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    if (s == "prflx") return NICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
    if (s == "relay") return NICE_CANDIDATE_TYPE_RELAYED;
    return NICE_CANDIDATE_TYPE_HOST;
}

struct IceSession {
    GMainContext* ctx{nullptr};
    NiceAgent* agent{nullptr};
    guint streamId{0};
    guint compId{1};
    bool controlling{true};
    bool forceTurn{false};

    bool gatheringDone{false};
    bool remoteSet{false};
    bool connected{false};

    std::string localUfrag;
    std::string localPwd;

    struct ICECandidate {
        std::string ipStr{};
        uint16_t port{};
        NiceCandidateType type{};
    };
    std::list<ICECandidate> localICECandidates;
    std::list<ICECandidate> remoteICECandidates;

    std::string remoteUfrag;
    std::string remotePwd;

    std::string lastError;

    std::mutex recvMutex;
    std::vector<std::vector<uint8_t>> recvQueue;

    static void cb_gathering_done(NiceAgent* agent, guint sid, gpointer user_data) {
        auto* self = static_cast<IceSession*>(user_data);
        if (!self || sid != self->streamId) return;

        gchar* uf = nullptr;
        gchar* pw = nullptr;
        if (!nice_agent_get_local_credentials(agent, sid, &uf, &pw)) {
            self->lastError = "nice_agent_get_local_credentials failed";
            self->gatheringDone = false;
            return;
        }
        self->localUfrag = uf ? uf : "";
        self->localPwd = pw ? pw : "";
        g_free(uf);
        g_free(pw);

        GSList* cands = nice_agent_get_local_candidates(agent, sid, self->compId);
        std::set<uint16_t> alreadyHaveICETypes{};
        for (GSList* node = cands; node; node = node->next) {
            auto* candidate = static_cast<NiceCandidate*>(node->data);
            if (!nice_address_is_valid(&candidate->addr)) {
                continue;
            }
            if (self->forceTurn) {
                if (candidate->type != NICE_CANDIDATE_TYPE_RELAYED) {
                    continue;
                }
            }

            if (alreadyHaveICETypes.contains(candidate->type)) {
                continue;
            }

            char ip[64]{};
            nice_address_to_string(&candidate->addr, static_cast<gchar*>(ip));
            self->localICECandidates.emplace_back();
            IceSession::ICECandidate& lastCandidate = self->localICECandidates.back();
            lastCandidate.ipStr = ip;
            lastCandidate.port = static_cast<uint16_t>(nice_address_get_port(&candidate->addr));
            lastCandidate.type = candidate->type;

            alreadyHaveICETypes.insert(lastCandidate.type);
        }
        for (GSList* el = cands; el; el = el->next) nice_candidate_free((NiceCandidate*)el->data);
        g_slist_free(cands);

        if (self->localICECandidates.empty()) {
            self->lastError = "No suitable local ICE candidate";
            self->gatheringDone = false;
            return;
        }

        self->gatheringDone = true;
    }

    static void cb_state_changed(NiceAgent* agent, guint sid, guint cid, guint state, gpointer user_data) {
        auto* self = static_cast<IceSession*>(user_data);
        if (!self || sid != self->streamId || cid != self->compId) return;
        if (state == NICE_COMPONENT_STATE_READY || state == NICE_COMPONENT_STATE_CONNECTED) {
            self->connected = true;
        } else if (state == NICE_COMPONENT_STATE_FAILED) {
            self->connected = false;
            self->lastError = "ICE component failed";
        }
    }

    static void cb_recv(NiceAgent* agent, guint sid, guint cid, guint len, gchar* buf, gpointer user_data) {
        auto* self = static_cast<IceSession*>(user_data);
        if (!self || sid != self->streamId || cid != self->compId) return;
        if (len <= 0) return;
        std::vector<uint8_t> pkt((size_t)len);
        std::memcpy(pkt.data(), buf, (size_t)len);
        std::lock_guard<std::mutex> lock(self->recvMutex);
        self->recvQueue.push_back(std::move(pkt));
    }

    bool init(const std::string& stunHost, uint16_t stunPort, const std::string& turnHost, uint16_t turnPort,
              const std::string& turnUser, const std::string& turnPass, bool forceTurnOnly, bool isControlling) {
        forceTurn = forceTurnOnly;
        controlling = isControlling;

        ctx = g_main_context_new();
        if (!ctx) {
            lastError = "g_main_context_new failed";
            return false;
        }

        agent = nice_agent_new(ctx, NICE_COMPATIBILITY_RFC5245);
        if (!agent) {
            lastError = "nice_agent_new failed";
            g_main_context_unref(ctx);
            ctx = nullptr;
            return false;
        }

        g_object_set(G_OBJECT(agent), "stun-server", stunHost.c_str(), "stun-server-port", (guint)stunPort, nullptr);

        streamId = nice_agent_add_stream(agent, 1);
        if (streamId == 0) {
            lastError = "nice_agent_add_stream failed";
            g_object_unref(agent);
            agent = nullptr;
            g_main_context_unref(ctx);
            ctx = nullptr;
            return false;
        }

        compId = 1;

        if (!turnHost.empty() && !turnUser.empty()) {
            gboolean ok = nice_agent_set_relay_info(agent, streamId, compId, turnHost.c_str(), turnPort,
                                                    turnUser.c_str(), turnPass.c_str(), NICE_RELAY_TYPE_TURN_UDP);
            if (!ok) {
                lastError = "nice_agent_set_relay_info failed";
                g_object_unref(agent);
                agent = nullptr;
                g_main_context_unref(ctx);
                ctx = nullptr;
                return false;
            }
        }

        g_object_set(G_OBJECT(agent), "controlling-mode", controlling ? TRUE : FALSE, nullptr);

        g_signal_connect(agent, "candidate-gathering-done", G_CALLBACK(cb_gathering_done), this);
        g_signal_connect(agent, "component-state-changed", G_CALLBACK(cb_state_changed), this);

        nice_agent_attach_recv(agent, streamId, compId, ctx, cb_recv, this);

        if (!nice_agent_gather_candidates(agent, streamId)) {
            lastError = "nice_agent_gather_candidates failed";
            return false;
        }
        return true;
    }

    void pump() {
        if (!ctx) return;
        while (g_main_context_iteration(ctx, FALSE)) {
            // обрабатываем события GLib/libnice
        }
    }

    bool buildLocalDescription(std::string& outDesc) const {
        if (!gatheringDone) return false;
        // Формат: ufrag,pwd,ip,port,type
        std::ostringstream oss;
        oss << localUfrag << ',' << localPwd << ',' << localICECandidates.size() << ':';
        for (const IceSession::ICECandidate& cand : localICECandidates) {
            oss << cand.ipStr << ',' << cand.port << ',' << cand.type << ';';
        }
        outDesc = oss.str();
        return true;
    }

    bool setRemoteDescription(const std::string& desc) {
        if (!agent || !ctx) {
            lastError = "ICE not initialized";
            return false;
        }
        std::istringstream iss(desc);
        std::string ufrag, pwd, candidatesCountStr;
        if (!std::getline(iss, ufrag, ',')) {
            return false;
        }
        if (!std::getline(iss, pwd, ',')) {
            return false;
        }
        if (!std::getline(iss, candidatesCountStr, ':')) {
            return false;
        }

        uint16_t candidatesCount = std::stoi(candidatesCountStr);
        remoteICECandidates.resize(candidatesCount);
        for (IceSession::ICECandidate& cand : remoteICECandidates) {
            std::string ipStr, portStr, typeStr;
            if (!std::getline(iss, ipStr, ',')) {
                return false;
            }
            cand.ipStr = ipStr;
            if (!std::getline(iss, portStr, ',')) {
                return false;
            }
            cand.port = std::stoi(portStr);
            if (!std::getline(iss, typeStr, ';')) {
                return false;
            }
            cand.type = static_cast<NiceCandidateType>(std::stoi(typeStr));
        }

        if (!nice_agent_set_remote_credentials(agent, streamId, ufrag.c_str(), pwd.c_str())) {
            lastError = "nice_agent_set_remote_credentials failed";
            return false;
        }

        GSList* cands = nullptr;
        for (const IceSession::ICECandidate& cand : remoteICECandidates) {
            NiceCandidate* cPtr = nice_candidate_new(cand.type);
            cPtr->component_id = compId;
            cPtr->stream_id = streamId;
            cPtr->transport = NICE_CANDIDATE_TRANSPORT_UDP;
            nice_address_init(&cPtr->addr);
            nice_address_set_from_string(&cPtr->addr, cand.ipStr.c_str());
            nice_address_set_port(&cPtr->addr, cand.port);

            cands = g_slist_append(cands, cPtr);
        }

        if (nice_agent_set_remote_candidates(agent, streamId, compId, cands) < 1) {
            lastError = "nice_agent_set_remote_candidates returned 0";
            for (GSList* l = cands; l; l = l->next) nice_candidate_free((NiceCandidate*)l->data);
            g_slist_free(cands);
            return false;
        }
        g_slist_free(cands);
        remoteSet = true;
        return true;
    }

    bool send(const uint8_t* data, size_t len) {
        if (!agent || !connected || !remoteSet) return false;
        int n = nice_agent_send(agent, streamId, compId, (guint)len, (const gchar*)data);
        return n == (int)len;
    }

    bool recvPacket(std::vector<uint8_t>& pkt) {
        std::lock_guard<std::mutex> lock(recvMutex);
        if (recvQueue.empty()) return false;
        pkt = std::move(recvQueue.front());
        recvQueue.erase(recvQueue.begin());
        return true;
    }

    void shutdown() {
        if (agent) {
            g_object_unref(agent);
            agent = nullptr;
        }
        if (ctx) {
            g_main_context_unref(ctx);
            ctx = nullptr;
        }
        recvQueue.clear();
        connected = false;
        gatheringDone = false;
        remoteSet = false;
    }
};

// ------------------------------------------------------------
// Signaling client (TCP, простые текстовые команды)
// ------------------------------------------------------------

class SignalingClient {
public:
    SignalingClient() = default;

    void setServer(const std::string& host, uint16_t port) {
        host_ = host;
        port_ = port;
    }
    void setCredentials(const std::string& user, const std::string& pwd) {
        user_ = user;
        pwd_ = pwd;
    }
    const std::string& user() const { return user_; }
    const std::string& token() const { return token_; }
    const RsaKeyPair& clientKey() const { return clientKey_; }

    bool authenticate(std::string& err) {
        err.clear();
        if (host_.empty() || user_.empty()) {
            err = "Signaling host or credentials not set";
            return false;
        }

        // 1. GETPUB
        std::string resp;
        if (!tcpSendRecv("GETPUB", resp)) {
            err = "GETPUB failed";
            return false;
        }
        if (not resp.starts_with("PUB ")) {
            err = "GETPUB bad response: " + resp;
            return false;
        }
        std::string serverPubB64 = Trim(resp.substr(4));
        std::vector<uint8_t> serverDer;
        if (!B64Decode(serverPubB64, serverDer)) {
            err = "GETPUB b64 decode failed";
            return false;
        }
        serverPubKey_.reset();
        serverPubKeyDer_ = serverDer;  // на будущее, если понадобится

        // 2. генерим свой RSA keypair
        if (!clientKey_.generate(2048)) {
            err = "RSA generate failed";
            return false;
        }
        std::string clientPubB64 = clientKey_.publicDerB64();

        // 3. AUTH: шлём clientPubB64 и зашифрованные creds
        std::string creds = user_ + ":" + pwd_;
        std::vector<uint8_t> credBytes(creds.begin(), creds.end());

        // Загружаем публичный ключ сервера в новый класс
        RsaPublicKey serverKey;
        if (!serverKey.loadDer(serverDer)) {
            err = "Failed to parse server RSA pubkey";
            return false;
        }

        // Шифруем креды RSA-OAEP+SHA512
        std::vector<uint8_t> credCipher;
        if (!serverKey.encrypt(credBytes, credCipher)) {
            err = "RSA encrypt creds failed";
            return false;
        }

        std::string credCipherB64 = B64Encode(credCipher);

        std::ostringstream line;
        line << "AUTH " << clientPubB64 << " " << credCipherB64;
        if (!tcpSendRecv(line.str(), resp)) {
            err = "AUTH timeout";
            return false;
        }
        if (not resp.starts_with("OK ")) {
            err = "AUTH failed: " + resp;
            return false;
        }
        std::string tokenCipherB64 = Trim(resp.substr(3));
        std::vector<uint8_t> tokenCipher;
        if (!B64Decode(tokenCipherB64, tokenCipher)) {
            err = "AUTH token b64 decode failed";
            return false;
        }
        std::vector<uint8_t> tokenPlain;
        if (!clientKey_.decrypt(tokenCipher, tokenPlain)) {
            err = "AUTH token RSA decrypt failed";
            return false;
        }
        token_ = std::string((char*)tokenPlain.data(), tokenPlain.size());
        return true;
    }

    bool getUserPubKey(const std::string& who, RsaPublicKey& out, std::string& err) {
        err.clear();
        if (token_.empty()) {
            err = "No auth token";
            return false;
        }

        std::ostringstream line;
        line << "PUBKEY " << token_ << " " << who;

        std::string resp;
        if (!tcpSendRecv(line.str(), resp)) {
            err = "PUBKEY timeout";
            return false;
        }
        if (not resp.starts_with("OK ")) {
            err = "PUBKEY failed: " + resp;
            return false;
        }

        std::string pubB64 = Trim(resp.substr(3));
        std::vector<uint8_t> der;
        if (!B64Decode(pubB64, der)) {
            err = "PUBKEY b64 decode failed";
            return false;
        }

        if (!out.loadDer(der)) {
            err = "PUBKEY der parse failed";
            return false;
        }
        return true;
    }

    // --- KEY exchange (RSA-шифрованием к публичному ключу peer’а) ---

    bool pushEncryptedKey(const std::string& peer, const std::string& keyCipherB64, std::string& err) {
        err.clear();
        if (token_.empty()) {
            err = "No auth token";
            return false;
        }
        std::ostringstream line;
        line << "KEY_PUSH " << token_ << " " << peer << " " << keyCipherB64;
        std::string resp;
        if (!tcpSendRecv(line.str(), resp)) {
            err = "KEY_PUSH timeout";
            return false;
        }
        if (resp != "OK") {
            err = "KEY_PUSH failed: " + resp;
            return false;
        }
        return true;
    }

    bool pollEncryptedKey(std::string& fromUser, std::string& keyCipherB64, std::string& err) {
        err.clear();
        if (token_.empty()) {
            err = "No auth token";
            return false;
        }
        std::ostringstream line;
        line << "KEY_POLL " << token_;
        std::string resp;
        if (!tcpSendRecv(line.str(), resp)) {
            err = "KEY_POLL timeout";
            return false;
        }
        if (resp == "EMPTY") {
            return false;
        }
        if (not resp.starts_with("OK ")) {
            err = "KEY_POLL failed: " + resp;
            return false;
        }
        std::istringstream iss(resp.substr(3));
        if (!(iss >> fromUser >> keyCipherB64)) {
            err = "KEY_POLL parse failed: " + resp;
            return false;
        }
        return true;
    }

    // --- ICE offer/answer (blob шифруется RSA ключом peer’а) ---

    bool pushEncryptedIceOffer(const std::string& peer, const std::string& blobB64, std::string& err) {
        err.clear();
        if (token_.empty()) {
            err = "No auth token";
            return false;
        }
        std::ostringstream line;
        line << "ICE_OFFER " << token_ << " " << peer << " " << blobB64;
        std::string resp;
        if (!tcpSendRecv(line.str(), resp)) {
            err = "ICE_OFFER timeout";
            return false;
        }
        if (resp != "OK") {
            err = "ICE_OFFER failed: " + resp;
            return false;
        }
        return true;
    }

    bool pollEncryptedIceOffer(std::string& fromUser, std::string& blobB64, std::string& err) {
        err.clear();
        if (token_.empty()) {
            err = "No auth token";
            return false;
        }
        std::ostringstream line;
        line << "ICE_POLL_OFFER " << token_;
        std::string resp;
        if (!tcpSendRecv(line.str(), resp)) {
            err = "ICE_POLL_OFFER timeout";
            return false;
        }
        if (resp == "EMPTY") return false;
        if (not resp.starts_with("OK ")) {
            err = "ICE_POLL_OFFER failed: " + resp;
            return false;
        }
        std::istringstream iss(resp.substr(3));
        if (!(iss >> fromUser >> blobB64)) {
            err = "ICE_POLL_OFFER parse failed: " + resp;
            return false;
        }
        return true;
    }

    bool pushEncryptedIceAnswer(const std::string& peer, const std::string& blobB64, std::string& err) {
        err.clear();
        if (token_.empty()) {
            err = "No auth token";
            return false;
        }
        std::ostringstream line;
        line << "ICE_ANSWER " << token_ << " " << peer << " " << blobB64;
        std::string resp;
        if (!tcpSendRecv(line.str(), resp)) {
            err = "ICE_ANSWER timeout";
            return false;
        }
        if (resp != "OK") {
            err = "ICE_ANSWER failed: " + resp;
            return false;
        }
        return true;
    }

    bool pollEncryptedIceAnswer(std::string& fromUser, std::string& blobB64, std::string& err) {
        err.clear();
        if (token_.empty()) {
            err = "No auth token";
            return false;
        }
        std::ostringstream line;
        line << "ICE_POLL_ANSWER " << token_;
        std::string resp;
        if (!tcpSendRecv(line.str(), resp)) {
            err = "ICE_POLL_ANSWER timeout";
            return false;
        }
        if (resp == "EMPTY") return false;
        if (not resp.starts_with("OK ")) {
            err = "ICE_POLL_ANSWER failed: " + resp;
            return false;
        }
        std::istringstream iss(resp.substr(3));
        if (!(iss >> fromUser >> blobB64)) {
            err = "ICE_POLL_ANSWER parse failed: " + resp;
            return false;
        }
        return true;
    }

private:
    bool tcpSendRecv(const std::string& line, std::string& out) {
        out.clear();
#ifdef _WIN32
        static WsaInit _wsa;
#endif
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port_);
        if (::inet_pton(AF_INET, host_.c_str(), &sa.sin_addr) != 1) {
            return false;
        }
        int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        if (::connect(sock, (sockaddr*)&sa, sizeof(sa)) != 0) {
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return false;
        }
        std::string sendLine = line + "\n";
        int s = (int)::send(sock, sendLine.data(), (int)sendLine.size(), 0);
        if (s != (int)sendLine.size()) {
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return false;
        }
        char buf[2048];
        int n = ::recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return false;
        }
        buf[n] = 0;
        out = Trim(buf);
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        return true;
    }

    struct ServerPubKeyHolder {
        void reset() {}
    } serverPubKey_;

    std::vector<uint8_t> serverPubKeyDer_;

    std::string host_{"213.171.24.94"};
    uint16_t port_{7777};
    std::string user_;
    std::string pwd_;
    std::string token_;
    RsaKeyPair clientKey_;
};

// ------------------------------------------------------------
// Shader helpers
// ------------------------------------------------------------

static GLuint compileShader(GLenum type, const char* src) {
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, nullptr);
    glCompileShader(s);
    GLint ok = 0;
    glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char log[512];
        glGetShaderInfoLog(s, sizeof(log), nullptr, log);
        std::cerr << "Shader compile error: " << log << "\n";
    }
    return s;
}

static GLuint createProgram(const std::string& vs, const std::string& fs) {
    GLuint v = compileShader(GL_VERTEX_SHADER, vs.c_str());
    GLuint f = compileShader(GL_FRAGMENT_SHADER, fs.c_str());
    GLuint p = glCreateProgram();
    glAttachShader(p, v);
    glAttachShader(p, f);
    glLinkProgram(p);
    GLint ok = 0;
    glGetProgramiv(p, GL_LINK_STATUS, &ok);
    if (!ok) {
        char log[512];
        glGetProgramInfoLog(p, sizeof(log), nullptr, log);
        std::cerr << "Program link error: " << log << "\n";
    }
    glDeleteShader(v);
    glDeleteShader(f);
    return p;
}

constexpr const char* kDefOrbVertCode = R"(
#version 330

layout(location = 0) in vec2 pos;
out vec2 uv;

void main() {
    uv = pos;
    gl_Position = vec4(pos, 0.0, 1.0);
}
)";

constexpr const char* kDefOrbFragCode = R"(
#version 330

in vec2 uv;
out vec4 fragColor;

uniform float u_level;
uniform float u_time;
uniform float u_aspect;

vec4 ColorOrbWave(vec4 col1, vec4 col2, float coef) {
    vec2 curPos = vec2(uv.x * u_aspect, uv.y);
    float sine1 = sin(2. * coef * atan(curPos.y / curPos.x) + u_time * coef);
    float sine2 = sin(4. * coef * atan(curPos.y / curPos.x) + u_time * coef);
    float wave = 0.4 + 0.1 * pow(u_level, 0.6) * coef * (1. + sine1 * sine2);

    float thickness = 0.01;
    float bloor = 0.05;
    float colorStart = wave - thickness / 2. - bloor / 2.;
    float colorEnd = wave + thickness / 2. + bloor / 2.;

    float r = length(curPos);
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
)";

void DrawVoiceOrb(const std::string& execPath, float level) {
    // Ленивое создание шейдера и геометрии
    static bool initialized = false;
    static GLuint prog = 0;
    static GLint levelLoc = -1;
    static GLint timeLoc = -1;
    static GLint aspectLoc = -1;
    static GLuint vao = 0;
    static GLuint vbo = 0;

    if (!initialized) {
        std::string execBasePath = execPath.substr(0, execPath.find_last_of('/'));
        std::string orbVertCode{};
        std::string orbFragCode{};
        try {
            orbVertCode = LoadFile(execBasePath + "/shaders/voice_vis_shader.vert");
            orbFragCode = LoadFile(execBasePath + "/shaders/voice_vis_shader.frag");
        } catch (const std::exception& e) {
            orbVertCode = kDefOrbVertCode;
            orbFragCode = kDefOrbFragCode;
        }
        prog = createProgram(orbVertCode.empty() ? std::string{kDefOrbVertCode} : orbVertCode,
                             orbFragCode.empty() ? std::string{kDefOrbFragCode} : orbFragCode);
        levelLoc = glGetUniformLocation(prog, "u_level");
        timeLoc = glGetUniformLocation(prog, "u_time");
        aspectLoc = glGetUniformLocation(prog, "u_aspect");

        float quadVerts[] = {-1.f, -1.f, 1.f, -1.f, 1.f,  1.f,

                             -1.f, -1.f, 1.f, 1.f,  -1.f, 1.f};

        glGenVertexArrays(1, &vao);
        glGenBuffers(1, &vbo);

        glBindVertexArray(vao);
        glBindBuffer(GL_ARRAY_BUFFER, vbo);
        glBufferData(GL_ARRAY_BUFFER, sizeof(quadVerts), quadVerts, GL_STATIC_DRAW);
        glEnableVertexAttribArray(0);
        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 2 * sizeof(float), (void*)0);
        glBindVertexArray(0);

        initialized = true;
    }

    // Позиция верхнего левого угла виджета в координатах фреймбуфера ImGui
    ImVec2 pos = ImGui::GetCursorScreenPos();

    // Резервируем место под орб
    ImVec2 avail = ImGui::GetContentRegionAvail();
    ImGui::InvisibleButton("##voice_orb", avail);

    ImDrawList* dl = ImGui::GetWindowDrawList();

    // Нам нужен прямоугольник орба и высота фреймбуфера,
    // чтобы правильно выставить glViewport/glScissor
    ImVec2 min = pos;
    ImVec2 max = ImVec2(pos.x + avail.x, pos.y + avail.y);
    float fbHeight = ImGui::GetIO().DisplaySize.y;

    struct OrbCtx {
        GLuint prog;
        GLint levelLoc;
        GLint timeLoc;
        GLint aspectLoc;
        GLuint vao;
        float level;
        float time;
        float aspect;
        ImVec2 min;
        ImVec2 max;
        float fbHeight;
    };

    static size_t startMsec =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();
    auto* ctx = new OrbCtx{.prog = prog,
                           .levelLoc = levelLoc,
                           .timeLoc = timeLoc,
                           .aspectLoc = aspectLoc,
                           .vao = vao,
                           .level = std::clamp(level, 0.0f, 1.0f),
                           .time = static_cast<float>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                          std::chrono::steady_clock::now().time_since_epoch())
                                                          .count() -
                                                      startMsec) /
                                   1000,
                           .aspect = avail.x / avail.y,
                           .min = min,
                           .max = max,
                           .fbHeight = fbHeight};

    dl->AddCallback(
        [](const ImDrawList*, const ImDrawCmd* cmd) {
            auto* c = static_cast<OrbCtx*>(cmd->UserCallbackData);

            // Преобразуем координаты ImGui (x1,y1,x2,y2) в viewport/scissor
            // OpenGL
            int x = (int)c->min.x;
            int yTop = (int)c->min.y;
            int width = (int)(c->max.x - c->min.x);
            int height = (int)(c->max.y - c->min.y);

            // OpenGL считает Y от нижнего края, ImGui — от верхнего
            int y = (int)(c->fbHeight) - yTop - height;

            // Ограничиваем и viewport, и scissor, чтобы орб рисовался только в
            // этом прямоугольнике
            glEnable(GL_SCISSOR_TEST);
            glScissor(x, y, width, height);
            glViewport(x, y, width, height);

            glUseProgram(c->prog);
            glUniform1f(c->levelLoc, c->level);
            glUniform1f(c->timeLoc, c->time);
            glUniform1f(c->aspectLoc, c->aspect);
            glBindVertexArray(c->vao);
            glDrawArrays(GL_TRIANGLES, 0, 6);
            glBindVertexArray(0);
            glUseProgram(0);

            // Сбрасывать scissor не обязательно — ImGui всё равно
            // ResetRenderState, но можно, чтобы не оставлять мусор
            glDisable(GL_SCISSOR_TEST);

            delete c;
        },
        ctx);

    dl->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
}

// ------------------------------------------------------------
// App state
// ------------------------------------------------------------

struct CallState {
    // audio
    AudioEngine audio;
    OpusCodec opus;

    // signaling
    SignalingClient signaling;
    std::string sigStatus;
    std::string sigError;

    // crypto (media)
    bool encryptionEnabled{true};
    AesGcmKey txKey{};
    AesGcmKey rxKey{};
    AesGcm aesTx;
    AesGcm aesRx;

    // ICE
    IceSession ice;
    bool iceInited{false};
    bool iceIsCaller{true};
    std::string iceLocalDesc;
    std::string iceRemoteDesc;
    std::string iceStatus;
    std::string iceError;

    // peer info
    std::string peerUser;
    RsaPublicKey peerPub;  // RSA pub собеседника

    // UI / misc
    bool micMuted{false};
    bool forceTurnOnly{false};
    float inLevel{0.0f};
    float outlevel{0.0f};
};

// ------------------------------------------------------------
// main()
// ------------------------------------------------------------

int main(int argc, char* argv[]) {
    std::string defaultCaller{"user1"};
    std::string defaultCallee{"user2"};
    bool isControlling{true};
    if (argc == 4) {
        defaultCaller = argv[1];
        defaultCallee = argv[2];
        isControlling = std::string{argv[3]} == std::string{"true"} ? true : false;
    }

    CallState app;
    app.iceIsCaller = isControlling;

    spdlog::set_default_logger(spdlog::stdout_color_mt("default", spdlog::color_mode::always));
    spdlog::set_level(spdlog::level::debug);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (not SDL_Init(SDL_INIT_VIDEO)) {
        spdlog::critical("SDL_Init failed: {}", SDL_GetError());
        return -1;
    }

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_ACCELERATED_VISUAL, 1);

    SDL_Window* window =
        SDL_CreateWindow("Zvonilka (ICE/TURN demo)", 1280, 720, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE);
    if (!window) {
        spdlog::critical("SDL_CreateWindow failed: {}", SDL_GetError());
        return -1;
    }
    SDL_GLContext glctx = SDL_GL_CreateContext(window);
    if (!glctx) {
        spdlog::critical("SDL_GL_CreateContext failed: {}", SDL_GetError());
        return -1;
    }

    SDL_GL_MakeCurrent(window, glctx);
    SDL_GL_SetSwapInterval(1);

    glewInit();

    // 7. Check GPU information
    const GLubyte* renderer = glGetString(GL_RENDERER);
    const GLubyte* vendor = glGetString(GL_VENDOR);
    const GLubyte* version = glGetString(GL_VERSION);
    const GLubyte* glsl = glGetString(GL_SHADING_LANGUAGE_VERSION);

    spdlog::debug("GPU Vendor: {}", vendor ? (const char*)vendor : "Unknown");
    spdlog::debug("GPU Renderer: {}", renderer ? (const char*)renderer : "Unknown");
    spdlog::debug("OpenGL Version: {}", version ? (const char*)version : "Unknown");
    spdlog::debug("GLSL Version: {}", glsl ? (const char*)glsl : "Unknown");

    // ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();

    if (!ImGui_ImplSDL3_InitForOpenGL(window, glctx)) {
        spdlog::critical("Failed to initialize ImGui SDL3 backend: {}", SDL_GetError());
        return -1;
    }
    if (!ImGui_ImplOpenGL3_Init("#version 330")) {
        spdlog::critical("Failed to initialize ImGui OpenGL3 backend");
        return -1;
    }

    if (!app.audio.init()) {
        std::cerr << "Audio init failed\n";
    }
    if (!app.opus.init()) {
        std::cerr << "Opus init failed\n";
    }

    randomKey(app.txKey);
    randomKey(app.rxKey);
    app.aesTx.setKey(app.txKey);
    app.aesRx.setKey(app.rxKey);

    bool running = true;
    auto lastNetTick = std::chrono::steady_clock::now();
    auto lastKeyPoll = std::chrono::steady_clock::now();
    auto lastIcePoll = std::chrono::steady_clock::now();

    // UI state
    static char sigHostBuf[64] = "213.171.24.94";
    static int sigPort = 7777;
    static char sigUserBuf[32] = "";
    static char callingUserBuf[32] = "";
    static char sigPassBuf[32] = "pass123";
    memcpy(static_cast<void*>(sigUserBuf), defaultCaller.c_str(), defaultCaller.size());
    memcpy(static_cast<void*>(callingUserBuf), defaultCallee.c_str(), defaultCallee.size());

    static char stunWTurnHostBuf[64] = "213.171.24.94";
    static int stunWTurnPortUI = 3478;

    while (running) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            ImGui_ImplSDL3_ProcessEvent(&ev);
            if (ev.type == SDL_EVENT_QUIT) running = false;
        }

        // --- network / ICE tick ---
        auto now = std::chrono::steady_clock::now();
        // прокручиваем glib/libnice
        if (app.iceInited) {
            app.ice.pump();
        }

        if (now - lastNetTick > std::chrono::milliseconds(1)) {
            lastNetTick = now;

            // capture & send
            AudioFrame f;
            if (app.ice.connected && app.ice.remoteSet) {
                while (app.audio.popCaptured(f)) {
                    app.inLevel = *std::ranges::max_element(f.samples);

                    std::vector<uint8_t> opusPkt;
                    if (app.opus.encode(f, opusPkt)) {
                        std::vector<uint8_t> payload;
                        if (app.encryptionEnabled) {
                            uint8_t iv[12];
                            RAND_bytes(iv, sizeof(iv));
                            std::array<uint8_t, 16> tag{};
                            app.aesTx.encrypt(opusPkt.data(), opusPkt.size(), nullptr, 0, iv, payload, tag);
                            // [E][iv(12)][tag(16)][cipher]
                            std::vector<uint8_t> pkt;
                            pkt.reserve(1 + 12 + 16 + payload.size());
                            pkt.push_back(1);  // encrypted
                            pkt.insert(pkt.end(), iv, iv + 12);
                            pkt.insert(pkt.end(), tag.begin(), tag.end());
                            pkt.insert(pkt.end(), payload.begin(), payload.end());
                            app.ice.send(pkt.data(), pkt.size());
                        } else {
                            // [0][plain opus]
                            std::vector<uint8_t> pkt;
                            pkt.reserve(1 + opusPkt.size());
                            pkt.push_back(0);
                            pkt.insert(pkt.end(), opusPkt.begin(), opusPkt.end());
                            app.ice.send(pkt.data(), pkt.size());
                        }
                    }
                }
            }

            // receive & playback
            for (;;) {
                std::vector<uint8_t> pkt;
                if (!app.ice.recvPacket(pkt)) break;
                if (pkt.empty()) continue;
                uint8_t encFlag = pkt[0];
                std::vector<uint8_t> opusPkt;
                if (encFlag == 1) {
                    if (pkt.size() <= 1 + 12 + 16) continue;
                    uint8_t iv[12];
                    std::memcpy(iv, &pkt[1], 12);
                    uint8_t tag[16];
                    std::memcpy(tag, &pkt[13], 16);
                    std::vector<uint8_t> cipher(pkt.begin() + 29, pkt.end());
                    std::vector<uint8_t> plain;
                    if (!app.aesRx.decrypt(cipher.data(), cipher.size(), nullptr, 0, iv, tag, plain)) {
                        std::cerr << "AES decrypt failed\n";
                        continue;
                    }
                    opusPkt = std::move(plain);
                } else {
                    opusPkt.assign(pkt.begin() + 1, pkt.end());
                }

                AudioFrame out;
                if (app.opus.decode(opusPkt, out)) {
                    app.outlevel = *std::ranges::max_element(out.samples);
                    app.audio.pushPlayback(out);
                }
            }
        }

        // периодический автопул ключей и ICE-ответов (чтобы не дергать руками
        // слишком часто)
        if (!app.signaling.token().empty()) {
            if (now - lastKeyPoll > std::chrono::milliseconds(3000)) {
                lastKeyPoll = now;
                std::string from, keyCipherB64, err;
                if (app.signaling.pollEncryptedKey(from, keyCipherB64, err)) {
                    std::vector<uint8_t> cipher;
                    if (B64Decode(keyCipherB64, cipher)) {
                        std::vector<uint8_t> plain;
                        if (app.signaling.clientKey().decrypt(cipher, plain)) {
                            if (plain.size() == 32) {
                                std::memcpy(app.rxKey.key.data(), plain.data(), 32);
                                app.aesRx.setKey(app.rxKey);
                                app.sigStatus = "Received new RX key from " + from;
                            }
                        }
                    }
                }
            }

            if (now - lastIcePoll > std::chrono::milliseconds(1000)) {
                lastIcePoll = now;
                // если мы callee, ждем offer
                if (!app.iceIsCaller && app.iceInited && !app.ice.remoteSet) {
                    std::string from, blobB64, err;
                    if (app.signaling.pollEncryptedIceOffer(from, blobB64, err)) {
                        std::vector<uint8_t> cipher;
                        if (B64Decode(blobB64, cipher)) {
                            std::vector<uint8_t> plain;
                            if (app.signaling.clientKey().decrypt(cipher, plain)) {
                                std::string desc((char*)plain.data(), plain.size());
                                if (app.ice.setRemoteDescription(desc)) {
                                    app.peerUser = from;
                                    app.iceRemoteDesc = desc;
                                    app.iceStatus = "Got ICE offer from " + from;
                                } else {
                                    app.iceError = app.ice.lastError;
                                }
                            }
                        }
                    }
                }
                // если мы caller, ждем answer
                if (app.iceIsCaller && app.iceInited && app.ice.remoteSet == false) {
                    std::string from, blobB64, err;
                    if (app.signaling.pollEncryptedIceAnswer(from, blobB64, err)) {
                        std::vector<uint8_t> cipher;
                        if (B64Decode(blobB64, cipher)) {
                            std::vector<uint8_t> plain;
                            if (app.signaling.clientKey().decrypt(cipher, plain)) {
                                std::string desc((char*)plain.data(), plain.size());
                                if (app.ice.setRemoteDescription(desc)) {
                                    app.peerUser = from;
                                    app.iceRemoteDesc = desc;
                                    app.iceStatus = "Got ICE answer from " + from;
                                } else {
                                    app.iceError = app.ice.lastError;
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- UI ---
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL3_NewFrame();
        ImGui::NewFrame();

        int w = 0, h = 0;
        SDL_GetWindowSizeInPixels(window, &w, &h);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(static_cast<float>(w), static_cast<float>(h)));
        // clang-format off
        ImGui::Begin("Zvonilka (ICE/TURN)", nullptr,
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize   |
            ImGuiWindowFlags_NoMove     |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);
        // clang-format on

        // Auth
        if (app.signaling.token().empty()) {
            ImGui::Text("Signaling");
            ImGui::InputText("Host", sigHostBuf, sizeof(sigHostBuf));
            ImGui::InputInt("Port", &sigPort);
            ImGui::InputText("Login", sigUserBuf, sizeof(sigUserBuf));
            ImGui::InputText("Password", sigPassBuf, sizeof(sigPassBuf), ImGuiInputTextFlags_Password);

            if (ImGui::Button("AUTH")) {
                app.sigError.clear();
                app.sigStatus.clear();
                app.signaling.setServer(sigHostBuf, (uint16_t)sigPort);
                app.signaling.setCredentials(sigUserBuf, sigPassBuf);
                if (app.signaling.authenticate(app.sigError)) {
                    app.sigStatus = "AUTH OK, token=" + app.signaling.token();
                } else {
                    app.sigStatus = "AUTH FAILED";
                }
            }
        } else {
            ImGui::InputText("Calling user", callingUserBuf, sizeof(callingUserBuf));

            app.peerUser = std::string{callingUserBuf};
            if (ImGui::Button("Get peer RSA pubkey")) {
                app.sigError.clear();
                app.sigStatus.clear();
                if (app.signaling.getUserPubKey(app.peerUser, app.peerPub, app.sigError)) {
                    app.sigStatus = "Got peer pubkey for " + app.peerUser;
                } else {
                    app.sigStatus = "PUBKEY FAILED";
                }
            }

            if (!app.sigStatus.empty()) ImGui::Text("Status: %s", app.sigStatus.c_str());
            if (!app.sigError.empty()) ImGui::TextColored(ImVec4(1, 0, 0, 1), "Error: %s", app.sigError.c_str());

            ImGui::Separator();

            // ICE
            ImGui::Text("ICE");
            ImGui::InputText("STUN/TURN host", stunWTurnHostBuf, sizeof(stunWTurnHostBuf));
            ImGui::InputInt("STUN/TURN port", &stunWTurnPortUI);
            ImGui::Checkbox("Force TURN only (no direct)", &app.forceTurnOnly);
            ImGui::SameLine();
            ImGui::Checkbox("This side is Caller (controlling)", &app.iceIsCaller);

            if (ImGui::Button("Init ICE")) {
                app.ice.shutdown();
                app.iceError.clear();
                app.iceStatus.clear();
                std::string stun = stunWTurnHostBuf;
                std::string turn = stunWTurnHostBuf;
                uint16_t stunPort = static_cast<uint16_t>(std::max(stunWTurnPortUI, 1));
                uint16_t turnPort = static_cast<uint16_t>(std::max(stunWTurnPortUI, 1));
                if (app.ice.init(stun, stunPort, turn, turnPort, sigUserBuf, sigPassBuf, app.forceTurnOnly,
                                 app.iceIsCaller)) {
                    app.iceInited = true;
                    app.iceStatus = "ICE initialized, gathering candidates...";
                } else {
                    app.iceInited = false;
                    app.iceError = app.ice.lastError;
                }
            }

            if (app.iceInited && app.ice.gatheringDone && app.iceLocalDesc.empty()) {
                std::string desc;
                if (app.ice.buildLocalDescription(desc)) {
                    app.iceLocalDesc = desc;
                }
            }

            if (!app.iceLocalDesc.empty()) {
                ImGui::TextWrapped("Local ICE: %s", app.iceLocalDesc.c_str());
            }
            if (!app.iceRemoteDesc.empty()) {
                ImGui::TextWrapped("Remote ICE: %s", app.iceRemoteDesc.c_str());
            }

            if (app.iceIsCaller) {
                if (ImGui::Button("Send ICE offer (Caller)")) {
                    if (!app.peerPub.valid()) {
                        app.iceError = "Peer pubkey not loaded";
                    } else if (app.iceLocalDesc.empty()) {
                        app.iceError = "Local ICE not ready yet";
                    } else {
                        std::vector<uint8_t> plain(app.iceLocalDesc.begin(), app.iceLocalDesc.end());
                        std::vector<uint8_t> cipher;
                        if (app.peerPub.encrypt(plain, cipher)) {
                            std::string b64 = B64Encode(cipher);
                            if (app.signaling.pushEncryptedIceOffer(app.peerUser, b64, app.iceError)) {
                                app.iceStatus = "ICE offer sent to " + app.peerUser;
                            } else {
                                app.iceStatus = "ICE_OFFER FAILED";
                            }
                        } else {
                            app.iceError = "RSA encrypt ICE offer failed";
                        }
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button("Poll ICE answer (Caller)")) {
                    std::string from, blobB64, err;
                    if (app.signaling.pollEncryptedIceAnswer(from, blobB64, err)) {
                        std::vector<uint8_t> cipher;
                        if (B64Decode(blobB64, cipher)) {
                            std::vector<uint8_t> plain;
                            if (app.signaling.clientKey().decrypt(cipher, plain)) {
                                std::string desc((char*)plain.data(), plain.size());
                                if (app.ice.setRemoteDescription(desc)) {
                                    app.peerUser = from;
                                    std::snprintf(app.peerUser.data(), app.peerUser.size(), "%s", from.c_str());
                                    app.iceRemoteDesc = desc;
                                    app.iceStatus = "Got ICE answer from " + from;
                                } else {
                                    app.iceError = app.ice.lastError;
                                }
                            }
                        }
                    } else if (!err.empty()) {
                        app.iceError = err;
                    }
                }
            } else {
                if (ImGui::Button("Send ICE answer (Callee)")) {
                    if (!app.peerPub.valid()) {
                        app.iceError = "Peer pubkey not loaded";
                    } else if (app.iceLocalDesc.empty()) {
                        app.iceError = "Local ICE not ready yet";
                    } else {
                        std::vector<uint8_t> plain(app.iceLocalDesc.begin(), app.iceLocalDesc.end());
                        std::vector<uint8_t> cipher;
                        if (app.peerPub.encrypt(plain, cipher)) {
                            std::string b64 = B64Encode(cipher);
                            if (app.signaling.pushEncryptedIceAnswer(app.peerUser, b64, app.iceError)) {
                                app.iceStatus = "ICE answer sent to " + app.peerUser;
                            } else {
                                app.iceStatus = "ICE_ANSWER FAILED";
                            }
                        } else {
                            app.iceError = "RSA encrypt ICE answer failed";
                        }
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button("Poll ICE offer (Callee)")) {
                    std::string from, blobB64, err;
                    if (app.signaling.pollEncryptedIceOffer(from, blobB64, err)) {
                        std::vector<uint8_t> cipher;
                        if (B64Decode(blobB64, cipher)) {
                            std::vector<uint8_t> plain;
                            if (app.signaling.clientKey().decrypt(cipher, plain)) {
                                std::string desc((char*)plain.data(), plain.size());
                                if (app.ice.setRemoteDescription(desc)) {
                                    app.peerUser = from;
                                    std::snprintf(app.peerUser.data(), app.peerUser.size(), "%s", from.c_str());
                                    app.iceRemoteDesc = desc;
                                    app.iceStatus = "Got ICE offer from " + from;
                                } else {
                                    app.iceError = app.ice.lastError;
                                }
                            }
                        }
                    } else if (!err.empty()) {
                        app.iceError = err;
                    }
                }
            }

            if (app.ice.connected) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "ICE connected");
            } else {
                ImGui::Text("ICE not connected");
            }

            if (!app.iceStatus.empty()) ImGui::Text("ICE status: %s", app.iceStatus.c_str());
            if (!app.iceError.empty()) ImGui::TextColored(ImVec4(1, 0, 0, 1), "ICE error: %s", app.iceError.c_str());

            ImGui::Separator();

            // Crypto / audio
            ImGui::Checkbox("Encrypt audio (AES-GCM)", &app.encryptionEnabled);
            if (ImGui::Checkbox("Mic muted", &app.micMuted)) {
                app.audio.setMuted(app.micMuted);
            }

            if (ImGui::Button("Rotate TX key & send to peer")) {
                if (!app.peerPub.valid()) {
                    app.sigError = "Peer pubkey not loaded";
                } else {
                    randomKey(app.txKey);
                    app.aesTx.setKey(app.txKey);
                    std::vector<uint8_t> plain(32);
                    std::memcpy(plain.data(), app.txKey.key.data(), 32);
                    std::vector<uint8_t> cipher;
                    if (app.peerPub.encrypt(plain, cipher)) {
                        std::string b64 = B64Encode(cipher);
                        if (app.signaling.pushEncryptedKey(app.peerUser, b64, app.sigError)) {
                            app.sigStatus = "TX key rotated & sent to " + app.peerUser;
                        } else {
                            app.sigStatus = "KEY_PUSH FAILED";
                        }
                    } else {
                        app.sigError = "RSA encrypt key failed";
                    }
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Poll RX key now")) {
                std::string from, keyCipherB64, err;
                if (app.signaling.pollEncryptedKey(from, keyCipherB64, err)) {
                    std::vector<uint8_t> cipher;
                    if (B64Decode(keyCipherB64, cipher)) {
                        std::vector<uint8_t> plain;
                        if (app.signaling.clientKey().decrypt(cipher, plain)) {
                            if (plain.size() == 32) {
                                std::memcpy(app.rxKey.key.data(), plain.data(), 32);
                                app.aesRx.setKey(app.rxKey);
                                app.sigStatus = "Manually received RX key from " + from;
                            }
                        }
                    }
                } else {
                    if (!err.empty()) app.sigError = err;
                }
            }

            ImGui::Text("Mic level: %.3f", app.inLevel);
            ImGui::ProgressBar(app.inLevel, ImVec2(0.0f, 0.0f));

            ImGui::Text("Caller level: %.3f", app.outlevel);
            DrawVoiceOrb(argv[0], app.outlevel);
        }

        ImGui::End();

        ImGui::Render();
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    ImGui::DestroyContext();

    SDL_GL_DestroyContext(glctx);
    SDL_DestroyWindow(window);
    SDL_Quit();

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
