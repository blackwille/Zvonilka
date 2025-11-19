// Zvonilka RTP+Opus demo (SDL3 + ImGui + miniaudio + OpenSSL + Opus)
// Single-file MVP: два инстанса общаются по RTP/UDP, звук кодируется Opus,
// шифруется AES-256-GCM. Сессионный ключ обновляется по кнопке и
// пересылается собеседнику через RSA (его публичный ключ).

#include <SDL3/SDL.h>
#include <SDL3/SDL_init.h>
#include <SDL3/SDL_opengl.h>
#include <SDL3/SDL_video.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
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
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <opus/opus.h>

#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"

#include "imgui.h"
#include "imgui_bindings/imgui_impl_opengl3.h"
#include "imgui_bindings/imgui_impl_sdl3.h"

// POSIX UDP (Linux/macOS; для Windows нужно будет заменить на winsock2)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// ---------- мелкие хелперы ----------

static uint64_t host_to_be64(uint64_t x) {
    return ((x & 0x00000000000000FFULL) << 56) |
           ((x & 0x000000000000FF00ULL) << 40) |
           ((x & 0x0000000000FF0000ULL) << 24) |
           ((x & 0x00000000FF000000ULL) << 8) |
           ((x & 0x000000FF00000000ULL) >> 8) |
           ((x & 0x0000FF0000000000ULL) >> 24) |
           ((x & 0x00FF000000000000ULL) >> 40) |
           ((x & 0xFF00000000000000ULL) >> 56);
}

static uint64_t be64_to_host(uint64_t x) { return host_to_be64(x); }

static bool rand_bytes(uint8_t *dst, size_t n) {
    return RAND_bytes(dst, (int)n) == 1;
}

// ---------- AEAD (AES-256-GCM) ----------

struct AeadCtx {
    std::array<uint8_t, 32> key{};  // 256-bit AES key
    std::array<uint8_t, 12> salt{}; // IV prefix
    std::atomic<uint64_t> seq{0};   // только для TX
};

static void make_iv(const std::array<uint8_t, 12> &salt, uint64_t seq,
                    uint8_t out[12]) {
    std::memcpy(out, salt.data(), 12);
    uint64_t be = host_to_be64(seq);
    // первые 4 байта остаются из соли, последние 8 — счётчик
    std::memcpy(out + 4, &be, 8);
}

static bool aead_seal_pkt(const AeadCtx &ctx, uint64_t seq,
                          std::span<const uint8_t> aad,
                          std::span<const uint8_t> plain,
                          std::vector<uint8_t> &outCipher) {
    uint8_t iv[12];
    make_iv(ctx.salt, seq, iv);

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        return false;

    int ok = 1, len = 0, outLen = 0;
    ok &= EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    ok &= EVP_EncryptInit_ex(c, nullptr, nullptr, ctx.key.data(), iv);

    if (!aad.empty())
        ok &= EVP_EncryptUpdate(c, nullptr, &len, aad.data(), (int)aad.size());

    outCipher.resize(plain.size() + 16);
    ok &= EVP_EncryptUpdate(c, outCipher.data(), &len, plain.data(),
                            (int)plain.size());
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

static bool aead_open_pkt(const AeadCtx &ctx, uint64_t seq,
                          std::span<const uint8_t> aad,
                          std::span<const uint8_t> cipherWithTag,
                          std::vector<uint8_t> &outPlain) {
    if (cipherWithTag.size() < 16)
        return false;
    const size_t clen = cipherWithTag.size() - 16;
    const uint8_t *tag = cipherWithTag.data() + clen;

    uint8_t iv[12];
    make_iv(ctx.salt, seq, iv);

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        return false;

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
    if (!ok)
        return false;

    outPlain.resize(outLen);
    return true;
}

// ---------- RTP и типы пакетов ----------

#pragma pack(push, 1)
struct RtpHeader {
    uint8_t vpxcc;
    uint8_t mpt;
    uint16_t seq;
    uint32_t timestamp;
    uint32_t ssrc;
};
#pragma pack(pop)

static constexpr uint8_t RTP_VERSION = 2;
static constexpr uint8_t RTP_PAYLOAD_TYPE_OPUS = 111;

enum class PacketType : uint8_t {
    RTP_AUDIO = 1,
    CTRL_PUBKEY = 2,
    CTRL_KEYUPDATE = 3
};

// ---------- аудиоконфиг ----------

struct AudioConfig {
    int sampleRate = 48000;
    int channels = 1;
    int frameMs = 20;

    int framesPerBuffer() const { return (sampleRate / 1000) * frameMs; }
};

// ---------- основное состояние приложения ----------

struct App {
    // audio
    AudioConfig cfg{};
    ma_context ctx{};
    ma_device dev{};
    std::atomic<bool> running{false};   // девайс открыт
    std::atomic<bool> capturing{false}; // микрофон включён

    // ring-buffer для принятых PCM
    ma_pcm_rb rb{};
    bool rbInitialized{false};
    ma_uint32 rbCapacityFrames{48000}; // 1 сек при 48k

    // Opus
    OpusEncoder *encoder{nullptr};
    OpusDecoder *decoder{nullptr};

    // crypto: раздельный контекст для TX и RX
    AeadCtx txCtx{};
    AeadCtx rxCtx{};
    bool txKeyValid{false};
    bool rxKeyValid{false};
    std::mutex crypto_mtx; // защищает key+salt, не seq

    // RSA
    EVP_PKEY *rsaKey{nullptr};       // наш приватный+публичный
    EVP_PKEY *remotePubKey{nullptr}; // публичный ключ собеседника
    bool pubkeySent{false};

    // network
    int sockfd{-1};
    sockaddr_in localAddr{};
    sockaddr_in remoteAddr{};
    std::atomic<bool> netRunning{false};
    std::thread recvThread;

    uint16_t rtpSeq{0};
    uint32_t rtpTimestamp{0};
    uint32_t rtpSSRC{0};

    // UI / визуал
    std::string lastError;
    std::atomic<float> remoteLevel{0.0f}; // RMS уровня удалённого голоса

    // --------- утилиты ---------
    static void print_hex(const char *label, std::span<const uint8_t> bytes) {
        std::stringstream ss;
        ss << "0x";
        for (uint8_t b : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        std::cout << label << " " << ss.str() << "\n";
    }

    void clearError() { lastError.clear(); }

    // --------- RSA ключ ---------
    bool initRSA() {
        if (rsaKey)
            return true;
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!kctx) {
            lastError = "EVP_PKEY_CTX_new_id failed";
            return false;
        }
        if (EVP_PKEY_keygen_init(kctx) <= 0) {
            EVP_PKEY_CTX_free(kctx);
            lastError = "EVP_PKEY_keygen_init failed";
            return false;
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0) {
            EVP_PKEY_CTX_free(kctx);
            lastError = "EVP_PKEY_CTX_set_rsa_keygen_bits failed";
            return false;
        }
        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(kctx);
            lastError = "EVP_PKEY_keygen failed";
            return false;
        }
        EVP_PKEY_CTX_free(kctx);
        rsaKey = pkey;
        return true;
    }

    std::string exportPublicKeyPEM() const {
        if (!rsaKey)
            return {};
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
            return {};
        if (PEM_write_bio_PUBKEY(bio, rsaKey) != 1) {
            BIO_free(bio);
            return {};
        }
        char *data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem;
        if (len > 0 && data)
            pem.assign(data, (size_t)len);
        BIO_free(bio);
        return pem;
    }

    bool importRemotePubKey(const uint8_t *data, size_t len) {
        BIO *bio = BIO_new_mem_buf(data, (int)len);
        if (!bio) {
            lastError = "BIO_new_mem_buf failed for peer pubkey";
            return false;
        }
        EVP_PKEY *pk = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pk) {
            lastError = "PEM_read_bio_PUBKEY failed";
            return false;
        }
        if (remotePubKey)
            EVP_PKEY_free(remotePubKey);
        remotePubKey = pk;
        return true;
    }

    // --------- сессионные ключи AES ---------
    // Ротация исходящего ключа (для отправки нашей речи).
    // sendToPeer == true => шлём обновление через RSA.
    bool rotateOutgoingKey(bool sendToPeer) {
        std::lock_guard<std::mutex> lg(crypto_mtx);

        if (!rand_bytes(txCtx.key.data(), txCtx.key.size())) {
            lastError = "rand_bytes(tx.key) failed";
            return false;
        }
        if (!rand_bytes(txCtx.salt.data(), txCtx.salt.size())) {
            lastError = "rand_bytes(tx.salt) failed";
            return false;
        }
        txCtx.seq.store(0, std::memory_order_relaxed);
        txKeyValid = true;

        print_hex("New TX key:", {txCtx.key.data(), txCtx.key.size()});
        print_hex("New TX salt:", {txCtx.salt.data(), txCtx.salt.size()});

        if (sendToPeer && netRunning.load() && remotePubKey && sockfd >= 0) {
            uint8_t blob[44]; // 32 key + 12 salt
            std::memcpy(blob, txCtx.key.data(), 32);
            std::memcpy(blob + 32, txCtx.salt.data(), 12);

            EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new(remotePubKey, nullptr);
            if (!cctx) {
                lastError = "EVP_PKEY_CTX_new(remotePubKey) failed";
                return false;
            }
            if (EVP_PKEY_encrypt_init(cctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_padding(cctx, RSA_PKCS1_OAEP_PADDING) <=
                    0) {
                EVP_PKEY_CTX_free(cctx);
                lastError = "EVP_PKEY_encrypt_init/OAEP failed";
                return false;
            }

            size_t outLen = 0;
            if (EVP_PKEY_encrypt(cctx, nullptr, &outLen, blob, sizeof(blob)) <=
                0) {
                EVP_PKEY_CTX_free(cctx);
                lastError = "EVP_PKEY_encrypt(size) failed";
                return false;
            }

            std::vector<uint8_t> cipher(outLen);
            if (EVP_PKEY_encrypt(cctx, cipher.data(), &outLen, blob,
                                 sizeof(blob)) <= 0) {
                EVP_PKEY_CTX_free(cctx);
                lastError = "EVP_PKEY_encrypt(data) failed";
                return false;
            }
            EVP_PKEY_CTX_free(cctx);
            cipher.resize(outLen);

            std::vector<uint8_t> pkt(1 + cipher.size());
            pkt[0] = static_cast<uint8_t>(PacketType::CTRL_KEYUPDATE);
            std::memcpy(pkt.data() + 1, cipher.data(), cipher.size());

            ::sendto(sockfd, pkt.data(), (int)pkt.size(), 0,
                     (sockaddr *)&remoteAddr, sizeof(remoteAddr));
        }

        return true;
    }

    // Обновление RX-ключа по входящему RSA-зашифрованному blob'у
    bool applyIncomingKeyUpdate(const uint8_t *data, size_t len) {
        if (!rsaKey)
            return false;

        EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new(rsaKey, nullptr);
        if (!cctx) {
            lastError = "EVP_PKEY_CTX_new(rsaKey) failed";
            return false;
        }
        if (EVP_PKEY_decrypt_init(cctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(cctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(cctx);
            lastError = "EVP_PKEY_decrypt_init/OAEP failed";
            return false;
        }

        size_t plainLen = 0;
        if (EVP_PKEY_decrypt(cctx, nullptr, &plainLen, data, len) <= 0) {
            EVP_PKEY_CTX_free(cctx);
            lastError = "EVP_PKEY_decrypt(size) failed";
            return false;
        }

        std::vector<uint8_t> plain(plainLen);
        if (EVP_PKEY_decrypt(cctx, plain.data(), &plainLen, data, len) <= 0) {
            EVP_PKEY_CTX_free(cctx);
            lastError = "EVP_PKEY_decrypt(data) failed";
            return false;
        }
        EVP_PKEY_CTX_free(cctx);
        plain.resize(plainLen);

        if (plain.size() < 44) {
            lastError = "KeyUpdate plain too short";
            return false;
        }

        std::lock_guard<std::mutex> lg(crypto_mtx);
        std::memcpy(rxCtx.key.data(), plain.data(), 32);
        std::memcpy(rxCtx.salt.data(), plain.data() + 32, 12);
        rxCtx.seq.store(0, std::memory_order_relaxed);
        rxKeyValid = true;

        print_hex("New RX key:", {rxCtx.key.data(), rxCtx.key.size()});
        print_hex("New RX salt:", {rxCtx.salt.data(), rxCtx.salt.size()});

        return true;
    }

    // --------- Opus ---------
    bool initOpus() {
        int err = 0;
        encoder = opus_encoder_create(cfg.sampleRate, cfg.channels,
                                      OPUS_APPLICATION_VOIP, &err);
        if (err != OPUS_OK || !encoder) {
            lastError = "opus_encoder_create failed: " +
                        std::string(opus_strerror(err));
            return false;
        }
        decoder = opus_decoder_create(cfg.sampleRate, cfg.channels, &err);
        if (err != OPUS_OK || !decoder) {
            lastError = "opus_decoder_create failed: " +
                        std::string(opus_strerror(err));
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

    // --------- сеть ---------
    bool startNetwork(const std::string &localIp, uint16_t localPort,
                      const std::string &remoteIp, uint16_t remotePort) {
        if (netRunning.load())
            return true;
        if (!initRSA())
            return false;

        sockfd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            lastError = "socket() failed";
            return false;
        }

        std::memset(&localAddr, 0, sizeof(localAddr));
        localAddr.sin_family = AF_INET;
        localAddr.sin_port = htons(localPort);
        localAddr.sin_addr.s_addr =
            localIp.empty() ? INADDR_ANY : ::inet_addr(localIp.c_str());

        if (::bind(sockfd, (sockaddr *)&localAddr, sizeof(localAddr)) < 0) {
            lastError = "bind() failed";
            ::close(sockfd);
            sockfd = -1;
            return false;
        }

        std::memset(&remoteAddr, 0, sizeof(remoteAddr));
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_port = htons(remotePort);
        remoteAddr.sin_addr.s_addr = ::inet_addr(remoteIp.c_str());

        rtpSeq = (uint16_t)std::rand();
        rtpTimestamp = 0;
        rtpSSRC = (uint32_t)std::rand();

        netRunning.store(true);
        pubkeySent = false;

        recvThread = std::thread(&App::recvLoop, this);

        // сразу шлём наш публичный ключ
        sendPublicKey();

        return true;
    }

    void stopNetwork() {
        if (!netRunning.load())
            return;
        netRunning.store(false);
        if (sockfd >= 0) {
            ::shutdown(sockfd, SHUT_RDWR);
            ::close(sockfd);
            sockfd = -1;
        }
        if (recvThread.joinable())
            recvThread.join();
    }

    void sendPublicKey() {
        if (!rsaKey || sockfd < 0)
            return;
        std::string pem = exportPublicKeyPEM();
        if (pem.empty())
            return;

        std::vector<uint8_t> pkt(1 + pem.size());
        pkt[0] = static_cast<uint8_t>(PacketType::CTRL_PUBKEY);
        std::memcpy(pkt.data() + 1, pem.data(), pem.size());

        ::sendto(sockfd, pkt.data(), (int)pkt.size(), 0,
                 (sockaddr *)&remoteAddr, sizeof(remoteAddr));
        pubkeySent = true;
    }

    void recvLoop() {
        std::vector<uint8_t> buf(2048);
        while (netRunning.load()) {
            sockaddr_in src{};
            socklen_t slen = sizeof(src);
            ssize_t n = ::recvfrom(sockfd, buf.data(), (int)buf.size(), 0,
                                   (sockaddr *)&src, &slen);
            if (n <= 0)
                break;
            if (n < 1)
                continue;

            uint8_t type = buf[0];
            const uint8_t *payload = buf.data() + 1;
            size_t plen = (size_t)n - 1;

            if (type == (uint8_t)PacketType::CTRL_PUBKEY) {
                if (importRemotePubKey(payload, plen)) {
                    // при первом получении чужого ключа — сразу генерим свой TX
                    if (!txKeyValid) {
                        rotateOutgoingKey(true);
                    }
                }
            } else if (type == (uint8_t)PacketType::CTRL_KEYUPDATE) {
                applyIncomingKeyUpdate(payload, plen);

            } else if (type == (uint8_t)PacketType::RTP_AUDIO) {
                if (plen < sizeof(RtpHeader) + 8 + 16)
                    continue;
                if (!decoder || !rxKeyValid)
                    continue;

                auto *hdr = reinterpret_cast<const RtpHeader *>(payload);
                (void)hdr; // пока заголовок почти не используем

                const uint8_t *p = payload + sizeof(RtpHeader);

                uint64_t seq_be = 0;
                std::memcpy(&seq_be, p, 8);
                uint64_t seq = be64_to_host(seq_be);

                size_t cipherLen = plen - sizeof(RtpHeader) - 8;
                std::span<const uint8_t> cipher(p + 8, cipherLen);
                std::span<const uint8_t> aad(payload, sizeof(RtpHeader));

                // snapshot RX key
                AeadCtx snap;
                {
                    std::lock_guard<std::mutex> lg(crypto_mtx);
                    snap.key = rxCtx.key;
                    snap.salt = rxCtx.salt;
                }

                std::vector<uint8_t> plain;
                if (!aead_open_pkt(snap, seq, aad, cipher, plain)) {
                    std::cerr << "Decrypt failed\n";
                    continue;
                }

                const int maxFrames = cfg.framesPerBuffer();
                std::vector<int16_t> pcm(maxFrames * cfg.channels);

                int decoded =
                    opus_decode(decoder, plain.data(), (opus_int32)plain.size(),
                                pcm.data(), maxFrames, 0);
                if (decoded <= 0) {
                    std::cerr << "Opus decode error: " << decoded << "\n";
                    continue;
                }

                // --- обновляем RMS уровень для анимации ---
                double sumSq = 0.0;
                int samples = decoded * cfg.channels;
                for (int i = 0; i < samples; ++i) {
                    float v = pcm[i] / 32768.0f;
                    sumSq += v * v;
                }
                float rms =
                    samples > 0 ? (float)std::sqrt(sumSq / samples) : 0.0f;
                float prev = remoteLevel.load(std::memory_order_relaxed);
                float lvl = std::max(rms, prev * 0.8f); // лёгкий decay
                if (lvl > 1.0f)
                    lvl = 1.0f;
                remoteLevel.store(lvl, std::memory_order_relaxed);

                // --- пишем в ring buffer для воспроизведения ---
                if (!rbInitialized)
                    continue;

                ma_uint32 framesToWrite = (ma_uint32)decoded;
                void *pWrite = nullptr;
                if (ma_pcm_rb_acquire_write(&rb, &framesToWrite, &pWrite) ==
                        MA_SUCCESS &&
                    framesToWrite >= (ma_uint32)decoded) {
                    std::memcpy(pWrite, pcm.data(),
                                decoded * cfg.channels * sizeof(int16_t));
                    ma_pcm_rb_commit_write(&rb, (ma_uint32)decoded);
                }
            }
        }
    }

    // --------- audio open/close ---------
    bool open() {
        if (running.load())
            return true;
        clearError();

        if (ma_context_init(nullptr, 0, nullptr, &ctx) != MA_SUCCESS) {
            lastError = "ma_context_init failed";
            return false;
        }
        if (!initOpus()) {
            ma_context_uninit(&ctx);
            return false;
        }

        ma_device_config cfgd = ma_device_config_init(ma_device_type_duplex);
        cfgd.sampleRate = (ma_uint32)cfg.sampleRate;
        cfgd.capture.format = ma_format_s16;
        cfgd.capture.channels = (ma_uint32)cfg.channels;
        cfgd.playback.format = ma_format_s16;
        cfgd.playback.channels = (ma_uint32)cfg.channels;
        cfgd.periodSizeInFrames = (ma_uint32)cfg.framesPerBuffer();
        cfgd.periods = 3;
        cfgd.dataCallback = &App::on_duplex;
        cfgd.pUserData = this;

        if (ma_device_init(&ctx, &cfgd, &dev) != MA_SUCCESS) {
            lastError = "ma_device_init failed";
            destroyOpus();
            ma_context_uninit(&ctx);
            return false;
        }

        if (ma_pcm_rb_init(ma_format_s16, (ma_uint32)cfg.channels,
                           rbCapacityFrames, nullptr, nullptr,
                           &rb) != MA_SUCCESS) {
            lastError = "ma_pcm_rb_init failed";
            ma_device_uninit(&dev);
            destroyOpus();
            ma_context_uninit(&ctx);
            return false;
        }
        rbInitialized = true;

        // ВАЖНО: стартуем девайс один раз здесь
        if (ma_device_start(&dev) != MA_SUCCESS) {
            lastError = "ma_device_start failed in open()";
            ma_device_uninit(&dev);
            ma_context_uninit(&ctx);
            destroyOpus();
            return false;
        }

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
            ma_device_stop(&dev);
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
        capturing.store(true);
        return true;
    }

    void stop_capture() {
        if (!running.load())
            return;
        capturing.store(false);
    }

    // --------- аудиоколбэк ---------
    static void on_duplex(ma_device *pDevice, void *pOutput, const void *pInput,
                          ma_uint32 frameCount) {
        App *self = static_cast<App *>(pDevice->pUserData);
        if (!self || !pOutput)
            return;

        const ma_uint32 ch = (ma_uint32)self->cfg.channels;
        const size_t bytesPCM = frameCount * ch * sizeof(int16_t);
        auto *out = static_cast<int16_t *>(pOutput);

        // 1) ВСЕГДА: воспроизведение из ring-buffer'а
        if (self->rbInitialized) {
            ma_uint32 framesToRead = frameCount;
            void *pRead = nullptr;

            if (ma_pcm_rb_acquire_read(&self->rb, &framesToRead, &pRead) ==
                    MA_SUCCESS &&
                framesToRead > 0) {
                ma_uint32 copyFrames = framesToRead;
                if (copyFrames > frameCount)
                    copyFrames = frameCount;

                size_t copyBytes = copyFrames * ch * sizeof(int16_t);
                std::memcpy(out, pRead, copyBytes);
                ma_pcm_rb_commit_read(&self->rb, copyFrames);

                if (copyFrames < frameCount) {
                    std::memset(reinterpret_cast<uint8_t *>(out) + copyBytes, 0,
                                bytesPCM - copyBytes);
                }
            } else {
                std::memset(out, 0, bytesPCM);
            }
        } else {
            std::memset(out, 0, bytesPCM);
        }

        // 2) ТОЛЬКО ЕСЛИ МИКРОФОН ВКЛЮЧЕН: захват, Opus, AES, отправка
        if (!self->capturing.load(std::memory_order_relaxed)) {
            return; // выходим, но out уже заполнен удалённым звуком
        }
        if (!pInput)
            return;
        if (!self->encoder)
            return;
        if (!self->netRunning.load())
            return;
        if (!self->txKeyValid)
            return;
        if (self->sockfd < 0)
            return;

        auto *in = static_cast<const int16_t *>(pInput);
        const int frameSize = (int)frameCount;

        // 1) Opus encode
        std::vector<uint8_t> opusPacket(4000);
        int nbBytes =
            opus_encode(self->encoder, in, frameSize, opusPacket.data(),
                        (opus_int32)opusPacket.size());
        if (nbBytes <= 0) {
            std::cerr << "Opus encode error: " << nbBytes << "\n";
            return;
        }
        opusPacket.resize(nbBytes);

        // 2) snapshot TX key + seq
        AeadCtx snap;
        uint64_t seq = 0;
        {
            std::lock_guard<std::mutex> lg(self->crypto_mtx);
            snap.key = self->txCtx.key;
            snap.salt = self->txCtx.salt;
            seq = self->txCtx.seq.fetch_add(1, std::memory_order_relaxed);
        }

        // 3) RTP header
        RtpHeader hdr{};
        hdr.vpxcc = (uint8_t)((RTP_VERSION << 6) | 0);
        hdr.mpt = (uint8_t)(0x00 | (RTP_PAYLOAD_TYPE_OPUS & 0x7F));
        hdr.seq = htons(self->rtpSeq++);
        hdr.timestamp = htonl(self->rtpTimestamp);
        hdr.ssrc = htonl(self->rtpSSRC);
        self->rtpTimestamp += frameSize;

        std::span<const uint8_t> aad(reinterpret_cast<uint8_t *>(&hdr),
                                     sizeof(RtpHeader));

        uint64_t seq_be = host_to_be64(seq);
        std::vector<uint8_t> cipher;
        if (!aead_seal_pkt(
                snap, seq, aad,
                std::span<const uint8_t>(opusPacket.data(), opusPacket.size()),
                cipher)) {
            std::cerr << "Encrypt failed\n";
            return;
        }

        std::vector<uint8_t> packet;
        packet.resize(1 + sizeof(RtpHeader) + 8 + cipher.size());
        packet[0] = static_cast<uint8_t>(PacketType::RTP_AUDIO);
        std::memcpy(packet.data() + 1, &hdr, sizeof(RtpHeader));
        std::memcpy(packet.data() + 1 + sizeof(RtpHeader), &seq_be, 8);
        std::memcpy(packet.data() + 1 + sizeof(RtpHeader) + 8, cipher.data(),
                    cipher.size());

        ::sendto(self->sockfd, packet.data(), (int)packet.size(), 0,
                 (sockaddr *)&self->remoteAddr, sizeof(self->remoteAddr));
    }
};

// ---------- UI helpers ----------

static bool MicButton(const char *id, bool active) {
    ImVec2 size = ImVec2(48, 48);
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 center = ImVec2(pos.x + size.x * 0.5f, pos.y + size.y * 0.5f);

    ImGui::InvisibleButton(id, size);
    bool hovered = ImGui::IsItemHovered();
    bool pressed = ImGui::IsItemClicked();

    ImDrawList *draw = ImGui::GetWindowDrawList();
    draw->AddCircleFilled(
        center, size.x * 0.5f,
        active ? IM_COL32(255, 60, 60, 255) : IM_COL32(200, 200, 200, 255), 32);

    float innerRadius = size.x * 0.2f;
    draw->AddCircleFilled(center, innerRadius, IM_COL32(255, 255, 255, 255),
                          16);

    if (hovered) {
        draw->AddCircle(center, size.x * 0.5f - 1, IM_COL32(255, 255, 255, 120),
                        32, 2.0f);
    }

    return pressed;
}

// Простая визуализация уровня голоса собеседника
static void DrawVoiceLevel(float level) {
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 size = ImVec2(ImGui::GetContentRegionAvail().x, 24.0f);

    ImGui::InvisibleButton("##voice_level", size);

    ImDrawList *draw = ImGui::GetWindowDrawList();

    ImU32 bgCol = IM_COL32(40, 40, 60, 255);
    ImU32 fgCol = IM_COL32(80, 200, 120, 255);

    ImVec2 p1 = pos;
    ImVec2 p2 = ImVec2(pos.x + size.x, pos.y + size.y);
    draw->AddRectFilled(p1, p2, bgCol, 6.0f);

    float clamped = std::clamp(level, 0.0f, 1.0f);
    float w = size.x * clamped;
    ImVec2 p3 = ImVec2(pos.x + w, pos.y + size.y);
    draw->AddRectFilled(p1, p3, fgCol, 6.0f);
}

// ---------- main ----------

int main(int, char **) {
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

    SDL_Window *window =
        SDL_CreateWindow("Zvonilka RTP+Opus", 1280, 720,
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
    app.initRSA();

    bool quit = false;
    bool showDemo = false;

    static char localIpBuf[64] = "127.0.0.1";
    static char remoteIpBuf[64] = "127.0.0.1";
    static int localPort = 5004;
    static int remotePort = 5005;

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
        ImGui::SetNextWindowSize(
            ImVec2(static_cast<float>(w), static_cast<float>(h)));
        // clang-format off
        ImGui::Begin("Zvonilka RTP+Opus", nullptr,
            ImGuiWindowFlags_NoTitleBar | 
            ImGuiWindowFlags_NoResize   |
            ImGuiWindowFlags_NoMove     | 
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);
        // clang-format on

        ImGui::Text("Audio: %d Hz, %d ch, %d ms", app.cfg.sampleRate,
                    app.cfg.channels, app.cfg.frameMs);
        ImGui::Separator();

        // Mic
        ImGui::Text("Mic:");
        ImGui::SameLine();
        if (MicButton("mic_btn", app.capturing.load())) {
            if (!app.capturing.load()) {
                if (!app.start_capture()) {
                    ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1),
                                       "Start capture failed");
                }
            } else {
                app.stop_capture();
            }
        }
        ImGui::SameLine();
        ImGui::Text("%s", app.capturing.load() ? "ON" : "OFF");

        // Audio device
        if (!app.running.load()) {
            if (ImGui::Button("Open device")) {
                if (!app.open()) {
                    ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1), "Open failed");
                }
            }
        } else {
            if (ImGui::Button("Close device")) {
                app.close();
            }
        }

        // Ключи
        if (ImGui::Button("Rotate session key (TX)")) {
            if (!app.rotateOutgoingKey(true)) {
                ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1),
                                   "Key rotation failed");
            }
        }
        ImGui::SameLine();
        ImGui::Text("TX key: %s, RX key: %s", app.txKeyValid ? "OK" : "none",
                    app.rxKeyValid ? "OK" : "none");

        ImGui::Separator();
        ImGui::Text("Network (RTP/UDP + AES-GCM + RSA key update)");

        ImGui::InputText("Local IP (empty = 0.0.0.0)", localIpBuf,
                         sizeof(localIpBuf));
        ImGui::InputInt("Local port", &localPort);
        ImGui::InputText("Remote IP", remoteIpBuf, sizeof(remoteIpBuf));
        ImGui::InputInt("Remote port", &remotePort);

        if (!app.netRunning.load()) {
            if (ImGui::Button("Start network")) {
                std::string localIp = localIpBuf;
                std::string remoteIp = remoteIpBuf;
                if (!app.startNetwork(localIp, (uint16_t)localPort, remoteIp,
                                      (uint16_t)remotePort)) {
                    ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1),
                                       "Network start failed");
                }
            }
        } else {
            if (ImGui::Button("Stop network")) {
                app.stopNetwork();
            }
        }

        ImGui::Text("Device:   %s", app.running.load() ? "open" : "closed");
        ImGui::Text("Capture:  %s", app.capturing.load() ? "on" : "off");
        ImGui::Text("Network:  %s", app.netRunning.load() ? "on" : "off");

        ImGui::Separator();
        ImGui::Text("Remote voice level:");
        float lvl = app.remoteLevel.load(std::memory_order_relaxed);
        lvl *= 0.9f; // затухание между кадрами
        app.remoteLevel.store(lvl, std::memory_order_relaxed);
        DrawVoiceLevel(lvl);

        if (!app.lastError.empty()) {
            ImGui::Separator();
            ImGui::TextColored(ImVec4(1, 0.5f, 0.5f, 1), "Last error: %s",
                               app.lastError.c_str());
        }

        ImGui::Checkbox("Show ImGui demo", &showDemo);

        ImGui::End();

        ImGui::Render();
        SDL_GL_MakeCurrent(window, gl_context);
        glViewport(0, 0, (int)ImGui::GetIO().DisplaySize.x,
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
