// src/main.cpp
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

struct AeadCtx {
    std::array<uint8_t, 32> key{};  // 256-bit
    std::array<uint8_t, 12> salt{}; // 96-bit IV prefix
    std::atomic<uint64_t> seq{0};
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
    // Первые 4 байта — префикс, оставшиеся 8 — счётчик (BE)
    std::memcpy(iv, salt.data(), 12);
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
    if (!c)
        return false;

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
    if (!ok)
        return false;

    std::memcpy(outCipher.data() + outLen, tag, 16);
    return true;
}

static bool aead_open(const AeadCtx &ctx, uint64_t seq,
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
    return ok != 0;
}

#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"

struct AudioConfig {
    int sampleRate = 48000;
    int channels = 1;
    int frameMs = 20; // 960 frames @48k
    int framesPerBuffer() const { return (sampleRate / 1000) * frameMs; }
};

struct App {
    AudioConfig cfg{};
    AeadCtx aeadEncode{};
    AeadCtx aeadDecode{};

    ma_context ctx{};
    ma_device dev{};

    std::atomic<bool> running{false};

    bool initCrypto() {
        if (!rand_bytes(aeadEncode.key.data(), aeadEncode.key.size())) {
            std::cerr << "RAND key failed\n";
            return false;
        }
        if (!rand_bytes(aeadEncode.salt.data(), aeadEncode.salt.size())) {
            std::cerr << "RAND salt failed\n";
            return false;
        }
        aeadEncode.seq.store(0);

        std::stringstream encodeKey{};
        encodeKey << "0x";
        for (const uint64_t &byte : aeadEncode.key) {
            encodeKey << std::hex << byte;
        }
        std::stringstream encodeSalt{};
        encodeSalt << "0x";
        for (const uint64_t &byte : aeadEncode.salt) {
            encodeSalt << std::hex << byte;
        }
        std::cout << "Encode session key (" << encodeKey.str() << "), salt ("
                  << encodeSalt.str() << ")\n";

        aeadDecode.seq.store(aeadEncode.seq);
        aeadDecode.key = aeadEncode.key;
        aeadDecode.salt = aeadEncode.salt;

        return true;
    }

    bool changeDecodeCrypto() {
        if (!rand_bytes(aeadDecode.key.data(), aeadDecode.key.size())) {
            std::cerr << "RAND key failed\n";
            return false;
        }
        if (!rand_bytes(aeadDecode.salt.data(), aeadDecode.salt.size())) {
            std::cerr << "RAND salt failed\n";
            return false;
        }
        aeadDecode.seq.store(0);

        std::stringstream decodeKey{};
        decodeKey << "0x";
        for (const uint64_t &byte : aeadDecode.key) {
            decodeKey << std::hex << byte;
        }
        std::stringstream decodeSalt{};
        decodeSalt << "0x";
        for (const uint64_t &byte : aeadDecode.salt) {
            decodeSalt << std::hex << byte;
        }
        std::cout << "Changed decode session key (" << decodeKey.str() << "), salt ("
                  << decodeSalt.str() << ")\n";

        return true;
    }

    static void on_duplex(ma_device *pDevice, void *pOutput, const void *pInput,
                          ma_uint32 frameCount) {
        App *self = (App *)pDevice->pUserData;
        if (!self || !pOutput)
            return;

        const ma_uint32 ch = (ma_uint32)self->cfg.channels;
        const size_t bytesPCM =
            frameCount * ma_get_bytes_per_frame(ma_format_s16, ch);

        // Если нет входа (например, устройство не даёт pInput) — просто тишина
        if (pInput == nullptr) {
            std::memset(pOutput, 0, bytesPCM);
            return;
        }

        // Сериализуем входной PCM (s16 mono) в байты
        std::vector<uint8_t> plain(bytesPCM);
        std::memcpy(plain.data(), pInput, bytesPCM);

        // В AAD кладём текущий seq (8 байт) — тот же будет на расшифровку
        uint64_t sealSeq = self->aeadEncode.seq.load(std::memory_order_relaxed);
        self->aeadDecode.seq.store(sealSeq);
        uint8_t aad[8];
        std::memcpy(aad, &sealSeq, 8);

        std::vector<uint8_t> cipher;
        if (!aead_seal(self->aeadEncode, std::span<const uint8_t>(aad, 8),
                       std::span<const uint8_t>(plain.data(), plain.size()),
                       cipher)) {
            // Не рискуем — тишина
            std::memset(pOutput, 0, bytesPCM);
            return;
        }

        std::vector<uint8_t> decrypted;
        if (!aead_open(self->aeadDecode, sealSeq, std::span<const uint8_t>(aad, 8),
                       cipher, decrypted)) {
            std::memset(pOutput, 0, bytesPCM);
            std::cerr << "wrong decode..." << std::endl;
            return;
        }

        // Копируем назад в выводной буфер (s16)
        std::memcpy(pOutput, decrypted.data(),
                    std::min(decrypted.size(), bytesPCM));
        if (decrypted.size() < bytesPCM) {
            std::memset((uint8_t *)pOutput + decrypted.size(), 0,
                        bytesPCM - decrypted.size());
        }
    }

    bool initDevice() {
        // Контекст только ALSA
        static ma_backend backends[] = {ma_backend_alsa};
        ma_context_config cctx = ma_context_config_init();
        if (ma_context_init(backends, 1, &cctx, &ctx) != MA_SUCCESS) {
            std::cerr << "context init failed (ALSA)\n";
            return false;
        }

        ma_device_config cfgd = ma_device_config_init(ma_device_type_duplex);
        cfgd.sampleRate = (ma_uint32)cfg.sampleRate;
        cfgd.capture.format = ma_format_s16;
        cfgd.capture.channels = (ma_uint32)cfg.channels;
        cfgd.playback.format = ma_format_s16;
        cfgd.playback.channels = (ma_uint32)cfg.channels;

        // Попросим miniaudio уравнять периоды ввода/вывода (важно для ALSA)
        cfgd.periodSizeInFrames = (ma_uint32)cfg.framesPerBuffer(); // 20ms
        cfgd.periods = 3;

        cfgd.dataCallback = on_duplex;
        cfgd.pUserData = this;

        if (ma_device_init(&ctx, &cfgd, &dev) != MA_SUCCESS) {
            std::cerr << "device init failed\n";
            return false;
        }

        std::cout << "Audio init OK: " << cfg.sampleRate << " Hz, "
                  << cfg.channels << " ch, frame " << cfg.framesPerBuffer()
                  << " samples\n";
        return true;
    }

    void start() {
        running.store(true);
        if (ma_device_start(&dev) != MA_SUCCESS) {
            std::cerr << "device start failed\n";
            running.store(false);
        }
    }

    void stop() {
        running.store(false);
        ma_device_stop(&dev);
        ma_device_uninit(&dev);
        ma_context_uninit(&ctx);
        std::cout << "Stopped.\n";
    }
};

int main() {
    std::cout
        << "Zvonilka demo: mic -> AES-GCM -> decrypt -> speakers (duplex)\n";
    App app;
    if (!app.initCrypto())
        return 1;
    if (!app.initDevice())
        return 1;

    app.start();
    std::cout << "Running. Press ENTER to rotate key, 'q'+ENTER to quit.\n";

    for (;;) {
        std::string line;
        if (!std::getline(std::cin, line))
            break;
        if (line == "q" || line == "Q")
            break;
        if (!app.changeDecodeCrypto())
            std::cerr << "Key rotate failed\n";
        else
            std::cout << "Key rotated (new session)\n";
    }

    app.stop();
    return 0;
}
