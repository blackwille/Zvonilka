// Zvonilka RTP+Opus demo (SDL3 + ImGui + miniaudio + OpenSSL + Opus)
// Single-file MVP: два инстанса общаются по RTP/UDP, звук кодируется Opus,
// шифруется AES-256-GCM. Сессионный ключ обновляется по кнопке и
// пересылается собеседнику через RSA (его публичный ключ).

#include <GLES3/gl3.h>
#include <SDL3/SDL.h>
#include <SDL3/SDL_init.h>
#include <SDL3/SDL_opengl.h>
#include <SDL3/SDL_video.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <netdb.h>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <glib.h>
#include <glib-object.h>
#include <nice/address.h>
#include <nice/agent.h>
#include <nice/debug.h>

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

// ------- Voice Orb Shader -------

static GLuint CompileShader(GLenum type, const char *src) {
    GLuint sh = glCreateShader(type);
    glShaderSource(sh, 1, &src, nullptr);
    glCompileShader(sh);
    GLint ok = 0;
    glGetShaderiv(sh, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char log[1024];
        glGetShaderInfoLog(sh, 1024, nullptr, log);
        std::cerr << "Shader compile error: " << log << "\n";
    }
    return sh;
}

static GLuint CreateProgram(const char *vs, const char *fs) {
    GLuint v = CompileShader(GL_VERTEX_SHADER, vs);
    GLuint f = CompileShader(GL_FRAGMENT_SHADER, fs);
    GLuint p = glCreateProgram();
    glAttachShader(p, v);
    glAttachShader(p, f);
    glLinkProgram(p);
    GLint ok = 0;
    glGetProgramiv(p, GL_LINK_STATUS, &ok);
    if (!ok) {
        char log[1024];
        glGetProgramInfoLog(p, 1024, nullptr, log);
        std::cerr << "Program link error: " << log << "\n";
    }
    glDeleteShader(v);
    glDeleteShader(f);
    return p;
}

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

static std::string b64_encode(const uint8_t *data, size_t len) {
    if (!data || len == 0)
        return {};
    size_t outLen = 4 * ((len + 2) / 3);
    std::string out(outLen, '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                            reinterpret_cast<const unsigned char *>(data),
                            (int)len);
    if (n < 0)
        return {};
    out.resize((size_t)n);
    return out;
}

static bool b64_decode(const std::string &in, std::vector<uint8_t> &out) {
    if (in.empty())
        return false;
    size_t outLen = 3 * (in.size() / 4) + 4;
    out.resize(outLen);
    int n = EVP_DecodeBlock(out.data(),
                            reinterpret_cast<const unsigned char *>(in.data()),
                            (int)in.size());
    if (n < 0)
        return false;
    size_t pad = 0;
    if (!in.empty()) {
        if (in[in.size() - 1] == '=')
            pad++;
        if (in.size() > 1 && in[in.size() - 2] == '=')
            pad++;
    }
    size_t finalLen = n >= (int)pad ? (size_t)(n - (int)pad) : 0;
    out.resize(finalLen);
    return true;
}

static bool pubkey_to_der(EVP_PKEY *pkey, std::vector<uint8_t> &der) {
    if (!pkey)
        return false;
    int len = i2d_PUBKEY(pkey, nullptr);
    if (len <= 0)
        return false;
    der.resize((size_t)len);
    unsigned char *p = der.data();
    if (i2d_PUBKEY(pkey, &p) != len)
        return false;
    return true;
}

static EVP_PKEY *pubkey_from_der(const uint8_t *data, size_t len) {
    const unsigned char *p = data;
    return d2i_PUBKEY(nullptr, &p, (long)len);
}

static bool rsa_encrypt(EVP_PKEY *pub, std::span<const uint8_t> plain,
                        std::vector<uint8_t> &cipher) {
    if (!pub)
        return false;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, nullptr);
    if (!ctx)
        return false;
    bool ok = false;
    if (EVP_PKEY_encrypt_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0) {
        size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, plain.data(),
                             plain.size()) > 0) {
            cipher.resize(outLen);
            if (EVP_PKEY_encrypt(ctx, cipher.data(), &outLen, plain.data(),
                                 plain.size()) > 0) {
                cipher.resize(outLen);
                ok = true;
            }
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static bool rsa_decrypt(EVP_PKEY *priv, std::span<const uint8_t> cipher,
                        std::vector<uint8_t> &plain) {
    if (!priv)
        return false;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx)
        return false;
    bool ok = false;
    if (EVP_PKEY_decrypt_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0) {
        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, cipher.data(),
                             cipher.size()) > 0) {
            plain.resize(outLen);
            if (EVP_PKEY_decrypt(ctx, plain.data(), &outLen, cipher.data(),
                                 cipher.size()) > 0) {
                plain.resize(outLen);
                ok = true;
            }
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static std::string trim(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])))
        ++start;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
        --end;
    return s.substr(start, end - start);
}

static std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> out;
    std::string cur;
    std::stringstream ss(s);
    while (std::getline(ss, cur, delim)) {
        out.push_back(cur);
    }
    return out;
}

static uint16_t default_port_for_user(const std::string &username) {
    uint32_t h = 0;
    for (char c : username) {
        h = h * 131 + static_cast<unsigned char>(c);
    }
    // 35000-45000 — чтобы не конфликтовать с системными сервисами
    return static_cast<uint16_t>(35000 + (h % 10000));
}

static std::filesystem::path secrets_path(const std::string &exeDir,
                                          const std::string &file) {
    return std::filesystem::path(exeDir) / "secrets" / file;
}

static bool parse_host_port_url(const std::string &url, std::string &hostOut,
                                uint16_t &portOut) {
    std::string s = url;
    if (s.rfind("http://", 0) == 0)
        s = s.substr(7);
    else if (s.rfind("https://", 0) == 0)
        s = s.substr(8);
    size_t slash = s.find('/');
    if (slash != std::string::npos)
        s = s.substr(0, slash);
    size_t colon = s.rfind(':');
    hostOut.clear();
    portOut = 0;
    if (colon == std::string::npos) {
        hostOut = s;
        portOut = 7777; // default for our simple signalling
        return !hostOut.empty();
    }
    hostOut = s.substr(0, colon);
    try {
        portOut = static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
    } catch (...) {
        return false;
    }
    return !hostOut.empty() && portOut > 0;
}

static bool resolve_ipv4(const std::string &host, uint16_t port,
                         sockaddr_in &out) {
    std::memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &out.sin_addr) == 1) {
        return true;
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
        return false;
    auto *addr = reinterpret_cast<sockaddr_in *>(res->ai_addr);
    out.sin_addr = addr->sin_addr;
    freeaddrinfo(res);
    return true;
}

static bool tcp_send_recv_line(const sockaddr_in &sa, const std::string &line,
                               std::string &respLine, int timeoutMs) {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return false;
    timeval tv{};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(sock, reinterpret_cast<const sockaddr *>(&sa), sizeof(sa)) <
        0) {
        ::close(sock);
        return false;
    }
    std::string payload = line;
    if (payload.empty() || payload.back() != '\n')
        payload.push_back('\n');
    if (::send(sock, payload.data(), (int)payload.size(), 0) <
        (ssize_t)payload.size()) {
        ::close(sock);
        return false;
    }
    respLine.clear();
    char buf[512];
    while (true) {
        ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        respLine.append(buf, buf + n);
        if (respLine.find('\n') != std::string::npos)
            break;
    }
    ::close(sock);
    size_t nl = respLine.find('\n');
    if (nl != std::string::npos)
        respLine = respLine.substr(0, nl);
    // trim CR
    if (!respLine.empty() && respLine.back() == '\r')
        respLine.pop_back();
    return !respLine.empty();
}

struct UserRecord {
    std::string username;
    std::string password;
    std::string host;
    uint16_t port{0}; // 0 => использовать default_port_for_user
};

struct TurnProbeState {
    std::atomic<bool> done{false};
    std::atomic<bool> timedOut{false};
    GMainLoop *loop{nullptr};
    GSource *timeout{nullptr};
    std::atomic<int> relayCount{0};
};

static void on_candidates_gathered_cb(NiceAgent *, guint, gpointer user_data) {
    auto *state = static_cast<TurnProbeState *>(user_data);
    if (state) {
        state->done.store(true, std::memory_order_relaxed);
        if (state->loop)
            g_main_loop_quit(state->loop);
    }
}

static const char *candidate_type_str(NiceCandidateType t) {
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

static void on_new_candidate_cb(NiceAgent *, guint, guint, NiceCandidate *c,
                                gpointer user_data) {
    auto *state = static_cast<TurnProbeState *>(user_data);
    if (!nice_address_is_valid(&c->addr)) {
        std::cout << "[TURN probe] candidate " << candidate_type_str(c->type)
                  << " (addr invalid)\n";
        return;
    }
    char ip[64] = {0};
    nice_address_to_string(&c->addr, ip);
    uint16_t port = nice_address_get_port(&c->addr);
    std::cout << "[TURN probe] candidate " << candidate_type_str(c->type) << " "
              << ip << ":" << port << "\n";
    if (state && c->type == NICE_CANDIDATE_TYPE_RELAYED) {
        state->relayCount.fetch_add(1, std::memory_order_relaxed);
    }
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
    // paths/config
    std::string execDir;

    // auth/secrets
    bool authenticated{false};
    std::string authUser;
    std::string authError;
    std::string remoteUser;
    uint16_t localPortOverride{0};
    std::string localBindIp{"0.0.0.0"};
    std::string authToken;
    EVP_PKEY *serverPubKey{nullptr};

    // STUN/TURN
    std::string stunServer{"127.0.0.1"};
    uint16_t stunPort{3478};
    std::string turnRealm{"local"};
    std::string turnUser;
    std::string turnPassword;
    std::string stunStatus;
    bool forceTurnOnly{false};

    // signalling
    std::string sigServer{"http://127.0.0.1:7777"};
    std::string sigStatus;

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

    bool authenticateUser(const std::string &user, const std::string &pwd) {
        // В этой версии логины/пароли проверяет signalling/turn, здесь просто
        // сохраняем
        authenticated = true;
        authUser = user;
        turnUser = user;
        turnPassword = pwd;
        authError.clear();
        // Привязываем порт детерминированно по user
        localPortOverride = default_port_for_user(user);
        localBindIp = "0.0.0.0";
        stunStatus.clear();
        return true;
    }

    bool parseSigServer(std::string &host, uint16_t &port) {
        if (!parse_host_port_url(sigServer, host, port)) {
            sigStatus = "Bad signalling URL";
            return false;
        }
        return true;
    }

    bool fetchServerPubKey() {
        std::string host;
        uint16_t port = 0;
        if (!parseSigServer(host, port))
            return false;
        sockaddr_in sa{};
        if (!resolve_ipv4(host, port, sa)) {
            sigStatus = "Signalling host resolve failed";
            return false;
        }
        std::string resp;
        if (!tcp_send_recv_line(sa, "GETPUB", resp, 2000)) {
            sigStatus = "Signalling GETPUB timeout";
            return false;
        }
        if (resp.rfind("PUB ", 0) != 0) {
            sigStatus = "GETPUB bad response";
            return false;
        }
        std::string b64 = resp.substr(4);
        std::vector<uint8_t> der;
        if (!b64_decode(b64, der)) {
            sigStatus = "GETPUB b64 decode failed";
            return false;
        }
        EVP_PKEY *pk = pubkey_from_der(der.data(), der.size());
        if (!pk) {
            sigStatus = "GETPUB parse failed";
            return false;
        }
        if (serverPubKey)
            EVP_PKEY_free(serverPubKey);
        serverPubKey = pk;
        std::cout << "[sig] GOT server pubkey, bytes=" << der.size() << "\n";
        return true;
    }

    bool loginWithSignalling(const std::string &user,
                             const std::string &password) {
        if (!initRSA()) {
            authError = "RSA init failed";
            return false;
        }
        if (!fetchServerPubKey()) {
            authError = sigStatus;
            return false;
        }

        std::vector<uint8_t> clientDer;
        if (!pubkey_to_der(rsaKey, clientDer)) {
            authError = "Client pubkey DER failed";
            return false;
        }
        std::string clientB64 = b64_encode(clientDer.data(), clientDer.size());
        std::cout << "[sig] Client pub DER size=" << clientDer.size()
                  << ", b64 len=" << clientB64.size() << "\n";

        std::string plain = user + ":" + password;
        std::vector<uint8_t> cipher;
        if (!rsa_encrypt(serverPubKey,
                         std::span<const uint8_t>(
                             reinterpret_cast<const uint8_t *>(plain.data()),
                             plain.size()),
                         cipher)) {
            authError = "Encrypt creds failed";
            return false;
        }
        std::string cipherB64 = b64_encode(cipher.data(), cipher.size());
        std::cout << "[sig] Encrypted creds bytes=" << cipher.size()
                  << ", b64 len=" << cipherB64.size() << "\n";

        std::string host;
        uint16_t port = 0;
        if (!parseSigServer(host, port))
            return false;
        sockaddr_in sa{};
        if (!resolve_ipv4(host, port, sa)) {
            authError = "Signalling host resolve failed";
            return false;
        }
        std::stringstream line;
        line << "AUTH " << clientB64 << " " << cipherB64;
        std::string resp;
        if (!tcp_send_recv_line(sa, line.str(), resp, 3000)) {
            authError = "Signalling auth timeout";
            return false;
        }
        std::cout << "[sig] AUTH response: " << resp << "\n";
        if (resp.rfind("OK ", 0) != 0) {
            authError = "Auth failed: " + resp;
            return false;
        }
        std::string tokenB64 = trim(resp.substr(3));
        std::vector<uint8_t> tokenCipher;
        if (!b64_decode(tokenB64, tokenCipher)) {
            authError = "Token b64 decode failed";
            return false;
        }
        std::cout << "[sig] Token cipher bytes=" << tokenCipher.size() << "\n";
        std::vector<uint8_t> tokenPlain;
        if (!rsa_decrypt(rsaKey, tokenCipher, tokenPlain)) {
            authError = "Token decrypt failed";
            return false;
        }
        authToken.assign(reinterpret_cast<char *>(tokenPlain.data()),
                         tokenPlain.size());
        std::cout << "[sig] Auth OK, token len=" << authToken.size() << "\n";

        authenticated = true;
        authUser = user;
        turnUser = user;
        turnPassword = password;
        authError.clear();
        sigStatus = "Auth OK";
        localPortOverride = default_port_for_user(user);
        localBindIp = "0.0.0.0";
        stunStatus.clear();
        return true;
    }

    bool signallingRegisterSelf() {
        if (authToken.empty()) {
            sigStatus = "No auth token";
            return false;
        }
        std::string host;
        uint16_t port = 0;
        if (!parseSigServer(host, port))
            return false;
        sockaddr_in sa{};
        if (!resolve_ipv4(host, port, sa)) {
            sigStatus = "Signalling host resolve failed";
            return false;
        }
        std::stringstream line;
        line << "REGISTER " << authToken << " " << localBindIp << " "
             << localPortOverride;
        std::string resp;
        if (!tcp_send_recv_line(sa, line.str(), resp, 2000)) {
            sigStatus = "Signalling register timeout";
            return false;
        }
        std::cout << "[sig] REGISTER resp: " << resp << "\n";
        if (resp.rfind("OK", 0) == 0) {
            sigStatus = "Registered at signalling";
            return true;
        }
        sigStatus = "Register failed: " + resp;
        return false;
    }

    bool signallingQueryPeer(const std::string &peer, std::string &ipOut,
                             uint16_t &portOut) {
        if (authToken.empty()) {
            sigStatus = "No auth token";
            return false;
        }
        std::string host;
        uint16_t port = 0;
        if (!parseSigServer(host, port))
            return false;
        sockaddr_in sa{};
        if (!resolve_ipv4(host, port, sa)) {
            sigStatus = "Signalling host resolve failed";
            return false;
        }
        std::stringstream line;
        line << "QUERY " << authToken << " " << peer;
        std::string resp;
        if (!tcp_send_recv_line(sa, line.str(), resp, 2000)) {
            sigStatus = "Signalling query timeout";
            return false;
        }
        std::cout << "[sig] QUERY resp: " << resp << "\n";
        if (resp.rfind("OK ", 0) == 0) {
            std::istringstream iss(resp.substr(3));
            std::string ip;
            uint16_t p = 0;
            iss >> ip >> p;
            if (ip.empty() || p == 0) {
                sigStatus = "Signalling response invalid";
                return false;
            }
            ipOut = ip;
            portOut = p;
            sigStatus = "Peer address received";
            return true;
        }
        sigStatus = "Peer not found: " + resp;
        return false;
    }

    // --- Простая TURN-ALLOCATE проверка (UDP, без ICE/libnice) ---
    struct StunAttr {
        uint16_t type;
        uint16_t len;
        std::vector<uint8_t> data;
    };

    static uint32_t crc32(const uint8_t *data, size_t len) {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < len; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                uint32_t mask = -(crc & 1u);
                crc = (crc >> 1) ^ (0xEDB88320 & mask);
            }
        }
        return ~crc;
    }

    static void add_attr(std::vector<uint8_t> &buf, uint16_t type,
                         std::span<const uint8_t> data) {
        uint16_t len = (uint16_t)data.size();
        uint16_t t_be = htons(type);
        uint16_t l_be = htons(len);
        buf.insert(buf.end(), reinterpret_cast<uint8_t *>(&t_be),
                   reinterpret_cast<uint8_t *>(&t_be) + 2);
        buf.insert(buf.end(), reinterpret_cast<uint8_t *>(&l_be),
                   reinterpret_cast<uint8_t *>(&l_be) + 2);
        buf.insert(buf.end(), data.begin(), data.end());
        // padding to 4 bytes
        size_t pad = (4 - (len % 4)) % 4;
        for (size_t i = 0; i < pad; ++i)
            buf.push_back(0);
    }

    static bool parse_attr(const uint8_t *buf, size_t len, uint16_t &typeOut,
                           std::span<const uint8_t> &dataOut, size_t &consumed) {
        if (len < 4)
            return false;
        typeOut = ntohs(*reinterpret_cast<const uint16_t *>(buf));
        uint16_t l = ntohs(*reinterpret_cast<const uint16_t *>(buf + 2));
        if (len < 4 + l)
            return false;
        dataOut = {buf + 4, l};
        consumed = 4 + ((l + 3) & ~3u);
        return true;
    }

    static void stun_set_length(std::vector<uint8_t> &buf) {
        uint16_t beLen = htons((uint16_t)(buf.size() - 20));
        std::memcpy(buf.data() + 2, &beLen, 2);
    }

    static void stun_add_fingerprint(std::vector<uint8_t> &buf) {
        stun_set_length(buf);
        uint32_t crc = crc32(buf.data(), buf.size());
        crc ^= 0x5354554E;
        uint32_t be = htonl(crc);
        add_attr(buf, 0x8028,
                 {reinterpret_cast<uint8_t *>(&be),
                  reinterpret_cast<uint8_t *>(&be) + 4});
        stun_set_length(buf);
    }

    static bool parse_xor_addr(std::span<const uint8_t> data,
                               const std::array<uint8_t, 12> &tid,
                               std::string &ip, uint16_t &port) {
        if (data.size() < 8)
            return false;
        uint8_t family = data[1];
        uint16_t p = ntohs(*reinterpret_cast<const uint16_t *>(data.data() + 2));
        uint32_t cookie = 0x2112A442;
        p ^= (uint16_t)(cookie >> 16);
        port = p;
        if (family == 0x01 && data.size() >= 8) {
            uint32_t addr =
                ntohl(*reinterpret_cast<const uint32_t *>(data.data() + 4));
            addr ^= cookie;
            in_addr ina{};
            ina.s_addr = htonl(addr);
            char buf[32];
            if (!inet_ntop(AF_INET, &ina, buf, sizeof(buf)))
                return false;
            ip = buf;
            return true;
        }
        if (family == 0x02 && data.size() >= 20) {
            std::array<uint8_t, 16> v6{};
            std::memcpy(v6.data(), data.data() + 4, 16);
            for (int i = 0; i < 4; ++i)
                v6[i] ^= (uint8_t)((cookie >> (24 - i * 8)) & 0xFF);
            for (int i = 0; i < 12; ++i)
                v6[4 + i] ^= tid[i];
            char buf[64];
            if (!inet_ntop(AF_INET6, v6.data(), buf, sizeof(buf)))
                return false;
            ip = buf;
            return true;
        }
        return false;
    }

    bool probeTurnOnce(std::string &relayInfoOut) {
        relayInfoOut.clear();
        if (turnUser.empty() || turnPassword.empty()) {
            lastError = "TURN user/password are empty";
            return false;
        }
        nice_debug_enable(TRUE);
        GMainContext *ctx = g_main_context_new();
        if (!ctx) {
            lastError = "g_main_context_new failed";
            return false;
        }
        g_main_context_push_thread_default(ctx);

        NiceAgent *agent = nice_agent_new(ctx, NICE_COMPATIBILITY_RFC5245);
        if (!agent) {
            g_main_context_pop_thread_default(ctx);
            g_main_context_unref(ctx);
            lastError = "nice_agent_new failed";
            return false;
        }

        // только UDP, без ICE-TCP/IPv6 — полагаемся на add_local_address(127.0.0.1)
        g_object_set(G_OBJECT(agent), "ice-tcp", FALSE, nullptr);
        g_object_set(G_OBJECT(agent), "upnp", FALSE, nullptr);
        // full-mode конструкторный — не трогаем, оставляем по умолчанию

        g_object_set(G_OBJECT(agent), "stun-server", stunServer.c_str(),
                     "stun-server-port", (guint)stunPort, nullptr);

        // Явно добавляем loopback-адрес, иначе libnice его игнорирует и STUN на
        // 127.0.0.1 не работает
        NiceAddress lo{};
        nice_address_init(&lo);
        nice_address_set_from_string(&lo, "127.0.0.1");
        nice_agent_add_local_address(agent, &lo);

        guint stream = nice_agent_add_stream(agent, 1);
        if (stream == 0) {
            g_object_unref(agent);
            g_main_context_pop_thread_default(ctx);
            g_main_context_unref(ctx);
            lastError = "nice_agent_add_stream failed";
            return false;
        }

        gboolean ok = nice_agent_set_relay_info(
            agent, stream, 1, stunServer.c_str(), stunPort, turnUser.c_str(),
            turnPassword.c_str(), NICE_RELAY_TYPE_TURN_UDP);
        if (!ok) {
            g_object_unref(agent);
            g_main_context_pop_thread_default(ctx);
            g_main_context_unref(ctx);
            lastError = "nice_agent_set_relay_info failed";
            return false;
        }

        TurnProbeState state;
        state.loop = g_main_loop_new(ctx, FALSE);
        g_signal_connect(agent, "new-candidate-full",
                         G_CALLBACK(on_new_candidate_cb), &state);
        g_signal_connect(agent, "candidate-gathering-done",
                         G_CALLBACK(on_candidates_gathered_cb), &state);

        if (!nice_agent_gather_candidates(agent, stream)) {
            g_object_unref(agent);
            g_main_context_pop_thread_default(ctx);
            g_main_context_unref(ctx);
            lastError = "nice_agent_gather_candidates failed";
            return false;
        }

        auto timeout_cb = [](gpointer data) -> gboolean {
            auto *st = static_cast<TurnProbeState *>(data);
            st->timedOut.store(true, std::memory_order_relaxed);
            if (st->loop)
                g_main_loop_quit(st->loop);
            return G_SOURCE_REMOVE;
        };
        GSource *timeoutSource = g_timeout_source_new(4000);
        g_source_set_callback(timeoutSource, timeout_cb, &state, nullptr);
        g_source_attach(timeoutSource, ctx);
        state.timeout = timeoutSource;

        g_main_loop_run(state.loop);

        bool success = state.done.load(std::memory_order_relaxed);
        bool timedOut = state.timedOut.load(std::memory_order_relaxed);
        bool haveRelay = false;
        std::stringstream relay;
        if (success) {
            GSList *cands = nice_agent_get_local_candidates(agent, stream, 1);
            for (GSList *l = cands; l != nullptr; l = l->next) {
                NiceCandidate *c = static_cast<NiceCandidate *>(l->data);
                char ip[64] = {0};
                nice_address_to_string(&c->addr, ip);
                if (c->type == NICE_CANDIDATE_TYPE_RELAYED) {
                    relay << ip << ":" << nice_address_get_port(&c->addr);
                    haveRelay = true;
                }
                nice_candidate_free(c);
            }
            g_slist_free(cands);
        }

        g_object_unref(agent);
        if (state.loop)
            g_main_loop_unref(state.loop);
        if (state.timeout) {
            g_source_destroy(state.timeout);
            g_source_unref(state.timeout);
        }
        g_main_context_pop_thread_default(ctx);
        g_main_context_unref(ctx);

        if (!success) {
            lastError = timedOut ? "TURN/STUN gather timed out"
                                 : "TURN/STUN gather failed";
            return false;
        }
        if (!haveRelay) {
            lastError = "TURN relay not allocated (check credentials)";
            return false;
        }
        relayInfoOut = relay.str();
        return true;
    }

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

        // Стартуем девайс один раз здесь
        if (ma_device_start(&dev) != MA_SUCCESS) {
            lastError = "ma_device_start failed in open()";
            ma_device_uninit(&dev);
            ma_context_uninit(&ctx);
            destroyOpus();
            return false;
        }

        running.store(true);
        capturing.store(false);
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

// Вычисление Фурье
// TODO: Использовать!
void ComputeDFT(const std::array<float, 512> &buf, std::array<float, 32> &out) {
    int N = buf.size();
    int K = out.size();

    for (int k = 0; k < K; ++k) {
        float re = 0, im = 0;
        for (int n = 0; n < N; ++n) {
            float angle = 2.0f * 3.1415926f * k * n / N;
            re += buf[n] * cosf(angle);
            im -= buf[n] * sinf(angle);
        }
        out[k] = sqrtf(re * re + im * im) / N;
    }
}

// Визуализация спектра голоса собеседника
// TODO: Использовать!
void DrawSpectrum(const std::array<float, 32> &s) {
    float w = ImGui::GetContentRegionAvail().x;
    float barW = w / s.size();

    float h = 80.0f;
    ImVec2 base = ImGui::GetCursorScreenPos();

    ImDrawList *dl = ImGui::GetWindowDrawList();

    for (int i = 0; i < s.size(); ++i) {
        float lvl = std::min(1.0f, s[i] * 8.0f);
        float barH = lvl * h;

        ImVec2 p1 = ImVec2(base.x + barW * i, base.y + h - barH);
        ImVec2 p2 = ImVec2(base.x + barW * (i + 1) - 2, base.y + h);

        ImU32 col = IM_COL32(80, 180, 255, 255);
        dl->AddRectFilled(p1, p2, col);
    }

    ImGui::Dummy(ImVec2(0, h));
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

std::string GetFileContent(const std::string &execPath,
                           const std::string &relativeFilePath) {
    std::string executablePath{execPath};
    executablePath = executablePath.erase(execPath.find_last_of('/'));
    const std::string kFilePath = executablePath + '/' + relativeFilePath;

    std::ifstream fs{kFilePath, std::ios::in};
    if (not fs.is_open()) {
        return {""};
    }

    const std::streamsize kFileSize = std::filesystem::file_size(kFilePath);
    std::string content(kFileSize, '\0');
    fs.read(content.data(), kFileSize);
    return content;
}

void DrawVoiceOrb(const std::string &execPath, float level) {
    // Ленивое создание шейдера и геометрии
    static bool initialized = false;
    static GLuint prog = 0;
    static GLint levelLoc = -1;
    static GLint timeLoc = -1;
    static GLuint vao = 0;
    static GLuint vbo = 0;

    const static std::string kOrbVertCode =
        GetFileContent(execPath, "shaders/voice_vis_shader.vert");
    const static std::string kOrbFragCode =
        GetFileContent(execPath, "shaders/voice_vis_shader.frag");

    if (!initialized) {
        prog = CreateProgram(kOrbVertCode.data(), kOrbFragCode.data());
        levelLoc = glGetUniformLocation(prog, "level");
        timeLoc = glGetUniformLocation(prog, "time");

        float quadVerts[] = {-1.f, -1.f, 1.f, -1.f, 1.f,  1.f,

                             -1.f, -1.f, 1.f, 1.f,  -1.f, 1.f};

        glGenVertexArrays(1, &vao);
        glGenBuffers(1, &vbo);

        glBindVertexArray(vao);
        glBindBuffer(GL_ARRAY_BUFFER, vbo);
        glBufferData(GL_ARRAY_BUFFER, sizeof(quadVerts), quadVerts,
                     GL_STATIC_DRAW);
        glEnableVertexAttribArray(0);
        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 2 * sizeof(float),
                              (void *)0);
        glBindVertexArray(0);

        initialized = true;
    }

    // Размер орба в окне (можно подогнать)
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float size = std::min(avail.x, 300.0f);
    ImVec2 widgetSize(size, size);

    // Позиция верхнего левого угла виджета в координатах фреймбуфера ImGui
    ImVec2 pos = ImGui::GetCursorScreenPos();

    // Резервируем место под орб
    ImGui::InvisibleButton("##voice_orb", widgetSize);

    ImDrawList *dl = ImGui::GetWindowDrawList();

    // Нам нужен прямоугольник орба и высота фреймбуфера,
    // чтобы правильно выставить glViewport/glScissor
    ImVec2 min = pos;
    ImVec2 max = ImVec2(pos.x + widgetSize.x, pos.y + widgetSize.y);
    float fbHeight = ImGui::GetIO().DisplaySize.y;

    struct OrbCtx {
        GLuint prog;
        GLint levelLoc;
        GLint timeLoc;
        GLuint vao;
        float level;
        float time;
        ImVec2 min;
        ImVec2 max;
        float fbHeight;
    };

    static size_t startMsec = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    auto *ctx = new OrbCtx{
        .prog = prog,
        .levelLoc = levelLoc,
        .timeLoc = timeLoc,
        .vao = vao,
        .level = std::clamp(level, 0.0f, 1.0f),
        .time = static_cast<float>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - startMsec) / 1000,
        .min = min,
        .max = max,
        .fbHeight = fbHeight};

    dl->AddCallback(
        [](const ImDrawList *, const ImDrawCmd *cmd) {
            auto *c = static_cast<OrbCtx *>(cmd->UserCallbackData);

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

// ---------- main ----------

int main(int argc, char *argv[]) {
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

    std::filesystem::path exePath = std::filesystem::absolute(argv[0]);
    app.execDir = exePath.parent_path().string();
    // secrets/users.txt больше не используем; логины/пароли проверяются на signalling/TURN

    bool quit = false;
    bool showDemo = false;

    static char loginUser[64] = "";
    static char loginPass[64] = "";
    static char remoteUserBuf[64] = "";
    static char turnHostBuf[128] = "";
    static bool cfgInit = false;
    int stunPortUI = (int)app.stunPort;
    if (!cfgInit) {
        std::snprintf(turnHostBuf, sizeof(turnHostBuf), "%s",
                      app.stunServer.c_str());
        cfgInit = true;
    }

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

        ImGui::Text("Auth & Signalling");

        if (!app.authenticated) {
            ImGui::InputText("Username", loginUser, sizeof(loginUser));
            ImGui::InputText("Password", loginPass, sizeof(loginPass),
                             ImGuiInputTextFlags_Password);
            if (ImGui::Button("Login")) {
                std::string u = trim(loginUser);
                std::string p = std::string(loginPass);
                app.loginWithSignalling(u, p);
            }
            if (!app.authError.empty()) {
                ImGui::TextColored(ImVec4(1, 0.3f, 0.3f, 1),
                                   "Auth error: %s", app.authError.c_str());
            }
        } else {
            ImGui::Text("Logged in as %s", app.authUser.c_str());
            ImGui::SameLine();
            if (ImGui::Button("Logout")) {
                app.stopNetwork();
                app.remoteUser.clear();
                app.authenticated = false;
                app.authUser.clear();
                app.turnUser.clear();
                app.turnPassword.clear();
            }
            ImGui::Text("Bind IP/port: %s:%u", app.localBindIp.c_str(),
                        (unsigned)app.localPortOverride);
        }

        ImGui::Separator();
        ImGui::Text("TURN/STUN server");

        if (ImGui::InputText("STUN/TURN host", turnHostBuf,
                             sizeof(turnHostBuf))) {
            app.stunServer = turnHostBuf;
        }
        if (ImGui::InputInt("STUN/TURN port", &stunPortUI)) {
            if (stunPortUI < 1)
                stunPortUI = 1;
            if (stunPortUI > 65535)
                stunPortUI = 65535;
            app.stunPort = (uint16_t)stunPortUI;
        }
        ImGui::Checkbox("Use only TURN (no host/STUN fallback)",
                        &app.forceTurnOnly);

        ImGui::Separator();
        ImGui::Text("Signalling server (register & fetch peer address)");
        static char sigUrlBuf[256] = "http://127.0.0.1:7777";
        ImGui::InputText("Signalling URL", sigUrlBuf, sizeof(sigUrlBuf));
        app.sigServer = sigUrlBuf;
        if (!app.sigStatus.empty()) {
            ImGui::Text("Signalling: %s", app.sigStatus.c_str());
        }

        ImGui::Separator();
        ImGui::Text("Call (remote username)");
        ImGui::InputText("Remote username", remoteUserBuf,
                         sizeof(remoteUserBuf));

        if (!app.netRunning.load()) {
            if (ImGui::Button("Call user")) {
                std::string remoteName = trim(remoteUserBuf);
                std::string rip;
                uint16_t rport = 0;
                if (remoteName.empty()) {
                    app.lastError = "Remote username is empty";
                } else if (!app.authenticated) {
                    app.lastError = "Login first";
                } else {
                    bool gotPeer = false;
                    if (!app.signallingRegisterSelf()) {
                        app.lastError = app.sigStatus;
                    } else if (app.signallingQueryPeer(remoteName, rip, rport)) {
                        gotPeer = true;
                        app.lastError.clear();
                    } else {
                        app.lastError = "Peer address not found (signalling)";
                    }

                    if (gotPeer) {
                        if (!app.startNetwork(app.localBindIp,
                                              app.localPortOverride, rip,
                                              rport)) {
                            app.lastError = "Network start failed";
                        } else {
                            app.remoteUser = remoteName;
                            app.lastError.clear();
                        }
                    }
                }
            }
        } else {
            if (ImGui::Button("Hang up")) {
                app.stopNetwork();
                app.remoteUser.clear();
            }
        }

        ImGui::Text("Device:   %s", app.running.load() ? "open" : "closed");
        ImGui::Text("Capture:  %s", app.capturing.load() ? "on" : "off");
        ImGui::Text("Network:  %s", app.netRunning.load() ? "on" : "off");
        if (!app.remoteUser.empty())
            ImGui::Text("Remote peer: %s", app.remoteUser.c_str());

        ImGui::Separator();
        ImGui::Text("Audio: %d Hz, %d ch, %d ms", app.cfg.sampleRate,
                    app.cfg.channels, app.cfg.frameMs);
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

        // Mic toggle
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

        ImGui::Text("Remote voice level:");
        float lvl = app.remoteLevel.load(std::memory_order_relaxed);
        lvl *= 0.9f; // затухание между кадрами
        app.remoteLevel.store(lvl, std::memory_order_relaxed);
        DrawVoiceLevel(lvl);

        ImGui::Text("Voice animation shader:");
        DrawVoiceOrb(std::string{argv[0]}, lvl);

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
