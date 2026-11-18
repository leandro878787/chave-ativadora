// license.h - verificacao de licenca offline (Ed25519 via libsodium)
// Windows / FFGL DLL. Header-only: inclua em UM .cpp do plugin.
//
// O cliente cria um arquivo license.txt com 2 linhas:
//   linha 1: e-mail usado na compra
//   linha 2: chave de ativacao
// Locais procurados (nesta ordem):
//   1) mesma pasta da DLL
//   2) %APPDATA%\MeuPlugin\license.txt
#pragma once

#include <windows.h>
#include <shlobj.h>
#include <sodium.h>
#include <fstream>
#include <string>
#include <algorithm>
#include <cctype>

namespace lic {

// Deve ser igual ao PRODUCT do keygen.py
static const char* PRODUCT = "MEUPLUGIN";

// Cole aqui a saida de: python keygen.py gen
static const unsigned char PUBKEY[crypto_sign_PUBLICKEYBYTES] =
    { 0 /* SUBSTITUA pelos 32 bytes da chave publica */ };

inline std::string dllFolder() {
    HMODULE hm = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&dllFolder, &hm);
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(hm, path, MAX_PATH);
    std::string p(path);
    size_t pos = p.find_last_of("\\/");
    return pos == std::string::npos ? "" : p.substr(0, pos + 1);
}

inline std::string appDataFolder() {
    char path[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path)))
        return std::string(path) + "\\MeuPlugin\\";
    return "";
}

inline std::string trim(std::string s) {
    auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

inline bool readLicense(const std::string& file, std::string& email, std::string& key) {
    std::ifstream f(file);
    if (!f) return false;
    std::getline(f, email);
    std::getline(f, key);
    email = trim(email);
    key = trim(key);
    return !email.empty() && !key.empty();
}

inline bool verify(std::string email, const std::string& key) {
    if (sodium_init() < 0) return false;
    std::transform(email.begin(), email.end(), email.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });

    unsigned char sig[crypto_sign_BYTES];
    size_t sigLen = 0;
    if (sodium_base642bin(sig, sizeof sig, key.c_str(), key.size(), nullptr,
                          &sigLen, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        return false;
    if (sigLen != crypto_sign_BYTES) return false;

    std::string msg = std::string(PRODUCT) + "|" + email;
    return crypto_sign_verify_detached(sig, (const unsigned char*)msg.data(),
                                       msg.size(), PUBKEY) == 0;
}

// Chame quando quiser; o resultado fica em cache.
inline bool isLicensed() {
    static int cached = -1;
    if (cached != -1) return cached == 1;

    std::string email, key;
    bool ok = false;
    const std::string dirs[] = { dllFolder(), appDataFolder() };
    for (const auto& d : dirs) {
        if (!d.empty() && readLicense(d + "license.txt", email, key)) {
            ok = verify(email, key);
            if (ok) break;
        }
    }
    cached = ok ? 1 : 0;
    return ok;
}

} // namespace lic

/* ---- Exemplo de uso no plugin FFGL ----

#include "license.h"

FFResult MeuPlugin::ProcessOpenGL(ProcessOpenGLStruct* pGL) {
    // ... desenha o efeito normalmente ...

    if (!lic::isLicensed()) {
        // Modo demo: escolha UMA estrategia
        //  - desenhar uma marca d'agua / texto "DEMO" por cima
        //  - misturar o resultado com preto a cada N segundos
        //  - simplesmente repassar a imagem original sem efeito
    }
    return FF_SUCCESS;
}
*/
