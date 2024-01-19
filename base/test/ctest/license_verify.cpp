#include <cstdlib>
#include <ctime>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <array>
#include "../../include/Dongle_API.h"
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#define MAX_OUTPUT_LEN 128
#define CHECK_LICENSE_SUCCESS 200

// Remove trailing spaces from a string
#include <cctype>

bool isSpaceOrNewline(char c) {
    return c == ' ' || c == '\n';
}

std::string rtrimSpaceAndNewline(std::string s) {
    while (!s.empty() && isSpaceOrNewline(s.back())) {
        s.pop_back();  // remove characters from the end
    }
    return s;
} 

// get command output
std::string commandOutput(const std::string& cmd) {
    std::array<char, MAX_OUTPUT_LEN> buffer;
    std::string result;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    try {
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            result += rtrimSpaceAndNewline(std::string(buffer.data()));
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);

    return result;
}

//检查license是否有效
std::array<unsigned char, 512> getEnv(){

    #define INOUT_BUF_LENGTH 1024
    int fileid = 0x0002;
    int ret =0;
    
    // fetch hardware information example
    std::string board_name = commandOutput("cat /sys/class/dmi/id/board_name");
    // log output
    //std::cout << "Board name: " << board_name << "\n";

    std::string board_serial = commandOutput("cat /sys/class/dmi/id/board_serial");
    //std::cout << "Board serial: " << board_serial << "\n";

    std::string board_vendor = commandOutput("cat /sys/class/dmi/id/board_vendor");
    //std::cout << "Board vendor: " << board_vendor << "\n";

    std::string product_name = commandOutput("cat /sys/class/dmi/id/product_name");
    //std::cout << "Product name: " << product_name << "\n";

    std::string product_version = commandOutput("cat /sys/class/dmi/id/product_version");
    //std::cout << "Product version: " << product_version << "\n";

    std::string product_serial = commandOutput("cat /sys/class/dmi/id/product_serial");
    //std::cout << "Product serial: " << product_serial << "\n";

    std::string product_uuid = commandOutput("cat /sys/class/dmi/id/product_uuid");
    //std::cout << "Product uuid: " << product_uuid << "\n";

    std::array<char,INOUT_BUF_LENGTH> InOutBuf;
    std::snprintf(InOutBuf.data(), InOutBuf.size(), "board_name:%s,board_serial:%s,board_vendor:%s,product_name:%s,product_version:%s,product_serial:%s,product_uuid:%s", board_name.c_str(), board_serial.c_str(), board_vendor.c_str(), product_name.c_str(), product_version.c_str(), product_serial.c_str(), product_uuid.c_str());
    //Inoutbuf转换为数组
    std::array<unsigned char, 512> str;
    for(std ::size_t i =0; i<str.size();i++) {
        str[i] = static_cast<unsigned char>(InOutBuf[i]);
    }
    return str;
	
}

std::string base64Decode(const std::string& data) {
    BIO* bio, * b64;

    int decodeLength = data.size();
    std::vector<char> buffer(decodeLength);

    bio = BIO_new_mem_buf(data.c_str(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer
    decodeLength = BIO_read(bio, buffer.data(), data.size());

    BIO_free_all(bio);
    
    return std::string(buffer.data(), decodeLength);
}


RSA* loadPublicKey() {
    std::string publicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
                               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1HwENS507VpuXLfan7wJ\n"
"tOE5YtpvzuaBr6W+QrH3eLlA+zpds4PENqJkya75ESs0SJqJPqZWufTphibZ+l8y\n"
"LpMjOZdtQDoWQ+fW0/CVpGgTBbPF0moL+9FxwOJK8N6aAJrcGlpKV6968JOAS0n6\n"
"XxEoThnywy2EF/GhEPAS55Gm/OmIM/GzqrtPkVVr2sUNV79dwxFBHAynDWfxHlJk\n"
"6ONKPV9wETVITSNF6E1VISWu/kDyvNcRp5h32BQzE6QDocUssbF6X+DcM0wp5Isz\n"
"1iV5m/ngF/C8m9fb7L6BStfYghSB4eOdUhAilReR69datl5NWDqj+ZRrK1m5fnXh\n"
"gwIDAQAB\n"
                               "-----END PUBLIC KEY-----\n";                           
    BIO* bio = BIO_new_mem_buf(publicKeyPem.c_str(), -1);
    if (bio == nullptr) {
        throw std::runtime_error("fail to create bio for publicKey");
    }

    RSA* rsa_public_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (rsa_public_key == nullptr) {
        BIO_free_all(bio);
        throw std::runtime_error("fail to load publicKey");
    }

    BIO_free_all(bio);
    return rsa_public_key;
}


bool rsaVerify(const std::string& data, const std::vector<unsigned char>& signature, RSA* public_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if(!SHA256((unsigned char*)data.c_str(), data.size(), hash)) {
        throw std::runtime_error("fail to compute SHA-256 hash");
    }

    // Verify the signature
    if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), signature.size(), public_key) != 1) {
        char* err = ERR_error_string(ERR_get_error(), NULL);
        std::cout << "OpenSSL Error: " << err << std::endl;
        return false;
    }
    return true;
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    if(!ctx) {
        throw std::runtime_error("fail to create EVP_CIPHER_CTX");
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        throw std::runtime_error("fail to initialize decryption");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;

    if(EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        throw std::runtime_error("fail to decrypt data");
    }

    int plaintext_len = len;

    if(EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        char *err = ERR_error_string(ERR_get_error(), NULL);
        //std::cout << "OpenSSL Decrypt Error: " << err << std::endl;
        throw std::runtime_error(err);
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return std::string((char*)plaintext.data(), plaintext_len);
}

int main(int argc, char *argv[]){
    //check license 
    // std::ifstream license_file(std::filesystem::path("./") / "license.txt");
    std::string filepath ="./license.txt";
    std::ifstream license_file(filepath);
    if (!license_file.is_open()){
        throw std::runtime_error("license file not exist!");
    }
    std::ostringstream license_stream;
    license_stream << license_file.rdbuf();
    std::string license = license_stream.str();
    std::string license_decode = base64Decode(license);
    //std::cout << "license_decode: " << license_decode << std::endl;

    //aes解密
    std::string key_hex = "d37dffe9718aa504f3624518628b3156b88e8ac8552b4a892ac02cfd93b40c16";
    std::string iv_hex = "20b2af9f545582950f267dec8596d190";
    std::vector<unsigned char> key = hexToBytes(key_hex);
    std::vector<unsigned char> iv = hexToBytes(iv_hex);
    std::vector<unsigned char> ciphertext = hexToBytes(license_decode);
    std::string license_data = aesDecrypt(ciphertext, key, iv);
    //std::cout << "license_data: " << license_data << std::endl;
    license_decode = license_data;

    //根据两个;分成三段;data;signature;data为license_env和license_endtime的组合
    std::string data = license_decode.substr(0, license_decode.find_last_of(';'));
    std::string license_env = license_decode.substr(0, license_decode.find(';'));
    std::string license_endtime = license_decode.substr(license_decode.find(';')+1, license_decode.find_last_of(';')-license_decode.find(';')-1);
    std::string license_signature = license_decode.substr(license_decode.find_last_of(';')+1, license_decode.size()-license_decode.find_last_of(';')-1);
    // std::cout << "data: " << data << std::endl;
    // std::cout << "license_env: " << license_env << std::endl;
    // std::cout << "license_endtime: " << license_endtime << std::endl;
    // std::cout << "license_signature: " << license_signature << std::endl;

    //判断license signature是否正确
    RSA* public_key = loadPublicKey();
    std::vector<unsigned char> signature = hexToBytes(license_signature);
    std::cout << "Signature length: " << signature.size() << std::endl;
    if (!rsaVerify(data, signature, public_key)) {
        throw std::runtime_error("fail to verify signature");
    }

    //判断license是否过期,时间戳进行比较
    time_t now = time(0);
    tm *ltm = localtime(&now);
    //std::cout << "now: " << now << std::endl;
    if (now > std::stoi(license_endtime)){
        throw std::runtime_error("license is expired!");
    }

    //判断license_env是否正确
    std::array<unsigned char, 512> licenseEnv = getEnv();
    std::string info = std::string((char*)licenseEnv.data(), licenseEnv.size());
    info = info.substr(0, info.find('\0'));
    // std::cout << "license is: " << license << "\n";
    std::cout << "info is: " << info << "\n";
    if (license_env != info) {
        throw std::runtime_error("license file is invalid!");
    } 
    std::cout << "license is valid!\n";
    return 0;

}