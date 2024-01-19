#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

std::string vectorToHexString(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (char c : data) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (static_cast<int>(c) & 0xFF);
    }
    return oss.str();
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

std::string caculateSHA256(std::string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::string sha256_hash;
    char hex[3];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        snprintf(hex, sizeof(hex), "%02x", hash[i]);
        sha256_hash += hex;
    }

    return sha256_hash;
}

std::vector<unsigned char> rsaSign(const std::string& data, RSA* private_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if(!SHA256((unsigned char*)data.c_str(), data.size(), hash)) {
        throw std::runtime_error("fail to compute SHA-256 hash");
    }

    std::vector<unsigned char> signature(RSA_size(private_key));
    unsigned int signature_length;

    if(!RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &signature_length, private_key)) {
        throw std::runtime_error("fail to sign");
    }
    std::cout << "Signature length: " << signature_length << std::endl;

    signature.resize(signature_length); // Resize to the actual signature length
    std::cout << "Signature length: " << signature.size() << std::endl;
    return signature;
}

RSA* loadPrivateKey()
{
    FILE* file = fopen("./privateKey.pem", "rb");
    if(file == nullptr)
        throw std::runtime_error("fail open privateKey");
    RSA* rsa_private_key = PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr);
    if (rsa_private_key == nullptr) {
        throw std::runtime_error("fail to load privateKey");
    }
    fclose(file);
    return rsa_private_key;
}

std::vector<unsigned char> aesEncrypt(const std::string& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    if(!ctx) {
        throw std::runtime_error("fail to create EVP_CIPHER_CTX");
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        throw std::runtime_error("fail to initialize encryption");
    }

    std::vector<unsigned char> ciphertext(data.size() + AES_BLOCK_SIZE);
    int len;

    if(EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)data.c_str(), data.size()) != 1) {
        throw std::runtime_error("fail to encrypt data");
    }

    int ciphertext_len = len;

    if(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        throw std::runtime_error("fail to finalize encryption");
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}


std::string base64Encode(const std::string& data) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newline
    BIO_write(bio, data.c_str(), data.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encodedData(bufferPtr->data, bufferPtr->length);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    return encodedData;
}

int main(int argc, char* argv[])
{
    std::string filePath = "./license_env.txt";
    std::ifstream license_env(filePath);
    if (!license_env.is_open()){
        throw std::runtime_error("license_env.txt is not exist!");
    }
    std::ostringstream buf;
    buf << license_env.rdbuf();
    std::string license_envstr = buf.str();
    license_envstr = license_envstr.substr(0, license_envstr.find_last_of('\\'));
    std::cout << "license_envstr: " << license_envstr << std::endl;
    //从终端输入天数，这里存储为license_days,默认为365天
    std::cout << "please input license_days: ";
    int license_days = 365;
    std::cin >> license_days;
    std::string license_days_str = std::to_string(license_days);
    //获取当前时间+天数得到过期时间
    time_t now = time(0);
    tm* ltm = localtime(&now);
    ltm->tm_mday += license_days;
    time_t end_time_t = mktime(ltm);
   //截止时间转换为时间戳字符串
    std::stringstream ss;
    ss << end_time_t;
    std::string end_time_str = ss.str();
    std::cout << "end_time_str: " << end_time_str << std::endl;
    //将license_env和end_time_str拼接，得到license_str
    std::string license_str = license_envstr + ";" + end_time_str;
    std::cout << "license_str: " << license_str << std::endl;

    //获取私钥,计算签名
    RSA* pricateKey = loadPrivateKey();
    std::vector<unsigned char> signature = rsaSign(license_str,pricateKey);
    std::string signature_str = vectorToHexString(signature);
    std::cout << "signature_str: " << signature_str << std::endl;

    //将license_str和signature_str拼接,";"分割，得到license，写入license.txt
    std::string license = license_str + ";" + signature_str;
    std::cout << "license: " << license << std::endl;

    //aes加密
    std::string key_hex = "d37dffe9718aa504f3624518628b3156b88e8ac8552b4a892ac02cfd93b40c16";
    std::string iv_hex = "20b2af9f545582950f267dec8596d190";
    std::vector<unsigned char> key = hexToBytes(key_hex);
    std::vector<unsigned char> iv = hexToBytes(iv_hex);
    std::vector<unsigned char> ciphertext = aesEncrypt(license, key, iv);
    std::string ciphertext_str = vectorToHexString(ciphertext);
    std::cout << "ciphertext_str: " << ciphertext_str << std::endl;
    //base64编码
     std::string encodedLicense = base64Encode(ciphertext_str);
    std::ofstream license_file("./license.txt");
    license_file << encodedLicense;
    license_file.close();

    return 0;
}