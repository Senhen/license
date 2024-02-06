
#include <torch/extension.h>
#include <filesystem>
#include <string>
#include <type_traits>
#include "chacha20.hpp"
#include "obfuscate.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
//#include "../../include/Dongle_API.h"
#include <unistd.h> 
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define MAX_OUTPUT_LEN 128

namespace glm
{
    constexpr int num_layers = 28;
    thread_local int num_heads;
    thread_local int hidden_size;
    thread_local int head_size;
    thread_local int multi_query_group_num;
    thread_local float softmax_scale;
    thread_local bool multi_query_attention;
    thread_local int num_key_value_heads;
    thread_local bool kv_cache_quantize;
    thread_local bool linear_quantize;
    thread_local float layernorm_epsilon;
    thread_local int word_embedding_min_id;
    thread_local int word_embedding_max_id;
    thread_local int word_embedding_null_id;
    thread_local torch::Tensor word_embedding_weight;
    thread_local torch::Tensor input_layer_norm_weights[28];
    thread_local torch::Tensor query_key_value_weights[28];
    thread_local c10::optional<torch::Tensor> query_key_value_weight_scales[28];
    thread_local c10::optional<torch::Tensor> query_key_value_biases[28];
    thread_local torch::Tensor cos_sin_caches[28];
    thread_local torch::Tensor o_proj_weights[28];
    thread_local c10::optional<torch::Tensor> o_proj_weight_scales[28];
    thread_local c10::optional<torch::Tensor> o_proj_biases[28];
    thread_local torch::Tensor kv_head_mappings[28];
    thread_local torch::Tensor output_layer_norm_weights[28];
    thread_local torch::Tensor gate_up_weights[28];
    thread_local c10::optional<torch::Tensor> gate_up_weight_scales[28];
    thread_local c10::optional<torch::Tensor> gate_up_biases[28];
    thread_local torch::Tensor gate_down_weights[28];
    thread_local c10::optional<torch::Tensor> gate_down_weight_scales[28];
    thread_local c10::optional<torch::Tensor> gate_down_biases[28];
    thread_local torch::Tensor final_layernorm_weight;

    // Remove trailing spaces from a string
    __attribute__((always_inline)) inline bool isSpaceOrNewline(char c) {
        return c == ' ' || c == '\n';
    }

    __attribute__((always_inline)) inline std::string rtrimSpaceAndNewline(std::string s) {
    while (!s.empty() && isSpaceOrNewline(s.back())) {
            s.pop_back();  // remove characters from the end
        }
        return s;
    } 

    //get command output
    __attribute__((always_inline)) inline std::string commandOutput(const std::string& cmd) {
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

    //get hardware information
    __attribute__((always_inline)) inline std::array<unsigned char, 512> getEnv(){

        #define INOUT_BUF_LENGTH 1024
        int fileid = 0x0002;
        int ret =0;
        
        // fetch hardware information example
        std::string board_name = commandOutput("cat /sys/class/dmi/id/board_name");

        std::string board_serial = commandOutput("cat /sys/class/dmi/id/board_serial");

        std::string board_vendor = commandOutput("cat /sys/class/dmi/id/board_vendor");

        std::string product_name = commandOutput("cat /sys/class/dmi/id/product_name");

        std::string product_version = commandOutput("cat /sys/class/dmi/id/product_version");

        std::string product_serial = commandOutput("cat /sys/class/dmi/id/product_serial");

        std::string product_uuid = commandOutput("cat /sys/class/dmi/id/product_uuid");

        std::array<char,INOUT_BUF_LENGTH> InOutBuf;
        std::snprintf(InOutBuf.data(), InOutBuf.size(), "board_name:%s,board_serial:%s,board_vendor:%s,product_name:%s,product_version:%s,product_serial:%s,product_uuid:%s", board_name.c_str(), board_serial.c_str(), board_vendor.c_str(), product_name.c_str(), product_version.c_str(), product_serial.c_str(), product_uuid.c_str());
        //Inoutbuf转换为数组
        std::array<unsigned char, 512> info;
        for(std ::size_t i =0; i<info.size();i++) {
            info[i] = static_cast<unsigned char>(InOutBuf[i]);
        }
        return info;	
    }

    __attribute__((always_inline)) inline std::string base64Decode(const std::string& data) {
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

    __attribute__((always_inline)) inline RSA* loadPublicKey() {
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

    __attribute__((always_inline)) inline bool rsaVerify(const std::string& data, const std::vector<unsigned char>& signature, RSA* public_key) {
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

    __attribute__((always_inline)) inline std::vector<unsigned char> hexToBytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }

        return bytes;
    }

    __attribute__((always_inline)) inline std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
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


    std::tuple<int, int, int, bool> LoadGLM2Model(const std::string &path, int rank, c10::Device device)
    {
        //add license check logic
        //std::string filepath ="./license.txt";
        std::ifstream license_file(std::filesystem::path(path) / "license.txt");
        if (!license_file.is_open()){
            throw std::runtime_error("license file not exist!");
        }
        std::ostringstream license_stream;
        license_stream << license_file.rdbuf();
        std::string license = license_stream.str();
        std::string license_decode = base64Decode(license);

        //aes decrypt
        std::string key_hex = "d37dffe9718aa504f3624518628b3156b88e8ac8552b4a892ac02cfd93b40c16";
        std::string iv_hex = "20b2af9f545582950f267dec8596d190";
        std::vector<unsigned char> key = hexToBytes(key_hex);
        std::vector<unsigned char> iv = hexToBytes(iv_hex);
        std::vector<unsigned char> ciphertext = hexToBytes(license_decode);
        std::string license_data = aesDecrypt(ciphertext, key, iv);
        //std::cout << "license_data: " << license_data << std::endl;
        license_decode = license_data;

        std::string data = license_decode.substr(0, license_decode.find_last_of('.'));
        std::string license_env = license_decode.substr(0, license_decode.find('.'));
        std::string license_endtime = license_decode.substr(license_decode.find('.')+1, license_decode.find_last_of('.')-license_decode.find('.')-1);
        std::string license_signature = license_decode.substr(license_decode.find_last_of('.')+1, license_decode.size()-license_decode.find_last_of('.')-1);

        //check license signature
        RSA* public_key = loadPublicKey();
        std::vector<unsigned char> signature = hexToBytes(license_signature);
        std::cout << "Signature length: " << signature.size() << std::endl;
        if (!rsaVerify(data, signature, public_key)) {
            throw std::runtime_error("fail to verify signature");
        }

        //check license_endtime
        time_t now = time(0);
        tm *ltm = localtime(&now);
        //std::cout << "now: " << now << std::endl;
        if (now > std::stoi(license_endtime)){
            throw std::runtime_error("license is expired!");
        }

        //check license_env
        if (license_env == "anymachine") {
            std::cout << "license is valid!\n";
        }
        else {
            std::array<unsigned char, 512> licenseEnv = getEnv();
            std::string info = std::string((char*)licenseEnv.data(), licenseEnv.size());
            info = info.substr(0, info.find('\0'));
            // std::cout << "license is: " << license << "\n";
            std::string delimiter = ";";
            size_t pos = 0;
            std::string token;
            bool found = false;
            while ((pos = license_env.find(delimiter)) != std::string::npos) {
                token = license_env.substr(0, pos);
                //std::cout << token << std::endl;
            if (token == info) {
                found = true;
                break;
            }
            license_env.erase(0, pos + delimiter.length());
            }
            if (!found && license_env != info) {
                throw std::runtime_error("license file is invalid!");
            }
            std::cout << "license is valid!\n";
        }

        if (rank == 0)
        {       
            std::ifstream input(std::filesystem::path(path) / (std::string)AY_OBFUSCATE("56O6PJJBYL492HSGHRYLDFZQ7YC34N1X.data"), std::ios::binary);
            std::vector<char> bytes((std::istreambuf_iterator<char>(input)), (std::istreambuf_iterator<char>()));
            input.close();

            const char *key_nonce = AY_OBFUSCATE("\xb6\x6e\x67\x96\xc2\xe2\x79\xa1\xd9\x00\x35\xeb\x0d\x68\xee\x36\x48\x38\x00\x02\x0f\x8a\xf9\x61\x07\xd8\x87\x45\x61\xbd\xe0\xb1\x9a\x5b\x65\x36\xc3\xff\xfd\xf4");
            Chacha20 chacha20((uint8_t*)key_nonce, (uint8_t*)key_nonce + 32, 0);
            chacha20.crypt((uint8_t *)bytes.data(), bytes.size());

            c10::Dict<at::IValue, at::IValue> weights = torch::pickle_load(bytes).toGenericDict();
            bytes.clear();
        
            auto metadata_int = weights.at("OZ6W89V3SQFQV7JAAIYEPSVRCASQKFUL").toTensor();
            int num_layers = metadata_int[0].item<int>();
            num_heads = metadata_int[1].item<int>();
            head_size = metadata_int[2].item<int>();
            hidden_size = metadata_int[3].item<int>();
            multi_query_group_num = metadata_int[4].item<int>();
            word_embedding_min_id = metadata_int[5].item<int>();
            word_embedding_max_id = metadata_int[6].item<int>();
            word_embedding_null_id = metadata_int[7].item<int>();

            auto metadata_bool = weights.at("L5M6NCDHJFWSL40A0DDFNEXNQXHMTE5F").toTensor();
            multi_query_attention = metadata_bool[0].item<bool>();
            kv_cache_quantize = metadata_bool[1].item<bool>();
            linear_quantize = metadata_bool[2].item<bool>();

            auto metadata_float = weights.at("OZXMMM0PEZDXC48PH3HVWXNVDGDIOADG").toTensor();
            softmax_scale = metadata_float[0].item<float>();
            layernorm_epsilon = metadata_float[1].item<float>();

            if (multi_query_attention)
                num_key_value_heads = multi_query_group_num;
            else
                num_key_value_heads = num_heads;

            auto load_tensor = [&](const char* name, int id, auto *list_to_append) __attribute__((always_inline))
            {
                auto iter = weights.find(name);
                if (iter != weights.end())
                    list_to_append[id] = iter->value().toTensor().to(device);
                else if constexpr (std::is_same_v<std::remove_pointer_t<decltype(list_to_append)>, c10::optional<torch::Tensor>>)
                    list_to_append[id] = c10::nullopt;
            };
        
            load_tensor(AY_OBFUSCATE("69PRWDTOAF54KO6OH11BKNP4ENINS4AE"), 26, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("3YK7WSAGDTJTPEVHSUKJ6IQSDHUI659N"), 9, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("YZZPXFKFWNEFFWLDW65R35L9KC07R1K1"), 0, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("R4W8HHZQJKMMNK3IG7G3Q3Z8K38S1CYD"), 4, gate_up_weights);
            load_tensor(AY_OBFUSCATE("LG6X0Y2VERJMTQCXI75MSM4DMZH4ZCUJ"), 11, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("0ONJ4ZA13VBRBGG4QIU4JW9YB0KID0CF"), 2, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("O3JJTXONGQJFHPKOAUOKOHUHIXCMTMJ6"), 5, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("IIDNY90W3HH2HV37GOOQXM34I0V4MR7D"), 3, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("AQYF313UQQVE23HCRCT0VBHEDS2NZIWE"), 26, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("42FT2ARJ0X9K8M7Z6KAPN2EOOPDWOSKJ"), 13, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("A3VNCG8HOGMBCU2LVFD90S09C2LJ8CK9"), 12, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("6HHA13I5AZ5SS7YDRFWK5NC0MPPDT7ON"), 1, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("EDTRXEANQ19XEUPOOBXSUT8MZDQNNMM3"), 3, gate_down_biases);
            load_tensor(AY_OBFUSCATE("M61FUGO6FTUHA8IOWCBO2MJ3E1PBM05R"), 0, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("Q90PVVCB3V2ECM8J5LL5K6AP4KKCRHSG"), 8, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("6LQRCN15V5FZ3CUMPCDTKWSL8WOG0YMV"), 14, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("KDPB140JPKMJZWLCWLK3KYTQI2G9ANKU"), 12, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("Q4KG64WOHJ1TL5CTFAZRMJ7C4AC91PUK"), 15, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("P0D2IC6RO5GCJI1CHC5E7A5TP9QGYCVD"), 25, gate_down_biases);
            load_tensor(AY_OBFUSCATE("AO96K9AC2EAIZPNX5L6Y2HPHEP5RROIT"), 23, o_proj_biases);
            load_tensor(AY_OBFUSCATE("2YC335XRTXRXO2HPAMDHIMLI27P12MT7"), 22, o_proj_biases);
            load_tensor(AY_OBFUSCATE("CZK9HM4DGPZP6F2LX411VF0MRXPLI2MW"), 17, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("H1GFO862T5KRRESISJJ3UER32VLFFQMT"), 18, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("4662NU6O09C9GHZSHUBVH9PDSPGZU577"), 24, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("G4WU63KS7H6E56UQASKZ7FUO5NSTVX3F"), 18, gate_down_weights);
            load_tensor(AY_OBFUSCATE("65LRVDUA0WKQCLXBQFG2SIGG73LM46US"), 12, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("RM9FKJN1CCKX2I6U1283SY3Z30NSGY6N"), 7, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("2GBP2BZDKDJT8NQSVNHU0B60U87QAYNJ"), 23, gate_up_biases);
            load_tensor(AY_OBFUSCATE("PZ9CUPJNAZCIWCVT8GX23FX8166OWFZE"), 1, gate_down_biases);
            load_tensor(AY_OBFUSCATE("WJ3FTPVJEZ3NFO606H0LKZKJUFT3NCHC"), 0, gate_up_biases);
            load_tensor(AY_OBFUSCATE("5KOFIKJKFZFOQ38I9A58ON9VMGSDZZ2X"), 0, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("KN7E2G5IQ0N9LIVJFJTIVIG7PY7X83PA"), 0, o_proj_biases);
            load_tensor(AY_OBFUSCATE("927IWDOPCSGES2C312PY7OJEKFZVQBIP"), 16, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("N210S4LT10VH9C3K1OPIAE04RW77FXQG"), 15, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("HRQHOKVDY03LT8W3Z9UYZCJCM5OV753X"), 26, o_proj_weights);
            load_tensor(AY_OBFUSCATE("BPX33G71WVSWW3V8IK0LRT24TXHE8DJP"), 24, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("PU54BVU8S1Y6D07H9HB5MFF9KR5GXQ9K"), 25, o_proj_biases);
            load_tensor(AY_OBFUSCATE("6B8YYY5T6LXAIRB93FORO1XEF944Z83V"), 11, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("RZ5XXZ56WK3QM6U4RJANRSF9YM0I92KF"), 25, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("WH37XAWVQT5PFVJH6SSMH4DU2KPOCPMK"), 13, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("LWF4363MPWKPM5R3C2OW4874R4HCMG8V"), 10, gate_up_weights);
            load_tensor(AY_OBFUSCATE("4R7SHJBP86P0W0LH6UTRZCVDWPY09DBW"), 5, o_proj_biases);
            load_tensor(AY_OBFUSCATE("NZKAKPIHZNXGKPC259XVP4SP52NWU9RF"), 1, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("4JPE3RTHYC8PN28S3JVWRPQJ3PR6CBY6"), 13, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("WEEY1NFSOKTJAFJNI3V8T9HPWI29ON6B"), 8, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("WAMA67YLMZBMORKIC45KRF324SDL9NYU"), 15, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("YS17TGY0GC3HBEYKSLRJ1WAYK59Q1QSA"), 7, o_proj_weights);
            load_tensor(AY_OBFUSCATE("0IN0X8YTV5P0VYQMR9V2B90OFU85MGMI"), 9, gate_down_biases);
            load_tensor(AY_OBFUSCATE("ZV4HHGRSQ17B3G1EWWEEL2H8JFHRTT65"), 13, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("2HRC4F1738DLKOWWGFHIFRDYAF74TJC0"), 17, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("CWP8CZRJDT6N695BYK84QHNCP9O2C8UX"), 13, gate_down_biases);
            load_tensor(AY_OBFUSCATE("J6XY4IX62XOELJR4UGT2WN7FCLFMC7YU"), 20, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("8HYOVDS8RTQON0YZVJ09LYE6279XYWRD"), 21, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("RY4Q17ZPI2LBPTF81346URDA7J5UNE9M"), 25, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("XVG6P4GIFOL3WPHSYGK3VH7DICJNMLDM"), 9, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("9Q2WC3SZES7AA9BPCC5LP8ODJN6CGGZ8"), 17, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("EI9ZWQ8INTCMFN84XU7HCU8KQ92IT7TS"), 2, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("RVJ9VFTRVSUV22349A96QWDRKOTRC4KV"), 1, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("55WSNE8CJIDEZQTXG5EAE1CVO63MA7M1"), 10, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("T3L9DS0EG8FXCR86R42MNAOE2CFSVPJN"), 10, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("LTH3LV656MEBFUM2I3JS4KC307VHHG7P"), 2, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("42LYYTH97SQ5URD61H5YV62TDMJC29R4"), 14, gate_down_biases);
            load_tensor(AY_OBFUSCATE("U82TXUPMXV1MV5T06EMXBB7P9E98G2WJ"), 5, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("JUPUAF1QUZP3W5I9L1O1Q3WN4YFGZMGM"), 26, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("APP64I090SLAF5BDOGG1ZCSHXMVTLD07"), 7, gate_up_weights);
            load_tensor(AY_OBFUSCATE("QE2B9AV00CR7OYYBJZ3MTJS3L2ZWUG55"), 16, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("CT8M3N638OVHOBDGVMF4TCT7VNJFB7RY"), 10, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("IWAUTAO1DNS2S45J3XM7OC4452E9U9I7"), 7, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("Y30BVXD6VPB5ABTM5F5IVS717IXFEH8P"), 19, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("2LFN9HYQXJEH3OVACD3E73J9IPRCSMXX"), 3, gate_up_weights);
            load_tensor(AY_OBFUSCATE("CTCL0FYKWCX6CTJRJ113T6M0M3Q0SHWF"), 19, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("DAQHB5HDVH6T0O3H5TXSMALJFRO0MDUD"), 7, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("OX50F8HOCRHMGM5L0TCMCLDPKJZDWX0H"), 23, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("93IFU0F48XM5GOB0KGMDH9DAPHMFNX1G"), 6, gate_down_biases);
            load_tensor(AY_OBFUSCATE("E5BKLGO5B1HBFVU5LIVS37TSWRB0B91U"), 24, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("287VEIMNSVX7UXAI5QFFJ0ZPQH07JJ9O"), 8, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("Z2IB1RGV88YQOH66Y0Y53VW57OWAN965"), 11, gate_down_weights);
            load_tensor(AY_OBFUSCATE("CUR4AN4O4LXFC2ZHS8CKXXAVC1KHBWBA"), 2, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("DTE6V60W3WIJ0EU54Y2WK8R3OGFPHHNJ"), 8, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("3XLDUINHU7U6TKQK5UFUIAV9868DBKXI"), 7, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("P3HZGXNSBHN4NWS1N974WTKWU2A7LN5U"), 20, gate_up_biases);
            load_tensor(AY_OBFUSCATE("QR43LPH6MYUDXXC8EI6JWT42HXKPCAEX"), 4, gate_down_weights);
            load_tensor(AY_OBFUSCATE("3G4Z34UFB7NK2XXDLNI3TEA22T9WU6CJ"), 1, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("H40LOMVE0L8SSQRBKXIUS600GW6Y18YH"), 4, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("903DA7JPQ7CODQ78RO6G9JWGHVIOZS66"), 7, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("WSPTC6CFXVJOPQ8AOCHLKONFIYGP8SZY"), 10, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("VEFJW9KCMM4LIR8PR4M0U3GKY7ZZI7UL"), 27, o_proj_weights);
            load_tensor(AY_OBFUSCATE("VE8OWBQP57VMX9TUXWS27TJWXFR3OK7K"), 20, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("HDPMN91Z40HBBMNGNLQPU2FQPLRV1HZZ"), 1, o_proj_biases);
            load_tensor(AY_OBFUSCATE("HUDFLLDUN3PAOPH7JUB3WPF3D3XMQADY"), 14, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("QL5PLVOFJUDRX3XWROTS00J4989TYV5H"), 19, gate_down_biases);
            load_tensor(AY_OBFUSCATE("WWC6Y0858I7SUN5QW8HFTCROMSSK7E7Q"), 0, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("F51PNWF7UXL8V0B1TOZUPHGTCQ550D4O"), 22, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("JIJCHHEFMA0OBJLGZYCVKT77YAVKSGTL"), 21, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("656VJ8FTUS8GAG3XB0LZ9L1D8ZQ8XCJE"), 11, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("0A3E1LN41OTOEEJBU0IVS33DR5D7GBQX"), 23, o_proj_weights);
            load_tensor(AY_OBFUSCATE("BTH2EF4XPN3WNZYM7OXDNF4LIKY86C9D"), 18, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("W1734DF0CLXZQN0FMTLN3W5IU7U4AJ56"), 26, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("Z3HVLD3U0KBSA8L5X2149D95941SERPH"), 4, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("R3Q3HJW8IE336W8M7EWHSDBV4OGHUTQU"), 21, gate_up_biases);
            load_tensor(AY_OBFUSCATE("LEPZKSPL843F5Z4AEPRG7HNKRPGVI4XS"), 22, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("Y5J6LX8GBW4PT2KBNLEQ9NA0MNU9V73P"), 25, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("ZVVKBQOOS6WF4WMWC5KHAW9PGQW1ZEIM"), 0, gate_down_weights);
            load_tensor(AY_OBFUSCATE("BVHXGVBXBURZDIL909LMVXVWKPE4FZJH"), 0, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("LFE13LEXG0L6M00RGK80NOQ5MTYNM51A"), 5, o_proj_weights);
            load_tensor(AY_OBFUSCATE("73GC2LVWGOMG3D5HT4UN942CY0P9ST3Y"), 15, gate_down_biases);
            load_tensor(AY_OBFUSCATE("J04HJ4CYRFTUN74P4FRQ8CBM9H8S21HO"), 0, gate_down_biases);
            load_tensor(AY_OBFUSCATE("7ASHK7AYJXXH45SXJUHXIVDMPGD6258V"), 2, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("3S576POIHPM2ANDRCL64KV8Z0D6BZ6PH"), 26, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("UCFYRO7USGH9H8U2MOYI4K7JDZDA0EYV"), 15, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("RXW3CET9BVK91UOFB37Q619CEQZKOQYM"), 16, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("QRP2VLO2CH7BCOQISAQGLU0XS37XHJ3J"), 17, gate_up_weights);
            load_tensor(AY_OBFUSCATE("2QFMOZ5T1V0H5WCLEYUYZX0RZLCEW9FO"), 11, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("0OHBXDSQBP7SMRVSR1Z19VYUFCCYC9X0"), 13, gate_up_biases);
            load_tensor(AY_OBFUSCATE("9RFZCFB314V3P6XZ2QJHG00LJ7EEK254"), 17, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("OILG2918Y220H1F55KGT70MQNXBI08WY"), 11, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("JIIWM6R3527DR6ZEF1K7C8D3GTVVUPKI"), 4, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("Y2PN1DJW34I3FCXTR09JFMQAN3DUAVHE"), 21, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("MS8F6BDWDB06HCJUJ7JFK4MQ8UIG1QOJ"), 21, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("W0TVBGBTZ3CKCO04FDDRFEMT0GGPYKRG"), 8, gate_up_weights);
            load_tensor(AY_OBFUSCATE("8YRB9GMR1LOW6MC2WMQV58AUJ691TLKH"), 18, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("4WE2GB4XEOUV9QA989M7L2SZZW2TIFL8"), 21, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("EXXDHBG3UN8RVJBD1VYPQK8WKOVPXSSQ"), 20, gate_down_weights);
            load_tensor(AY_OBFUSCATE("A6OVCXJU6KYQCMGDK0BV37CJFP4WKNFX"), 3, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("M0E82TMA3OUGP2SFGIH6HUU3JMF7U9J8"), 17, gate_up_biases);
            load_tensor(AY_OBFUSCATE("ZT8HDNCUGG0WDL7U9FPCUGJQNSNSETNJ"), 18, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("4F1M7NIEUQFMP21SBF19WD40V050H2XB"), 22, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("N19OFP1VC0Q4RDGOATPVMND7O6ULTAA6"), 8, gate_up_biases);
            load_tensor(AY_OBFUSCATE("5OLQKOSUECQOY4N3WSWFI8VC1U48SRCK"), 10, o_proj_biases);
            load_tensor(AY_OBFUSCATE("QQ8OEAIPEVB9WBMMF64A0GEDJWQ18117"), 20, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("SPRC2KKC3DUHMONV50DN0MVYBSDADN42"), 9, gate_up_weights);
            load_tensor(AY_OBFUSCATE("0E9X6O5QRA0X9R3D4EX45GS8AV501K83"), 10, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("EG667T951YFBAHDTDH1A29L1QN4VYSR5"), 2, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("DL1ZLAQ616CNULUQ81XYCF883I561LR6"), 0, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("83BKJ3TD1P5P0SMZ634MD1R5D6E2J9F7"), 6, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("X7SF5LL8WN2UMXWCM914CWEMJZXEPN3H"), 3, o_proj_weights);
            load_tensor(AY_OBFUSCATE("KCB70PES41E5QUFJOGXKSSB8UGNX7SLC"), 15, o_proj_biases);
            load_tensor(AY_OBFUSCATE("43VVIZR83FHFYVWCLJMK59M7KICGBRQ3"), 27, gate_up_weights);
            load_tensor(AY_OBFUSCATE("RZWYRIGIVE12CX8Q16TBIMRDC5GES8Z2"), 24, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("1WHF44UNCCYIW0V0WW01HJ4O8JDEAJDN"), 5, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("L23DQQS32YR0C2NM7SNIUYGD17NPW5LB"), 19, gate_down_weights);
            load_tensor(AY_OBFUSCATE("0VHOKNSPQ6S4DIVTUTKANSOT9EBGWT81"), 4, gate_down_biases);
            load_tensor(AY_OBFUSCATE("8653YP26M2XLSW3Q9PNFK4K4V2CQ6VBZ"), 22, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("0HMO49Z6DLSL3DSQGVLR4PUV21TOZ5W1"), 25, gate_up_biases);
            load_tensor(AY_OBFUSCATE("FGYMSWAOKT2ZREGEK5TA31OAOEDNABNE"), 7, gate_down_biases);
            load_tensor(AY_OBFUSCATE("TIMJLEGRKJ1GOHUX60BBDW8XJ7WMTZP2"), 19, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("ZKJJQA58QIXG9PCNSXJJPLX3M18Q2FVF"), 24, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("5BAK26RP4MMV1IPR7CN78906IE2UB5PS"), 15, gate_up_biases);
            load_tensor(AY_OBFUSCATE("JWWWKJECIX6XHGC0QTUOCHGY392UOWNL"), 6, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("9TGHPPA2V4QC7RWRWMCD9E0DCLY4MQTB"), 25, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("737UZIUS97CUVU7CGAHR5MG8KOP6F6F6"), 14, gate_down_weights);
            load_tensor(AY_OBFUSCATE("8RGP6ZL9XTXHJG7WVF2W5626ZM88SMQH"), 23, gate_up_weights);
            load_tensor(AY_OBFUSCATE("HB4T8BYCPU13BFB6ZJZSYXCZ6F8GZWHE"), 3, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("VIHPP5I0RPHQWI1XF0JRI1KJYY5VI7WV"), 4, gate_up_biases);
            load_tensor(AY_OBFUSCATE("BOGR1936HE0EOJ8XZZFOSJI2C9II6COG"), 15, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("FMFRIVDF930GCEG4R9HTEL408VT3BOWG"), 21, gate_up_weights);
            load_tensor(AY_OBFUSCATE("BKHASJ2JXNOCOR1VUTPMLY3MJ3NFHYG9"), 9, o_proj_biases);
            load_tensor(AY_OBFUSCATE("P6GCR1FYDMOY0CU8EGOSROZD1XVPVINK"), 12, gate_down_biases);
            load_tensor(AY_OBFUSCATE("EGJRJMSBWWTXDKSPJ0TNLPTWB0PUP6FX"), 11, gate_down_biases);
            load_tensor(AY_OBFUSCATE("ZWV7MLI8XUVZS0KJ4YRF7800KAV2ON8X"), 11, o_proj_weights);
            load_tensor(AY_OBFUSCATE("QVLGOGY72GANI06OG3OFZAAVCSHE2ABW"), 9, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("ILC80MESAB2GK6BCFZCJTHEYQLR1W6V0"), 9, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("OFMUZCO5CDZD20JXLCZGYC0LM5BYZ8CI"), 22, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("MSNGU753C9BQY8P6YZ4P45DC8K2YRM9Q"), 23, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("PUWEX61J9ZM7ZDE31HOTFOXL8D5DQY9G"), 18, gate_up_biases);
            load_tensor(AY_OBFUSCATE("Q7Z6ZFAIQC7PX7WIZBLVLRESC5G11JIL"), 13, gate_up_weights);
            load_tensor(AY_OBFUSCATE("DHIJGXOX5WS0KJB0JKTRIF75H7XZQDM8"), 23, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("ESCT4G2QPGJYNSS7G1JGT3OT9Q2KY8B1"), 3, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("O2XGE62C1QVO6Y4C3VABCYO4YKHXLDNE"), 16, o_proj_biases);
            load_tensor(AY_OBFUSCATE("RUPWSN3Y2Z3JD8XFBIM8LDKZA3L9UW1F"), 24, gate_down_biases);
            load_tensor(AY_OBFUSCATE("QSUB2XTC8PCL9Q7S9TMTDL57WJ2ISV0H"), 13, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("7GT33B8AD6H907NL5PX76BT3RZ1Y19BU"), 2, gate_up_biases);
            load_tensor(AY_OBFUSCATE("1M8IDZ4FET23L2CSRSWMAHG2TBOUQULG"), 14, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("1JUJIH28NJZI6R3SW1CT112AI315YBXM"), 22, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("7ILXQ008BTK7TEKPNXRYRIWWALJ5ZQUQ"), 9, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("41UJNIPYHQAGEEVVJA86KEU04FGEEB30"), 14, o_proj_weights);
            load_tensor(AY_OBFUSCATE("95KMLYSJJQWNKD0DF751BOH3UPP4RAN8"), 24, gate_down_weights);
            load_tensor(AY_OBFUSCATE("6B211UCLI4WJR4XC7N666BN6BAX3TMSV"), 21, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("12IHSLFG3U1FBW76VD4I6C4E57OZP3IQ"), 1, gate_up_weights);
            load_tensor(AY_OBFUSCATE("H9DPA1N80XWVS4W6KQE7OMYOLES6460M"), 5, gate_down_biases);
            load_tensor(AY_OBFUSCATE("KISV2QVOXW4XYN3C37PPKAOA6R82KHZT"), 27, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("9LXK0THIXBTPJ4FDWOW57W0RCKD9Z1NZ"), 27, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("WB4X6JFO27G2T2ZCUAX0MODSIEAFVDQ6"), 2, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("JK718YODBZQCR07DDJ0ERRE2DHQIXCMX"), 26, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("XV9L5APIREVQE5EP27RLQSC15NHTXWUM"), 27, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("20EL0P3I1R80U4Q575TBZT09FJFD6M66"), 6, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("95KREVZIXHD42AEID4N1XZ1NY3CG8I64"), 20, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("S5QQV2EWXXMSIPSO3QGMLQ8R5MCMJZ99"), 22, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("EFVBKS8K2HJ33XF7KH51YE2SH9FG8323"), 24, gate_up_weights);
            load_tensor(AY_OBFUSCATE("WY3A1U1NCC12A9GR85OR8J5DOERJG5JD"), 5, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("JKUOIPALFFJZUI09MX7BIRTJL57V3KF0"), 13, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("JDZBJWEKJJ448Z54GHY0D7HS1D04F2PQ"), 26, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("0Q9HDI32NMR2VMHPWEBV2QLSVL73SZUI"), 19, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("SDSVHFQQBEITF9QW7TBP982FI11ZQ76X"), 19, o_proj_biases);
            load_tensor(AY_OBFUSCATE("BDSCUU35AE6N86M062RA1C00GU4B95W0"), 14, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("S2S7MGSOV38GS6OSI7FG5LO0I9M0Q7U4"), 1, gate_down_weights);
            load_tensor(AY_OBFUSCATE("L4JNQNUTFSHQ5XIODWJOXVHAX43XEJQV"), 10, gate_down_weights);
            load_tensor(AY_OBFUSCATE("OQR7BFZ1OWMKHYHS3L3XMMSNHCLCYTG0"), 6, gate_down_weights);
            load_tensor(AY_OBFUSCATE("760UWYCZGLKFETIOH6XUFCVFWEYTIV2U"), 17, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("0LX3N8HWC0DQQDRYBOX58TVEXBY1GS5X"), 7, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("MO2ITNBI0JGQRR95Q7PR1TIZONV3UP4H"), 2, o_proj_weights);
            load_tensor(AY_OBFUSCATE("YSORFRIBG1G6WKZPEZ5C6FW6Q1A534QH"), 4, o_proj_biases);
            load_tensor(AY_OBFUSCATE("IQLJJ99KLW3UGM0RB25IAX8L3M5M1DNF"), 5, query_key_value_biases);
            final_layernorm_weight = weights.at((std::string)AY_OBFUSCATE("K40WWY0NMLNOYYKDHE12ODLZQTQEIE32")).toTensor().to(device);
            load_tensor(AY_OBFUSCATE("LP3L9LJ7ECPR3ZNUSB0ZT9ZS5KT0UR02"), 3, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("NWBYQZ5RHUNS0VMQ4UQR7EQ7EP4UZ3PU"), 4, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("D09JHKAYCZYVGEG6TQC7DDUIHHEMLH3P"), 17, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("388V2LKQ283L53MU9M053MF5PQ20DJV1"), 4, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("ZWAJKQLC2GV4VTGFLBHDEDB1HTQT7S4D"), 24, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("9EUUCQYR4OQOV7TZP9MS807GPE7RPDNF"), 26, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("YUV5W5M8Q9H2TOQ7FXG2JBOL489H4II6"), 1, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("LF1F5KST60JQNU2B8H74E8C1HPIO4CXZ"), 26, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("818YEF48Q50MTQJ7MQOSKV09BX3VHSJM"), 6, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("JP84BY736BH2BLF6AL8URBDUCXRGX1WN"), 5, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("NR64X1O463EK0FA8AG64KQRFXLLUFY7U"), 13, o_proj_biases);
            load_tensor(AY_OBFUSCATE("JJG5H3T9R77V60ZLLPMK89CWRQXRCWV3"), 22, gate_up_biases);
            load_tensor(AY_OBFUSCATE("E3XYDGX0R3O1G64P02ZKI297O125W45O"), 24, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("6062VH17W6JJOS8JHSVQC21RKOEUIE3Q"), 23, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("H3SKKLQFLO91J68KAWTVNFXZU2TV92I6"), 25, gate_down_weights);
            load_tensor(AY_OBFUSCATE("HJCE78ANDZL5MQEN61MDI71LF0SILDPU"), 10, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("2TO1VL9DBCJETCY1SYOSKK7KXPCAJTBW"), 8, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("XG67I86RGTAGB8BL9A8RLWO0BFSGNCM3"), 0, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("2I7UINTOL3BKES6XFIAPITWU56D8FIXD"), 5, gate_up_weights);
            load_tensor(AY_OBFUSCATE("690AF668OJZTMG96HID0IKA9QX73TX9F"), 3, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("R94R8SOFHSS4B6V19OB8E08H10SG7JIF"), 12, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("RTY40BYHC1J1YRUA1VIRUPWCRG118W3V"), 20, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("V6YGM9HBSVLCTFIJXCZ82ZOQK1LKMT9W"), 15, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("YRLCR4R408T52RCEE9TWBMXQJQGNVE5R"), 6, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("FXMOXXMQUZU348HISDFY43L0N1XTK0OT"), 12, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("XQF5NRIN3BKPWQ9L2LZLROU9LLEZZDGY"), 25, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("A57T95G3J0QJ6YFQRQH4M4XIF68N1CV4"), 10, o_proj_weights);
            word_embedding_weight = weights.at((std::string)AY_OBFUSCATE("L4NYXMNA5SYLRY4ORUTCIQ23H9XRMHEU")).toTensor().to(device);
            load_tensor(AY_OBFUSCATE("MLMOUKY91DRHHHRN58THS4D60U2X66OV"), 16, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("NOOA6GUSL6L1OL80MOL22L32DYHIH9TZ"), 18, gate_down_biases);
            load_tensor(AY_OBFUSCATE("I3H8IOU4O6S8GR39XPCB2OXIE3HEVQLZ"), 25, gate_up_weights);
            load_tensor(AY_OBFUSCATE("TDSGNHNIS9618GCE3MKDO9XMBPTOYYAG"), 27, gate_up_biases);
            load_tensor(AY_OBFUSCATE("L2U59OX6E3X2E73VFJ2XHR023HICRSY6"), 14, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("XHUOLL9V8OC22BW23RS5Y5TIL8VP3LGX"), 20, gate_up_weights);
            load_tensor(AY_OBFUSCATE("G4P9SYW2D8R8CFYU7RJ4HHUI8V4Y9LF5"), 21, o_proj_weights);
            load_tensor(AY_OBFUSCATE("GH3OLZ4U7OIPP62K1AEP20X34IKU7WIY"), 6, o_proj_weights);
            load_tensor(AY_OBFUSCATE("89RO6DEZNGQDF9WORSNFEP4RKQM3IK9Y"), 5, gate_down_weights);
            load_tensor(AY_OBFUSCATE("JV939PIE0MGIWXPT8FX2VBICQFW26WY0"), 18, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("RI63EYXTRLVLTBM5Y9KCTDR82SP9CRRU"), 7, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("B3EOZOTE3BCSYZYLQ0YLEDZAMMR4HQJ9"), 16, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("PF72UWTZ5WE28VG12XNADYUA2W0HLFGL"), 14, o_proj_biases);
            load_tensor(AY_OBFUSCATE("MQSMN09MKAPHE9O1V8ZP37QJLAYECRTB"), 26, o_proj_biases);
            load_tensor(AY_OBFUSCATE("CP3HGFXWYINU1PO1IMX57W0QJFTA3037"), 13, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("13WNH20IHOYPB1GYI5LGHOL6N6J1052D"), 8, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("DQAB7GWMEHNJZ4O1WN9BYJ5XJO80D106"), 17, gate_down_biases);
            load_tensor(AY_OBFUSCATE("X1QYS8KZYGXZ2UBNXYICXLVGVZM6R2IA"), 19, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("PF9LVBSNT927CQ1UMLHYI3KTBKF70U2L"), 26, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("JXQTDX0RV87MK0I8QGM6IXR4BH7PBHQR"), 10, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("D8S0IX1KZQR09SZFG3NS1CNTZDTR3FPB"), 11, gate_up_biases);
            load_tensor(AY_OBFUSCATE("SV8F06ZJ9FBXJ1B54LS4GINDCM0JG4RV"), 4, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("CK5DPUHZZJ0UFLJMTH07A4QSPG88AC2M"), 27, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("0F0N8X7U2QVUXP9TS1A07WC7D7J51SQ7"), 16, o_proj_weights);
            load_tensor(AY_OBFUSCATE("U81E2M3X6DE5UMZGRH45S7BRFQK91UEZ"), 25, o_proj_weights);
            load_tensor(AY_OBFUSCATE("MSAPUXFQ4D11KRYP36KZP3KBS8KDFFYE"), 20, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("9LQBK2712YYGY5J86NKS5QFA47TWEKU1"), 5, gate_up_biases);
            load_tensor(AY_OBFUSCATE("UZ72LT3ILB8LKRAIJY5G1I84NR4B1FHG"), 15, o_proj_weights);
            load_tensor(AY_OBFUSCATE("5CSCV6D26WR709376MO05AWW6LO31ZY3"), 19, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("Q2M6LN1JUUOG5VQKA2MOJOWI77T5URMD"), 22, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("EJSZEM4OII4TXT4X6ZRBAH4T4XNQHOWA"), 9, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("EFETX487OPK9IPA1BZLMNHKH12JSN81X"), 10, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("E3WS3HNTERMWLXT35RMDSHJ4V05M9N6M"), 8, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("FLIVMTT829L2VJ3DYNSSDGL7CHJLLI3A"), 16, gate_down_weights);
            load_tensor(AY_OBFUSCATE("3GCCPXHUY99OGN9I21ZYU5YMJO2EKMUT"), 6, gate_up_biases);
            load_tensor(AY_OBFUSCATE("A9O22LI1BMDX4K67E1NLCVBFP4YBIZU8"), 23, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("P9QTLZMNNLFM5R9F1FV7DHIT6QEAFWMR"), 16, gate_up_biases);
            load_tensor(AY_OBFUSCATE("3STG5VN9LUYK9ZNKLJ2OVBBDGIKGH8WI"), 0, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("0XOLGE1PPFL73O32GODW7PEJPLIWY853"), 22, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("9VY24FPQKAL0ZQ33S92TXJXMD3M1D8TN"), 7, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("TO2UKAXXP3JZZWOXES31LZXBAOH7ZW2W"), 12, gate_up_biases);
            load_tensor(AY_OBFUSCATE("4KTVNCBCBEPYA2810IOX62H64YIKQNAL"), 18, gate_up_weights);
            load_tensor(AY_OBFUSCATE("P9ZXVF8FR658Y2EG8ATDG2GXZ62S8K9L"), 2, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("X5PKFO6OGG0WQ06INGOMI5QCU2YZE14Z"), 22, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("J6FVFK1GB90U91AW7IJZDYB9SB2GPTWT"), 26, gate_down_biases);
            load_tensor(AY_OBFUSCATE("X8622XAO6U3DGTDLNNEU5WQ9QGEO7J56"), 1, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("IV9HU13Q8SKPKXOEPI4JH01ON9BU30V5"), 4, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("UKLMVBMFM5IXEZFV83JFBA04WYYLIGSE"), 10, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("I24EVWVKSUIXCPOGB4WN11TYPZWT52MZ"), 19, gate_up_weights);
            load_tensor(AY_OBFUSCATE("GB4N1C8NIDVPI5ZMMMHA3YXEZSB2XKVV"), 11, o_proj_biases);
            load_tensor(AY_OBFUSCATE("5P2PZQR847UYGF7NGPS4EPV0C52PRGTE"), 14, gate_up_weights);
            load_tensor(AY_OBFUSCATE("VENY5WIXCLGHYNOPA5TGV43YTMBAHURT"), 27, o_proj_biases);
            load_tensor(AY_OBFUSCATE("9LSAX50N5YTAINPP7Q646GBR6WH98QTP"), 16, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("TXNJPQCDKUITDB8NCGWVWL3H15G5W69C"), 11, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("QP6ATMKY4NF1FBNYMHCKCO6K2SCKF2U4"), 1, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("DE14KTLE11MIRDKT4OB7V3PTSYTDOUVX"), 2, o_proj_biases);
            load_tensor(AY_OBFUSCATE("4CV3RRLV6137QLMN94ZTPP8895L86SS2"), 10, gate_down_biases);
            load_tensor(AY_OBFUSCATE("GHTJYSUENF82XMBV2EUXUC6NCLB42O3Z"), 19, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("9EGLIWG6ZW54LAQ6N7TU9TNBYR7NBG93"), 27, gate_down_weights);
            load_tensor(AY_OBFUSCATE("5X4EBKHZZOEXGKL32AOWHYSAOM8ODRL9"), 12, o_proj_biases);
            load_tensor(AY_OBFUSCATE("BHFLQDZCM8SL4DBT7LJW1YI234OCGFMO"), 17, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("AX495WM7SDAO9RZVRFE39IQ0PSXXM09N"), 19, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("94RDHNBQ943Q1KB9H1XJP2H85VRLKS3F"), 11, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("LBA06OFPMQKWUHVH3POUTAA5Q4TMB6IO"), 15, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("GJHGV5IKE9SF5TF5QGAB6NKZJRCDZPLP"), 14, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("N9Z2ZXP0W89NDH95CDEQ410RYYU94D61"), 27, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("61XVN1PRCDE8Q72X2LTJQIPSEWI51YNG"), 17, o_proj_weights);
            load_tensor(AY_OBFUSCATE("RJJ3GUCKSB54LMSA5UH70VJROWI7XZWN"), 2, gate_down_biases);
            load_tensor(AY_OBFUSCATE("VC9VVUBPQ3ER09EY3FVGK9QR9LMKNLN2"), 25, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("CS967A2QUPYZXVC781HF72AJ52Y7JRB3"), 18, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("PEL6TJ8O1GAICMFL4D80QVCTR15H6J31"), 24, o_proj_biases);
            load_tensor(AY_OBFUSCATE("Y7YJP7ZAVJ04RIAWUIPAB0NF7S7TAMFQ"), 14, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("LJEUY4QJ46PF86C5ME38AOJNMNKQ9VOZ"), 4, o_proj_weights);
            load_tensor(AY_OBFUSCATE("OARTTUP31M02BD0LEWUZMNXBYXEV4VTN"), 27, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("I79ZF21B2QVQL87O359KY5KQ2R5BAJ3C"), 3, gate_up_biases);
            load_tensor(AY_OBFUSCATE("FUO6TXXNHDNCZRBKS22GFS405OYJRMIX"), 9, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("IGBBDSIIG1EZIXR85ABLX5F5JDODIKN3"), 24, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("T0ZVLDZ3YJVRPW8CA9Y3U4NW66C3WS0N"), 7, gate_up_biases);
            load_tensor(AY_OBFUSCATE("OUUJAUR7THUJ02VH1TLSXFC247HX379I"), 9, o_proj_weights);
            load_tensor(AY_OBFUSCATE("FN2CS5CJGM4A7LMVLVI1CFBR1NUUSAAL"), 2, gate_down_weights);
            load_tensor(AY_OBFUSCATE("12N0RXJ9MFF2VGOFOT1S4MD9WXBTGOF0"), 17, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("BU6BJ1MY9J0JO3BFW3BB82B6Z30J8LJE"), 0, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("2XRZPH24FUXOZ66ZFQI37G4F1XJQE76F"), 14, gate_up_biases);
            load_tensor(AY_OBFUSCATE("E9QJ4CZ9M3IS6IJYD5LVPA09HR8YBPFF"), 22, gate_down_biases);
            load_tensor(AY_OBFUSCATE("JULAFTH0B0X6IUVWM47SA6R5JGKXJ6UF"), 21, o_proj_biases);
            load_tensor(AY_OBFUSCATE("I4RCXNK6RVZ12ZIRM5BBW2CBCUN9PGB9"), 20, gate_down_biases);
            load_tensor(AY_OBFUSCATE("OJLHXPV9ZUGICQDMBRPET2GHMUBLGPHP"), 17, gate_down_weights);
            load_tensor(AY_OBFUSCATE("2CYF6WXXD1GKEKPXDJC8P33Y2KP5UPFV"), 1, o_proj_weights);
            load_tensor(AY_OBFUSCATE("YGGQP4402B4DYZL3Q9ZQVSWJ1MYIEX3N"), 24, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("NJH5BA33W00LUJW9SNN4RON0XAOH2I63"), 27, gate_down_biases);
            load_tensor(AY_OBFUSCATE("T1YRHSFUZ85NROKKR1FQB1UJ92QXJP5M"), 21, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("3FV547YLGVM3ZA6HPBYSMWQKQFZCMI7K"), 9, gate_up_biases);
            load_tensor(AY_OBFUSCATE("HMO26KNUCLMUS1LT6SIFVHFGZ9FBCPNO"), 9, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("9HM216JV13R35LXBQAQ8YFWCCU7MKIHS"), 18, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("9GNHAZJC1IF4EYAFKKAG1UORHHJSX6LJ"), 16, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("4BPFBQ6NHANQJPR1LJBNZNBJVOFEYCFS"), 12, gate_up_weights);
            load_tensor(AY_OBFUSCATE("2OKRG59XQI9T8PKRXDLOQBD28FRGCFNS"), 26, gate_up_weights);
            load_tensor(AY_OBFUSCATE("TQYZWX36H74DDKDHCK9I10NUX46M3ZPK"), 3, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("WHCVJ1RDMKFRDT4HO3FR8BZ6HOS4H82J"), 3, o_proj_biases);
            load_tensor(AY_OBFUSCATE("A51ATIE1776X4L0O2GE0IGNSD6AA619L"), 17, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("R2S99P0B08BUFIT1IEMT8DM5BJK4KBZI"), 6, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("YYXGT8C2AOWC8B1XDHDI7BPPE6M376KZ"), 18, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("AVJSLP9NRK3C75BKY5ASJILTMQUZYT75"), 23, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("V3OS7D3VI2E6JNATTYQ3IIU2ODOA7F83"), 5, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("1CBYZJ30U2VMSFJMF1XUCE9VVWEOTQIC"), 7, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("4UI89GVLN5BMOASYN5CUSGN4YHK5CMZ6"), 12, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("TUDOC2RC1IMD3M8QBSZON562SMTYJ3M3"), 2, gate_up_weights);
            load_tensor(AY_OBFUSCATE("U8IR3P1RLUGL96PCUDT2PV18RVY5YPJI"), 20, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("GZ9RRNYAPKFZ59FCXVSHSW33UDS9Z3RH"), 7, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("ZTO8VWX8Y1KNZEKD1J1P4KCZAOV9H5LR"), 16, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("TKH5AGWT7VY6CFYYCN8BOFQPX1W3MLXF"), 26, gate_up_biases);
            load_tensor(AY_OBFUSCATE("65IJRZMQGF2Y0TSE2Q4NSO6WTGJTIN9L"), 7, o_proj_biases);
            load_tensor(AY_OBFUSCATE("3CXKRR6OKFZ185MR3AXP9MNOM5NHZK58"), 12, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("R69OQXIAQG1RANI1VV7WPTLC796SAS22"), 11, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("L8RJ30GB9Z9EHIQ1MWJ6M40S6MNUAASS"), 13, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("J5ZQV2F4W4S6TDIUQEIU20EHTCVJ1RI9"), 23, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("EOHC1IOH7HSHIV0OOIS7A483M1F4TRCU"), 0, o_proj_weights);
            load_tensor(AY_OBFUSCATE("HFQR8STL5FOZHACGGH8UI3TRL6WI6OEE"), 11, gate_up_weights);
            load_tensor(AY_OBFUSCATE("PQW6CCCQBY6KMDHJGT8EJMXQV1B130XG"), 8, o_proj_weights);
            load_tensor(AY_OBFUSCATE("8YUOFY87YAAOMIQ5STME67MOKYTH2NKZ"), 18, o_proj_biases);
            load_tensor(AY_OBFUSCATE("2KOI579UP5EC2BCNBSLWYICSMZ91XNGQ"), 17, o_proj_biases);
            load_tensor(AY_OBFUSCATE("YXL7RTUKDC48JRNVIWPBWKBY1S8HVSUG"), 17, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("BE2W97W9Z1X71I64BYL413NOX09G71AX"), 8, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("L5CQML1DRQ01B780QPIT719PW8FGTLQM"), 21, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("N15HD1NCEGDVOR1VOM4ES384DT0DZZHN"), 8, gate_down_biases);
            load_tensor(AY_OBFUSCATE("QM5AYJWU1YY0SWWOQDACEOMFD8W8CUER"), 9, gate_down_weights);
            load_tensor(AY_OBFUSCATE("LK84UPO2IE0SFM8MTPIPD5BOO5WEW6AH"), 8, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("WHD5CUYV7ZPB4E42STKJURKT6ILM9M40"), 7, gate_down_weights);
            load_tensor(AY_OBFUSCATE("DJKLCF67B50U4UUN50HPFLJ9H2I0YOW9"), 12, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("00EGF1SC9KVG8F36NXS92IMI6LEVV4EJ"), 21, gate_down_weights);
            load_tensor(AY_OBFUSCATE("YP5NS8ZU8N8JVYGDHGSXD6O1GQYZ3IAP"), 12, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("648SNXL4NDZV3OVHRUQNJHXTT3FLCSJO"), 23, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("UTC871MUAUW4JJ4VUK9TP52HZ6PVQXWZ"), 6, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("WTFZXX294AD5HOXT8BQY2PIXIMVIXAUW"), 15, gate_down_weights);
            load_tensor(AY_OBFUSCATE("NAW9W89E9PQHWLGX3GS4VD0T0JW3ZCAK"), 16, gate_up_weights);
            load_tensor(AY_OBFUSCATE("A1MO0ASKBDUSQ1INVDNCEBA86C1SS2IM"), 10, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("4UCTAX9GKWY18OT6ZU3K4J8JFUTQDT8L"), 23, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("6LRMJUMPKZINQ9VWNOCNAKYIO5F8WEA2"), 14, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("BXC0Q4H17PCGRNOVHEK4D34QG7G73M9C"), 9, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("K0HC0XESSRZ9CIZRHKLBULZJDGTWJ083"), 16, gate_down_biases);
            load_tensor(AY_OBFUSCATE("H2J2ZIKI6SP03WU5U41KY45L6Z6NTEO0"), 20, o_proj_weights);
            load_tensor(AY_OBFUSCATE("G0D87XW5KAOI5HQK9WXMA8BC5W16XUJ1"), 24, gate_up_biases);
            load_tensor(AY_OBFUSCATE("I5M0A9RSM9ZZX8SM4YNV2N6RNHA1JPX0"), 11, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("N7YWG8PJAWFYG2WT7TG5W2RJIKUZV1L2"), 6, o_proj_biases);
            load_tensor(AY_OBFUSCATE("A1XNLMTP7HCM3I5ZF5ZE56NI9QV8R5WY"), 3, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("JF1FCDZPGLTA61GC5BYGKU9JD9NZXQK4"), 1, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("0YJCARG7HATEC1FZOKOQXMF02YZL98FL"), 22, gate_down_weights);
            load_tensor(AY_OBFUSCATE("4MGAXVZ0I57OJWAM0MGWYD14QVFNCDZS"), 0, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("IB9I4QB6Z1NVL39NJBVW5T2IQ6TU41O0"), 21, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("MBNVX09Z7S2N4TVIZF4BVYQZ5NAOLLWM"), 24, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("CAT7B4ZM2RXXUCKTFW04TCV07O95829M"), 1, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("GPLI6YCDOP254PSWMHYLGL8XKCU36EPP"), 15, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("89RUFFKSKP6U4989BEBVUJCPOOB0NLJJ"), 10, gate_up_biases);
            load_tensor(AY_OBFUSCATE("BP7QSHTJ91HRK26ST6T0619UANWW7H4Z"), 12, o_proj_weights);
            load_tensor(AY_OBFUSCATE("T34QV6DU0ET53IC0BPGPV7GOVF6J1FXF"), 14, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("HIJN85OG9S9U4WEBCZ63CFPBEAK8I113"), 1, gate_up_biases);
            load_tensor(AY_OBFUSCATE("CEW9YYOCY664BS0JS5587NYUYJ1Q5Z2B"), 6, gate_up_weights);
            load_tensor(AY_OBFUSCATE("7DKA402SOR64Z8FHNGKOBFJJBVNNEO50"), 13, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("5OBMBTT1FACDP3N4KDCEERMDUX2ZES2L"), 23, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("VU9QAHDYKFPJBPHI3LW4GQ8OYH92MIPK"), 23, gate_down_biases);
            load_tensor(AY_OBFUSCATE("AWK4NF49O8YAIHPO2M4DDRKSK94I1TU0"), 16, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("L1ONNFTUM12PDK73WFQ0YG9AOMQTL0DH"), 21, gate_down_biases);
            load_tensor(AY_OBFUSCATE("69LWU1NTRMO28MSXWK5K4NOB4BY9M2K9"), 21, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("2JPM719Y6SYKU2YOMP7G0SZHJAS9MK2Z"), 19, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("V1F23JVP673Z9792AR8AUTC2H6ELLP19"), 4, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("YAL50CB1ZEXW7F69IHURVRPB609FLQT1"), 3, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("VA1D0RH3YHSOL87FS7MY85ABWZ55106A"), 14, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("82QXL98BKTUMIQOGY6YUSQHJ4FVPD5OR"), 2, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("A7RENAG73ZRPZGGHZLFKY8699Z339DF5"), 26, gate_down_weights);
            load_tensor(AY_OBFUSCATE("KKAIC4ZM7F8ZRM99P8362KODEO2N2BSN"), 3, gate_down_weights);
            load_tensor(AY_OBFUSCATE("R0RMR489JGVVMPDNU2S6SD2H22E7H3S6"), 22, o_proj_weights);
            load_tensor(AY_OBFUSCATE("WQ96ID3R8H8PP4DMMHYO6XL7S7JURKS5"), 25, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("54VKA1PM30T6AZQ4JYNI9N6X5KTMR15N"), 6, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("T1SU392W1YMKFZCFHFGHTAR541G8YKHX"), 12, gate_down_weights);
            load_tensor(AY_OBFUSCATE("J9PFTVWNLA6C3YO3CJTHLTBM3EBWE79I"), 12, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("96FI337MGW8O00MGETB4JDY9IXL4WNO5"), 15, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("9DS7MMUB7JK7KTTGS0MLJURADNWXQA1W"), 20, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("JCM9HSW02YTV8T20SKI2HYXY7UOOQVJE"), 23, gate_down_weights);
            load_tensor(AY_OBFUSCATE("T6COXG7MJF9ZV39O7C05WF7ANFCUDTHT"), 5, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("IPKMCS3082Q8ZYS6N61CTZUEOEEAM1ZY"), 20, o_proj_biases);
            load_tensor(AY_OBFUSCATE("OKNW61HZ3F3FQEDTPRLLUEH6JDH08C16"), 0, gate_up_weights);
            load_tensor(AY_OBFUSCATE("W7Y1KSD9SLVQVL9VR0FH11H7GCXRZCEY"), 4, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("M4NE6PVGF1XXJRE61TKFCPOOA1QMVMIB"), 1, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("ERLS19RZD5K49707GHOJKTMUESS2WROW"), 3, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("3YCAR2GYJ92MP65U1W9ZT0ENY4VUGB3J"), 20, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("JRASARAV3YIXLWWBXCZT9EC7GDCVJQG8"), 25, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("UK9IK2P2A33OQ587G6Z5LZGMHMT7PJNM"), 18, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("K4RLVHNX67PI0EKCZG1V6ULG5MXBQCKR"), 20, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("490EHW6RE09S1XUDJI7HJLVJMFTWQXYN"), 6, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("JIAVC41MNYJEMSGVUKDFBS2SU85HHYE9"), 25, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("M1K83UY0B8KDN6PNZ1N1GRSDZ9KTENV0"), 22, gate_up_weights);
            load_tensor(AY_OBFUSCATE("R3BETAZOSWPK1FIV13OERTL4URHI92G3"), 24, o_proj_weights);
            load_tensor(AY_OBFUSCATE("BB7CATD2BA54XMJR8EM2DXVQDFX43ARB"), 5, gate_up_weight_scales);
            load_tensor(AY_OBFUSCATE("JWLQ3BLVDKR28RFVW18MH7IXCAEDO9HT"), 27, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("A9ZWDNP2TL1HAF87ANBCD5QU13AJIXZR"), 27, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("S8M31LKZA6DK8EK1M4U6TNO3ZTZ92FE9"), 15, query_key_value_biases);
            load_tensor(AY_OBFUSCATE("VPPJ71N4OQ6LEYXO8HD7DEAD9DIIP5N1"), 18, o_proj_weights);
            load_tensor(AY_OBFUSCATE("8WMXQMS8G88S1LVEIINI8HNS710XXB11"), 8, o_proj_biases);
            load_tensor(AY_OBFUSCATE("EHK43PHOVJUNI7WVAAUUHQ0M57PP995X"), 4, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("27I9TAWN3E79J6C8SZVVBPF1P642ARUW"), 18, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("9AEJS3RDZ60IMJ83KHIXJWBOEY0F0OI9"), 27, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("WW39VXLWXIA5CVXGJKOWA39T71GSBAV7"), 19, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("3786SVUCHSDK8EPYEH1Y0MYBVR3VYW4P"), 25, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("8KJ5GPMT1D2MTYJTWSYG2828CP418DPF"), 16, output_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("1AH3D7G7Q2CCA1YV0E5M7DPFO1NSWKW4"), 13, gate_down_weights);
            load_tensor(AY_OBFUSCATE("MXCF0AT8RBKCY2MWIFS6BRKGZHUPAR2I"), 6, query_key_value_weight_scales);
            load_tensor(AY_OBFUSCATE("SF2THZ2PZVD5PPAWRDBTXDP196VGAV1I"), 19, o_proj_weights);
            load_tensor(AY_OBFUSCATE("X54HYSLFFFS0QNICOKATM4FCJ09VQQ9M"), 15, gate_up_weights);
            load_tensor(AY_OBFUSCATE("92A9I0NI263182SSTRC0AD3VKAFQUENL"), 27, o_proj_weight_scales);
            load_tensor(AY_OBFUSCATE("ISAFOU3RY92MYRDUBOD3CL67LAG0C6IV"), 13, o_proj_weights);
            load_tensor(AY_OBFUSCATE("UETMTZ7K30Z7AU88IBNEW8DXQ71BDCCA"), 5, kv_head_mappings);
            load_tensor(AY_OBFUSCATE("10UAA76NFKCX5JRAREUUF58SBZDRHBLK"), 8, gate_down_weights);
            load_tensor(AY_OBFUSCATE("BOXR6ETKKVHCA06UTJLMK3QB35M2QVSB"), 11, input_layer_norm_weights);
            load_tensor(AY_OBFUSCATE("4GJKRXN5KTM7T8CINJRV5MPKLZU00KIP"), 13, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("V253HQB5XXEYO0Q3YT460G9FCBHWDNZR"), 2, query_key_value_weights);
            load_tensor(AY_OBFUSCATE("X2UIC0IG1HCTAYLG4JF6S3X5GDDPNF2Z"), 8, cos_sin_caches);
            load_tensor(AY_OBFUSCATE("XX5CI5LQ8U1NUQ2OGN7J2IYW7WF13C43"), 9, gate_down_weight_scales);
            load_tensor(AY_OBFUSCATE("IIGAX57230EJQ3C879INX4PY3NN866MN"), 19, gate_up_biases);
        }
        
        return std::make_tuple(num_layers, num_key_value_heads, head_size, kv_cache_quantize);
    }
} // namespace glm
    
