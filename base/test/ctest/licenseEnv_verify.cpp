#//include <cstdio>
// #include "../../include/Dongle_API.h"
#include <array>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <sstream>
#include <stdio.h>
#include <vector>
#define MAX_OUTPUT_LEN 128
#define CHECK_LICENSE_SUCCESS 200

// Remove trailing spaces from a string

bool isSpaceOrNewline(char c) {
    return c == ' ' || c == '\n';
}

std::string rtrimSpaceAndNewline(std::string s) {
    while (!s.empty() && isSpaceOrNewline(s.back())) {
        s.pop_back(); // remove characters from the end
    }
    return s;
}

// get command output
std::string commandOutput(const std::string &cmd) {
    std::array<char, MAX_OUTPUT_LEN> buffer;
    std::string result;

    FILE *pipe = popen(cmd.c_str(), "r");
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

// 检查license是否有效
std::array<unsigned char, 512> getEnv() {
#define INOUT_BUF_LENGTH 1024
    int fileid = 0x0002;
    int ret = 0;

    // fetch hardware information example
    std::string board_name = commandOutput("cat /sys/class/dmi/id/board_name");
    // log output
    // std::cout << "Board name: " << board_name << "\n";

    std::string board_serial =
        commandOutput("cat /sys/class/dmi/id/board_serial");
    // std::cout << "Board serial: " << board_serial << "\n";

    std::string board_vendor =
        commandOutput("cat /sys/class/dmi/id/board_vendor");
    // std::cout << "Board vendor: " << board_vendor << "\n";

    std::string product_name =
        commandOutput("cat /sys/class/dmi/id/product_name");
    // std::cout << "Product name: " << product_name << "\n";

    std::string product_version =
        commandOutput("cat /sys/class/dmi/id/product_version");
    // std::cout << "Product version: " << product_version << "\n";

    std::string product_serial =
        commandOutput("cat /sys/class/dmi/id/product_serial");
    // std::cout << "Product serial: " << product_serial << "\n";

    std::string product_uuid =
        commandOutput("cat /sys/class/dmi/id/product_uuid");
    // std::cout << "Product uuid: " << product_uuid << "\n";

    std::array<char, INOUT_BUF_LENGTH> InOutBuf;

    std::snprintf(InOutBuf.data(), InOutBuf.size(),
                  "board_name:%s,board_serial:%s,board_vendor:%s,product_name:%s,product_version:%s,product_serial:%s,product_uuid:%s",
                  board_name.c_str(), board_serial.c_str(), board_vendor.c_str(),
                  product_name.c_str(), product_version.c_str(), product_serial.c_str(),
                  product_uuid.c_str());
    // std::snprintf(InOutBuf.data(), InOutBuf.size(),
    // "222");
    // std::snprintf(
    // InOutBuf.data(), InOutBuf.size(),
    // "board_name:,board_serial:,board_vendor:,product_name:KVM,product_version:Standard PC (i440FX + PIIX, 1996),product_serial:,product_uuid:d73d5742-de99-4d09-bcd7-748932f829db\0");

    // Inoutbuf转换为数组
    std::array<unsigned char, 512> str;
    for (std ::size_t i = 0; i < str.size(); i++) {
        str[i] = static_cast<unsigned char>(InOutBuf[i]);
    }
    return str;
}

int main(int argc, char *argv[]) {
    std::array<unsigned char, 512> licenseEnv = getEnv();
    std::string info =
        std::string((char *)licenseEnv.data(), licenseEnv.size());
    info = info.substr(0, info.find('\0'));
    std::cout << "license env: " << info << "\n";
}