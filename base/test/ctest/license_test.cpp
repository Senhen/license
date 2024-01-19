#include <cstdlib>

#include <ctime>
#include <stdio.h>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <array>
#include "../../include/Dongle_API.h"
#include <cstring>
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

    // DWORD dwRet =0;
    // int nCount = 0;
    // int nIndex = 0;
    // std::array<char,10> UserPin = {"aminer123"};
    // int nRemainCount = 0;
    // int retcode =0;

    // time_t tm;
    // struct tm *ptm = nullptr;
    // DWORD dwTime = 0;

    // DONGLE_HANDLE hDongle = nullptr;
    // DONGLE_INFO *pDongleInfo = nullptr;

    // //enum key
    // dwRet = Dongle_Enum(NULL,&nCount);
    // std::cout << "Enum " << nCount << "Dongle ARM." << std::endl;
    
    // pDongleInfo = new DONGLE_INFO[nCount];
    // dwRet = Dongle_Enum(pDongleInfo,&nCount);

    // for (int i = 0; i<nCount;i++){
    //     if (pDongleInfo[i].m_Type == 0 || pDongleInfo[i].m_Type == 1){
    //         nIndex = i;
    //     }
    // }

    // if (nIndex ==-1)
    // {
    //     std::cout << "No Dongle ARM." << std::endl;
    //     Dongle_Close(hDongle);
    //     retcode = 100;
    //     delete[] pDongleInfo;
    //     return retcode;
    // }
    // dwRet = Dongle_Open(&hDongle,0);
    // std::cout <<"Open Dongle ARM. Return : 0x" << std::hex << dwRet << std::endl;

    // dwRet = Dongle_VerifyPIN(hDongle,0,UserPin.data(),&nRemainCount);

    #define INOUT_BUF_LENGTH 1024
    int fileid = 0x0002;
    int ret =0;
    
    // fetch hardware information example
    std::string board_name = commandOutput("cat /sys/class/dmi/id/board_name");
    // log output
    std::cout << "Board name: " << board_name << "\n";

    std::string board_serial = commandOutput("cat /sys/class/dmi/id/board_serial");
    std::cout << "Board serial: " << board_serial << "\n";

    std::string board_vendor = commandOutput("cat /sys/class/dmi/id/board_vendor");
    std::cout << "Board vendor: " << board_vendor << "\n";

    std::string product_name = commandOutput("cat /sys/class/dmi/id/product_name");
    std::cout << "Product name: " << product_name << "\n";

    std::string product_version = commandOutput("cat /sys/class/dmi/id/product_version");
    std::cout << "Product version: " << product_version << "\n";

    std::string product_serial = commandOutput("cat /sys/class/dmi/id/product_serial");
    std::cout << "Product serial: " << product_serial << "\n";

    std::string product_uuid = commandOutput("cat /sys/class/dmi/id/product_uuid");
    std::cout << "Product uuid: " << product_uuid << "\n";

    std::array<char,INOUT_BUF_LENGTH> InOutBuf;
    std::snprintf(InOutBuf.data(), InOutBuf.size(), "board_name:%s,board_serial:%s,board_vendor:%s,product_name:%s,product_version:%s,product_serial:%s,product_uuid:%s", board_name.c_str(), board_serial.c_str(), board_vendor.c_str(), product_name.c_str(), product_version.c_str(), product_serial.c_str(), product_uuid.c_str());
    //Inoutbuf转换为数组
    std::array<unsigned char, 512> str;
    for(std ::size_t i =0; i<str.size();i++) {
        str[i] = static_cast<unsigned char>(InOutBuf[i]);
    }

    // ret = Dongle_RunExeFile(hDongle, fileid, str.data(),256,&retcode);
    // if (ret == DONGLE_SUCCESS)
	// {
	// 	// On success the input buffer should now be changed by Dongle. Print new content.
	// 	printf("The executable ran successfully. The new buffer content is: %s\n", InOutBuf.data());
	// }else{
    //     printf("The executable ran failed. The new buffer content is: %s\n", InOutBuf.data());
    // }

    // dwRet = Dongle_Close(hDongle);

    // if (pDongleInfo != nullptr)
    // {
    //     delete[] pDongleInfo;
    //     pDongleInfo = nullptr;
    // }
    return str;
	
}


int main(int argc, char *argv[]){
    //check license 
    // std::ifstream license_file(std::filesystem::path("./") / "license.txt");
    std::string filepath ="./license.txt";
    std::ifstream license_file(filepath);
    if (!license_file.is_open()){
        throw std::runtime_error("license file not exist!");
        return 1;
    }
    std::ostringstream license_stream;
    license_stream << license_file.rdbuf();
    std::string license = license_stream.str();
    //找到license中倒数第二个是\并且最后一个是0；\前面的为license
    license = license.substr(0, license.find_last_of('\\'));
    std::array<unsigned char, 512> licenseEnv = getEnv();
    std::string info = std::string((char*)licenseEnv.data(), licenseEnv.size());
    info = info.substr(0, info.find('\0'));
    std::cout << "license is: " << license << "\n";
    std::cout << "info is: " << info << "\n";
    if (license != info)
        throw std::runtime_error("license file is invalid!");
    std::cout << "license is valid!\n";
    return 0;

}