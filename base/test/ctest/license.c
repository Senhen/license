// Sample06.cpp : Defines the entry point for the console application.
//
//#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../../include/Dongle_API.h"
#include <string.h> // Add this line
#include <unistd.h> 

// #include <conio.h>

#define MAX_OUTPUT_LEN 128
#define CHECK_LICENSE_SUCCESS 200

// Remove trailing spaces from a string
void rtrim(char * str) {
    if (str == NULL || *str == '\0') {
        return;
    }
    int len = strlen(str);
    char *end_ptr = str + len - 1;  // Point to the last character in the string
    // Move backwards until we hit a non-space character
    while (end_ptr >= str && (*end_ptr == ' ' || *end_ptr == '\n')) {
        --end_ptr;
    }
    // Mark the next character as the end of the string
    *(end_ptr + 1) = '\0';
}

//get command output
void commandOutput(char* cmd, char* output) {
    FILE *fp;
    
    // Ensure the output buffer is empty
    memset(output, 0, sizeof(char) * MAX_OUTPUT_LEN);

    if ((fp = popen(cmd, "r")) == NULL) {
        perror("popen error");
        return;
    }

    char line[MAX_OUTPUT_LEN];
    while (fgets(line, sizeof(line), fp)) {
		rtrim(line);  // Remove trailing spaces
        strncat(output, line, MAX_OUTPUT_LEN - strlen(output) - 1);
		printf("Command Output so far: %s\n",output);
    }
    pclose(fp);
}

//检查license是否有效
int checkLicense(){
	DWORD dwRet = 0;
	int nCount = 0;
	int i = 0;
	int nIndex = -1;
	int year, mon, day, hour, min, sec;
	char UserPin[] = "aminer123";		  // 默认用户PIN码
	int nRemainCount = 0;
    int retcode =0;

	time_t tm;
	struct tm *ptm = NULL;
	DWORD dwTime = 0;

	DONGLE_HANDLE hDongle = NULL;
	DONGLE_INFO *pDongleInfo = NULL;

	// 枚举锁
	dwRet = Dongle_Enum(NULL, &nCount);
	printf("Enum %d Dongle ARM. \n", nCount);

	pDongleInfo = (DONGLE_INFO *)malloc(nCount * sizeof(DONGLE_INFO));

	dwRet = Dongle_Enum(pDongleInfo, &nCount);

	for (i = 0; i < nCount; i++)
	{ // 0xFF表示标准版, 0x00为时钟锁,0x01为带时钟的U盘锁,0x02为标准U盘锁
		if (pDongleInfo[i].m_Type == 0 || pDongleInfo[i].m_Type == 1)
		{
			nIndex = i;
		}
	}

	if (nIndex == -1)
	{ // 没有找到时钟锁
		printf("Can't Find Time Dongle ARM.\n");
		Dongle_Close(hDongle);
        retcode = 100;
		return retcode;
	}

	// 打开锁
	dwRet = Dongle_Open(&hDongle, 0);

	printf("Open Dongle ARM. Return : 0x%08X . \n", dwRet);

	// // 验证开发商PIN码
	// dwRet = Dongle_VerifyPIN(hDongle, FLAG_ADMINPIN, AdminPin, &nRemainCount);
	// printf("Verify Admin PIN. Return: 0x%08X\n", dwRet);

	// //验证用户PIN码
	// dwRet = Dongle_VerifyPIN(hDongle, FLAG_USERPIN, UserPin, &nRemainCount);
	// printf("Verify user PIN. Return: 0x%08X\n", dwRet);

	// 获取锁内时间
	dwRet = Dongle_GetUTCTime(hDongle, &dwTime);
	printf("Get UTC Time. Return: 0x%08X\n", dwRet);
	printf("Current Time. ReturnL 0x%08X\n", dwTime);

	if (DONGLE_SUCCESS == dwRet)
	{
		// ptm = gmtime((const time_t *)&dwTime);
		time_t actualTime = dwTime;
		ptm = gmtime(&actualTime);
		if (ptm == NULL)
		{
			fprintf(stderr, "gmtime failed\n");
			return 1; // 或者其它代表错误的返回值
		}
		// 转换为公历时间
		year = ptm->tm_year + 1900;
		mon = ptm->tm_mon + 1;
		day = ptm->tm_mday;
		hour = ptm->tm_hour + 8; // 将小时数加 8，转为上海时区时间
		if (hour >= 24)			 // 如果超过 24，表示已经到次日，小时减 24，将日期加 1
		{
			hour -= 24;
			day += 1;
			// 注意这里没有处理 day 超过当月天数的情况，如果需要，还需进一步处理
		}
		min = ptm->tm_min;
		sec = ptm->tm_sec;
		printf("Date: %04d-%02d-%02d %02d:%02d:%02d \n", year, mon, day, hour, min, sec);
	}

	// 设置到期时间共三种方式
	// 1.设置小时数，校验了用户PIN之后开始计时。
	//	dwTime = 24;//使用24小时，dwTime的取值范围为1~65535
	//	dwRet = Dongle_SetDeadline(hDongle, dwTime);
	//	printf("1.Set Deadline [hour] time. Return: 0x%08X\n", dwRet);

	// 2.设置日期
	//	dwTime = 0;//获取从现在开始计算，1年后的utc时间。这里的UTC值大于65535
	//	dwRet = Dongle_SetDeadline(hDongle, dwTime);
	//	printf("2.Set Deadline [date] time. Return: 0x%08X\n", dwRet);

	// 3.取消时间限制
	//	dwTime = 0xFFFFFFFF;//取消时间限制
	//	dwRet = Dongle_SetDeadline(hDongle, dwTime);
	//	printf("3.Cancel Deadline time. Return: 0x%08X\n", dwRet);

	// 获取到期时间
	// dwTime = 0;
	dwRet = Dongle_GetDeadline(hDongle, &dwTime);
	printf("Get Deadline time. Return: 0x%08X\n", dwRet);
	if (DONGLE_SUCCESS == dwRet)
	{
		if (dwTime == 0xFFFFFFFF)
		{
			printf("Unlimited time. \n");
		}
		else
		{
			if ((dwTime & 0xFFFF0000) == 0)
			{ // 小时数
				printf("Limit hour: %d. \n", dwTime);
			}
			else
			{ // 日期
				tm = (time_t)dwTime;
				ptm = gmtime(&tm);
				year = ptm->tm_year + 1900;
				mon = ptm->tm_mon + 1;
				day = ptm->tm_mday;
				hour = ptm->tm_hour;
				min = ptm->tm_min;
				sec = ptm->tm_sec;
				printf("Deadline: %04d-%02d-%02d %02d:%02d:%02d \n", year, mon, day, hour, min, sec);
			}
		}
	}
	// 执行可执行文件

#define INOUT_BUF_LENGTH 1024
	DWORD ret =0;
	int rets =0;
	
	WORD fileid = 0x0002;
	char board_name[MAX_OUTPUT_LEN];
    char board_serial[MAX_OUTPUT_LEN];
    char board_vendor[MAX_OUTPUT_LEN];
    char product_name[MAX_OUTPUT_LEN];
    char product_version[MAX_OUTPUT_LEN];
    char product_serial[MAX_OUTPUT_LEN];
    char product_uuid[MAX_OUTPUT_LEN];

    commandOutput("cat /sys/class/dmi/id/board_name", board_name);
    commandOutput("cat /sys/class/dmi/id/board_serial", board_serial);
    commandOutput("cat /sys/class/dmi/id/board_vendor", board_vendor);
    commandOutput("cat /sys/class/dmi/id/product_name", product_name);
    commandOutput("cat /sys/class/dmi/id/product_version", product_version);
    commandOutput("cat /sys/class/dmi/id/product_serial", product_serial);
    commandOutput("cat /sys/class/dmi/id/product_uuid", product_uuid);

	char InOutBuf[INOUT_BUF_LENGTH];
	snprintf(InOutBuf, INOUT_BUF_LENGTH, "board_name:%s,board_serial:%s,board_vendor:%s,product_name:%s,product_version:%s,product_serial:%s,product_uuid:%s", 
	board_name, board_serial, board_vendor, product_name, product_version, product_serial, product_uuid);
	// InoutBuf转换为数组
	unsigned char str[128];
	//unsigned char *str =(unsigned char *)malloc(len * sizeof(unsigned char));
	int i1 = 0;
	for (i1 = 0; i1 < 128; i1++)
	{
		str[i1] = InOutBuf[i1];
	}
	ret = Dongle_RunExeFile(hDongle, fileid,(BYTE *)str, 128, &retcode);
	if (ret == DONGLE_SUCCESS)
	{
		// On success the input buffer should now be changed by Dongle. Print new content.
		printf("The executable ran successfully. The new buffer content is: %s\n", InOutBuf);
	}
	else
	{
		// On failure print the error code
		printf("Executable failed to run. Error code: %u\n", ret);

	}
	// 打印retcode
	printf("retcode:%d\n", retcode);
	// printf("%s\n",str);
	printf("RunExeFile. Return: 0x%08X\n", ret);

	// 关闭加密锁
	dwRet = Dongle_Close(hDongle);
	printf("Close Dongle ARM. Return: 0x%08X\n", dwRet);

	if (pDongleInfo != NULL)
	{
		free(pDongleInfo);
		pDongleInfo = NULL;
	}
	//	getch();
	return retcode;
}

int rsaAuthentication(){
	BYTE buffer[256];
	BYTE tmpbuf[256];
	DWORD dwRet = 0;
	int nCount = 0;
	int i = 0;
	int nInDataLen = 0;
	int nOutDataLen = 0;
	int nIndex = -1;
	int retcode = 0;

	DONGLE_INFO *pDongleInfo = NULL;
	DONGLE_HANDLE hDongle = NULL;

	RSA_PUBLIC_KEY  rsaPub;
	FILE *fp = NULL;
	WORD wPriID = 0x0002;

    // 枚举锁
	dwRet = Dongle_Enum(NULL, &nCount);
	printf("Enum %d Dongle ARM. \n", nCount);
	pDongleInfo = (DONGLE_INFO *)malloc(nCount * sizeof(DONGLE_INFO));
	dwRet = Dongle_Enum(pDongleInfo, &nCount);
	for (i = 0; i < nCount; i++)
	{ // 0xFF表示标准版, 0x00为时钟锁,0x01为带时钟的U盘锁,0x02为标准U盘锁
		if (pDongleInfo[i].m_Type == 0 || pDongleInfo[i].m_Type == 1)
		{
			nIndex = i;
		}
	}
	if (nIndex == -1)
	{ // 没有找到时钟锁
		printf("Can't Find Time Dongle ARM.\n");
		Dongle_Close(hDongle);
		 retcode = 100;
		return retcode;
	}
	// 打开锁
	dwRet = Dongle_Open(&hDongle, 0);
	printf("Open Dongle ARM. Return : 0x%08X . \n", dwRet);

	//生成随机数
	for (i = 0 ; i < 128; i++)
	{
		buffer[i] = rand() % 256;
	}
	nInDataLen = (128-11);
	nOutDataLen = 256;
	memcpy(tmpbuf, buffer, nInDataLen);
	for (i = 0; i < nInDataLen; i++) {
    	printf("%02X ", tmpbuf[i]);
	}

	fp = fopen("public.Rsapub", "rb");
	if (fp == NULL) {
        printf("Error! Unable to open file.\n");
        return -1;
    }
    size_t readSize = fread(&rsaPub, 1, sizeof(RSA_PUBLIC_KEY), fp);

    // Check if the full data had been read
    if (readSize != sizeof(RSA_PUBLIC_KEY)) {
        printf("Error! Only %zu bytes were read out of %zu.\n", readSize, sizeof(RSA_PUBLIC_KEY));
        return -1;
    }
    printf("Public key read successfully.\n");

    // Continue processing public key...

    fclose(fp);


	//rsa加密随机数
	dwRet = Dongle_RsaPub(hDongle, FLAG_ENCODE,&rsaPub,buffer,nInDataLen,buffer,&nOutDataLen);
	printf("RSA public key encode. Return: 0x%08X\n", dwRet);
	for (i = 0; i < nOutDataLen; i++) {
    	printf("%02X ", buffer[i]);
	}

	//rsa私钥解密随机数
	nInDataLen = 256;
	nOutDataLen = (128-11);
	dwRet = Dongle_RsaPri(hDongle,wPriID,FLAG_DECODE,buffer,nInDataLen,buffer,&nOutDataLen);
	printf("RSA private key decode. Return: 0x%08X\n", dwRet);

	//比较解密后的随机数
	if (memcmp(tmpbuf, buffer, nOutDataLen) == 0)
	{   
		printf("the public encode and private decode result is right. \n");
		retcode = 200;
		return retcode;
	}
	else
	{
		printf("the public encode and private decode result is wrong. \n");
		retcode = 500;
		return retcode;
	}

	// 关闭加密锁
	dwRet = Dongle_Close(hDongle);
	printf("Close Dongle ARM. Return: 0x%08X\n", dwRet);

	if (pDongleInfo != NULL)
	{
		free(pDongleInfo);
		pDongleInfo = NULL;
	}

}

int main(int argc, char *argv[])
{   
	//校验license硬件指纹和有效期
	int retcodes=checkLicense(); //retcodes返回值：200表示license有效，100表示无法打开加密锁；300表示硬件指纹校验失败；400表示license过期
    printf("retcodes:%d\n", retcodes);
    if (retcodes!=CHECK_LICENSE_SUCCESS){
        printf("License is valid!\n");
		//验证license失败，退出
		return 0;
    } 

	int retcode =0;
	//动态验证加密锁是否存在，每分钟执行一次
	while(1){
		retcode =rsaAuthentication(); //retcode返回值：200表示加密锁存在，500表示加密锁不存在
		printf("retcode:%d\n", retcode);
		if (retcode!=CHECK_LICENSE_SUCCESS){
			printf("rsaAuthentication is valid!\n");
			break;
		}
		sleep(60);
	}
	return retcode;

    
}
