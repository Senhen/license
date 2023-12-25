#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>

#include <cctype>


#include "NetRockeyARM.h"

//PIN码类型
#define FLAG_USERPIN   			   0 //用户PIN
#define FLAG_ADMINPIN			   1 //开发商PIN


int     Count;
DONGLE_INFO * pKEYList=NULL;
//
DONGLE_HANDLE  hKey=NULL;

static int O_flag = 0;
static int uq_flag[64];
static int index_num;






void StrPrintf(const char * fmt, ...)
{
	va_list vals;
    char buf[1024];
	//
	memset(buf, 0, sizeof(buf));
	//	
	va_start(vals, fmt); 	
	vsprintf(buf, fmt, vals);
	va_end(vals);
	//
//	strcat(buf, "\n");
	//
	printf(buf);
}

unsigned long showRet(const char *name , unsigned long dwRet)
{
	if (DONGLE_SUCCESS != dwRet)
	{
		StrPrintf("\r\n%s retcode=%08X\r\n",name, dwRet);
	}
	else
	{
		StrPrintf("\r\n%s success\r\n",name, dwRet);
	}
	return dwRet;
	
}

void SaveBinFile(char* pname, unsigned char* pbuf, int len)
{
	FILE*  pf;  
	//
	pf = fopen(pname, "wb");
	//
	if(pf) 
	{
		fwrite(pbuf, len, 1, pf);
		//
		fclose(pf);
	}
}

//
void ReadBinFile(char* pname, unsigned char* pbuf, int len)
{
	FILE* pf;
	//
	pf = fopen(pname, "rb");
	//
	if(pf) 
	{
		fread(pbuf, len, 1, pf);
		//
		fclose(pf);
	}
}

void ShowBinHex(unsigned char* pBin, int len)
{
	// Show 16 bytes each line.
	int  i, j ,k, kk;
	int  lLines = len / 16;
	int  lCharInLastLine = 0;
	//
	if(0 != len % 16)
	{
		lCharInLastLine = len - lLines * 16;
	}

	for(i = 0; i < lLines; ++i)
	{
		for(j = 0; j < 16; ++j)
		{
			printf("%02X ", pBin[16 * i + j]);

			if(j == 7)
				printf("- ");
		}

		printf("    ");

/*		for(j = 0; j < 16; ++j)
		{
			if(isprint(pBin[16 * i + j]))
				printf("%c", pBin[16 * i + j]);
			else
				printf(".");
		}*/

		printf("\n");
	}

	if(0 != lCharInLastLine)
	{
		for(j = 0; j < lCharInLastLine; ++j)
		{
			printf("%02X ", pBin[16 * i + j]);

			if(j == 7 && lCharInLastLine > 8)
				printf("- ");
		}

		k = 0;

		k += ((16 - lCharInLastLine) * 3);

		if(lCharInLastLine <= 8)
		{
			k += 2;
		}

		for(kk = 0; kk < k; ++kk)
			printf(" ");

		printf("    ");

	/*	for(j = 0; j < lCharInLastLine; ++j)
		{
			if(isprint(pBin[16 * i + j]))
				printf("%c", pBin[16 * i + j]);
			else
				printf(".");
		}*/

		printf("\n");
	}
	printf("\n");
}


void DongleEnum()
{
	int   i;
	unsigned long dwRet;
	

	dwRet = Dongle_Enum(NULL, &Count);

	if( dwRet != 0 || Count == 0 )
	{
		StrPrintf("ROCKEY-ARM not found, Dongle_Enum(1) = %08X\r\n", dwRet);
		return;
	}

	pKEYList = (DONGLE_INFO *)malloc( sizeof(DONGLE_INFO) * Count);
	dwRet = Dongle_Enum(pKEYList, &Count);  
	
	if( dwRet != 0 )
	{
		StrPrintf("ROCKEY-ARM not found, Dongle_Enum(2) = %08X\r\n", dwRet);
		return;
	}

	for( i=0; i<Count; i++)
	{
		StrPrintf("======KEY: %d======\r\n", i);
		StrPrintf("Version:%04X\r\n", pKEYList[i].m_Ver);
        StrPrintf("BirthDay: ");
		ShowBinHex(pKEYList[i].m_BirthDay, 8); 
		StrPrintf("Agent:  %08X\r\n", pKEYList[i].m_Agent);
		StrPrintf("PID:    %08X\r\n", pKEYList[i].m_PID);
		StrPrintf("UserID: %08X\r\n", pKEYList[i].m_UserID);
		StrPrintf("Mother: %08X\r\n", pKEYList[i].m_IsMother);		
		StrPrintf("HID: ");
		ShowBinHex(pKEYList[i].m_HID, 8);

	}
	//
    StrPrintf("The number of Rockey-ARM : %d \n", i);
	//

	free(pKEYList);

}



void OpenDongle()
{
	int   index;
    unsigned long retcode;
	char  buff;

	//
	if(Count >= 0)
	{
		//memset(buff, 0, sizeof(buff));
		printf("Please Input key's index need to open <0-%d>: ", Count-1);
		//fflush(stdin);
		//buff = getchar();
		//
	    //index = atoi(buff);
	    scanf("%x", &index);
	}
	else
	{
        index = 0;
	}
	//
	retcode = Dongle_Open(&hKey, index);
	if(DONGLE_SUCCESS == retcode)
	{
		O_flag = 1;
		index_num = index;
	}
	// 
	showRet("Dongle_Open()" , retcode);

}

void CloseDongle()
{
	unsigned long retcode;

	//
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
	//	retcode = Dongle_ResetState(hKey);
	//	showRet("Dongle_ResetState()" , retcode);

		retcode = Dongle_Close(hKey);
		if(DONGLE_SUCCESS == retcode)
			O_flag = 0;
		showRet("Dongle_Close()" , retcode); 
	}
}


void  SeedTest()
{
	int    i;
	unsigned long  retcode;
	unsigned char   tmpbuf[256] = "12";
	unsigned char   outbuf[16];

	//
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
		//
		memset(outbuf, 0, sizeof(outbuf));
		//
		retcode = Dongle_Seed(hKey, tmpbuf, strlen((char *)tmpbuf), outbuf);
		showRet("Dongle_Seed()" , retcode);
		//
		ShowBinHex(outbuf, 16);
	}
}

void DongleGenRandom()
{
	unsigned long retcode;
	unsigned char   bybuff[128]= "12";
	int   len_need;

	//
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
		//
		len_need = atoi((char*)bybuff);
		//
		memset(bybuff, 0, sizeof(bybuff));
		//
		retcode = Dongle_GenRandom(hKey , len_need, bybuff); 
		showRet("Dongle_GenRandom()", retcode);
		//
		ShowBinHex(bybuff, len_need);
	}
}

void DongleLEDControl()
{
	unsigned long retcode;

	
	if(O_flag == 0)
		printf(" Rockey-ARM are not open ! \n");
	else
	{
		printf("led  will  off => on => wink \n");

		retcode = Dongle_LEDControl(hKey , LED_OFF);//灭

		showRet("Dongle_LEDControl(LED_OFF)" , retcode); 

		usleep(1000);

		retcode = Dongle_LEDControl(hKey , LED_ON);//亮

		showRet("Dongle_LEDControl(LED_ON)" , retcode);

		usleep(1000);

		retcode = Dongle_LEDControl(hKey , LED_BLINK);//闪

		showRet("Dongle_LEDControl(LED_BLINK)" , retcode);

	}
}

void RSATestIt(unsigned short fileid, PRIKEY_FILE_ATTR* pPFA)
{
	int   i, inlen, outlen;
	unsigned long retcode;
	unsigned char  inbuf[256];
	unsigned char  outbuf[256];
	RSA_PUBLIC_KEY  pub_key;
    RSA_PRIVATE_KEY pri_key;

	//
	memset(&pub_key, 0, sizeof(pub_key));
	memset(&pri_key, 0, sizeof(pri_key));
	//
	inlen = (pPFA->m_Size / 8) - 11;
	//
    memset(inbuf, 0, sizeof(inbuf));	
	//
	for(i=0; i<inlen; i++)
	{
        inbuf[i] = i;
	}

	if(pPFA->m_Size == 1024)
		ReadBinFile("Pubkey24.bin", (unsigned char*)&pub_key, sizeof(RSA_PUBLIC_KEY));
	else
		ReadBinFile("Pubkey48.bin", (unsigned char*)&pub_key, sizeof(RSA_PUBLIC_KEY));
    //
	StrPrintf("Plaintext data: \n");
    ShowBinHex(inbuf, inlen); 
	
	//私钥加密(签名)
	memset(outbuf, 0, sizeof(outbuf));
	outlen  = sizeof(outbuf);
	retcode = Dongle_RsaPri(hKey, fileid, FLAG_ENCODE, inbuf, inlen, outbuf, &outlen);
	showRet("Dongle_RsaPri(FLAG_ENCODE)", retcode); 
	if(retcode != 0) return;

	StrPrintf("Private key encryption result: \n");
	ShowBinHex(outbuf, outlen);

	//公钥解密(验签)
	memset(inbuf, 0, sizeof(inbuf));
	inlen = outlen;
	memcpy(inbuf, outbuf, inlen);
    memset(outbuf, 0, sizeof(outbuf));
	outlen  = sizeof(outbuf);
	retcode = Dongle_RsaPub(hKey, FLAG_DECODE, &pub_key, inbuf, inlen, outbuf, &outlen);
	showRet("Dongle_RsaPub(FLAG_DECODE)", retcode); 
	if(retcode != 0) return;

	StrPrintf("Public key to decrypt the result: \n");
	ShowBinHex(outbuf, outlen);

	//公钥加密
    memset(inbuf, 0, sizeof(inbuf));
	inlen = outlen;
	memcpy(inbuf, outbuf, inlen);
    memset(outbuf, 0, sizeof(outbuf));
	outlen  = sizeof(outbuf);
	retcode = Dongle_RsaPub(hKey, FLAG_ENCODE, &pub_key, inbuf, inlen, outbuf, &outlen);
	showRet("Dongle_RsaPub(FLAG_ENCODE)", retcode); 
	if(retcode != 0) return;

	StrPrintf("Public key encryption result: \n");
	ShowBinHex(outbuf, outlen);

	//私钥解密
	memset(inbuf, 0, sizeof(inbuf));
	inlen = outlen;
	memcpy(inbuf, outbuf, inlen);
    memset(outbuf, 0, sizeof(outbuf));
	outlen  = sizeof(outbuf);
	retcode = Dongle_RsaPri(hKey, fileid, FLAG_DECODE, inbuf, inlen, outbuf, &outlen);
	showRet("Dongle_RsaPri(FLAG_DECODE)", retcode);
	if(retcode != 0) return;
    //

	StrPrintf("Private key to decrypt the result: \n");
	ShowBinHex(outbuf, outlen);
}

void  RSATest()
{
	PRIKEY_FILE_ATTR pfa;
	//===============================

	//========1024位测试
    memset(&pfa, 0, sizeof(pfa));
	//
	pfa.m_Type = FILE_PRIKEY_RSA;
	pfa.m_Size = 1024;
	pfa.m_Lic.m_Count      = -1;
	pfa.m_Lic.m_IsDecOnRAM = 0;
	pfa.m_Lic.m_IsReset    = 0;
	pfa.m_Lic.m_Priv       = 0;
	//
	RSATestIt(0x1001, &pfa);

    //========2048位测试
    memset(&pfa, 0, sizeof(pfa));
	//
	pfa.m_Type = FILE_PRIKEY_RSA;
	pfa.m_Size = 2048;
	pfa.m_Lic.m_Count      = -1;
	pfa.m_Lic.m_IsDecOnRAM = 0;
	pfa.m_Lic.m_IsReset    = 0;
	pfa.m_Lic.m_Priv       = 0;
	//
	RSATestIt(0x1002, &pfa);

	
}

void ECCTestIt(unsigned short fileid, PRIKEY_FILE_ATTR* pPFA)
{
	int   len_hash;
	unsigned long retcode;
	ECCSM2_PUBLIC_KEY  pub_key;
    ECCSM2_PRIVATE_KEY pri_key;
	unsigned char  hash[32];
	unsigned char  sign[64];

	if(pPFA->m_Size == 192)
		ReadBinFile("Pubkey192.bin", (unsigned char*)&pub_key, sizeof(RSA_PUBLIC_KEY));
	else
		ReadBinFile("Pubkey256.bin", (unsigned char*)&pub_key, sizeof(RSA_PUBLIC_KEY));

    memset(hash, 0, sizeof(hash));
	memset(sign, 0, sizeof(sign));
	//
	len_hash = 16;
	memcpy(hash, "\x47\xED\x73\x3B\x8D\x10\xBE\x22\x5E\xCE\xBA\x34\x4D\x53\x35\x86", 16);
	StrPrintf("Hash: \r\n");
	ShowBinHex(hash, 32);
	//

	retcode = Dongle_EccSign(hKey, fileid, hash, len_hash, sign);
	showRet("Dongle_EccSign()", retcode);
	if(retcode != 0) return;
	
	StrPrintf("Sign(R:S): \r\n");
	ShowBinHex(sign, 64);
	//
	retcode = Dongle_EccVerify(hKey, &pub_key, hash, len_hash, sign);
	showRet("Dongle_EccVerify()", retcode);
}

void ECCTest()
{
	PRIKEY_FILE_ATTR pfa;


    //========256位测试
    memset(&pfa, 0, sizeof(pfa));
	//
	pfa.m_Type = FILE_PRIKEY_ECCSM2;
	pfa.m_Size = 256;
	pfa.m_Lic.m_Count      = -1;
	pfa.m_Lic.m_IsDecOnRAM = 0;
	pfa.m_Lic.m_IsReset    = 0;
	pfa.m_Lic.m_Priv       = 0;
	//
	ECCTestIt(0x2001, &pfa);
	
    //========192位测试
    memset(&pfa, 0, sizeof(pfa));
	//
	pfa.m_Type = FILE_PRIKEY_ECCSM2;
	pfa.m_Size = 192;
	pfa.m_Lic.m_Count      = -1;
	pfa.m_Lic.m_IsDecOnRAM = 0;
	pfa.m_Lic.m_IsReset    = 0;
	pfa.m_Lic.m_Priv       = 0;
	//
	ECCTestIt(0x2002, &pfa);
}

void TDESTest()
{
    int   i;
	unsigned long retcode;
	unsigned char  tmpbuf[128];

	//	
    for(i=0; i<sizeof(tmpbuf); i++)
	{
		tmpbuf[i] = i;
	}
	//
	StrPrintf("Plaintext : \r\n");
	ShowBinHex(tmpbuf, sizeof(tmpbuf));
	//
    retcode = Dongle_TDES(hKey, 0x0004, FLAG_ENCODE, tmpbuf, tmpbuf, sizeof(tmpbuf));
	//
    showRet("Dongle_TDES ENCODE" , retcode); 
	//
	StrPrintf("Encrypted: \r\n");
	ShowBinHex(tmpbuf, sizeof(tmpbuf));
	//============	
    retcode = Dongle_TDES(hKey, 0x0004, FLAG_DECODE, tmpbuf, tmpbuf, sizeof(tmpbuf));
    //
    showRet("Dongle_TDES DECODE" , retcode); 
	//
	StrPrintf("Decrypted: \r\n");
	ShowBinHex(tmpbuf, sizeof(tmpbuf));	
}

//==================================
#define		MAXSIZE		8
#define     PARAMNUM    8
//
#define     TYPE_DOUBLE     0
#define     TYPE_INTEGER    1
#define     TYPE_FLOAT      2
#define     TYPE_LONG       3
#define		TYPE_BYTE		4

//
typedef struct
{
	union
	{
	   unsigned char	   buffer[8];	//数据
	   double  m_double;	   
	   float   m_float;
	   int     m_int;
	   unsigned char    m_long[8];
	   unsigned char    m_byte;
	};
    //
	unsigned long	type;			//数据类型
}Param;
//
typedef struct
{
	Param data[MAXSIZE];
	int	top;
}COS_Stack;
//
typedef struct
{
    Param      InputParam[PARAMNUM];
	Param	   Constant[PARAMNUM];
    COS_Stack  InStatck;
}InParam;       //输入参数
//
typedef struct
{
    Param      OutputParam[PARAMNUM];
    COS_Stack  OutStatck;
}OutParam;      //输出参数



double ReverseDouble(double num)
{
	double  result;
    unsigned long*  pd;
	unsigned long*  presult;
	//
	pd      = (unsigned long*) &num;
	presult = (unsigned long*) &result;
	//
	presult[0] = pd[1];
	presult[1] = pd[0];
	//
	return result;
}

void encrypttest()
{
	char   bInput;

	
	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{

		RSATest();
		sleep(1);

		ECCTest();
		sleep(1);

		TDESTest();
		sleep(1);

	}
}


void ReadFiles()
{
	unsigned long  retcode;
	int    FileSize=10;
	unsigned char   FileBuff[1024];

	
	retcode = Dongle_ReadFile(hKey, FILE_DATA,  0x0001,  FileBuff, FileSize);
	
	showRet("Dongle_ReadFile(FILE_DATA)" , retcode);
}

void RunExeFile()
{
	printf(" no complete !\n");
}

void filetest()
{
	char   bInput;


	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
		ReadFiles();
		sleep(1);

		RunExeFile();
		sleep(1);

	}

}


void memorytest()
{
	unsigned long retcode;
	int   offset;
	int   len;
	int i=0;
	char  buf[16] = "125";
	unsigned char  bin_buf[128];	

	//
	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{
	
		offset = atoi(buf);
		//
		len = atoi(buf);
		//
		printf("Gen data for write: \r\n");
		for( i=0; i<len; i++)
		{
			bin_buf[i] = i;
		}
		ShowBinHex(bin_buf, len);
		//	
		retcode = Dongle_WriteData(hKey, offset, bin_buf, len);	
		showRet("Dongle_WriteData()" , retcode);
		
		memset(bin_buf, 0, sizeof(bin_buf));
		retcode = Dongle_ReadData(hKey, offset, bin_buf, len);
		showRet("Dongle_ReadData()" , retcode);
		ShowBinHex(bin_buf, len);
		
	}
}


//公钥
static unsigned char s_byte_n[128] = {
	    //宋浩提供
        /*
		0x6B,0xE6,0x87,0x41,0x75,0xE0,0xA8,0x73,0x34,0xBE,0xE2,0x71,0x40,0x26,0xC9,0x81,
		0xF5,0x11,0x53,0xC9,0x25,0xC5,0xF3,0x8A,0x57,0x23,0xB5,0xB0,0xC7,0x7D,0x49,0xAD,
		0xE5,0xDF,0x51,0x5F,0x84,0xE5,0x38,0xA8,0x34,0x32,0xDF,0x6A,0x07,0x5A,0xC1,0x73,
		0xD4,0xAE,0xF7,0x6C,0xB6,0x40,0x71,0xFF,0x92,0xB7,0x21,0x0C,0x25,0x71,0x50,0x7A,
		0x88,0xA8,0x00,0xCB,0xC9,0x3A,0x0C,0x48,0xFC,0xB5,0xF6,0xF8,0x5E,0x9B,0x2B,0xE3,
		0x26,0x84,0x4D,0x18,0x2B,0xBA,0x57,0x88,0x5B,0x62,0x8B,0xA7,0x26,0x31,0x6C,0x67,
		0x2A,0x6D,0x33,0xE1,0xDE,0xF1,0x99,0x6B,0xF8,0x6D,0xBC,0xC9,0x22,0x56,0x70,0xD4,
		0x8A,0x8B,0xF1,0xF5,0x2C,0x3E,0x9D,0x5F,0xA8,0xC0,0xB0,0xA5,0xE0,0x51,0xD7,0xC9
		*/
	    //麻宝华工具生成
	    0xC5,0x6D,0x9E,0x1C,0x52,0x08,0x18,0x11,
		0x3F,0xE6,0x75,0x3D,0x80,0xA5,0xA9,0xC8,
		0x65,0xD8,0x0F,0xBE,0x90,0xD1,0x3E,0xA0,
		0x29,0x91,0xF2,0x39,0xEC,0x4E,0x6C,0x1F,
		0xC6,0x1D,0x3A,0xB1,0x43,0xDF,0x63,0xEA,
		0x22,0x65,0x23,0x8A,0x8E,0x9D,0x2A,0x54,
		0x54,0xFE,0xC8,0x04,0x31,0xF0,0xBC,0xE7,
		0xD9,0x62,0xD7,0x83,0x56,0x09,0xC9,0x36,
		0xB0,0xB5,0x45,0xB1,0xF7,0xD6,0xC5,0xFF,
		0x41,0xED,0x8C,0x94,0xF3,0xD2,0x05,0x1F,
		0x44,0x4F,0x9C,0xB7,0x1C,0xAE,0x05,0xF5,
		0x1E,0x76,0xF7,0x21,0x9B,0x3C,0x06,0x53,
		0xC4,0x6A,0x77,0xE7,0x99,0xE2,0x58,0x21,
		0x70,0x39,0x29,0xEB,0x01,0x9C,0xB9,0x07,
		0x31,0xBE,0xEA,0xB0,0xD0,0x6C,0x5C,0x71,
		0x6C,0xB9,0xA2,0xB1,0xF3,0xE0,0x91,0xED 

};

//私钥
static unsigned char s_byte_d[128] = {
	    //宋浩提供
	    /*
		0xC1,0x1F,0x9D,0xB2,0x3A,0x17,0xD1,0x15,0x99,0xC0,0xC0,0xC0,0x14,0x1C,0x60,0x85,
		0x0F,0x4E,0xFA,0x38,0x3D,0xE5,0x3C,0x71,0xA1,0x6E,0x57,0xDD,0x0D,0xC6,0xB1,0xCC,
		0xF9,0xB0,0xB8,0xB1,0xDD,0x47,0xDE,0x2D,0x25,0x5A,0xF1,0xDF,0xC1,0x26,0x47,0xD2,
		0xA0,0x23,0x37,0x9F,0x2C,0x5C,0xA3,0x4F,0xCE,0x42,0xDD,0xD3,0xEB,0xE2,0x81,0x04,
		0xD7,0xC1,0x7C,0x19,0x0F,0x8C,0x78,0xED,0x98,0x40,0x24,0x23,0xBF,0xF1,0x3A,0x3E,
		0xC5,0x79,0x12,0x62,0xFC,0xED,0xFE,0x89,0xAF,0x46,0xED,0xF4,0xE9,0x48,0xAE,0x72,
		0x81,0x0F,0x26,0x92,0x80,0xC7,0x61,0xC3,0xA3,0x7D,0xFA,0x9D,0x66,0x4A,0x55,0x4C,
		0x0E,0xA4,0xE9,0x44,0x9E,0x7C,0x69,0x6F,0x75,0xD8,0xB7,0xD4,0xBE,0x0E,0x79,0x3D
		*/
        //麻宝华工具生成
	    0x27,0x10,0x0C,0x53,0xA0,0x2B,0x77,0xCF, 
		0x99,0xEC,0x18,0x50,0x65,0xEE,0xE1,0x4C, 
		0x04,0x52,0x9E,0xB2,0xDE,0xE6,0x77,0xD4, 
		0xAA,0xC4,0xF4,0xBF,0x5F,0x31,0x19,0x15, 
		0xA4,0x56,0x4E,0x31,0x9A,0xB3,0x4D,0x8A, 
		0x9A,0xE9,0x96,0x01,0xA9,0x3C,0x11,0x8F, 
		0x04,0x0E,0x31,0x37,0x1B,0x46,0x7D,0xAA, 
		0x06,0x0A,0x17,0x88,0x25,0xF2,0xE3,0xBB, 
		0xB4,0x06,0x56,0xFC,0x48,0x4B,0x5F,0xE4, 
		0x50,0x2E,0x97,0xBB,0x86,0x05,0x32,0x36, 
		0xFF,0x30,0xAA,0x1A,0x68,0x87,0x6A,0xC0, 
		0xF0,0xC3,0xFA,0x2B,0x9E,0x6A,0xBF,0x27, 
		0xB9,0x4E,0xE7,0xA5,0xCF,0xB7,0x77,0xC1, 
		0x60,0xE7,0x80,0x06,0x90,0x72,0x41,0x49, 
		0x03,0x24,0x27,0x7B,0xD1,0x71,0xB6,0x7F, 
        0x1E,0x2F,0xCF,0xAB,0x71,0x4B,0xFD,0x65
};



void authoritytest()
{
	int    i;
	unsigned long  retcode;
	char   User_PIN2[16]="87654321";
	int    RemainCount;   
	unsigned char   Seedbuf[256];
	char   PIDbuf[16];
    char   AdminPswdbuf[32];
	unsigned long  pdwUTCTime[32];
	unsigned long  pdwTime[32];

	//	
	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{

		retcode = Dongle_GetUTCTime(hKey, pdwUTCTime);
		showRet("Dongle_GetUTCTime()" , retcode);
	
		retcode = Dongle_GetDeadline(hKey, pdwTime);
		showRet("Dongle_GetUTCTime()" , retcode);


		
	}
}


void VerifyPin()
{
	int    i;
	unsigned long  retcode;
    char   Pswdbuf[32] = "12345678";
	int    RemainCount;   
	//
	unsigned char   Seedbuf[256];
	char   PIDbuf[16];
    char   AdminPswdbuf[32];


	if(O_flag == 0)
		printf("Rockey-ARM are not open !\n");
	else
	{

		retcode = Dongle_VerifyPin(hKey,FLAG_USERPIN, Pswdbuf, &RemainCount);
		printf("Dongle_VerifyPIN(FLAG_USERPIN), retcode=%08X, RemainCount=%d\r\n", retcode, RemainCount);	       

	}
}


//================================================
//#ifdef BUILD_FULL

//通讯公钥N
const  unsigned char comm_rsa_nn[128] = {
	    0xC5, 0x6D, 0x9E, 0x1C, 0x52, 0x08, 0x18, 0x11,
		0x3F, 0xE6, 0x75, 0x3D, 0x80, 0xA5, 0xA9, 0xC8,
		0x65, 0xD8, 0x0F, 0xBE, 0x90, 0xD1, 0x3E, 0xA0,
		0x29, 0x91, 0xF2, 0x39, 0xEC, 0x4E, 0x6C, 0x1F,
		0xC6, 0x1D, 0x3A, 0xB1, 0x43, 0xDF, 0x63, 0xEA,
		0x22, 0x65, 0x23, 0x8A, 0x8E, 0x9D, 0x2A, 0x54,
		0x54, 0xFE, 0xC8, 0x04, 0x31, 0xF0, 0xBC, 0xE7,
		0xD9, 0x62, 0xD7, 0x83, 0x56, 0x09, 0xC9, 0x36,
		0xB0, 0xB5, 0x45, 0xB1, 0xF7, 0xD6, 0xC5, 0xFF,
		0x41, 0xED, 0x8C, 0x94, 0xF3, 0xD2, 0x05, 0x1F,
		0x44, 0x4F, 0x9C, 0xB7, 0x1C, 0xAE, 0x05, 0xF5,
		0x1E, 0x76, 0xF7, 0x21, 0x9B, 0x3C, 0x06, 0x53,
		0xC4, 0x6A, 0x77, 0xE7, 0x99, 0xE2, 0x58, 0x21,
		0x70, 0x39, 0x29, 0xEB, 0x01, 0x9C, 0xB9, 0x07,
		0x31, 0xBE, 0xEA, 0xB0, 0xD0, 0x6C, 0x5C, 0x71,
		0x6C, 0xB9, 0xA2, 0xB1, 0xF3, 0xE0, 0x91, 0xED
};

//通讯私钥D
const  unsigned char comm_rsa_dd[128] = {
	    0x27, 0x10, 0x0C, 0x53, 0xA0, 0x2B, 0x77, 0xCF, 
		0x99, 0xEC, 0x18, 0x50, 0x65, 0xEE, 0xE1, 0x4C, 
		0x04, 0x52, 0x9E, 0xB2, 0xDE, 0xE6, 0x77, 0xD4, 
		0xAA, 0xC4, 0xF4, 0xBF, 0x5F, 0x31, 0x19, 0x15, 
		0xA4, 0x56, 0x4E, 0x31, 0x9A, 0xB3, 0x4D, 0x8A, 
		0x9A, 0xE9, 0x96, 0x01, 0xA9, 0x3C, 0x11, 0x8F, 
		0x04, 0x0E, 0x31, 0x37, 0x1B, 0x46, 0x7D, 0xAA, 
		0x06, 0x0A, 0x17, 0x88, 0x25, 0xF2, 0xE3, 0xBB, 
		0xB4, 0x06, 0x56, 0xFC, 0x48, 0x4B, 0x5F, 0xE4, 
		0x50, 0x2E, 0x97, 0xBB, 0x86, 0x05, 0x32, 0x36, 
		0xFF, 0x30, 0xAA, 0x1A, 0x68, 0x87, 0x6A, 0xC0, 
		0xF0, 0xC3, 0xFA, 0x2B, 0x9E, 0x6A, 0xBF, 0x27, 
		0xB9, 0x4E, 0xE7, 0xA5, 0xCF, 0xB7, 0x77, 0xC1, 
		0x60, 0xE7, 0x80, 0x06, 0x90, 0x72, 0x41, 0x49, 
		0x03, 0x24, 0x27, 0x7B, 0xD1, 0x71, 0xB6, 0x7F, 
		0x1E, 0x2F, 0xCF, 0xAB, 0x71, 0x4B, 0xFD, 0x65
};

//#endif
//================================================
int  main(int argc, char* argv[])
{ 

		DongleEnum();
		sleep(1);

		OpenDongle();
		sleep(1);

        SeedTest();
		sleep(1);

		DongleGenRandom();
		sleep(1);

		DongleLEDControl();
		sleep(1);

		filetest();
		sleep(1);

		encrypttest();
		sleep(1);

		authoritytest();
		sleep(1);

		memorytest();
		sleep(1);

		VerifyPin();
		sleep(1);

		CloseDongle();
		sleep(1);

	
	return 0;
}


