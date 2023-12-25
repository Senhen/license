#ifndef _NETROCKEYARM_H_
#define _NETROCKEYARM_H_


#ifdef __cplusplus
extern "C" {
#endif


//加密锁的句柄
typedef void*   DONGLE_HANDLE;

//x 锁的索引 y 模块号
#define MAKEDWORD(x,y)((unsigned long)(((unsigned long)(x)<<16)&0xFFFF0000)|(unsigned long)(((unsigned long)(y)&0x0000FFFF)))
		
//错误码
#define   DONGLE_SUCCESS                       0x00000000          // 操作成功
#define   DONGLE_NOT_FOUND                     0xF0000001          // 未找到指定的设备
#define   DONGLE_INVALID_HANDLE				   0xF0000002		   // 无效的句柄
#define   DONGLE_INVALID_PARAMETER			   0xF0000003		   // 参数错误
#define   DONGLE_COMM_ERROR					   0xF0000004		   // 通讯错误
#define   DONGLE_INSUFFICIENT_BUFFER		   0xF0000005		   // 缓冲区空间不足
#define   DONGLE_NOT_INITIALIZED               0xF0000006		   // 产品尚未初始化 (即没设置PID)
#define   DONGLE_ALREADY_INITIALIZED		   0xF0000007		   // 产品已经初始化 (即已设置PID)
#define   DONGLE_ADMINPIN_NOT_CHECK			   0xF0000008		   // 开发商密码没有验证
#define   DONGLE_USERPIN_NOT_CHECK			   0xF0000009		   // 用户密码没有验证
#define   DONGLE_INCORRECT_PIN				   0xF000FF00		   // 密码不正确 (后2位指示剩余次数)
#define   DONGLE_PIN_BLOCKED				   0xF000000A		   // PIN码已锁死
#define   DONGLE_ACCESS_DENIED				   0xF000000B		   // 访问被拒绝 
#define   DONGLE_FILE_EXIST					   0xF000000E		   // 文件已存在
#define   DONGLE_FILE_NOT_FOUND				   0xF000000F		   // 未找到指定的文件
#define	  DONGLE_READ_ERROR                    0xF0000010          // 读取数据错误
#define	  DONGLE_WRITE_ERROR                   0xF0000011          // 写入数据错误
#define	  DONGLE_FILE_CREATE_ERROR             0xF0000012          // 创建文件错误
#define	  DONGLE_FILE_READ_ERROR               0xF0000013          // 读取文件错误
#define	  DONGLE_FILE_WRITE_ERROR              0xF0000014          // 写入文件错误
#define	  DONGLE_FILE_DEL_ERROR                0xF0000015          // 删除文件错误
#define   DONGLE_FAILED                        0xF0000016          // 操作失败
#define   DONGLE_CLOCK_EXPIRE                  0xF0000017          // 加密锁时钟到期
#define   DONGLE_ERROR_UNKNOWN		           0xFFFFFFFF		   // 未知的错误

//网络锁相关操作
#define	  DONGLE_FAILED_NET_CONNECTED		   0xF0000018			//已经建立连接
#define   DONGLE_FAILED_NET_FULL			   0xF0000019			//连接数已满
#define	  DONGLE_FAILED_NET_NOTFINDNETLOCK	   0xF0000020			//没有找到可用的网络加密锁
#define	  DONGLE_FAILED_NET_NOCONNECTED		   0xF0000021			//还没有建立连接
#define	  DONGLE_FAILED_NET_DELETED			   0xF0000022			//客户端已经断开
#define	  DONGLE_FAILED_NET_DENIED			   0xF0000023			//客户被拒绝访问服务器

//网络通讯返回值
#define   R_CONNECTFAILED					   0xC0000001	        //连接失败
#define   R_SENDDATAFAILED					   0xC0000002	        //发送数据失败
#define   R_SENDDATATIMEOUT					   0xC0000003	        //发送数据超时
#define   R_CREATESOCKETFAILED				   0xC0000004	        //创建套接字失败
#define   R_RECVDATATIMEOUT					   0xC0000005	        //接收数据超时
#define   R_RECVDATAERROR					   0xC0000006	        //接收数据错误

//出厂时默认的USERPIN
#define CONST_USERPIN              "12345678"


#define LED_OFF			           0 //灯灭
#define LED_ON			           1 //灯亮
#define LED_BLINK		           2 //灯闪

//文件类型定义
#define FILE_DATA                  1 //普通数据文件
#define FILE_PRIKEY_RSA            2 //RSA私钥文件
#define FILE_PRIKEY_ECCSM2         3 //ECC或者SM2私钥文件(SM2私钥文件和ECC私钥文件结构相同，属相同文件类型)
#define FILE_KEY                   4 //SM4和3DES密钥文件
#define FILE_EXE                   5 //可执行文件


#define FLAG_ENCODE                0 //加密
#define FLAG_DECODE                1 //解密

/**   
 *   锁内文件说明
 *   1.RSA私钥文件允许创建的最大数量为8个
 *   2.ECCSM2私钥文件允许创建的最大数量为16个
 *   3.3DES/SM4密钥文件允许创建的最大数量为32个
 *   4.可执行文件允许创建的最大数量为64个,总大小不能超过64K
 *   5.数据文件创建个数受锁内空间大小和文件系统其他因素的影响，文件最大个数不超过54个。    
 *   6.文件ID取值范围为0x0000~0xFFFF之间，其中ID：0x0000、0xFFFF、0x3F00被锁内系统占用，用户不能使用。
 */


//RSA公钥格式(兼容1024,2048)
typedef struct {
	unsigned int  bits;                   // length in bits of modulus
	unsigned int  modulus;				  // modulus
	unsigned char exponent[256];          // public exponent
} RSA_PUBLIC_KEY;

//RSA私钥格式(兼容1024,2048)
typedef struct {
	unsigned int  bits;                   // length in bits of modulus
	unsigned int  modulus;                // modulus
	unsigned char publicExponent[256];    // public exponent
	unsigned char exponent[256];          // private exponent
} RSA_PRIVATE_KEY;

//外部ECC公钥格式 (兼容192,256)
typedef struct{
	unsigned int bits;                    // length in bits of modulus
	unsigned int XCoordinate[8];          // 曲线上点的X坐标
	unsigned int YCoordinate[8];          // 曲线上点的Y坐标
} ECCSM2_PUBLIC_KEY;

//外部ECC私钥格式 (兼容192,256)
typedef struct{
	unsigned int bits;                    // length in bits of modulus
	unsigned int PrivateKey[8];           // 私钥
} ECCSM2_PRIVATE_KEY;

//锁的信息
typedef struct
{	
	unsigned short  m_Ver;               //COS版本,比如:0x0201,表示2.01版    
	unsigned char   m_BirthDay[8];       //出厂日期(BCD码的年月日时分秒)
	unsigned int    m_Agent;             //代理商编号,比如:默认的0xFFFFFFFF
	unsigned int    m_PID;               //产品ID
	unsigned int    m_UserID;            //用户ID
	unsigned char   m_HID[8];            //8字节的硬件ID
	int            m_IsMother;          //母锁标志: 1表示是母锁, 0表示不是母锁     
	//
	unsigned short  m_Reserve;           //保留,用于4字节对齐
} DONGLE_INFO;

//私钥文件授权结构
typedef struct
{
	long           m_Count;        //可调次数: 0xFFFFFFFF表示不限制, 递减到0表示已不可调用
	unsigned char  m_Priv;         //调用权限: 0为最小匿名权限，1为最小用户权限，2为最小开发商权限
	unsigned char  m_IsDecOnRAM;   //是否是在内存中递减: 1为在内存中递减，0为在FLASH中递减
	unsigned char  m_IsReset;      //用户态调用后是否自动回到匿名态: TRUE为调后回到匿名态 (开发商态不受此限制)
	unsigned char  m_Reserve;      //保留,用于4字节对齐

} PRIKEY_LIC;


//ECCSM2/RSA私钥文件属性数据结构
typedef struct
{
	unsigned short  m_Type;       //数据类型:ECCSM2私钥 或 RSA私钥
	unsigned short  m_Size;       //数据长度:RSA该值为1024或2048, ECC该值为192或256, SM2该值为0x8100
	PRIKEY_LIC      m_Lic;        //授权
	
} PRIKEY_FILE_ATTR;


/** 
* @brief  枚举网络锁。枚举出服务器端所有的网络加密锁
*
* @param  pDongleInfo     [out]     设备信息的数组。当此参数为NULL时, pCount返回找到的设备的数目。
* @param  pCount 	      [out]     设备数目。该函数最多可以同时枚举出32个HID设备和32个CCID设备。
*
* @return DONGLE_SUCCESS            执行成功。
*/
unsigned long  Dongle_Enum(DONGLE_INFO * pDongleInfo, int * pCount);

/**
* @brief  打开指定的加密锁的指定模块号。
*
* @param  phDongle     [out]     句柄指针。如果打开成功,会被填充。
* @param  nIndex       [in]      包含指定的加密锁和模块号 其中高字为锁索引，低字为模块号
*
* @return DONGLE_SUCCESS         打开成功。
*/
unsigned long  Dongle_Open(DONGLE_HANDLE * phDongle, int nIndex);

/**
* @brief  关闭打开的加密锁。
*
* @param  hDongle     [in]     打开的加密锁句柄。
*
* @return DONGLE_SUCCESS       关闭成功。
*/
unsigned long  Dongle_Close(DONGLE_HANDLE hDongle);

/**
* @brief  产生随机数。匿名权限即可操作。
*
* @param  hDongle          [in]      打开的加密锁句柄。
* @param  nLen             [in]      要产生的随机数的长度。nLen的取值范围为 1~128。
* @param  pRandom          [out]     随机数缓冲区。
*
* @return DONGLE_SUCCESS             获取随机数成功。
*/
unsigned long  Dongle_GenRandom(DONGLE_HANDLE hDongle, int nLen, unsigned char * pRandom);

/**
* @brief  LED灯的控制操作。匿名权限即可操作。
*
* @param  hDongle     [in]     打开的加密锁句柄。
* @param  nFlag       [in]     控制类型。例如：nFlag = LED_ON，表示控制LED为亮的状态；
*                              nFlag = LED_OFF，表示控制LED为灭的状态；nFlag = LED_BLINK，
*                              表示控制LED为闪烁的状态。
*
* @return DONGLE_SUCCESS       命令执行成功。
*/
unsigned long  Dongle_LEDControl(DONGLE_HANDLE hDongle, int nFlag);

/**
* @brief  读取加密锁内的数据文件。数据文件的读取权限取决于创建时的设定。
*
* @param  hDongle      [in]         打开的加密锁句柄。
* @param  wFileID      [in]         文件ID。
* @param  wOffset      [in]         文件偏移量。
* @param  pOutData     [in]         数据缓冲区。
* @param  nDataLen     [out]        参数pOutData的长度。读取的最大长度不能超过1024个字节
*
* @return DONGLE_SUCCESS            读取数据文件成功  
*/
unsigned long  Dongle_ReadFile(DONGLE_HANDLE hDongle, unsigned short wFileID, unsigned short wOffset, unsigned char* pOutData, int nDataLen);


/**
* @brief  校验密码
*
* @param  hDongle		   [in]       打开的加密锁句柄。
* @param  nFlags           [in]       PIN码类型。参数取值为FLAG_USERPIN或者FLAG_ADMINPIN。
* @param  pPIN             [in]       PIN码。
* @param  pRemainCount     [out]      剩余重试次数。返回0表示已锁死；1~253表示剩余次数；255表示不限制重试次数。
*
* @return DONGLE_SUCCESS              校验成功。如果校验失败，函数的返回值中也含有剩余的重试次数，
*                                     (错误码 & 0xFFFFFF00) == DONGLE_INCORRECT_PIN，即后两位表示剩余次数。
*/
unsigned long  Dongle_VerifyPin(DONGLE_HANDLE hDongle, int nFlags, char* pPIN, int* pRemainCount);

/**
* @brief  读取锁内数据区数据。数据区大小共8k，前4k(0~4095)的读写没有权限限制，后4k(4096~8191)任意权限可读，
*         但是只有开发商权限可写。
* 
* @param  hDongle      [in]      打开的加密锁句柄。
* @param  nOffset      [in]      起始偏移。范围在0~8191
* @param  pData        [out]     读取的数据缓冲区。
* @param  nDataLen     [in]      参数pData的缓冲区大小。最大不能超过1024个字节
*
* @return  DONGLE_SUCCESS        读取数据区数据成功。 
*/
unsigned long  Dongle_ReadData(DONGLE_HANDLE hDongle, int nOffset, unsigned char* pData, int nDataLen);

/**
* @brief  写入锁内数据区数据。数据区大小共8k，前4k(0~4095)的读写没有权限限制，后4k(4096~8191)任意权限可读，
*         但是只有开发商权限可写。
* 
* @param  hDongle      [in]      打开的加密锁句柄。
* @param  nOffset      [in]      起始偏移。范围在0~8191
* @param  pData        [in]      写入的数据缓冲区。
* @param  nDataLen     [in]      参数pData的缓冲区大小。最大不能超过1024个字节
*
* @return  DONGLE_SUCCESS        写入数据区数据成功。 
*/
unsigned long  Dongle_WriteData(DONGLE_HANDLE hDongle, int nOffset, unsigned char* pData, int nDataLen);

/**
* @brief  RSA私钥运算。函数的使用权限取决于锁内RSA私钥文件的权限，在RSA私钥文件创建时设定。说明：
*         1.对于加密运算,输入数据长度必须小于私钥ID为wPriFileID的密钥长度减去11,以便在函数内部进行padding
*         2.对于解密运算,输入数据长度必须与wPriFileID中指示的密钥长度相一致(比如1024位密钥时为128，2048时为256)
*         3.加密时内部padding方式为:PKCS1_TYPE_1 (即第二个字节为0x01,空数据填充0XFF)   
*
* @param  hDongle         [in]         打开的加密锁句柄。
* @param  wPriFileID      [in]         RSA私钥文件ID。
* @param  nFlag           [in]         运算类型。例如，FLAG_ENCODE表示加密运算；FLAG_DECODE表示解密运算。
* @param  pInData         [in]         输入数据。
* @param  nInDataLen      [in]         参数pInData的大小
* @param  pOutData        [out]        输出数据缓冲区。
* @param  pOutDataLen     [in,out]     参数pOutData的大小和返回的数据大小。
*
* @return DONGLE_SUCCESS               RSA私钥运算成功。 
*/
unsigned long  Dongle_RsaPri(DONGLE_HANDLE hDongle, unsigned short wPriFileID, int nFlag, unsigned char* pInData, int nInDataLen, unsigned char* pOutData, int* pOutDataLen);

/**
* @brief  RSA公钥运算。匿名权限可调用。说明：
*         1.对于加密运算,输入数据长度必须小于pPubKey中指示的密钥长度-11,以便在函数内部进行padding
*         2.对于解密运算,输入数据长度必须与pPubKey中指示的密钥长度相一致(比如1024位密钥时为128，2048时为256)
*         3.加密时内部padding方式为:PKCS1_TYPE_2 (即第二个字节为0x02,空数据填充随机数)  
*
* @param  hDongle         [in]         打开的加密锁句柄。
* @param  nFlag           [in]         运算类型。例如，FLAG_ENCODE表示加密运算；FLAG_DECODE表示解密运算。
* @param  pPubKey         [in]         RSA公钥数据。该数据来源于生成RSA公私钥时的公钥数据。
* @param  pInData         [in]         输入数据。
* @param  nInDataLen      [in]         参数pInData的大小。
* @param  pOutData        [out]        输出数据缓冲区。
* @param  pOutDataLen     [in,out]     参数pOutData的大小和返回的数据大小。
*
* @return DONGLE_SUCCESS               RSA公钥运算成功。
*/
unsigned long  Dongle_RsaPub(DONGLE_HANDLE hDongle, int nFlag, RSA_PUBLIC_KEY* pPubKey, unsigned char* pInData, int nInDataLen, unsigned char* pOutData, int* pOutDataLen);

/**
* @brief  ECC私钥签名。函数的使用权限取决于锁内ECC私钥文件的权限，在ECC私钥文件创建时设定。说明：
*         1.锁内签名算法为: ECDSA_Sign
*         2.输入的Hash值的长度与ECC私钥的密钥长度有关(如果密钥是192位的,则hash值长度不能超过24(192/8 = 24)字节)
*                                                    (如果密钥是256位的,则hash值长度不能超过32(256/8 = 32)字节)
*         3.曲线参数为:EC_NIST_PRIME_192及EC_NIST_PRIME_256
*
* @param  hDongle          [in]      打开的加密锁句柄。
* @param  wPriFileID       [in]      ECC私钥文件ID。
* @param  pHashData        [in]      Hash数据。
* @param  nHashDataLen     [in]      参数pHashData的大小。
* @param  pOutData         [out]     签名数据。大小固定为64字节(256位ECC时是正好,192位ECC时的位会补0)
*
* @return DONGLE_SUCCESS             表示签名成功。
*/
unsigned long  Dongle_EccSign(DONGLE_HANDLE hDongle, unsigned short wPriFileID, unsigned char* pHashData, int nHashDataLen, unsigned char* pOutData);


/**
* @brief  ECC公钥验签。函数的使用权限取决于锁内ECC私钥文件的权限，在ECC私钥文件创建时设定。说明：
*         1.锁内签名算法为: ECDSA_Verify
*         2.输入的Hash值的长度与ECC私钥的密钥长度有关(如果密钥是192位的,则hash值长度不能超过24(192/8 = 24)字节)
*                                                    (如果密钥是256位的,则hash值长度不能超过32(256/8 = 32)字节)
*         3.曲线参数为:EC_NIST_PRIME_192及EC_NIST_PRIME_256
*
* @param  hDongle          [in]      打开的加密锁句柄。
* @param  pPubKey          [in]      ECC公钥数据。
* @param  pHashData        [in]      Hash数据。
* @param  nHashDataLen     [in]      参数pHashData的大小。
* @param  pSign            [in]      签名数据。大小固定为64字节，为Dongle_EccSign函数返回的pOutData数据。
*
* @return DONGLE_SUCCESS             表示验签成功,否则表示验签失败。
*/
unsigned long  Dongle_EccVerify(DONGLE_HANDLE hDongle, ECCSM2_PUBLIC_KEY* pPubKey, unsigned char* pHashData, int nHashDataLen, unsigned char* pSign);

/**
* @brief  3DES加解密。解密运算匿名权限即可, 加密运算的权限取决于密钥文件的权限。
* 
* @param  hDongle        [in]      打开的加密锁句柄。
* @param  wKeyFileID     [in]      密钥文件ID。
* @param  nFlag          [in]      运算类型。例如，FLAG_ENCODE表示加密运算；FLAG_DECODE表示解密运算。
* @param  pInData        [in]      输入数据缓冲区。
* @param  pOutData       [out]     输出数据缓冲区。大小至少要和输入数据缓冲区相同，输入和输出数据缓冲区可以为同一个。
* @param  nDataLen       [in]      参数pInData的数据大小。数据长度必须是16的整数倍,允许的最大值是1024。
*
* @return DONGLE_SUCCESS           3DES加密或解密运算成功。
*/
unsigned long  Dongle_TDES(DONGLE_HANDLE hDongle, unsigned short wKeyFileID, int nFlag, unsigned char* pInData, unsigned char* pOutData, int nDataLen);

/**
* @brief  种子码算法。匿名权限可使用, 开发商可设置可运算次数。
*         1.种子码算法与PID有关，空锁(即PID=FFFFFFFF)不能进行种子码运算。
*         2.如果内部种子码可运算次数不为-1，当其递减到0后此函数将不能使用。
*
* @param  hDongle        [in]      打开的加密锁句柄。
* @param  pSeed          [in]      输入的种子码数据。 
* @param  nSeedLen       [in]      种子码长度。取值范围为1~250字节。
* @param  pOutData       [out]     输出数据缓冲区。输出的大小固定为16字节。
*
* @return DONGLE_SUCCESS           种子码运算成功。
*/
unsigned long  Dongle_Seed(DONGLE_HANDLE hDongle, unsigned char* pSeed, int nSeedLen, unsigned char* pOutData);

/**
* @brief  获取加密锁的UTC时间。
* 
* @param  hDongle     [in]     打开的加密锁句柄。
* @param  pdwUTCTime  [in]     时间值。
*
* @return DONGLE_SUCCESS       设置加密锁到期时间成功。
*/
unsigned long  Dongle_GetUTCTime(DONGLE_HANDLE hDongle, unsigned long * pdwUTCTime);

/** 
* @brief  获取加密锁到期时间。匿名权限获取。
*
* @param  hDongle     [in]      打开的加密锁句柄。
* @param  pdwTime     [out]     获取的到期UTC时间值。
*                               若*pdwTime = 0XFFFFFFFF，表示不限制到期时间
*                               若(*pdwTime & 0XFFFF0000) == 0，值表示还剩余几小时
*                               若(*pdwTime & 0XFFFF0000) != 0，值表示到期的UTC的时间，可以通过gmtime等将该值进行转换。
*
* @return DONGLE_SUCCESS        获取加密锁到期时间成功。
*/
unsigned long  Dongle_GetDeadline(DONGLE_HANDLE hDongle, unsigned long * pdwTime);

/**
 * @brief  运行指定的锁内可执行程序。运行可执行文件的权限，取决于批量下载时，中每个可执行文件的设置，
 *         即，EXE_FILE_INFO中的m_Priv参数。
 *         1.输入数据的长度最大不能超过1020字节，输出的数据长度最大不超过1024字节。
 *         2.输出数据的前四个字节是主函数的返回值。
 *
 * @param  hDongle            [in]         打开的加密锁句柄。
 * @param  wFileID            [in]         可执行文件的ID。
 * @param  pInData            [in]         可执行文件的输入数据。
 * @param  wInDataLen         [in]         参数pInData的长度。
 * @param  pOutResultData     [out]        输出的数据缓冲区。
 * @param  pwOutResultLen     [in,out]     pOutResultData缓冲区的大小，函数执行成功返回输出数据的长度。
 *
 * @return DONGLE_SUCCESS                  运行指定的可执行文件成功。
 */
unsigned long  Dongle_RunExeFile(DONGLE_HANDLE hDongle, unsigned short wFileID, unsigned char * pInOutBuf, unsigned short wInOutBufLen, int * pMainRet);

#ifdef __cplusplus
}
#endif

#endif




