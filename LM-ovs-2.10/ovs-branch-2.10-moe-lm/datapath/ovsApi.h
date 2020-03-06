#ifndef OVSAPI_H
#define OVSAPI_H 1

#include <linux/types.h>

 /*
 *
 * Update 2020/03/04
 *              Update history: LM-MEC(2019) v1.3.9
 *			Switch IPs are rollback.
 */

#define IP_HLEN		20  // IP option header: 4bit+additional bit
#define MOE_HLEN	36 //SHA-256
#define HASH_LEN	32 //SHA-256
#define UDP_HLEN    8

#define SWITCHTYPE_NONE 0   // Unknown or other devices
#define SWITCHTYPE_IMS  1   // Intermediate Switch
#define SWITCHTYPE_ES   2   // Edge Switch

#define SENDERTYPE_NONE 0   // Unknown or other devices
#define SENDERTYPE_UE   1   // UE (or MS)
#define SENDERTYPE_SW   2   // Switch

#define INADDR_SEND     INADDR_LOOPBACK

#define OPCODE_BOOTUP               0
#define OPCODE_GET_HASH             1
#define OPCODE_GET_IP               2
#define OPCODE_INFORM_CONNECTION    3
#define OPCODE_APP_MOBILTY          4
#define OPCODE_CTN_MOBILTY          5
#define OPCODE_GET_IPPORT               6
#define OPCODE_TOGGLE_LOGGING             101
#define OPCODE_IPC_KRN_APP          10
#define OPCODE_IPC_APP_KRN          11

#define OPCODE_SET_SWTYPE   0
#define OPCODE_QUERIED_HASH 1
#define OPCODE_QUERIED_IP   2
#define OPCODE_UPDATE_IP    3
#define OPCODE_NEW_APP      4
#define OPCODE_NEW_CTN      5

#define DO_NOT_FORWARD      -1
#define DO_FORWARD          0
#define DO_FORWARD_AFTER_HANDLING	1

void os_mySrand(uint32_t seed);
uint32_t os_myRand(void);
void os_WriteLog(const char* str);
void os_WriteLogX(const char* str, const int numArgs,
    const int arg1, const int arg2, const int arg3, const int arg4, const int arg5, const int arg6, const int arg7, const int arg8, const int arg9, const int arg10);

#define os_WriteLog1(str, a) os_WriteLogX(str, 1, a, 0, 0, 0, 0, 0, 0, 0, 0, 0)
#define os_WriteLog2(str, a, b) os_WriteLogX(str, 2, a, b, 0, 0, 0, 0, 0, 0, 0, 0)
#define os_WriteLog3(str, a, b, c) os_WriteLogX(str, 3, a, b, c, 0, 0, 0, 0, 0, 0, 0)
#define os_WriteLog4(str, a, b, c, d) os_WriteLogX(str, 4, a, b, c, d, 0, 0, 0, 0, 0, 0)
#define os_WriteLog5(str, a, b, c, d, e) os_WriteLogX(str, 5, a, b, c, d, e, 0, 0, 0, 0, 0)
#define os_WriteLog6(str, a, b, c, d, e, f) os_WriteLogX(str, 6, a, b, c, d, e, f, 0, 0, 0, 0)
#define os_WriteLog7(str, a, b, c, d, e, f, g) os_WriteLogX(str, 7, a, b, c, d, e, f, g, 0, 0, 0)
#define os_WriteLog8(str, a, b, c, d, e, f, g, h) os_WriteLogX(str, 8, a, b, c, d, e, f, g, h, 0, 0)
#define os_WriteLog9(str, a, b, c, d, e, f, g, h, i) os_WriteLogX(str, 9, a, b, c, d, e, f, g, h, i, 0)
#define os_WriteLog10(str, a, b, c, d, e, f, g, h, i, j) os_WriteLogX(str, 10, a, b, c, d, e, f, g, h, i, j)

uint16_t BytesTo16(uint8_t X, uint8_t Y);
uint16_t CalculateIPChecksum(uint8_t* IP_Header, int Hdr_Len);
uint16_t CalculateUDPChecksum(
        uint32_t SourceIP, uint32_t DestinationIP,
        uint16_t SourcePort, uint16_t DestinationPort,
        uint8_t* UserData, int DataLen);
#endif
