#include "ovsApi.h"
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/string.h>

static uint32_t rand_num = 23; // seed number

void os_mySrand(uint32_t seed)
{
	rand_num = seed;
}

uint32_t os_myRand(void)
{
	// A random number generated in the range [0, s). myRand() keeps the value of previous step.
	rand_num = (1613 * rand_num + 19);
	return rand_num;
} // end function myRand

/*static uint32_t os_timeStampUs(void)
{
	struct timespec64 tv;
	ktime_get_ts64(&tv);
	return tv.tv_sec*1000000 + tv.tv_nsec/1000;
}

inline uint32_t os_GetMicroseconds(void)
{
	return os_timeStampUs();
}*/

void os_WriteLog(const char* str)
{
	
	printk(KERN_ERR "%s", str);
	/*uint32_t us = os_GetMicroseconds();
	uint32_t sec = us/1000/1000;
	uint32_t rem = us -sec * 1000 * 1000;
	uint32_t len;
	char log[128];
	if ((len = snprintf(log, 128, "[%5d.%06d]: %s", sec, rem, str)) <= 0)
		return;*/
	
}

void os_WriteLogX(const char* str, const int numArgs,
	const int arg1, const int arg2, const int arg3, const int arg4, const int arg5, const int arg6, const int arg7, const int arg8, const int arg9, const int arg10)
{
	/*uint32_t us = os_GetMicroseconds();
	uint32_t sec = us/1000/1000;
	uint32_t rem = us -sec * 1000 * 1000;
	char log[128];*/

	uint32_t len = 0;
	char msg[128];
	switch (numArgs)
	{
	case 1: len = snprintf(msg, 128, str, arg1); break;
	case 2: len = snprintf(msg, 128, str, arg1, arg2); break;
	case 3: len = snprintf(msg, 128, str, arg1, arg2, arg3); break;
	case 4: len = snprintf(msg, 128, str, arg1, arg2, arg3, arg4); break;
	case 5: len = snprintf(msg, 128, str, arg1, arg2, arg3, arg4, arg5); break;
	case 6: len = snprintf(msg, 128, str, arg1, arg2, arg3, arg4, arg5, arg6); break;
	case 7: len = snprintf(msg, 128, str, arg1, arg2, arg3, arg4, arg5, arg6, arg7); break;
	case 8: len = snprintf(msg, 128, str, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8); break;
	case 9: len = snprintf(msg, 128, str, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9); break;
	case 10:len = snprintf(msg, 128, str, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10); break;
	}
	printk(KERN_ERR "%s", msg);
	/*if ((len = snprintf(log, 128, "[%5d.%06d]: %s", sec, rem, msg)) <= 0)
		return;*/

}

uint16_t BytesTo16(uint8_t X, uint8_t Y)
{
	uint16_t Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}

uint16_t CalculateIPChecksum(uint8_t* IP_Header, int Hdr_Len)
{
	uint16_t CheckSum = 0;
	int i;
	for (i = 0; i < Hdr_Len; i += 2)
	{
		uint16_t Tmp = BytesTo16(IP_Header[i], IP_Header[i+1]);
		uint16_t Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference)
			CheckSum += 1;
	}
	CheckSum = ~CheckSum; // One's complement
	return CheckSum;
}

static uint8_t PseudoHeader[3000];
uint16_t CalculateUDPChecksum(
		uint32_t SourceIP, uint32_t DestinationIP,
		uint16_t SourcePort, uint16_t DestinationPort,
		uint8_t* UserData, int DataLen)
{
	uint16_t CheckSum = 0;
	uint16_t PseudoLength = DataLen + UDP_HLEN + 9; // Length of PseudoHeader = Data Length + 8 bytes UDP header + 2 X 4 bytes IP's + 1 byte protocol
	uint16_t UDPLength = DataLen + UDP_HLEN; // Actual data length in UDP header
	int i;
	PseudoLength += PseudoLength % 2; // If bytes are not an even number, add an extra.
	memset((void*)PseudoHeader, 0, PseudoLength);
	PseudoHeader[0] = 0x11; // Protocol. UDP is 0x11 (17).

	memcpy((void*)(PseudoHeader + 1), (void*)&SourceIP, 4); // Source and Destination IP
	memcpy((void*)(PseudoHeader + 5), (void*)&DestinationIP, 4);
	UDPLength = htons(UDPLength);
	memcpy((void*)(PseudoHeader + 9), (void*)&UDPLength, 2);
	memcpy((void*)(PseudoHeader + 11), (void*)&UDPLength, 2);
	SourcePort = htons(SourcePort);
	memcpy((void*)(PseudoHeader + 13), (void*)&SourcePort, 2);
	DestinationPort = htons(DestinationPort);
	memcpy((void*)(PseudoHeader + 15), (void*)&DestinationPort, 2);
	memcpy((void*)(PseudoHeader + 17), (void*)UserData, DataLen);

	for (i = 0; i < PseudoLength; i+=2)
	{
		unsigned short Tmp = BytesTo16(PseudoHeader[i], PseudoHeader[i+1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference)
			CheckSum += 1;
	}
	CheckSum = ~CheckSum; // One's complement
	return CheckSum;
}
