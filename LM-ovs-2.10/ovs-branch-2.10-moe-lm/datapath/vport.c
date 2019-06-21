/*
 * Copyright (c) 2007-2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

/**
 * Update 2018/02/20
 * 		Update history: MoE(2016) > SOMO(2017) > LM(2018) > LM-MEC(2019)
 *
 * Update 2019/01/09
 * 		Update history: LM(2018) > LM-MEC(2019)
 * 			OvS version porting: 2.3.1 > 2.10.x (Ubuntu Linux 4.15 support)
 *
 * Update 2019/04/29
 *              Update history: LM-MEC(2019) v1.0
 *                      Testbed IP revised.
 * 
 * Update 2019/05/01
 *              Update history: LM-MEC(2019) v1.1
 *                      IPC sending message codes are revised.
 *                      However, still now works.
 *
 * Update 2019/05/02
 *              Update history: LM-MEC(2019) v1.2
 *                      IPC sending message codes are revised.
 * 			Excluded case of DHCP port numbers.
 *
 * Update 2019/05/03
 *              Update history: LM-MEC(2019) v1.3
 *                      IPC sending message codes are revised.
 * 			Excluded case of DHCP port numbers.
 *			IPC sending message codes are working.
 *
 * Update 2019/05/14
 *              Update history: LM-MEC(2019) v1.3.1
 *			Added specific cases.
 *
 * Update 2019/06/07
 *              Update history: LM-MEC(2019) v1.3.2
 *			Confirm checksum error.
 *
 * Update 2019/06/19
 *              Update history: LM-MEC(2019) v1.3.3
 *			Fixed check New UE bug. 
 *
 * Update 2019/06/20
 *              Update history: LM-MEC(2019) v1.3.4
 *			Made a DHCP register an UE. 
 *
 * Update 2019/06/21
 *              Update history: LM-MEC(2019) v1.3.5
 *			Condition of that a destination IP is a SW IP is revised.
 */


#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/module.h>
#include <linux/if_link.h>
#include <net/net_namespace.h>
#include <net/lisp.h>
#include <net/gre.h>
#include <net/geneve.h>
#include <net/stt.h>
#include <net/vxlan.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"
#include "vport-internal_dev.h"

// ------------------------------------------------------------
// LOHan: MoE Support
// ------------------------------------------------------------
#include "ovsApi.h"
#include <linux/workqueue.h>
#include <net/sock.h>
#include <linux/hashtable.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <linux/time.h>
#define OVS_MODE_MININET    0
#define OVS_MODE_TESTBED    1
// ------------------------------------------------------------
// LOHan: MoE Support End
// ------------------------------------------------------------

// ------------------------------------------------------------
// Jaehee: LM Support
// 			SWITCH_NUMS 6::server room testbed
//			SWITCH_NUMS 3::laboratory testbed
// ------------------------------------------------------------
#define SWITCH_NUMS         6
//#define SWITCH_NUMS         3

//uint32_t SWITCHS_IP[SWITCH_NUMS] = {16781322, 16785418, 16789514, 19398666, 20054026, 16793610};
//  10.16.0.1,10.32.0.1,10.48.0.1,10.0.40.1,10.0.50.1,10.64.0.1
uint32_t SWITCHS_IP[SWITCH_NUMS] = {17432586, 18087946, 18743306, 19398666, 20054026, 16793610};
//  10.0.10.1,10.0.20.1,10.0.30.1,10.0.40.1,10.0.50.1,10.64.0.1
//uint32_t SWITCHS_IP[SWITCH_NUMS] = {17432586,  18087946,  18743306};
//  10.0.10.1, 10.0.20.1, 10.0.30.1

static const uint8_t OVS_MODE = OVS_MODE_TESTBED;
static struct socket* udpsocket = NULL;
static struct socket* sendsocket = NULL;
static struct workqueue_struct* wq;
typedef struct work_queue {
	struct work_struct worker;
	struct sock* sk;
} _WQ;
static _WQ wq_data;
//static struct dentry* debug_file;
static char* MMAP_DATA = NULL;
static uint32_t CUR_MM_POS = 0;
static uint16_t PRT_START_PAGE = 0;
static uint16_t PRT_END_PAGE = 0;
static uint16_t LIMIT_PAGE = 200;

static DEFINE_HASHTABLE(OBJ_TBL, 3);
static DEFINE_HASHTABLE(OBJ_REV_TBL, 3);
static DEFINE_HASHTABLE(OBJ_MOIP_TBL, 3);



/* Protected by RCU read lock for reading, ovs_mutex for writing. */
static struct hlist_head *dev_table;
#define VPORT_HASH_BUCKETS 1024

typedef struct object_entry {
	uint32_t switchNum;
	uint32_t destIP;
	uint16_t destPort;
	uint32_t switchIP;
	uint32_t moIP;
	uint8_t objHash[HASH_LEN];
	struct hlist_node hlist_ip;
	struct hlist_node hlist_moip;
	struct hlist_node hlist_hash;
} _OE;

static LIST_HEAD(SKB_LIST);
typedef struct list_entry {
	uint32_t switchNum;
	uint32_t destIP;
	struct vport* vp;
	struct sk_buff* skb;
	struct list_head list;
} _LE;

//Jaehee & Jaehyun modified 170415 ---
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};//Jaehee & Jaehyun modified End ---

uint8_t SW_TYPES[SWITCH_NUMS];
struct timeval START_TIME;
struct timeval END_TIME;
struct timeval STAT_TIMES[SWITCH_NUMS];
uint16_t STAT_NEW_UES[SWITCH_NUMS];

int LOGGING = 1;
int LOGGING_SEARCH_LATENCY = 0;

static uint8_t sendBuffer[128];

static void ipc_ReceiveMessages(struct work_struct* data);
static void ipc_SendMessage(uint8_t switchNum, uint8_t opCode, uint32_t clientIP, uint8_t* data);
static void os_CreateIPCSocket(void);
static void os_CloseIPCSocket(void);
static void moe_CleanUp(void);
static void moe_InsertObject(uint32_t switchNum, uint32_t destIP, uint16_t destPort, uint8_t* objHash, uint32_t switchIP, uint32_t moIP);
static uint32_t moe_GetOriginIPFromSrcIP(uint32_t switchNum, uint32_t srcIP, uint16_t srcPort, uint8_t** objHash, uint32_t* originIP);
static uint32_t moe_GetObjectFromIP(uint32_t switchNum, uint32_t destIP, uint16_t destPort, uint8_t** objHash, uint32_t* pSwitchIP);
static uint32_t moe_GetObjectFromHash(uint32_t switchNum, uint8_t* objHash, uint32_t* pOldDestIP, uint32_t* pDestIP);
static void moe_DeleteObjectAll(uint32_t switchNum, uint32_t destIP, uint16_t destPort);
static void moe_DeleteObjectHash(uint32_t switchNum, uint8_t* objHash);
static void moe_DeleteMOIPAll(uint32_t switchNum, uint32_t moIP, uint16_t destPort);
static void moe_SaveSKB(uint32_t switchNum, uint32_t destIP, struct vport *vp, struct sk_buff *skb); //SKB = Socket Buffer
static void moe_ForwardSKB(uint32_t switchNum, uint32_t destIP);
static int32_t moe_CheckHeader(struct vport *vp, struct sk_buff *skb, struct sw_flow_key *key);
static int32_t moe_AddHeader(struct sk_buff *skb, uint32_t newSrcIP, uint8_t* hashed, uint32_t esIP, int proto, int doInsertObjID);
static int32_t moe_RemoveHeader(struct sk_buff *skb, uint32_t oldIP, uint32_t newIP, int proto);
unsigned short csum(unsigned short *ptr, int nbytes);
// ------------------------------------------------------------
// Jaehee: LM Support End
// ------------------------------------------------------------


static LIST_HEAD(vport_ops_list);
static bool compat_gre_loaded = false;
static bool compat_ip6_tunnel_loaded = false;

/* Protected by RCU read lock for reading, ovs_mutex for writing. */
static struct hlist_head *dev_table;
#define VPORT_HASH_BUCKETS 1024
// ------------------------------------------------------------
// Jaehee: LM Support
// ------------------------------------------------------------
static void cb_SocketDataReady(struct sock* sk)//, int bytes)
{
    wq_data.sk = sk;
    if (wq == NULL) return;
    queue_work(wq, &wq_data.worker);
}


static void ipc_ReceiveMessages(struct work_struct* data)
{
	_WQ* wrapper = container_of(data, _WQ, worker);
	uint8_t opCode = 0, switchNum = 0;
	uint32_t destIP = 0, switchIP = 0;
	uint8_t objHash[HASH_LEN] = {0,};
	int len = 0;
	uint16_t i = 0, total = 0, idx = 0;
	uint8_t type = 0;
	struct sk_buff* skb = NULL;
	uint8_t* tempHash = NULL;
	uint32_t temp = 0, newmoIP = 0;
	uint16_t destPort = 0;
	while ((len = skb_queue_len(&wrapper->sk->sk_receive_queue)) > 0) {
		skb = skb_dequeue(&wrapper->sk->sk_receive_queue);
		opCode = *(uint8_t*)(skb->data);
		switchNum = *(uint8_t*)(skb->data+ 1);
		if(LOGGING){os_WriteLog10("Received data=%u%u%u%u%u%u%u%u%u%u.\n",*((uint8_t*)skb->data + 0),*((uint8_t*)skb->data + 1),*((uint8_t*)skb->data + 2),*((uint8_t*)skb->data + 3),*((uint8_t*)skb->data + 4),*((uint8_t*)skb->data + 5),*((uint8_t*)skb->data + 6),*((uint8_t*)skb->data + 7),*((uint8_t*)skb->data + 8),*((uint8_t*)skb->data + 9));}
		if(LOGGING){os_WriteLog2("Received a UDP message, opCode=%u, SwitchNum=%u\n", opCode, switchNum);}


		if (opCode == OPCODE_SET_SWTYPE) {
			if(LOGGING){os_WriteLog("OPCODE_SET_SWTYPE\n");}
			i = 0;
			total = 0;
			idx = 0;
			type = *(uint8_t*)(skb->data + 2);
			total = ntohs(*(uint16_t*)(skb->data + 3));
			for (i = 0; i < total; i++) {
				idx = ntohs(*(uint16_t*)(skb->data + 5 + i * sizeof(uint16_t)));
				if (idx != -1){
					SW_TYPES[idx] = type;
				}
			}
			moe_CleanUp();
			// LOHan: Statistics Support
			/*
			{ int i; for (i = 0; i < SWITCH_NUMS; i++){
				if (STAT_TIMES[i].tv_sec != 0 && STAT_TIMES[i].tv_usec != 0){
			if(LOGGING){os_WriteLog3("SwitchNum=%u, Execution Time=%u.%06d\n", i, STAT_TIMES[i].tv_sec, STAT_TIMES[i].tv_usec);} }} }
			*/
		} else if (opCode == OPCODE_QUERIED_HASH) {
			if(LOGGING){os_WriteLog("OPCODE_QUERIED_HASH\n");}
			tempHash = NULL;
			temp = 0;
			destIP = *(uint32_t*)(skb->data + 2);
			memcpy(objHash, skb->data + 6, HASH_LEN);
			switchIP = *(uint32_t*)(skb->data + 6 + HASH_LEN);

			if (!moe_GetObjectFromIP(switchNum, destIP, 0, &tempHash, &temp)) {		// If not exist,
				if(LOGGING){os_WriteLog8("Host IP=%u.%u.%u.%u, Connected Switch IP=%u.%u.%u.%u\n",
										 *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3),
										 *((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3));}
				moe_InsertObject(switchNum, destIP, 0, objHash, switchIP, 0);
				moe_ForwardSKB(switchNum, destIP);
			}
		} else if (opCode == OPCODE_QUERIED_IP) {
			if(LOGGING){os_WriteLog("OPCODE_QUERIED_IP\n");}
			tempHash = NULL;
			temp = 0;
			destIP = *(uint32_t*)(skb->data + 2);
			memcpy(objHash, skb->data + 6, HASH_LEN);
			switchIP = *(uint32_t*)(skb->data + 6 + HASH_LEN);
			if (!moe_GetObjectFromIP(switchNum, destIP, 0, &tempHash, &temp)) {		// If not exist,

				moe_InsertObject(switchNum, destIP, 0, objHash, switchIP, 0);
				moe_ForwardSKB(switchNum, switchIP); // Should be the switch's IP
			}
		} else if (opCode == OPCODE_UPDATE_IP) {
			if(LOGGING){os_WriteLog("OPCODE_UPDATE_IP\n");}
			tempHash = NULL;
			temp = 0;
			destIP = *(uint32_t*)(skb->data + 2);
			switchIP = *(uint32_t*)(skb->data + 6);
			memcpy(objHash, skb->data + 10, HASH_LEN);
			if (moe_GetObjectFromIP(switchNum, destIP, 0, &tempHash, &temp) && switchIP != temp) {
				if(LOGGING){os_WriteLog8("End-host Mobility Support! Switch IP=%u.%u.%u.%u when Host IP=%u.%u.%u.%u\n",
										 *((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3),
										 *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3));}
				moe_InsertObject(switchNum, destIP, 0, objHash, switchIP, 0);
			} else if (switchIP != temp) {

				if(LOGGING){os_WriteLog8("End-host Mobility Support! Switch IP=%u.%u.%u.%u when Host IP=%u.%u.%u.%u\n",
										 *((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3),
										 *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3));}
				moe_InsertObject(switchNum, destIP, 0, objHash, switchIP, 0);
			}
		} else if (opCode == OPCODE_NEW_APP) { // Jaehee: TODO
			if(LOGGING){os_WriteLog("OPCODE_NEW_APP\n");}
			tempHash = NULL;
			newmoIP = 0;
			temp = 0;
			destPort = 0;
			destIP = *(uint32_t*)(skb->data + 2);
			switchIP = *(uint32_t*)(skb->data + 6);
			newmoIP = *(uint32_t*)(skb->data + 10);
			destPort = ntohs(*(uint16_t*)(skb->data + 14));
			//if (moe_GetObjectFromIP(switchNum, destIP, 0, &tempHash, &temp) && switchIP != temp) {
			if(LOGGING){os_WriteLog9("Application Mobility Support! Switch IP=%u.%u.%u.%u when Host IP=%u.%u.%u.%u with dstPort=%u\n",
									 *((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3),
									 *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), destPort);}
			memcpy(objHash, skb->data + 16, HASH_LEN);
			moe_InsertObject(switchNum, destIP, destPort, objHash, switchIP, newmoIP);
			//}
		} /*else if (opCode == OPCODE_NEW_CTN) { // Jaehee: Is it necessarily needed?
			uint8_t* tempHash;
			uint32_t newmoIP, temp = 0;
            uint16_t destPort = 0;
			destIP = *(uint32_t*)(skb->data + 2);
			switchIP = *(uint32_t*)(skb->data + 6);
			newmoIP = *(uint32_t*)(skb->data + 10);
			if (moe_GetObjectFromIP(switchNum, destIP, 0, &tempHash, &temp) && switchIP != temp) {
				if(LOGGING){os_WriteLog9("Container Mobility Support! Switch IP=%u.%u.%u.%u when Host IP=%u.%u.%u.%u\n",
					*((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3),
				*((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3));}
				memcpy(objHash, skb->data + 14, HASH_LEN);
				moe_InsertObject(switchNum, destIP, 0, objHash, switchIP, newmoIP);
			}
		}*/
		else if (opCode == OPCODE_TOGGLE_LOGGING) {
			LOGGING=(LOGGING == 0)?1:0;
		} else if (opCode == 100) {
			PRT_START_PAGE = *(uint32_t*)(skb->data + 2);
		}
		kfree_skb(skb);
	}
}

static void ipc_SendMessage(
		uint8_t switchNum, uint8_t opCode,
		uint32_t clientIP, uint8_t* data)
{
	struct sockaddr_in to;
	struct msghdr msg;
	struct iovec iov;
	struct iov_iter msg_iov_iter;
	unsigned long nr_segments = 1;
 	int result = 0;	
	size_t count = 0;
	 
	mm_segment_t oldfs;
	int len = sizeof(opCode) + sizeof(switchNum);

	if(LOGGING){os_WriteLog2("Sending a message to the upper layer. SwitchNum=%u, opCode=%u\n", switchNum, opCode);}
	sendBuffer[0] = opCode;
	sendBuffer[1] = switchNum;
	memcpy(sendBuffer + len, (void*)&clientIP, sizeof(clientIP));
	len += sizeof(clientIP);
	if (opCode == OPCODE_GET_IP && data != NULL) {
		memcpy(sendBuffer + len, data, HASH_LEN);
		len += HASH_LEN;

	} else if (opCode == OPCODE_GET_HASH && data != NULL) {  //Jaehee 170327
		memcpy(sendBuffer + len, data, 2);
		len += 2;
	}

	// Generate a request message
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = htonl(INADDR_SEND);
	to.sin_port = htons(10000 + switchNum);
	if(LOGGING){os_WriteLog3("Info of the upper layer. AF_INET =%u, s_addr=%u, sin_port=%u.\n", to.sin_family, INADDR_SEND , 10000+switchNum);}
	if(LOGGING){os_WriteLog3("SendBuffer[0]=%u. SendBuffer[1]=%u, length=%u.\n",sendBuffer[0],sendBuffer[1],len);}	
	memset(&msg, 0, sizeof(msg));
        memset(&iov, 0, sizeof(iov));
        memset(&msg_iov_iter, 0, sizeof(msg_iov_iter));
	msg.msg_name = &to;
	msg.msg_namelen = sizeof(to);
	iov.iov_base = sendBuffer;
	iov.iov_len  = len;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg_iov_iter = msg.msg_iter;
	count = len;
	//msg.msg_iov = &iov;
	//msg.msg_iovlen = 1;

	iov_iter_init(&msg_iov_iter, READ, &iov, nr_segments, count); //Jaehee 190502
	// Adjust memory boundaries and send the message
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	msg.msg_iter = msg_iov_iter;
	result = sock_sendmsg(sendsocket, &msg);
	set_fs(oldfs);

	if(LOGGING){os_WriteLog1("Result of sock_sendmsg=%u.\n", result);}
}

static void os_CreateIPCSocket(void)
{
	struct sockaddr_in server;
	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &udpsocket) < 0)
		return;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons((unsigned short)9999);
	if (udpsocket->ops->bind(udpsocket, (struct sockaddr*)&server, sizeof(server))) {
		sock_release(udpsocket);
		return;
	}

	udpsocket->sk->sk_data_ready = cb_SocketDataReady;

	INIT_WORK(&wq_data.worker, ipc_ReceiveMessages);
	wq = create_singlethread_workqueue("myworkqueue");

	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sendsocket) < 0)
		return;
}

static void os_CloseIPCSocket(void)
{
	if (udpsocket)
		sock_release(udpsocket);
	if (sendsocket)
		sock_release(sendsocket);
	if (wq) {
		flush_workqueue(wq);
		destroy_workqueue(wq);
	}
}

static void moe_CleanUp(void)
{
	{
		int bucket = 0;
		_OE *current_entry = NULL, *previous_entry = NULL;
		hash_for_each(OBJ_TBL, bucket, current_entry, hlist_ip) {
			if (previous_entry != NULL) {
				hash_del(&previous_entry->hlist_ip); // 'hash_del' also initializes the hlist.
				if (previous_entry->hlist_hash.next == NULL && previous_entry->hlist_hash.pprev == NULL && previous_entry->hlist_moip.next == NULL && previous_entry->hlist_moip.pprev == NULL)
					kfree(previous_entry);
			}
			previous_entry = current_entry;
		}
		if (previous_entry != NULL) {
			hash_del(&previous_entry->hlist_ip);
			if (previous_entry->hlist_hash.next == NULL && previous_entry->hlist_hash.pprev == NULL && previous_entry->hlist_moip.next == NULL && previous_entry->hlist_moip.pprev == NULL)
				kfree(previous_entry);
		}

		previous_entry = NULL;
		hash_for_each(OBJ_REV_TBL, bucket, current_entry, hlist_hash) {
			if (previous_entry != NULL) {
				hash_del(&previous_entry->hlist_hash);
				if (previous_entry->hlist_ip.next == NULL && previous_entry->hlist_ip.pprev == NULL && previous_entry->hlist_moip.next == NULL && previous_entry->hlist_moip.pprev == NULL)
					kfree(previous_entry);
			}
			previous_entry = current_entry;
		}

		if (previous_entry != NULL) {
			hash_del(&previous_entry->hlist_hash);
			if (previous_entry->hlist_ip.next == NULL && previous_entry->hlist_ip.pprev == NULL && previous_entry->hlist_moip.next == NULL && previous_entry->hlist_moip.pprev == NULL)
				kfree(previous_entry);
		}

		previous_entry = NULL;
		hash_for_each(OBJ_MOIP_TBL, bucket, current_entry, hlist_moip) {
			if (previous_entry != NULL) {
				hash_del(&previous_entry->hlist_moip);
				if (previous_entry->hlist_ip.next == NULL && previous_entry->hlist_ip.pprev == NULL && previous_entry->hlist_hash.next == NULL && previous_entry->hlist_hash.pprev == NULL)
					kfree(previous_entry);
			}
			previous_entry = current_entry;
		}

		if (previous_entry != NULL) {
			hash_del(&previous_entry->hlist_moip);
			if (previous_entry->hlist_ip.next == NULL && previous_entry->hlist_ip.pprev == NULL && previous_entry->hlist_hash.next == NULL && previous_entry->hlist_hash.pprev == NULL)
				kfree(previous_entry);
		}
	}

	{_LE *current_entry = NULL, *previous_entry = NULL;
		list_for_each_entry(current_entry, &SKB_LIST, list) {
			if (previous_entry != NULL) { list_del(&previous_entry->list); kfree(previous_entry); }
			previous_entry = current_entry;
		}
		if (previous_entry != NULL) { list_del(&previous_entry->list); kfree(previous_entry); }}
}

static void moe_InsertObject(uint32_t switchNum, uint32_t destIP, uint16_t destPort, uint8_t* objHash, uint32_t switchIP, uint32_t moIP)
{
	int i = 0;
	_OE* entry = NULL;
	if(LOGGING){
		os_WriteLog10("Updating cache: SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u, SwitchIP=%u.%u.%u.%u,\n",switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), destPort, *((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3));
		os_WriteLog4("moIP=%u.%u.%u.%u\n", *((uint8_t*)&moIP + 0), *((uint8_t*)&moIP + 1), *((uint8_t*)&moIP + 2), *((uint8_t*)&moIP + 3));
	}
	entry = kmalloc(sizeof(_OE), GFP_KERNEL);
	moe_DeleteObjectAll(switchNum, destIP, destPort);
	entry->switchNum = switchNum;
	entry->destIP = destIP;
	entry->destPort = destPort;
	entry->switchIP = switchIP;
	entry->moIP = moIP;
	memcpy(entry->objHash, objHash, HASH_LEN);
	if(LOGGING){
		os_WriteLog("ObjID=\n");
		for (i=0 ; i<(HASH_LEN/8) ; i++) {
			os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)objHash+((i*8))),*((uint8_t*)objHash+((i*8)+1)),*((uint8_t*)objHash+((i*8)+2)),*((uint8_t*)objHash+((i*8)+3)),*((uint8_t*)objHash+((i*8)+4)),*((uint8_t*)objHash+((i*8)+5)),*((uint8_t*)objHash+((i*8)+6)),*((uint8_t*)objHash+((i*8)+7)));
		}
	}

	INIT_HLIST_NODE(&entry->hlist_ip);
	INIT_HLIST_NODE(&entry->hlist_hash);
	hash_add(OBJ_TBL, &entry->hlist_ip, entry->destIP);
	hash_add(OBJ_REV_TBL, &entry->hlist_hash, *(uint64_t*)entry->objHash);

	INIT_HLIST_NODE(&entry->hlist_moip);
	hash_add(OBJ_MOIP_TBL, &entry->hlist_moip, entry->moIP);

}

static uint32_t moe_GetObjectFromIP(uint32_t switchNum, uint32_t destIP, uint16_t destPort, uint8_t** objHash, uint32_t* pSwitchIP)
{
	_OE* current_entry = NULL;
	int i = 0;
	struct timeval startTime, endTime;
	long gap = 0;

	if (destPort!=(uint16_t)0 && (destPort > (uint16_t)61000 || destPort < (uint16_t)32768)) {

		if(LOGGING_SEARCH_LATENCY) {
			do_gettimeofday(&startTime);
		}
		if(LOGGING){
			os_WriteLog6("Searching cache. SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u\n", switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), destPort);}
		hash_for_each_possible(OBJ_TBL, current_entry, hlist_ip, destIP) {
			if (current_entry->switchNum == switchNum &&
				current_entry->destIP == destIP && current_entry->destPort == destPort) {
				*objHash = current_entry->objHash;
				*pSwitchIP = current_entry->switchIP;
				if(LOGGING){
					os_WriteLog6("Cache hit! SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u\n", switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), destPort);
					os_WriteLog4("ESIP=%u.%u.%u.%u", *((uint8_t*)pSwitchIP + 0), *((uint8_t*)pSwitchIP + 1), *((uint8_t*)pSwitchIP + 2), *((uint8_t*)pSwitchIP + 3));
					os_WriteLog("ObjID=\n");

					for (i=0 ; i<(HASH_LEN/8) ; i++) {
						os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)*objHash+((i*8))),*((uint8_t*)*objHash+((i*8)+1)),*((uint8_t*)*objHash+((i*8)+2)),*((uint8_t*)*objHash+((i*8)+3)),*((uint8_t*)*objHash+((i*8)+4)),*((uint8_t*)*objHash+((i*8)+5)),*((uint8_t*)*objHash+((i*8)+6)),*((uint8_t*)*objHash+((i*8)+7)));
					}
				}
				if(LOGGING_SEARCH_LATENCY) {
					do_gettimeofday(&endTime);
					gap = (long)((1000000*(endTime.tv_sec - startTime.tv_sec))+endTime.tv_usec - startTime.tv_usec);
					os_WriteLog1("Search time: %ld\n", gap);
				}
				return 1;
			}
		}
	}



	current_entry = NULL;
	//destPort == 0
	if(LOGGING_SEARCH_LATENCY) {
		do_gettimeofday(&startTime);
	}
	if(LOGGING){
		os_WriteLog6("Searching cache. SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u\n", switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), (uint16_t)0);	}
	hash_for_each_possible(OBJ_TBL, current_entry, hlist_ip, destIP) {
		if (current_entry->switchNum == switchNum &&
			current_entry->destIP == destIP && current_entry->destPort == (uint16_t)0) {
			*objHash = current_entry->objHash;
			*pSwitchIP = current_entry->switchIP;
			if(LOGGING){
				os_WriteLog6("Cache hit! SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u\n", switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), (uint16_t)0);
				os_WriteLog4("ESIP=%u.%u.%u.%u", *((uint8_t*)pSwitchIP + 0), *((uint8_t*)pSwitchIP + 1), *((uint8_t*)pSwitchIP + 2), *((uint8_t*)pSwitchIP + 3));
				os_WriteLog("ObjID=\n");
				for (i=0 ; i<(HASH_LEN/8) ; i++) {
					os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)*objHash+((i*8))),*((uint8_t*)*objHash+((i*8)+1)),*((uint8_t*)*objHash+((i*8)+2)),*((uint8_t*)*objHash+((i*8)+3)),*((uint8_t*)*objHash+((i*8)+4)),*((uint8_t*)*objHash+((i*8)+5)),*((uint8_t*)*objHash+((i*8)+6)),*((uint8_t*)*objHash+((i*8)+7)));
				}
			}
			if(LOGGING_SEARCH_LATENCY) {
				do_gettimeofday(&endTime);
				gap = (long)((1000000*(endTime.tv_sec - startTime.tv_sec))+endTime.tv_usec - startTime.tv_usec);
				os_WriteLog1("Search time: %ld\n", gap);
			}
			return 1;
		}
	}


	return 0;
}

static uint32_t moe_GetOriginIPFromSrcIP(uint32_t switchNum, uint32_t srcIP, uint16_t srcPort, uint8_t** objHash, uint32_t* originIP)
{

	_OE* current_entry = NULL;
	uint32_t moIP = srcIP;

	if (srcPort != (uint16_t)0 && (srcPort < (uint16_t)32768 || srcPort > (uint16_t)61000)) {
		if(LOGGING){os_WriteLog6("Searching cache. SwitchNum=%u, SrcIP=%u.%u.%u.%u, SrcPort=%u\n", switchNum, *((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3), srcPort);}

		hash_for_each_possible(OBJ_MOIP_TBL, current_entry, hlist_moip, moIP) {
			if (current_entry->switchNum == switchNum &&
				current_entry->moIP == moIP && current_entry->destPort == srcPort) {
				*originIP = current_entry->destIP;
				if(LOGGING){os_WriteLog6("Cache hit! SwitchNum=%u, OriginalIP=%u.%u.%u.%u, SrcPort=%u\n", switchNum, *((uint8_t*)originIP + 0), *((uint8_t*)originIP + 1), *((uint8_t*)originIP + 2), *((uint8_t*)originIP + 3), srcPort);}

				return 1;
			}
		}
	}


	current_entry = NULL;
	//destPort == 0
	if(LOGGING){os_WriteLog6("Searching cache. SwitchNum=%u, SrcIP=%u.%u.%u.%u, SrcPort=%u\n", switchNum, *((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3), (uint32_t)0);}
	hash_for_each_possible(OBJ_MOIP_TBL, current_entry, hlist_moip, moIP) {
		if (current_entry->switchNum == switchNum &&
			current_entry->moIP == moIP && current_entry->destPort == (uint16_t)0) {
			*originIP = current_entry->destIP;
			if(LOGGING){os_WriteLog6("Cache hit! SwitchNum=%u, OriginalIP=%u.%u.%u.%u, SrcPort=%u\n", switchNum, *((uint8_t*)originIP + 0), *((uint8_t*)originIP + 1), *((uint8_t*)originIP + 2), *((uint8_t*)originIP + 3), (uint16_t)0);}

			return 1;
		}
	}
	return 0;

}

static uint32_t moe_GetObjectFromHash(uint32_t switchNum, uint8_t* objHash, uint32_t* pOldDestIP, uint32_t* pDestIP)
{
	_OE* current_entry = NULL;
	int i = 0;
	if(LOGGING){
		os_WriteLog1("Searching cache. SwitchNum=%u\n", switchNum);
		os_WriteLog("ObjID=\n");

		for (i=0 ; i<(HASH_LEN/8) ; i++) {
			os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)objHash+((i*8))),*((uint8_t*)objHash+((i*8)+1)),*((uint8_t*)objHash+((i*8)+2)),*((uint8_t*)objHash+((i*8)+3)),*((uint8_t*)objHash+((i*8)+4)),*((uint8_t*)objHash+((i*8)+5)),*((uint8_t*)objHash+((i*8)+6)),*((uint8_t*)objHash+((i*8)+7)));
		}
	}
	current_entry = NULL;
	hash_for_each_possible(OBJ_REV_TBL, current_entry, hlist_hash, *(uint64_t*)objHash) {
		if (current_entry->switchNum == switchNum && memcmp(current_entry->objHash, objHash, HASH_LEN) == 0) {
			*pOldDestIP = current_entry->destIP;
			if (current_entry->moIP == 0) {
				*pDestIP = current_entry->destIP;
			}
			else {
				*pDestIP = current_entry->moIP;
			}
			if(LOGGING){
				os_WriteLog4("Cache hit! OldDestIP=%u.%u.%u.%u\n", *((uint8_t*)pOldDestIP + 0), *((uint8_t*)pOldDestIP + 1), *((uint8_t*)pOldDestIP + 2), *((uint8_t*)pOldDestIP + 3));
				os_WriteLog5("SwitchNum=%u, DestIP=%u.%u.%u.%u\n", switchNum, *((uint8_t*)pDestIP + 0), *((uint8_t*)pDestIP + 1), *((uint8_t*)pDestIP + 2), *((uint8_t*)pDestIP + 3));
			}
			return 1;
		}
	}
	return 0;
}

static void moe_DeleteObjectAll(uint32_t switchNum, uint32_t destIP, uint16_t destPort)
{
	_OE* current_entry = NULL;
	if(LOGGING){os_WriteLog("Delete Object\n");}
	hash_for_each_possible(OBJ_TBL, current_entry, hlist_ip, destIP) {
		if (current_entry->switchNum == switchNum &&
			current_entry->destIP == destIP && current_entry->destPort == destPort) {
			hash_del(&current_entry->hlist_ip);
			if (current_entry->hlist_hash.next == NULL && current_entry->hlist_hash.pprev == NULL && current_entry->hlist_moip.next == NULL && current_entry->hlist_moip.pprev == NULL)
				kfree(current_entry);
			else
				moe_DeleteObjectHash(switchNum, current_entry->objHash);
			moe_DeleteMOIPAll(switchNum, current_entry->moIP, destPort);
			return;
		}
	}

}

static void moe_DeleteObjectHash(uint32_t switchNum, uint8_t* objHash)
{
	_OE* current_entry = NULL;

	if(LOGGING){os_WriteLog("Delete Object Hash\n");}
	hash_for_each_possible(OBJ_REV_TBL, current_entry, hlist_hash, *(uint64_t*)objHash) {
		if (current_entry->switchNum == switchNum && memcmp(current_entry->objHash, objHash, HASH_LEN) == 0) {
			hash_del(&current_entry->hlist_hash);
			if (current_entry->hlist_ip.next == NULL && current_entry->hlist_ip.pprev == NULL && current_entry->hlist_moip.next == NULL && current_entry->hlist_moip.pprev == NULL)
				kfree(current_entry);
			return;
		}
	}
}

static void moe_DeleteMOIPAll(uint32_t switchNum, uint32_t moIP, uint16_t destPort)
{
	_OE* current_entry = NULL;

	if(LOGGING){os_WriteLog("Delete MOIP Hash\n");}
	hash_for_each_possible(OBJ_MOIP_TBL, current_entry, hlist_moip, moIP) {
		if (current_entry->switchNum == switchNum && current_entry->moIP == moIP && current_entry->destPort == destPort) {
			hash_del(&current_entry->hlist_moip);
			if (current_entry->hlist_ip.next == NULL && current_entry->hlist_ip.pprev == NULL && current_entry->hlist_hash.next == NULL && current_entry->hlist_hash.pprev == NULL)
				kfree(current_entry);
			return;
		}
	}
}


static void moe_SaveSKB(uint32_t switchNum, uint32_t destIP, struct vport *vp, struct sk_buff *skb)
{
	_LE* entry = NULL;
	entry = kmalloc(sizeof(_LE), GFP_KERNEL);
	entry->switchNum = switchNum;
	entry->destIP = destIP;
	entry->vp = vp;
	entry->skb = skb;
	INIT_LIST_HEAD(&entry->list);
	list_add_tail(&entry->list, &SKB_LIST);
}

static void moe_ForwardSKB(uint32_t switchNum, uint32_t destIP)
{
	_LE* entry = NULL;
	_LE* previous = NULL;
	list_for_each_entry(entry, &SKB_LIST, list) {
		if (previous != NULL) {
			list_del(&previous->list);
			kfree(previous); previous = NULL;
		}
		if (entry->switchNum == switchNum && entry->destIP == destIP) {
			if (moe_CheckHeader(entry->vp, entry->skb, NULL) == -1) {continue;}
			rcu_read_lock();
            ovs_dp_process_packet(entry->skb, NULL);
			rcu_read_unlock();
			previous = entry;
		}
	}
	if (previous != NULL) {
		list_del(&previous->list);
		kfree(previous); previous = NULL;
	}
}

static void moe_CheckNewUE(const uint8_t switchNum, const uint16_t protocol, uint8_t* data)
{
	uint32_t senderIP = 0;

	// --------------------------------------------------------------------------------
	// New UE signaled by an ARP Request message
	// --------------------------------------------------------------------------------
	if (protocol == ETH_P_ARP) {
		uint16_t hType, pType;
		uint8_t hLen, pLen;
		uint16_t opCode;
		hType = ntohs(*(uint16_t*)(data + 0));	// Hardware Type
		pType = ntohs(*(uint16_t*)(data + 2));	// Protocol Type
		hLen = data[4]; 						// Hardware Length
		pLen = data[5]; 						// Protocol Length
		opCode = ntohs(*(uint16_t*)(data + 6));	// ARP Operation
		if (!(hType == 0x01 && pType == ETH_P_IP && hLen == ETH_ALEN && pLen == 4 && opCode == 0x01)) return;
		senderIP = *(uint32_t*)(data + hLen + 8);	// Do not use 'ntohl'
	}
		// --------------------------------------------------------------------------------
		// New UE signaled by a TCP message (for DPDK PktGen test)
		// --------------------------------------------------------------------------------
	else if (protocol == ETH_P_IP) {
		senderIP = *(uint32_t*)(data + 12);	// Do not use 'ntohl'
	}

	if (senderIP == 0) return;
	// LOHan: Statistics Support
	if(LOGGING){
		if (++STAT_NEW_UES[switchNum] == 1000) {
			os_WriteLog1("SwitchNum=%u, 1K new UEs are connected.\n", switchNum);
			STAT_NEW_UES[switchNum] = 0;
		}
	}
	if (MMAP_DATA != NULL) {
		uint32_t cur_page = (PRT_START_PAGE == PRT_END_PAGE) ? PRT_END_PAGE : ((PRT_END_PAGE + 1) % LIMIT_PAGE);
		if (CUR_MM_POS + 2 + sizeof(senderIP) > (cur_page + 1) * PAGE_SIZE) {
			ipc_SendMessage(switchNum, OPCODE_IPC_KRN_APP, cur_page, NULL);
			PRT_END_PAGE = cur_page;
			cur_page = (cur_page + 1) % LIMIT_PAGE;
			CUR_MM_POS = cur_page * PAGE_SIZE;
			if (cur_page != PRT_START_PAGE) memset(MMAP_DATA + CUR_MM_POS, 0, PAGE_SIZE);
		}
		if ((PRT_END_PAGE + 1) % LIMIT_PAGE != PRT_START_PAGE) {
			MMAP_DATA[CUR_MM_POS + 0] = OPCODE_INFORM_CONNECTION;
			MMAP_DATA[CUR_MM_POS + 1] = switchNum;
			memcpy(MMAP_DATA + CUR_MM_POS + 2, (void*)&senderIP, sizeof(senderIP));
			CUR_MM_POS += (2 + sizeof(senderIP));
			return;
		}
	}
	ipc_SendMessage(switchNum, OPCODE_INFORM_CONNECTION, senderIP, NULL);
}

//Jaehee & Jaehyun modified  2017/04/15
//Jaehee modified 2018/02/19
//Jaehee modified 2018/02/20
//Jaehee modified 2019/06/21
static int32_t moe_AddHeader(struct sk_buff *skb, uint32_t newSrcIP, uint8_t* hashed, uint32_t esIP, int proto, int doInsertObjID)
{
	uint8_t* data = NULL;
	uint16_t len = 0, temp = 0;
	uint16_t org_tp_check = 0;
	uint32_t oldSrcIP = 0;
	uint16_t pre16 = 0, post16 = 0;
	uint32_t sum = 0;
	int i = 0;

	if(doInsertObjID) {

		if(LOGGING){os_WriteLog("Adding header operation.\n");}
		if (skb_cow_head(skb, MOE_HLEN) < 0){
			return -1;
		}

		skb_put(skb, MOE_HLEN);
		/* Move the data to the beginning of the new data position. */
		memmove(skb->data + MOE_HLEN + ETH_HLEN + IP_HLEN, skb->data + ETH_HLEN + IP_HLEN, skb->len - ETH_HLEN - IP_HLEN);
		
		data = skb->data + ETH_HLEN;


		memcpy(data + 0, (void*)"\x4E", 1);
		len = ntohs(*(uint16_t*)(data + 2));
		if(LOGGING){os_WriteLog1("packet length(before)=%d\n",len);}
		len = htons(len + MOE_HLEN);
		if(LOGGING){os_WriteLog1("packet length(after)=%d\n",ntohs(len));}
		memcpy(data + 2, (void*)&len, 2);


		memcpy(data + 10, (void*)"\x0000", 2);
		memcpy(&oldSrcIP, data + 12, sizeof(uint32_t));
		memcpy(data + 16, (void*)&esIP, sizeof(esIP));
		memcpy(data + IP_HLEN + 0, (void*)"\x00", 1);
		memcpy(data + IP_HLEN + 1, (void*)"\x24", 1); // option field length
		memcpy(data + IP_HLEN + 2, (void*)"\x0000", 2);
		memcpy(data + IP_HLEN + 4, hashed, HASH_LEN);

		/*
		if (LOGGING){
			os_WriteLog("ObjID=\n");
			for (i=0 ; i<(HASH_LEN/8) ; i++) {
						os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)hashed+((i*8))),*((uint8_t*)hashed+((i*8)+1)),*((uint8_t*)hashed+((i*8)+2)),*((uint8_t*)hashed+((i*8)+3)),*((uint8_t*)hashed+((i*8)+4)),*((uint8_t*)hashed+((i*8)+5)),*((uint8_t*)hashed+((i*8)+6)),*((uint8_t*)hashed+((i*8)+7)));
					}
			
						
			os_WriteLog("Inserted ObjID=\n");
			for (i=0 ; i<(HASH_LEN/8) ; i++) {
						os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)(data + IP_HLEN + 4)+((i*8))),*((uint8_t*)(data + IP_HLEN + 4)+((i*8)+1)),*((uint8_t*)(data + IP_HLEN + 4)+((i*8)+2)),*((uint8_t*)(data + IP_HLEN + 4)+((i*8)+3)),*((uint8_t*)(data + IP_HLEN + 4)+((i*8)+4)),*((uint8_t*)(data + IP_HLEN + 4)+((i*8)+5)),*((uint8_t*)(data + IP_HLEN + 4)+((i*8)+6)),*((uint8_t*)(data + IP_HLEN + 4)+((i*8)+7)));
					}
			
		}*/

		temp = htons(CalculateIPChecksum(data, IP_HLEN + MOE_HLEN));
		memcpy(data + 10, (void*)&temp, 2);
	}
	else {
		if(LOGGING){os_WriteLog("No adding header operation. Just calculate checksum.\n");}
		data = skb->data + ETH_HLEN;

		memcpy(&oldSrcIP, data + 12, sizeof(uint32_t));

		if (newSrcIP != oldSrcIP) {
			memcpy(data + 10, (void*)"\x0000", 2);
			temp = htons(CalculateIPChecksum(data, IP_HLEN));
			memcpy(data + 10, (void*)&temp, 2);
		}
	}

	//tcph_len = (*(uint8_t*)(data + IP_HLEN + MOE_HLEN + 12) & 0xf0) >> 4;
	//if(LOGGING){print_hex_dump(KERN_ALERT, "data ", DUMP_PREFIX_OFFSET, 16, 1, data + IP_HLEN + MOE_HLEN + (tcph_len*4), ntohs(len) - IP_HLEN - MOE_HLEN - (tcph_len*4), 1);}

	if (proto != IPPROTO_ICMP && newSrcIP != oldSrcIP) {

		if (proto == IPPROTO_UDP) {
			memcpy(&org_tp_check, data + IP_HLEN + MOE_HLEN + 6, sizeof(uint16_t));
			if(LOGGING){os_WriteLog1("original udp checksum=%04x\n",ntohs(org_tp_check));}
		} // UDP calculates checksum


//		if (proto == IPPROTO_UDP) {
//			memcpy(data + IP_HLEN + MOE_HLEN + 6, (void*)"\x0000", sizeof(uint16_t));
//
//		} //UDP don't calculates checksum

		else if (proto == IPPROTO_TCP) {
			memcpy(&org_tp_check, data + IP_HLEN + MOE_HLEN + 16, sizeof(uint16_t));
			if(LOGGING){os_WriteLog1("original tcp checksum=%04x\n",ntohs(org_tp_check));}
		} //TCP calculates checksum

		org_tp_check = ~ntohs(org_tp_check);
		if(LOGGING){os_WriteLog1("tp check 1s cmpl=%04x\n",org_tp_check);}
		newSrcIP = ntohl(newSrcIP);
		oldSrcIP = ntohl(oldSrcIP);
		if(LOGGING){
			os_WriteLog1("new src ip addr=%08x\n",newSrcIP);
			os_WriteLog1("old src ip addr=%08x\n",oldSrcIP);
		}

		pre16 = (uint16_t) ((newSrcIP & 0xffff0000) >> 16);
		post16 = (uint16_t) (newSrcIP & 0x0000ffff);
		if(LOGGING){
			os_WriteLog1("new src ip preaddr=%04x\n",pre16);
			os_WriteLog1("new src ip postaddr=%04x\n",post16);
		}

		if (org_tp_check < pre16) {
			sum = org_tp_check + 0xffff - pre16;
		}
		else {
			sum = org_tp_check - pre16;
		}
		if (sum < post16) {
			sum = sum + 0xffff - post16;
		}
		else {
			sum = sum - post16;
		}

		pre16 = (uint16_t) ((oldSrcIP & 0xffff0000) >> 16);
		post16 = (uint16_t) (oldSrcIP & 0x0000ffff);

		if(LOGGING){
			os_WriteLog1("old src ip preaddr=%04x\n",pre16);
			os_WriteLog1("old src ip postaddr=%04x\n",post16);
		}

		sum += pre16;
		if (sum>0xffff) {
			sum = (sum&0xffff) + ((sum&0xffff0000)>>16);
		}
		sum += post16;
		if (sum>0xffff) {
			sum = (sum&0xffff) + ((sum&0xffff0000)>>16);
		}

		if(LOGGING){os_WriteLog1("new tp check 1s cmpl=%04x\n",sum);}

		org_tp_check = htons((uint16_t)(~sum));

		if(LOGGING){os_WriteLog1("new tp checksum=%04x\n",ntohs(org_tp_check ));}


		if (proto == IPPROTO_UDP) {
			memcpy(data + IP_HLEN + MOE_HLEN + 6, &org_tp_check, sizeof(uint16_t));
		} // UDP calculates checksum

		else if (proto == IPPROTO_TCP) {
			memcpy(data + IP_HLEN + MOE_HLEN + 16, &org_tp_check, sizeof(uint16_t));
		}

	}
	/*
	if (proto != IPPROTO_ICMP && newSrcIP != oldSrcIP) {
		org_tp_check = kmalloc(sizeof(uint16_t),GFP_KERNEL);

		if (proto == IPPROTO_UDP) {
			memcpy(org_tp_check, data + IP_HLEN + MOE_HLEN + 6, sizeof(uint16_t));
			if(LOGGING){os_WriteLog1("original udp checksum=%04x\n",ntohs(*org_tp_check));}
		}

		else if (proto == IPPROTO_TCP) {
			memcpy(org_tp_check, data + IP_HLEN + MOE_HLEN + 16, sizeof(uint16_t));
			if(LOGGING){os_WriteLog1("original tcp checksum=%04x\n",ntohs(*org_tp_check));}
		}

		*org_tp_check = ~ntohs(*org_tp_check);
		if(LOGGING){os_WriteLog1("tp check 1s cmpl=%04x\n",*org_tp_check);}
		newSrcIP = ntohl(newSrcIP);
		oldSrcIP = ntohl(oldSrcIP);
		if(LOGGING){
			os_WriteLog1("new src ip addr=%08x\n",newSrcIP);
			os_WriteLog1("old src ip addr=%08x\n",oldSrcIP);
		}

		pre16 = (uint16_t) ((newSrcIP & 0xffff0000) >> 16);
		post16 = (uint16_t) (newSrcIP & 0x0000ffff);
		if(LOGGING){
			os_WriteLog1("new src ip preaddr=%04x\n",pre16);
			os_WriteLog1("new src ip postaddr=%04x\n",post16);
			}

		if (*org_tp_check < pre16) {
			sum = *org_tp_check + 0xffff - pre16;
		}
		else {
			sum = *org_tp_check - pre16;
		}
		if (sum < post16) {
			sum = sum + 0xffff - post16;
		}
		else {
			sum = sum - post16;
		}

		pre16 = (uint16_t) ((oldSrcIP & 0xffff0000) >> 16);
		post16 = (uint16_t) (oldSrcIP & 0x0000ffff);

		if(LOGGING){
			os_WriteLog1("old src ip preaddr=%04x\n",pre16);
			os_WriteLog1("old src ip postaddr=%04x\n",post16);
			}

		sum += pre16;
		if (sum>0xffff) {
			sum = (sum&0xffff) + ((sum&0xffff0000)>>16);
		}
		sum += post16;
		if (sum>0xffff) {
			sum = (sum&0xffff) + ((sum&0xffff0000)>>16);
		}

		if(LOGGING){os_WriteLog1("new tp check 1s cmpl=%04x\n",sum);}

		*org_tp_check = htons((uint16_t)(~sum));

		if(LOGGING){os_WriteLog1("new tp checksum=%04x\n",ntohs(*org_tp_check ));}

		if (proto == IPPROTO_UDP) {
			memcpy(data + IP_HLEN + MOE_HLEN + 6, org_tp_check, sizeof(uint16_t));
		}
		else if (proto == IPPROTO_TCP) {
			memcpy(data + IP_HLEN + MOE_HLEN + 16, org_tp_check, sizeof(uint16_t));
		}

		kfree(org_tp_check);
	}*/


	if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;
}

//Jaehee modified 2017/09/30
//Jaehee modified 2018/02/20
//Jaehee modified 2019/06/21
static int32_t moe_RemoveHeader(struct sk_buff *skb, uint32_t oldIP, uint32_t newIP, int proto)
{
	uint8_t* data = NULL;
	uint16_t len = 0, temp = 0;
	uint16_t pre16 = 0, post16 = 0;

	uint16_t org_tp_check = 0;
	//struct pseudo_header psh;
	uint32_t sum = 0;
	//int psize = 0;
	//char *pseudogram = NULL;
	//if(LOGGING){print_hex_dump(KERN_ALERT, "(pre)skb->data ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, ntohs(*(uint16_t*)(skb->data + 2 + ETH_HLEN))+ETH_HLEN, 1);}
	if(LOGGING){os_WriteLog("Removing header operation.\n");}

	memmove(skb->data + MOE_HLEN, skb->data, ETH_HLEN + IP_HLEN);
	skb_pull(skb, MOE_HLEN);
	data = skb->data + ETH_HLEN;

	memcpy(data + 0, (void*)"\x45", 1);
	len = ntohs(*(uint16_t*)(data + 2));
	if(LOGGING){os_WriteLog1("packet length(before)=%d\n",len);}
	len = htons(len - MOE_HLEN);
	if(LOGGING){os_WriteLog1("packet length(after)=%d\n",ntohs(len));}
	memcpy(data + 2, (void*)&len, 2);


	memcpy(data + 10, (void*)"\x0000", 2);
	memcpy(data + 16, (void*)&newIP, sizeof(newIP));
	temp = htons(CalculateIPChecksum(data, IP_HLEN));
	memcpy(data + 10, (void*)&temp, 2);

	if (proto != IPPROTO_ICMP && oldIP != newIP) {

		if (proto == IPPROTO_UDP) {
			memcpy(&org_tp_check, data + IP_HLEN + 6, sizeof(uint16_t));
			if(LOGGING){os_WriteLog1("original udp checksum=%04x\n",ntohs(org_tp_check));}
		} // UDP calculates checksum

//		if (proto == IPPROTO_UDP) {
//			memcpy(data + IP_HLEN + 6, (void*)"\x0000", sizeof(uint16_t));
//		} // UDP don't calculates checksum
//
		else if (proto == IPPROTO_TCP) {
			memcpy(&org_tp_check, data + IP_HLEN + 16, sizeof(uint16_t));
			if(LOGGING){os_WriteLog1("original tcp checksum=%04x\n",ntohs(org_tp_check));}
		} // TCP calculates checksum

		org_tp_check = ~ntohs(org_tp_check);
		if(LOGGING){os_WriteLog1("tp check 1s cmpl=%04x\n",org_tp_check);}
		oldIP = ntohl(oldIP);
		newIP = ntohl(newIP);
		if(LOGGING){
			os_WriteLog1("new dst ip addr=%08x\n",newIP);
			os_WriteLog1("old dst ip addr=%08x\n",oldIP);
		}

		pre16 = (uint16_t) ((oldIP & 0xffff0000) >> 16);
		post16 = (uint16_t) (oldIP & 0x0000ffff);
		if(LOGGING){
			os_WriteLog1("old dst ip preaddr=%04x\n",pre16);
			os_WriteLog1("old dst ip postaddr=%04x\n",post16);}

		if (org_tp_check < pre16) {
			sum = org_tp_check + 0xffff - pre16;
		}
		else {
			sum = org_tp_check - pre16;
		}
		if (sum < post16) {
			sum = sum + 0xffff - post16;
		}
		else {
			sum = sum - post16;
		}

		pre16 = (uint16_t) ((newIP & 0xffff0000) >> 16);
		post16 = (uint16_t) (newIP & 0x0000ffff);

		if(LOGGING){
			os_WriteLog1("new dst ip preaddr=%04x\n",pre16);
			os_WriteLog1("new dst ip postaddr=%04x\n",post16);
		}

		sum += pre16;
		if (sum>0xffff) {
			sum = (sum&0xffff) + ((sum&0xffff0000)>>16);
		}
		sum += post16;
		if (sum>0xffff) {
			sum = (sum&0xffff) + ((sum&0xffff0000)>>16);
		}

		if(LOGGING){os_WriteLog1("new tp check 1s cmpl=%04x\n",sum);}

		org_tp_check = htons((uint16_t)(~sum));

		if(LOGGING){os_WriteLog1("new tp checksum=%04x\n",ntohs(org_tp_check ));}


		if (proto == IPPROTO_UDP) {
			memcpy(data + IP_HLEN + 6, &org_tp_check, sizeof(uint16_t));
		} // UDP calculates checksum

		else if (proto == IPPROTO_TCP) {
			memcpy(data + IP_HLEN + 16, &org_tp_check, sizeof(uint16_t));
		}

	}
	/*if (proto != IPPROTO_ICMP && oldIP != newIP) {
		org_tp_check = kmalloc(sizeof(uint16_t),GFP_KERNEL);

		if (proto == IPPROTO_UDP) {
			memcpy(org_tp_check, data + IP_HLEN + 6, sizeof(uint16_t));
			if(LOGGING){os_WriteLog1("original udp checksum=%04x\n",ntohs(*org_tp_check));}
		}

		else if (proto == IPPROTO_TCP) {
			memcpy(org_tp_check, data + IP_HLEN + 16, sizeof(uint16_t));
			if(LOGGING){os_WriteLog1("original tcp checksum=%04x\n",ntohs(*org_tp_check));}
		}

		*org_tp_check = ~ntohs(*org_tp_check);
		if(LOGGING){os_WriteLog1("tp check 1s cmpl=%04x\n",*org_tp_check);}
		oldIP = ntohl(oldIP);
		newIP = ntohl(newIP);
		if(LOGGING){
			os_WriteLog1("new dst ip addr=%08x\n",newIP);
			os_WriteLog1("old dst ip addr=%08x\n",oldIP);
		}

		pre16 = (uint16_t) ((oldIP & 0xffff0000) >> 16);
		post16 = (uint16_t) (oldIP & 0x0000ffff);
		if(LOGGING){
			os_WriteLog1("old dst ip preaddr=%04x\n",pre16);
			os_WriteLog1("old dst ip postaddr=%04x\n",post16);}

		if (*org_tp_check < pre16) {
			sum = *org_tp_check + 0xffff - pre16;
		}
		else {
			sum = *org_tp_check - pre16;
		}
		if (sum < post16) {
			sum = sum + 0xffff - post16;
		}
		else {
			sum = sum - post16;
		}

		pre16 = (uint16_t) ((newIP & 0xffff0000) >> 16);
		post16 = (uint16_t) (newIP & 0x0000ffff);

		if(LOGGING){
			os_WriteLog1("new dst ip preaddr=%04x\n",pre16);
			os_WriteLog1("new dst ip postaddr=%04x\n",post16);
			}

		sum += pre16;
		if (sum>0xffff) {
			sum = (sum&0xffff) + ((sum&0xffff0000)>>16);
		}
		sum += post16;
		if (sum>0xffff) {
			sum = (sum&0xffff) + ((sum&0xffff0000)>>16);
		}

		if(LOGGING){os_WriteLog1("new tp check 1s cmpl=%04x\n",sum);}

		*org_tp_check = htons((uint16_t)(~sum));

		if(LOGGING){os_WriteLog1("new tp checksum=%04x\n",ntohs(*org_tp_check ));}

		if (proto == IPPROTO_UDP) {
			memcpy(data + IP_HLEN + 6, org_tp_check, sizeof(uint16_t));
		}
		else if (proto == IPPROTO_TCP) {
			memcpy(data + IP_HLEN + 16, org_tp_check, sizeof(uint16_t));
		}

		kfree(org_tp_check);

	}*/

	//---ancient legacy---by Jaehee
	/*
    if (!is_icmp){

		if(LOGGING){os_WriteLog("received tcp segment\n");}
		if(LOGGING){os_WriteLog("-----after change IP-----\n");}

		org_tp_check = kmalloc(sizeof(uint16_t),GFP_KERNEL);
		memcpy(org_tp_check, data + IP_HLEN + 16, sizeof(uint16_t));
		if(LOGGING){os_WriteLog1("original tcp checksum=%04x\n",ntohs(*org_tp_check));}
		//memcpy(data + IP_HLEN + 16, (void*)"\x0000",2);  //checksum = 0



		memcpy(&psh.source_address,(uint32_t*)(data + 12), 4);
		memcpy(&psh.dest_address, (uint32_t*)(data + 16), 4);
		if(LOGGING){os_WriteLog1("ip saddr=%08x\n",psh.source_address);}
		if(LOGGING){os_WriteLog1("ip daddr=%08x\n",psh.dest_address);}
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(ntohs(len) - IP_HLEN);
		if(LOGGING){os_WriteLog1("tcp_length=%d\n",psh.tcp_length);}
		psize = sizeof(struct pseudo_header) + ntohs(len) - IP_HLEN;
		pseudogram = kmalloc(psize,GFP_KERNEL);

		memcpy(pseudogram, (char*) &psh, sizeof (struct pseudo_header));
		memcpy(pseudogram + sizeof(struct pseudo_header), data + IP_HLEN, ntohs(len) - IP_HLEN);
		tcp_check = csum((unsigned short*) pseudogram, psize);
		if(LOGGING){os_WriteLog1("manual tcp checksum=%04x\n",tcp_check);}
		//memcpy(data + IP_HLEN + 16, (void*)&tcp_check, sizeof(tcp_check));

		//if(LOGGING){print_hex_dump(KERN_ALERT, "data ", DUMP_PREFIX_OFFSET, 16, 1, data, ntohs(len)+ETH_HLEN, 1);}
		kfree(pseudogram);
		kfree(org_tp_check);



		if(LOGGING){os_WriteLog1("original skb csum=%04x\n",skb->csum);}
		struct iphdr *iph;
        struct tcphdr *tcph;
        int tcplen = ntohs(len) - IP_HLEN;
		if(LOGGING){os_WriteLog1("tcp seg length=%d\n",tcplen);}
        iph = (struct iphdr *)data;
        tcph = (struct tcphdr *)(data + IP_HLEN);
        tcph->check = 0;
		if(LOGGING){os_WriteLog1("zero tcp checksum=%4x\n",tcph->check);}
        csum_p = csum_partial((char *)tcph, tcplen, 0);
        tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_p);
		if(LOGGING){os_WriteLog1("csum partial=%04x\n",csum_p);}
		if(LOGGING){os_WriteLog1("ip saddr=%08x\n",iph->saddr);}
		if(LOGGING){os_WriteLog1("ip daddr=%08x\n",iph->daddr);}
		if(LOGGING){os_WriteLog1("ip hdr len=%d\n",iph->ihl);}
		if(LOGGING){os_WriteLog1("ip tot len=%d\n",ntohs(iph->tot_len));}
		if(LOGGING){os_WriteLog1("tcp src=%d\n",ntohs(tcph->source));}
		if(LOGGING){os_WriteLog1("tcp dst=%d\n",ntohs(tcph->dest));}
		tcph_len = (*(uint8_t*)(data + IP_HLEN + 12) & 0xf0) >> 4;
		if(LOGGING){os_WriteLog1("tcp hdr len=%x\n",tcph_len);}
		if(LOGGING){os_WriteLog1("kern api tcp checksum=%04x\n",ntohs(tcph->check));}
		if(LOGGING){print_hex_dump(KERN_ALERT, "data ", DUMP_PREFIX_OFFSET, 16, 1, data + IP_HLEN + (tcph_len*4), ntohs(len) - IP_HLEN - (tcph_len*4), 1);}
		kfree(org_tp_check);

		if(LOGGING){os_WriteLog("-----END after change IP-----\n");}
	}
	*/



	if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;
}

//Jaehee & Jaehyun modified ---
unsigned short csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while(nbytes>1){
		sum+=*ptr++;
		nbytes-=2;

	}
	if(nbytes==1){
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	return answer;

}


uint16_t tcp_checksum(const void *buff, size_t len, uint32_t src_addr, uint32_t dest_addr)
{
	const uint16_t *buf=buff;
	uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
	uint32_t sum;
	size_t length=len;

	// Calculate the sum                                            //
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if ( len & 1 )
		// Add the padding if the packet lenght is odd          //
		sum += *((uint8_t *)buf);

	// Add the pseudo-header                                        //
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(6);
	sum += htons(length);

	// Add the carries                                              //
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum                           //
	return ( (uint16_t)(~sum)  );
}
//Jaehee & Jaehyun modified End ---


static uint8_t moe_GetSwitchNum(struct sk_buff* skb)
{
	uint8_t i = 0, switchNum = 0;
	uint8_t* addr = skb->dev->dev_addr;
	if (OVS_MODE == OVS_MODE_MININET) {
		for (i = 0; i <= sizeof(i) * 0xFF; i++) {
			if (!(skb->dev->name[i] >= '0' && skb->dev->name[i] <= '9') && switchNum != 0) break;
			if (skb->dev->name[i] >= '0' && skb->dev->name[i] <= '9')
				switchNum = switchNum * 10 + (skb->dev->name[i] - '0');
		}
		if (skb->dev->name[0] == 's')
			switchNum -= 1; // Our switch number increases from one.
		else if (skb->dev->name[0] == 'e')
			switchNum -= 1; // Real interface number increases from one.
	}
	else if (OVS_MODE == OVS_MODE_TESTBED) {
		if(LOGGING){os_WriteLog6("Switch MAC=%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);}
		if (addr[0] == 0x20 && addr[1] == 0x00 && addr[2] == 0x00 && addr[3] == 0x00)
			return (uint8_t)(addr[4]+1);
	}
	return switchNum;
}

//Jaehee modified 2018/02/19
//Jaehee modified 2018/02/20
//Jaehee modified 2019/01/10
//Jaehee modified 2019/05/01
//Jaehee modified 2019/05/14
//Jaehee modified 2019/06/19
//Jaehee modified 2019/06/21
static int32_t moe_CheckHeader(struct vport *vp, struct sk_buff *skb, struct sw_flow_key *key)
{
	uint8_t switchNum = 0;
	uint8_t switchType = SWITCHTYPE_NONE;
	uint8_t senderType = SENDERTYPE_NONE;
	uint8_t* data = NULL;
	uint16_t protocol = 0;


	uint8_t IHL = 0, tp_protocol = 0; //IHL = Protocol version number + IP Header Length
	//original ip header length is 20
	//moe header added, 44(sha1) -> 56(sha256)
	uint32_t srcIP = 0, dstIP = 0;
	uint16_t totalLen = 0, srcPort = 0, dstPort = 0;
	uint32_t oldIP = 0, newIP = 0;
	uint8_t dstPortByteArr[2] = {0,0};
	//uint8_t srcPortByteArr[2];
	uint32_t* ptrSrcIP = NULL;
	uint32_t originalIP = 0;
	uint8_t dstIPisSWIP = 0;
	int i=0;
	uint8_t frag = 0;

	uint8_t* hashed = NULL;

	if (LOGGING){os_WriteLog("A new packet.\n");}
	switchNum = moe_GetSwitchNum(skb);
	if (switchNum > SWITCH_NUMS) {if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;}
	switchType = SW_TYPES[switchNum-1];
	if (switchType != SWITCHTYPE_ES) {if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;}

	data = skb->data;

	if(LOGGING){os_WriteLog4("Received data mac header=%02x:%02x:%02x:%02x:xx:xx.\n",data[ETH_ALEN+0],data[ETH_ALEN+1],data[ETH_ALEN+2],data[ETH_ALEN+3]);}
	if (data[ETH_ALEN+0] == 0x10 && data[ETH_ALEN+1] == 0x00 && data[ETH_ALEN+2] == 0x00 && data[ETH_ALEN+3] == 0x00) {senderType = SENDERTYPE_UE;}
	if (data[ETH_ALEN+0] == 0x50 && data[ETH_ALEN+1] == 0x3e && data[ETH_ALEN+2] == 0xaa ) {senderType = SENDERTYPE_UE;}
	if (data[ETH_ALEN+0] == 0x20 && data[ETH_ALEN+1] == 0x00 && data[ETH_ALEN+2] == 0x00 && data[ETH_ALEN+3] == 0x00) {senderType = SENDERTYPE_SW;}
	if (senderType == SENDERTYPE_NONE) {if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;}

	protocol = ntohs(*(uint16_t*)(data + ETH_ALEN*2));
	if (protocol != ETH_P_IP && protocol != ETH_P_ARP) {if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;}

	data += ETH_HLEN;

	if (protocol == ETH_P_ARP && senderType == SENDERTYPE_UE) {
		if(LOGGING){os_WriteLog("New UE. Check new UE.\n");}
		moe_CheckNewUE(switchNum, protocol, data);
		if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;
	}

	else if (protocol == ETH_P_IP) {
		IHL = *(uint8_t*)data;           // Do not use 'ntohl'
		if (IHL != 0x45 && IHL != 0x4E) {if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;} //4B(SHA1) -> 4E(SHA256)
		srcIP = *(uint32_t*)(data + 12);	// Do not use 'ntohl'
		ptrSrcIP = (uint32_t*)(data + 12);

		dstIP = *(uint32_t*)(data + 16);	// Do not use 'ntohl'

		frag = *(uint8_t*)(data + 6); // if this packet fragmented, frag is 0x20

		for (i=0 ; i<SWITCH_NUMS ; i++){ 
			if(dstIP==SWITCHS_IP[i]) {
				dstIPisSWIP = 1;
				break;
			}
		}
		if (senderType==SENDERTYPE_UE && !dstIPisSWIP) {
			if(LOGGING){
				os_WriteLog3("Check header. Switch num=%u, type=%u, Sender type=%u\n", switchNum, switchType, senderType);
				os_WriteLog8("New packet. Source IP=%u.%u.%u.%u, Destination IP=%u.%u.%u.%u\n",
							 *((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3),
							 *((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3));
				os_WriteLog4("Value of source IP pointer=%u.%u.%u.%u\n", *((uint8_t*)ptrSrcIP + 0),*((uint8_t*)ptrSrcIP + 1),*((uint8_t*)ptrSrcIP + 2),*((uint8_t*)ptrSrcIP + 3));
			}
		} else if (dstIPisSWIP) {
			if(LOGGING){
				os_WriteLog8("Check header. Source IP=%u.%u.%u.%u, Destination SWIP=%u.%u.%u.%u\n",*((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3),
							 *((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3));
			}
		}
		
		
		
		if (dstIP == 0 || dstIP == 0xFFFFFFFF) {if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;}

		totalLen = ntohs(*(uint16_t*)(data + 2));
		tp_protocol = *(data + 9);


		// --------------------------------------------------------------------------------
		// ICMP Header Addition Operation
		// --------------------------------------------------------------------------------
		// or
		// --------------------------------------------------------------------------------
		// Sender exists in subnet
		// --------------------------------------------------------------------------------

		if (tp_protocol == IPPROTO_ICMP){
			if(LOGGING){
				os_WriteLog8("ICMP packet check header. Source IP=%u.%u.%u.%u, Destination IP=%u.%u.%u.%u\n",*((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3),
							 *((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3));
			}


			if ((IHL == 0x45 && (totalLen - IP_HLEN >= 18) && ((dstIP&0x00ffffff)!=(SWITCHS_IP[switchNum-1]&0x00ffffff)) && dstIP != 16777343 && dstIP != SWITCHS_IP[switchNum-1])||(senderType == SENDERTYPE_UE && (totalLen - IP_HLEN >= 18) && IHL == 0x45 && !dstIPisSWIP)) {
				//normal IP packet
				//dstIP is not 127.0.0.1 and not this switch's ip
				//host is in other subnet
				//or
				//sender type is UE and dest ip is in sender's subnet
				//data += IP_HLEN;
				//if (data[0] == 0x08 && data[1] == 0x10); // Type (ECHO_REQUEST) and Code
				//ipc_SendMessage(switchNum, OPCODE_INFORM_CONNECTION, srcIP, data + 8); // 170327 Jaehee

				if (srcIP != 16777343 && srcIP != SWITCHS_IP[switchNum-1] && moe_GetOriginIPFromSrcIP(switchNum, srcIP, 0, &hashed, &originalIP)) {
					if(LOGGING){os_WriteLog("Changing src IP operation.\n");}
					memcpy(ptrSrcIP,&originalIP,sizeof(uint32_t));
					if(LOGGING){os_WriteLog9("ICMP, Switch num=%u, SrcIP=%u.%u.%u.%u, Original IP=%u.%u.%u.%u\n", switchNum,
											 *((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3),
											 *((uint8_t*)&originalIP + 0), *((uint8_t*)&originalIP + 1), *((uint8_t*)&originalIP + 2), *((uint8_t*)&originalIP + 3));}

				}

				if (!dstIPisSWIP && !moe_GetObjectFromIP(switchNum, dstIP, 0, &hashed, &newIP)) { // If it doesn't exist,
					dstPortByteArr[1] = 0;
					dstPortByteArr[0] = 0;
					// Send a request message to the upper layer
					ipc_SendMessage(switchNum, OPCODE_GET_HASH, dstIP, dstPortByteArr);
					moe_SaveSKB(switchNum, dstIP, vp, skb);
					if(LOGGING){os_WriteLog("Not forwarding, buffering.");}  return DO_NOT_FORWARD;

				}
				if(LOGGING){os_WriteLog9("Switch num=%u, Packet's original destination IP=%u.%u.%u.%u, New IP in the cache=%u.%u.%u.%u\n", switchNum,
										 *((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3),
										 *((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3));}

				if (newIP == SWITCHS_IP[switchNum-1]) { 
					if(LOGGING){os_WriteLog8("No adding header, because new IP in the cache=%u.%u.%u.%u equals to this switch IP=%u.%u.%u.%u\n", 
										 *((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3),
										 *((uint8_t*)&SWITCHS_IP[switchNum-1] + 0), *((uint8_t*)&SWITCHS_IP[switchNum-1] + 1), *((uint8_t*)&SWITCHS_IP[switchNum-1] + 2), *((uint8_t*)&SWITCHS_IP[switchNum-1] + 3));}
					if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD; // newIP (ESIP) equals to this switch IP.
				}
					
				if (newIP == 0) {
					return moe_AddHeader(skb, srcIP, hashed, 0, IPPROTO_ICMP, 0); //new IP is 0 and doInsertObjID is 0
				}

				return moe_AddHeader(skb, srcIP, hashed, newIP, IPPROTO_ICMP, 1); //new IP is newIP(ESIP) and doInsertObjID is 1

			}

			// --------------------------------------------------------------------------------
			// Ignore ICMP Packet 
			// --------------------------------------------------------------------------------
			if (IHL == 0x45) {
				if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;
				
			}
			
			// --------------------------------------------------------------------------------
			// ICMP Header Removal Operation
			// --------------------------------------------------------------------------------
			else if (senderType == SENDERTYPE_SW && IHL == 0x4E && dstIPisSWIP) {

				hashed = data + IP_HLEN + 4;
				if (!moe_GetObjectFromHash(switchNum, hashed, &oldIP, &newIP)) { // If it doesn't exist,
					// Send a request message to the upper layer
					ipc_SendMessage(switchNum, OPCODE_GET_IP, dstIP, hashed);
					moe_SaveSKB(switchNum, dstIP, vp, skb);
					if(LOGGING){os_WriteLog("Not forwarding, buffering.");}  return DO_NOT_FORWARD;
				}
				if(LOGGING){os_WriteLog9("Switch num=%u, Received IP=%u.%u.%u.%u, Host IP=%u.%u.%u.%u\n", switchNum,
										 *((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3),
										 *((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3));}
				if (newIP == 0) {
					if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;
				}

				return moe_RemoveHeader(skb, oldIP, newIP, IPPROTO_ICMP);

			}
		}

		srcPort = dstPort = 0;
		if (tp_protocol == IPPROTO_TCP || tp_protocol == IPPROTO_UDP) {
			if (IHL == 0x45) {
				srcPort = ntohs(*(uint16_t*)(data + IP_HLEN));
				dstPort = ntohs(*(uint16_t*)(data + IP_HLEN + 2));
			} else if (IHL == 0x4E) {
				srcPort = ntohs(*(uint16_t*)(data + IP_HLEN + MOE_HLEN));
				dstPort = ntohs(*(uint16_t*)(data + IP_HLEN + MOE_HLEN + 2));
			}

		}

		if (senderType == SENDERTYPE_UE && tp_protocol == IPPROTO_TCP && totalLen == 246 && srcPort == 4001 && dstPort == 14999) {
			if(LOGGING){os_WriteLog("New UE.\n");}
			moe_CheckNewUE(switchNum, protocol, data);
			if(LOGGING){os_WriteLog("Not forwarding, buffering.");}  return DO_NOT_FORWARD;
		}
		
		if (senderType == SENDERTYPE_UE && tp_protocol == IPPROTO_UDP && (dstPort == 67 || dstPort == 68)) { //DHCP ports
			if(LOGGING){os_WriteLog("DHCP of new UE.\n");}
			moe_CheckNewUE(switchNum, protocol, data);
			if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;

		}
		
		// --------------------------------------------------------------------------------
		// Header Addition Operation
		// --------------------------------------------------------------------------------
		// or
		// --------------------------------------------------------------------------------
		// Sender exists in subnet
		// --------------------------------------------------------------------------------
		if(LOGGING){
			os_WriteLog8("IP packet check header. Source IP=%u.%u.%u.%u, Destination SWIP=%u.%u.%u.%u\n",*((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3),
						 *((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3));
		}


		if ((senderType == SENDERTYPE_UE && IHL == 0x45) || (senderType == SENDERTYPE_SW && IHL == 0x45 && !dstIPisSWIP))  {
			hashed = NULL;
			// Check entry in order to append an MoE header
			/*if (!moe_GetObjectFromIP(switchNum, dstIP, 0, &hashed, &newIP)) { // If it doesn't exist,
				// Send a request message to the upper layer
				ipc_SendMessage(switchNum, OPCODE_GET_HASH, dstIP, 0);
				moe_SaveSKB(switchNum, dstIP, vp, skb);
				if(LOGGING){os_WriteLog("Not forwarding, buffering.");}  return DO_NOT_FORWARD;
			}*/
			if (srcIP != 16777343 && srcIP != SWITCHS_IP[switchNum-1] && moe_GetOriginIPFromSrcIP(switchNum, srcIP, srcPort, &hashed, &originalIP)) {
				if(LOGGING){os_WriteLog("Changing src IP operation.\n");}
				memcpy(ptrSrcIP,&originalIP,sizeof(uint32_t));
				if(LOGGING){os_WriteLog10("Switch num=%u, SrcIP=%u.%u.%u.%u, srcPort=%u, Original IP=%u.%u.%u.%u\n", switchNum,
										  *((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3), srcPort,
										  *((uint8_t*)&originalIP + 0), *((uint8_t*)&originalIP + 1), *((uint8_t*)&originalIP + 2), *((uint8_t*)&originalIP + 3));}

			}

			if (dstIP != 16777343 && dstIP != SWITCHS_IP[switchNum-1] && !moe_GetObjectFromIP(switchNum, dstIP, dstPort, &hashed, &newIP)) { // If it doesn't exist,
				//not 127.0.0.1 and not this switch's ip
				dstPortByteArr[1] = dstPort & 0xff;
				dstPortByteArr[0] = ((dstPort >> 8) & 0xff);
				if(LOGGING){os_WriteLog1("cache does not have 'port number' of dest = %u.\n", dstPort);}
				// Send a request message to the upper layer
				if (dstPort > 61000 || dstPort < 32768) {
					ipc_SendMessage(switchNum, OPCODE_GET_HASH, dstIP, dstPortByteArr);
					moe_SaveSKB(switchNum, dstIP, vp, skb);
					if(LOGGING){os_WriteLog("Not forwarding, buffering.");}  return DO_NOT_FORWARD;
				} else {
					dstPortByteArr[0] = 0;
					dstPortByteArr[1] = 0;
					ipc_SendMessage(switchNum, OPCODE_GET_HASH, dstIP, dstPortByteArr);
					moe_SaveSKB(switchNum, dstIP, vp, skb);
					if(LOGGING){os_WriteLog("Not forwarding, buffering.");}  return DO_NOT_FORWARD;
				}
				// 170327 Jaehee
			}
			if(LOGGING){os_WriteLog10("Switch num=%u, Packet's original destination IP=%u.%u.%u.%u, dstPort=%u, New IP in the cache=%u.%u.%u.%u\n", switchNum,
									  *((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3), dstPort,
									  *((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3));}

			if (frag == 0x20) {
				tp_protocol = IPPROTO_ICMP;
			} // this packet is fragmented

			if (newIP == SWITCHS_IP[switchNum-1]) { 
				if(LOGGING){os_WriteLog8("No adding header, because new IP in the cache=%u.%u.%u.%u equals to this switch IP=%u.%u.%u.%u\n", 
										 *((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3),
										 *((uint8_t*)&SWITCHS_IP[switchNum-1] + 0), *((uint8_t*)&SWITCHS_IP[switchNum-1] + 1), *((uint8_t*)&SWITCHS_IP[switchNum-1] + 2), *((uint8_t*)&SWITCHS_IP[switchNum-1] + 3));}
				if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD; // newIP (ESIP) equals to this switch IP.
			}
			
			if (newIP == 0) {
				return moe_AddHeader(skb, srcIP, hashed, 0, tp_protocol, 0); //new IP is 0 and doInsertObjID is 0
			}

			return moe_AddHeader(skb, srcIP, hashed, newIP, tp_protocol, 1); //new IP is newIP(ESIP) and doInsertObjID is 1
		}

			// --------------------------------------------------------------------------------
			// Header Removal Operation
			// --------------------------------------------------------------------------------
		else if (senderType == SENDERTYPE_SW && IHL == 0x4E && dstIPisSWIP) {

			hashed = data + IP_HLEN + 4;
			if (!moe_GetObjectFromHash(switchNum, hashed, &oldIP, &newIP)) { // If it doesn't exist,
				// Send a request message to the upper layer
				ipc_SendMessage(switchNum, OPCODE_GET_IP, dstIP, hashed);
				moe_SaveSKB(switchNum, dstIP, vp, skb);
				if(LOGGING){os_WriteLog("Not forwarding, buffering.");}  return DO_NOT_FORWARD;
			}
			if(LOGGING){os_WriteLog10("Switch num=%u, Received IP=%u.%u.%u.%u, dstPort=%u, Host IP=%u.%u.%u.%u\n", switchNum,
									  *((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3), dstPort,
									  *((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3));
				os_WriteLog4("Old IP=%u.%u.%u.%u\n", *((uint8_t*)&oldIP + 0), *((uint8_t*)&oldIP + 1), *((uint8_t*)&oldIP + 2), *((uint8_t*)&oldIP + 3));}
			if (newIP == 0) {
				
				if(LOGGING){os_WriteLog("Forwarding.");} return DO_FORWARD;
			}

			/*
			if (tp_protocol == IPPROTO_UDP) {
				if(LOGGING){os_WriteLog("received udp segment\n");}
				*(uint16_t*)(data + IP_HLEN + MOE_HLEN + 6) = (uint16_t)0;

				uint16_t udp_check = CalculateUDPChecksum(srcIP, newIP, srcPort, dstPort,
					data + IP_HLEN + MOE_HLEN , ntohs(*(uint16_t*)(data + IP_HLEN + MOE_HLEN + 4)) );

				memcpy(data + IP_HLEN + MOE_HLEN + 6, (void*)&udp_check, sizeof(udp_check));
				if(LOGGING){os_WriteLog1("udp checksum=%x\n",udp_check);}

			} */
			if (frag == 0x20) {
				tp_protocol = IPPROTO_ICMP;
			} // this packet is fragmented

			return moe_RemoveHeader(skb, oldIP, newIP, tp_protocol);
		}
	}

	if(LOGGING){os_WriteLog("Forwarding.");} 
 return DO_FORWARD;
}

// ------------------------------------------------------------
// Jaehee: LM Support End
// ------------------------------------------------------------
/**
 *	ovs_vport_init - initialize vport subsystem
 *
 * Called at module load time to initialize the vport subsystem.
 */
int ovs_vport_init(void)
{
	int err;

	dev_table = kzalloc(VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dev_table)
		return -ENOMEM;

	err = lisp_init_module();
	if (err)
		goto err_lisp;
	err = gre_init();
	if (err && err != -EEXIST) {
		goto err_gre;
	} else {
		if (err == -EEXIST) {
			pr_warn("Cannot take GRE protocol rx entry"\
				"- The GRE/ERSPAN rx feature not supported\n");
			/* continue GRE tx */
		}

		err = ipgre_init();
		if (err && err != -EEXIST) 
			goto err_ipgre;
		compat_gre_loaded = true;
	}
	err = ip6gre_init();
	if (err && err != -EEXIST) {
		goto err_ip6gre;
	} else {
		if (err == -EEXIST) {
			pr_warn("IPv6 GRE/ERSPAN Rx mode is not supported\n");
			goto skip_ip6_tunnel_init;
		}
	}

	err = ip6_tunnel_init();
	if (err)
		goto err_ip6_tunnel;
	else
		compat_ip6_tunnel_loaded = true;

skip_ip6_tunnel_init:
	err = geneve_init_module();
	if (err)
		goto err_geneve;
	err = vxlan_init_module();
	if (err)
		goto err_vxlan;
	err = ovs_stt_init_module();
	if (err)
		goto err_stt;

	// ------------------------------------------------------------
	// Jaehee: LM Support
	// ------------------------------------------------------------
	os_CreateIPCSocket();
	hash_init(OBJ_TBL);
	hash_init(OBJ_MOIP_TBL);
	hash_init(OBJ_REV_TBL);
	os_WriteLog("--- OvS with LM-MEC has successfully been loaded. v1.3.5 --- \n");
	{int i; for (i = 0; i < SWITCH_NUMS; i++) SW_TYPES[i] = SWITCHTYPE_IMS;}
	{int i; for (i = 0; i < SWITCH_NUMS; i++) { STAT_TIMES[i].tv_sec = STAT_TIMES[i].tv_usec = 0; STAT_NEW_UES[i] = 0; }}
	ipc_SendMessage(0, OPCODE_BOOTUP, 0, NULL);
	do_gettimeofday(&START_TIME);
	os_mySrand(START_TIME.tv_usec % 100);
	// ------------------------------------------------------------
	// Jaehee: LM Support End
	// ------------------------------------------------------------


	return 0;
	ovs_stt_cleanup_module();
err_stt:
	vxlan_cleanup_module();
err_vxlan:
	geneve_cleanup_module();
err_geneve:
	ip6_tunnel_cleanup();
err_ip6_tunnel:
	ip6gre_fini();
err_ip6gre:
	ipgre_fini();
err_ipgre:
	gre_exit();
err_gre:
	lisp_cleanup_module();
err_lisp:
	kfree(dev_table);
	return err;
}

/**
 *	ovs_vport_exit - shutdown vport subsystem
 *
 * Called at module exit time to shutdown the vport subsystem.
 */
void ovs_vport_exit(void)
{
	if (compat_gre_loaded) {
		gre_exit();
		ipgre_fini();
	}
	ovs_stt_cleanup_module();
	vxlan_cleanup_module();
	geneve_cleanup_module();
	if (compat_ip6_tunnel_loaded)
		ip6_tunnel_cleanup();
	ip6gre_fini();
	lisp_cleanup_module();
	kfree(dev_table);
	// ------------------------------------------------------------
	// Jaehee: LM Support
	// ------------------------------------------------------------
	os_CloseIPCSocket();
	moe_CleanUp();
	// ------------------------------------------------------------
	// Jaehee: LM Support End
	// ------------------------------------------------------------
}

static struct hlist_head *hash_bucket(const struct net *net, const char *name)
{
	unsigned int hash = jhash(name, strlen(name), (unsigned long) net);
	return &dev_table[hash & (VPORT_HASH_BUCKETS - 1)];
}

int __ovs_vport_ops_register(struct vport_ops *ops)
{
	int err = -EEXIST;
	struct vport_ops *o;

	ovs_lock();
	list_for_each_entry(o, &vport_ops_list, list)
		if (ops->type == o->type)
			goto errout;

	list_add_tail(&ops->list, &vport_ops_list);
	err = 0;
errout:
	ovs_unlock();
	return err;
}
EXPORT_SYMBOL_GPL(__ovs_vport_ops_register);

void ovs_vport_ops_unregister(struct vport_ops *ops)
{
	ovs_lock();
	list_del(&ops->list);
	ovs_unlock();
}
EXPORT_SYMBOL_GPL(ovs_vport_ops_unregister);

/**
 *	ovs_vport_locate - find a port that has already been created
 *
 * @name: name of port to find
 *
 * Must be called with ovs or RCU read lock.
 */
struct vport *ovs_vport_locate(const struct net *net, const char *name)
{
	struct hlist_head *bucket = hash_bucket(net, name);
	struct vport *vport;

	hlist_for_each_entry_rcu(vport, bucket, hash_node)
		if (!strcmp(name, ovs_vport_name(vport)) &&
		    net_eq(ovs_dp_get_net(vport->dp), net))
			return vport;

	return NULL;
}

/**
 *	ovs_vport_alloc - allocate and initialize new vport
 *
 * @priv_size: Size of private data area to allocate.
 * @ops: vport device ops
 *
 * Allocate and initialize a new vport defined by @ops.  The vport will contain
 * a private data area of size @priv_size that can be accessed using
 * vport_priv().  vports that are no longer needed should be released with
 * vport_free().
 */
struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			  const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size;

	alloc_size = sizeof(struct vport);
	if (priv_size) {
		alloc_size = ALIGN(alloc_size, VPORT_ALIGN);
		alloc_size += priv_size;
	}

	vport = kzalloc(alloc_size, GFP_KERNEL);
	if (!vport)
		return ERR_PTR(-ENOMEM);

	vport->dp = parms->dp;
	vport->port_no = parms->port_no;
	vport->ops = ops;
	INIT_HLIST_NODE(&vport->dp_hash_node);

	if (ovs_vport_set_upcall_portids(vport, parms->upcall_portids)) {
		kfree(vport);
		return ERR_PTR(-EINVAL);
	}

	return vport;
}
EXPORT_SYMBOL_GPL(ovs_vport_alloc);

/**
 *	ovs_vport_free - uninitialize and free vport
 *
 * @vport: vport to free
 *
 * Frees a vport allocated with vport_alloc() when it is no longer needed.
 *
 * The caller must ensure that an RCU grace period has passed since the last
 * time @vport was in a datapath.
 */
void ovs_vport_free(struct vport *vport)
{
	/* vport is freed from RCU callback or error path, Therefore
	 * it is safe to use raw dereference.
	 */
	kfree(rcu_dereference_raw(vport->upcall_portids));
	kfree(vport);
}
EXPORT_SYMBOL_GPL(ovs_vport_free);

static struct vport_ops *ovs_vport_lookup(const struct vport_parms *parms)
{
	struct vport_ops *ops;

	list_for_each_entry(ops, &vport_ops_list, list)
		if (ops->type == parms->type)
			return ops;

	return NULL;
}

/**
 *	ovs_vport_add - add vport device (for kernel callers)
 *
 * @parms: Information about new vport.
 *
 * Creates a new vport with the specified configuration (which is dependent on
 * device type).  ovs_mutex must be held.
 */
struct vport *ovs_vport_add(const struct vport_parms *parms)
{
	struct vport_ops *ops;
	struct vport *vport;

	ops = ovs_vport_lookup(parms);
	if (ops) {
		struct hlist_head *bucket;

		if (!try_module_get(ops->owner))
			return ERR_PTR(-EAFNOSUPPORT);

		vport = ops->create(parms);
		if (IS_ERR(vport)) {
			module_put(ops->owner);
			return vport;
		}

		bucket = hash_bucket(ovs_dp_get_net(vport->dp),
				     ovs_vport_name(vport));
		hlist_add_head_rcu(&vport->hash_node, bucket);
		return vport;
	}

	if (parms->type == OVS_VPORT_TYPE_GRE && !compat_gre_loaded) {
		pr_warn("GRE protocol already loaded!\n");
		return ERR_PTR(-EAFNOSUPPORT);
	}
	/* Unlock to attempt module load and return -EAGAIN if load
	 * was successful as we need to restart the port addition
	 * workflow.
	 */
	ovs_unlock();
	request_module("vport-type-%d", parms->type);
	ovs_lock();

	if (!ovs_vport_lookup(parms))
		return ERR_PTR(-EAFNOSUPPORT);
	else
		return ERR_PTR(-EAGAIN);
}

/**
 *	ovs_vport_set_options - modify existing vport device (for kernel callers)
 *
 * @vport: vport to modify.
 * @options: New configuration.
 *
 * Modifies an existing device with the specified configuration (which is
 * dependent on device type).  ovs_mutex must be held.
 */
int ovs_vport_set_options(struct vport *vport, struct nlattr *options)
{
	if (!vport->ops->set_options)
		return -EOPNOTSUPP;
	return vport->ops->set_options(vport, options);
}

/**
 *	ovs_vport_del - delete existing vport device
 *
 * @vport: vport to delete.
 *
 * Detaches @vport from its datapath and destroys it.  ovs_mutex must be
 * held.
 */
void ovs_vport_del(struct vport *vport)
{
	ASSERT_OVSL();

	hlist_del_rcu(&vport->hash_node);
	module_put(vport->ops->owner);
	vport->ops->destroy(vport);
}

/**
 *	ovs_vport_get_stats - retrieve device stats
 *
 * @vport: vport from which to retrieve the stats
 * @stats: location to store stats
 *
 * Retrieves transmit, receive, and error stats for the given device.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
void ovs_vport_get_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	const struct rtnl_link_stats64 *dev_stats;
	struct rtnl_link_stats64 temp;

	dev_stats = dev_get_stats(vport->dev, &temp);
	stats->rx_errors  = dev_stats->rx_errors;
	stats->tx_errors  = dev_stats->tx_errors;
	stats->tx_dropped = dev_stats->tx_dropped;
	stats->rx_dropped = dev_stats->rx_dropped;

	stats->rx_bytes	  = dev_stats->rx_bytes;
	stats->rx_packets = dev_stats->rx_packets;
	stats->tx_bytes	  = dev_stats->tx_bytes;
	stats->tx_packets = dev_stats->tx_packets;
}

/**
 *	ovs_vport_get_options - retrieve device options
 *
 * @vport: vport from which to retrieve the options.
 * @skb: sk_buff where options should be appended.
 *
 * Retrieves the configuration of the given device, appending an
 * %OVS_VPORT_ATTR_OPTIONS attribute that in turn contains nested
 * vport-specific attributes to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room, or another
 * negative error code if a real error occurred.  If an error occurs, @skb is
 * left unmodified.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct nlattr *nla;
	int err;

	if (!vport->ops->get_options)
		return 0;

	nla = nla_nest_start(skb, OVS_VPORT_ATTR_OPTIONS);
	if (!nla)
		return -EMSGSIZE;

	err = vport->ops->get_options(vport, skb);
	if (err) {
		nla_nest_cancel(skb, nla);
		return err;
	}

	nla_nest_end(skb, nla);
	return 0;
}

/**
 *	ovs_vport_set_upcall_portids - set upcall portids of @vport.
 *
 * @vport: vport to modify.
 * @ids: new configuration, an array of port ids.
 *
 * Sets the vport's upcall_portids to @ids.
 *
 * Returns 0 if successful, -EINVAL if @ids is zero length or cannot be parsed
 * as an array of U32.
 *
 * Must be called with ovs_mutex.
 */
int ovs_vport_set_upcall_portids(struct vport *vport, const struct nlattr *ids)
{
	struct vport_portids *old, *vport_portids;

	if (!nla_len(ids) || nla_len(ids) % sizeof(u32))
		return -EINVAL;

	old = ovsl_dereference(vport->upcall_portids);

	vport_portids = kmalloc(sizeof(*vport_portids) + nla_len(ids),
				GFP_KERNEL);
	if (!vport_portids)
		return -ENOMEM;

	vport_portids->n_ids = nla_len(ids) / sizeof(u32);
	vport_portids->rn_ids = reciprocal_value(vport_portids->n_ids);
	nla_memcpy(vport_portids->ids, ids, nla_len(ids));

	rcu_assign_pointer(vport->upcall_portids, vport_portids);

	if (old)
		kfree_rcu(old, rcu);
	return 0;
}

/**
 *	ovs_vport_get_upcall_portids - get the upcall_portids of @vport.
 *
 * @vport: vport from which to retrieve the portids.
 * @skb: sk_buff where portids should be appended.
 *
 * Retrieves the configuration of the given vport, appending the
 * %OVS_VPORT_ATTR_UPCALL_PID attribute which is the array of upcall
 * portids to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room.
 * If an error occurs, @skb is left unmodified.  Must be called with
 * ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_upcall_portids(const struct vport *vport,
				 struct sk_buff *skb)
{
	struct vport_portids *ids;

	ids = rcu_dereference_ovsl(vport->upcall_portids);

	if (vport->dp->user_features & OVS_DP_F_VPORT_PIDS)
		return nla_put(skb, OVS_VPORT_ATTR_UPCALL_PID,
			       ids->n_ids * sizeof(u32), (void *)ids->ids);
	else
		return nla_put_u32(skb, OVS_VPORT_ATTR_UPCALL_PID, ids->ids[0]);
}

/**
 *	ovs_vport_find_upcall_portid - find the upcall portid to send upcall.
 *
 * @vport: vport from which the missed packet is received.
 * @skb: skb that the missed packet was received.
 *
 * Uses the skb_get_hash() to select the upcall portid to send the
 * upcall.
 *
 * Returns the portid of the target socket.  Must be called with rcu_read_lock.
 */
u32 ovs_vport_find_upcall_portid(const struct vport *vport, struct sk_buff *skb)
{
	struct vport_portids *ids;
	u32 ids_index;
	u32 hash;

	ids = rcu_dereference(vport->upcall_portids);

	if (ids->n_ids == 1 && ids->ids[0] == 0)
		return 0;

	hash = skb_get_hash(skb);
	ids_index = hash - ids->n_ids * reciprocal_divide(hash, ids->rn_ids);
	return ids->ids[ids_index];
}

/**
 *	ovs_vport_receive - pass up received packet to the datapath for processing
 *
 * @vport: vport that received the packet
 * @skb: skb that was received
 * @tun_key: tunnel (if any) that carried packet
 *
 * Must be called with rcu_read_lock.  The packet cannot be shared and
 * skb->data should point to the Ethernet header.
 */
int ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
		      const struct ip_tunnel_info *tun_info)
{
	struct sw_flow_key key;
	int error;

	// LOHan: Statistics Support
	/*uint8_t switchNum = moe_GetSwitchNum(skb);
	do_gettimeofday(&START_TIME);*/

	OVS_CB(skb)->input_vport = vport;
	OVS_CB(skb)->mru = 0;
	OVS_CB(skb)->cutlen = 0;
	if (unlikely(dev_net(skb->dev) != ovs_dp_get_net(vport->dp))) {
		u32 mark;

		mark = skb->mark;
		skb_scrub_packet(skb, true);
		skb->mark = mark;
		tun_info = NULL;
	}

	ovs_skb_init_inner_protocol(skb);
	skb_clear_ovs_gso_cb(skb);

	/* Extract flow from 'skb' into 'key'. */
	error = ovs_flow_key_extract(tun_info, skb, &key);
	if (unlikely(error)) {
		kfree_skb(skb);
		return error;
	}

	// LOHan: Load Balancing Support
	/*if (switchNum == 7) {
		uint8_t randnum = os_myRand() % 16;
		if (randnum >= 8) {
			uint8_t* data = skb->data;
			if (data[ETH_ALEN+0] == 0x10 && data[ETH_ALEN+1] == 0x00 && data[ETH_ALEN+2] == 0x00 && data[ETH_ALEN+3] == 0x00)
			if (moe_CheckHeader(vport, skb, &key) == -1) return;
		}
	}
	 else */if (moe_CheckHeader(vport, skb, &key) == -1) {return;}
	ovs_dp_process_packet(skb, &key);
	// LOHan: Statistics Support
	/*do_gettimeofday(&END_TIME);
	if (END_TIME.tv_usec >= START_TIME.tv_usec) {
		STAT_TIMES[switchNum].tv_sec += (END_TIME.tv_sec - START_TIME.tv_sec);
		STAT_TIMES[switchNum].tv_usec += (END_TIME.tv_usec - START_TIME.tv_usec);
	}
	else {
		STAT_TIMES[switchNum].tv_sec += (END_TIME.tv_sec - 1 - START_TIME.tv_sec);
		STAT_TIMES[switchNum].tv_usec += (1000000 + END_TIME.tv_usec - START_TIME.tv_usec);
	}*/
	return 0;
}

static int packet_length(const struct sk_buff *skb,
			 struct net_device *dev)
{
	int length = skb->len - dev->hard_header_len;

	if (!skb_vlan_tag_present(skb) &&
	    eth_type_vlan(skb->protocol))
		length -= VLAN_HLEN;

	/* Don't subtract for multiple VLAN tags. Most (all?) drivers allow
	 * (ETH_LEN + VLAN_HLEN) in addition to the mtu value, but almost none
	 * account for 802.1ad. e.g. is_skb_forwardable().
	 */

	return length > 0 ? length: 0;
}

void ovs_vport_send(struct vport *vport, struct sk_buff *skb, u8 mac_proto)
{
	int mtu = vport->dev->mtu;

	switch (vport->dev->type) {
	case ARPHRD_NONE:
		if (mac_proto == MAC_PROTO_ETHERNET) {
			skb_reset_network_header(skb);
			skb_reset_mac_len(skb);
			skb->protocol = htons(ETH_P_TEB);
		} else if (mac_proto != MAC_PROTO_NONE) {
			WARN_ON_ONCE(1);
			goto drop;
		}
		break;
	case ARPHRD_ETHER:
		if (mac_proto != MAC_PROTO_ETHERNET)
			goto drop;
		break;
	default:
		goto drop;
	}

	if (unlikely(packet_length(skb, vport->dev) > mtu &&
		     !skb_is_gso(skb))) {
		net_warn_ratelimited("%s: dropped over-mtu packet: %d > %d\n",
				     vport->dev->name,
				     packet_length(skb, vport->dev), mtu);
		vport->dev->stats.tx_errors++;
		goto drop;
	}

	skb->dev = vport->dev;
	vport->ops->send(skb);
	return;

drop:
	kfree_skb(skb);
}
