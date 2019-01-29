/*
 ns2-champino
 * Copyright (c) 2007-2012 Nicira, Inc.
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

#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/version.h>
#include <net/net_namespace.h>

#include "datapath.h"
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
//#include <linux///mm.h>
//#include <linux/debugfs.h>
#define OVS_MODE_MININET    0
#define OVS_MODE_TESTBED    1
#define SWITCH_NUMS         6


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
typedef struct object_entry {
	uint32_t switchNum;
	uint32_t destIP;
	uint16_t destPort;
	uint32_t switchIP;
	uint32_t mnIP;
	uint8_t objHash[HASH_LEN];
	struct hlist_node hlist_ip;
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

//jaehee & jaehyun modified  170415
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};//jaehee & jaehyun modified  --- end

uint8_t SW_TYPES[SWITCH_NUMS];
struct timeval START_TIME;
struct timeval END_TIME;
struct timeval STAT_TIMES[SWITCH_NUMS];
uint16_t STAT_NEW_UES[SWITCH_NUMS];
uint32_t SWITCHS_IP[SWITCH_NUMS] = {16781322, 16785418, 16789514, 19398666, 20054026, 16793610}; //10.16.0.1, 10.32.0.1, 10.48.0.1, 10.0.40.1, 10.0.50.1, 10.64.0.1 

int LOGGING = 1;


static void moe_CleanUp(void);
static void moe_InsertObject(uint32_t switchNum, uint32_t destIP, uint16_t destPort, uint8_t* objHash, uint32_t switchIP, uint32_t mnIP);
static uint32_t moe_GetOriginIPFromSrcIP(uint32_t switchNum, uint32_t srcIP, uint16_t srcPort, uint8_t** objHash, uint32_t* originIP);
static uint32_t moe_GetObjectFromIP(uint32_t switchNum, uint32_t destIP, uint16_t destPort, uint8_t** objHash, uint32_t* pSwitchIP);
static uint32_t moe_GetObjectFromHash(uint32_t switchNum, uint8_t* objHash, uint32_t* pDestIP);
static void moe_DeleteObjectAll(uint32_t switchNum, uint32_t destIP, uint16_t destPort);
static void moe_DeleteObjectHash(uint32_t switchNum, uint8_t* objHash);
static void moe_SaveSKB(uint32_t switchNum, uint32_t destIP, struct vport *vp, struct sk_buff *skb); //SKB = Socket Buffer
static void moe_ForwardSKB(uint32_t switchNum, uint32_t destIP);
static int32_t moe_CheckHeader(struct vport *vp, struct sk_buff *skb);
unsigned short csum(unsigned short *ptr, int nbytes);


static void cb_SocketDataReady(struct sock* sk, int bytes)
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
	uint32_t temp = 0, newMNIP = 0;
    uint16_t destPort = 0;
	while ((len = skb_queue_len(&wrapper->sk->sk_receive_queue)) > 0) {
		skb = skb_dequeue(&wrapper->sk->sk_receive_queue);
		opCode = *(uint8_t*)(skb->data + UDP_HLEN);
		switchNum = *(uint8_t*)(skb->data + UDP_HLEN + 1);
		if(LOGGING){os_WriteLog2("Received a UDP message, opCode=%u, SwitchNum=%u\n", opCode, switchNum);}

		if (opCode == OPCODE_SET_SWTYPE) {
			if(LOGGING){os_WriteLog("OPCODE_SET_SWTYPE\n");}
			i = 0; 
			total = 0; 
			idx = 0;
			type = *(uint8_t*)(skb->data + UDP_HLEN + 2);
			total = ntohs(*(uint16_t*)(skb->data + UDP_HLEN + 3));
			for (i = 0; i < total; i++) {
				idx = ntohs(*(uint16_t*)(skb->data + UDP_HLEN + 5 + i * sizeof(uint16_t)));
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
			destIP = *(uint32_t*)(skb->data + UDP_HLEN + 2);
			memcpy(objHash, skb->data + UDP_HLEN + 6, HASH_LEN);
			switchIP = *(uint32_t*)(skb->data + UDP_HLEN + 6 + HASH_LEN);
		
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
			destIP = *(uint32_t*)(skb->data + UDP_HLEN + 2);
			memcpy(objHash, skb->data + UDP_HLEN + 6, HASH_LEN);
			switchIP = *(uint32_t*)(skb->data + UDP_HLEN + 6 + HASH_LEN);
			if (!moe_GetObjectFromIP(switchNum, destIP, 0, &tempHash, &temp)) {		// If not exist,
				
				moe_InsertObject(switchNum, destIP, 0, objHash, switchIP, 0);
				moe_ForwardSKB(switchNum, switchIP); // Should be the switch's IP
			}
		} else if (opCode == OPCODE_UPDATE_IP) {
			if(LOGGING){os_WriteLog("OPCODE_UPDATE_IP\n");}
			tempHash = NULL; 
			temp = 0;
			destIP = *(uint32_t*)(skb->data + UDP_HLEN + 2);
			switchIP = *(uint32_t*)(skb->data + UDP_HLEN + 6);
			memcpy(objHash, skb->data + UDP_HLEN + 10, HASH_LEN);
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
			newMNIP = 0;
			temp = 0;
            destPort = 0;
			destIP = *(uint32_t*)(skb->data + UDP_HLEN + 2);
			switchIP = *(uint32_t*)(skb->data + UDP_HLEN + 6);
			newMNIP = *(uint32_t*)(skb->data + UDP_HLEN + 10);
			destPort = ntohs(*(uint16_t*)(skb->data + UDP_HLEN + 14));
			//if (moe_GetObjectFromIP(switchNum, destIP, 0, &tempHash, &temp) && switchIP != temp) {
				if(LOGGING){os_WriteLog9("Application Mobility Support! Switch IP=%u.%u.%u.%u when Host IP=%u.%u.%u.%u with dstPort=%u\n",
					*((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3),
				*((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), destPort);}
				memcpy(objHash, skb->data + UDP_HLEN + 16, HASH_LEN);
				moe_InsertObject(switchNum, destIP, destPort, objHash, switchIP, newMNIP);
			//}
		} /*else if (opCode == OPCODE_NEW_CTN) { // Jaehee: Is it necessarily needed?
			uint8_t* tempHash;
			uint32_t newMNIP, temp = 0;
            uint16_t destPort = 0;
			destIP = *(uint32_t*)(skb->data + UDP_HLEN + 2);
			switchIP = *(uint32_t*)(skb->data + UDP_HLEN + 6);
			newMNIP = *(uint32_t*)(skb->data + UDP_HLEN + 10);
			if (moe_GetObjectFromIP(switchNum, destIP, 0, &tempHash, &temp) && switchIP != temp) {
				if(LOGGING){os_WriteLog9("Container Mobility Support! Switch IP=%u.%u.%u.%u when Host IP=%u.%u.%u.%u\n",
					*((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3),
				*((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3));}
				memcpy(objHash, skb->data + UDP_HLEN + 14, HASH_LEN);
				moe_InsertObject(switchNum, destIP, 0, objHash, switchIP, newMNIP);
			}
		}*/ 
		else if (opCode == OPCODE_TOGGLE_LOGGING) {
			LOGGING=(LOGGING == 0)?1:0;
		} else if (opCode == 100) {
			PRT_START_PAGE = *(uint32_t*)(skb->data + UDP_HLEN + 2);
		} 
		kfree_skb(skb);
	}
}

static uint8_t sendBuffer[128];
static void ipc_SendMessage(
	uint8_t switchNum, uint8_t opCode,
	uint32_t clientIP, uint8_t* data)
{
	struct sockaddr_in to;
	struct msghdr msg;
	struct iovec iov;
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
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &to;
	msg.msg_namelen = sizeof(to);

	iov.iov_base = sendBuffer;
	iov.iov_len  = len;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Adjust memory boundaries and send the message
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	len = sock_sendmsg(sendsocket, &msg, len);
	set_fs(oldfs);
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
/*
struct mmap_info { char* data; int reference; };

void mmap_open(struct vm_area_struct* vma)
{
	struct mmap_info* info = (struct mmap_info*)vma->vm_private_data;
	if(LOGGING){os_WriteLog("mmap_open\n");}
	info->reference++;
}

void mmap_close(struct vm_area_struct* vma)
{
	struct mmap_info* info = (struct mmap_info*)vma->vm_private_data;
	if(LOGGING){os_WriteLog("mmap_close\n");}
	info->reference--;
}

static int mmap_fault(struct vm_area_struct* vma, struct vm_fault* vmf)
{
	struct page* page;
	struct mmap_info* info = (struct mmap_info*)vma->vm_private_data;
	if (!info->data) return 0;
	if(LOGGING){os_WriteLog1("mmap_fault, offset=%u\n", vmf->pgoff);}
	//page = virt_to_page(info->data + PAGE_SIZE * vmf->pgoff);
	page = vmalloc_to_page(info->data + PAGE_SIZE * vmf->pgoff);
	get_page(page);
	vmf->page = page;
	if (vmf->pgoff == 1023) MMAP_DATA = info->data;
	return 0;
}

struct vm_operations_struct mmap_vm_ops = {
	.open  = mmap_open,
	.close = mmap_close,
	.fault = mmap_fault,
};

int IPC_mmopen(struct inode* inode, struct file* filp)
{
	struct mmap_info* info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
	if(LOGGING){os_WriteLog("IPC_mmopen\n");}
	//info->data = (char*)__get_free_pages(GFP_KERNEL, 10);
	info->data = vmalloc(PAGE_SIZE * 1024);
	if (!info->data) if(LOGGING){os_WriteLog("Getting free pages failed.\n");}
	filp->private_data = info;
	return 0;
}

int IPC_mmclose(struct inode* inode, struct file* filp)
{
	struct mmap_info* info = filp->private_data;
	if(LOGGING){os_WriteLog("IPC_mmclose\n");}
	MMAP_DATA = NULL;
	//free_pages((unsigned long)info->data, 10);
	vfree(info->data);
	kfree(info);
	filp->private_data = NULL;
	return 0;
}

int IPC_mmap(struct file* filp, struct vm_area_struct* vma)
{
	if(LOGGING){os_WriteLog("IPC_mmap\n");}
	vma->vm_ops = &mmap_vm_ops;
	vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_private_data = filp->private_data;
	mmap_open(vma);
	return 0;
}

static const struct file_operations IPC_mmfops = {
	.open = IPC_mmopen,
	.release = IPC_mmclose,
	.mmap = IPC_mmap,
};
*/
static void moe_CleanUp(void)
{
	{int bucket = 0;
	_OE *current_entry = NULL, *previous_entry = NULL;
	hash_for_each(OBJ_TBL, bucket, current_entry, hlist_ip) {
		if (previous_entry != NULL) {
			hash_del(&previous_entry->hlist_ip); // 'hash_del' also initializes the hlist.
			if (previous_entry->hlist_hash.next == NULL && previous_entry->hlist_hash.pprev == NULL)
				kfree(previous_entry);
		}
		previous_entry = current_entry;
	}
	if (previous_entry != NULL) {
		hash_del(&previous_entry->hlist_ip);
		if (previous_entry->hlist_hash.next == NULL && previous_entry->hlist_hash.pprev == NULL)
			kfree(previous_entry);
	}

	previous_entry = NULL;
	hash_for_each(OBJ_REV_TBL, bucket, current_entry, hlist_hash) {
		if (previous_entry != NULL) {
			hash_del(&previous_entry->hlist_hash);
			if (previous_entry->hlist_ip.next == NULL && previous_entry->hlist_ip.pprev == NULL)
				kfree(previous_entry);
		}
		previous_entry = current_entry;
	}
	if (previous_entry != NULL) {
		hash_del(&previous_entry->hlist_hash);
		if (previous_entry->hlist_ip.next == NULL && previous_entry->hlist_ip.pprev == NULL)
			kfree(previous_entry);
	}}

	{_LE *current_entry = NULL, *previous_entry = NULL;
	list_for_each_entry(current_entry, &SKB_LIST, list) {
		if (previous_entry != NULL) { list_del(&previous_entry->list); kfree(previous_entry); }
		previous_entry = current_entry;
	}
	if (previous_entry != NULL) { list_del(&previous_entry->list); kfree(previous_entry); }}
}

static void moe_InsertObject(uint32_t switchNum, uint32_t destIP, uint16_t destPort, uint8_t* objHash, uint32_t switchIP, uint32_t mnIP)
{
	int i = 0;
	_OE* entry = NULL;
	if(LOGGING){os_WriteLog10("Updating cache: SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u, SwitchIP=%u.%u.%u.%u,\n",switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), destPort, *((uint8_t*)&switchIP + 0), *((uint8_t*)&switchIP + 1), *((uint8_t*)&switchIP + 2), *((uint8_t*)&switchIP + 3));}
	if(LOGGING){os_WriteLog4("MNIP=%u.%u.%u.%u\n", *((uint8_t*)&mnIP + 0), *((uint8_t*)&mnIP + 1), *((uint8_t*)&mnIP + 2), *((uint8_t*)&mnIP + 3));}
	entry = kmalloc(sizeof(_OE), GFP_KERNEL);
	moe_DeleteObjectAll(switchNum, destIP, destPort);
	entry->switchNum = switchNum;
	entry->destIP = destIP;
	entry->destPort = destPort;
	entry->switchIP = switchIP;
	entry->mnIP = (mnIP == 0 ? destIP : mnIP);
	memcpy(entry->objHash, objHash, HASH_LEN);
	if(LOGGING)os_WriteLog("ObjID=\n");
	if(LOGGING){
		for (i=0 ; i<(MOE_HLEN/8) ; i++) {
			os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)objHash+((i*8))),*((uint8_t*)objHash+((i*8)+1)),*((uint8_t*)objHash+((i*8)+2)),*((uint8_t*)objHash+((i*8)+3)),*((uint8_t*)objHash+((i*8)+4)),*((uint8_t*)objHash+((i*8)+5)),*((uint8_t*)objHash+((i*8)+6)),*((uint8_t*)objHash+((i*8)+7)));
		}
	}
	
	INIT_HLIST_NODE(&entry->hlist_ip);
	INIT_HLIST_NODE(&entry->hlist_hash);
	hash_add(OBJ_TBL, &entry->hlist_ip, entry->destIP);
	hash_add(OBJ_REV_TBL, &entry->hlist_hash, *(uint64_t*)entry->objHash);
}

static uint32_t moe_GetObjectFromIP(uint32_t switchNum, uint32_t destIP, uint16_t destPort, uint8_t** objHash, uint32_t* pSwitchIP)
{
	_OE* current_entry = NULL;
	int i = 0;
	
	if (destPort!=(uint16_t)0 && (destPort > (uint16_t)61000 || destPort < (uint16_t)32768)) {
		if(LOGGING){os_WriteLog6("Searching cache. SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u\n", switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), destPort);}
		hash_for_each_possible(OBJ_TBL, current_entry, hlist_ip, destIP) {
			if (current_entry->switchNum == switchNum &&
				current_entry->destIP == destIP && current_entry->destPort == destPort) {
				*objHash = current_entry->objHash;
				*pSwitchIP = current_entry->switchIP;
				if(LOGGING){os_WriteLog6("cache hit! SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u\n", switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), destPort);}
				if(LOGGING){os_WriteLog("ObjID=\n");}
				if(LOGGING){
					for (i=0 ; i<(MOE_HLEN/8) ; i++) {
						os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)*objHash+((i*8))),*((uint8_t*)*objHash+((i*8)+1)),*((uint8_t*)*objHash+((i*8)+2)),*((uint8_t*)*objHash+((i*8)+3)),*((uint8_t*)*objHash+((i*8)+4)),*((uint8_t*)*objHash+((i*8)+5)),*((uint8_t*)*objHash+((i*8)+6)),*((uint8_t*)*objHash+((i*8)+7)));
					}
				}
				
				return 1;
			}
		}
	}

	
	
	current_entry = NULL;
	//destPort == 0
	if(LOGGING){os_WriteLog6("Searching cache. SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u\n", switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), (uint16_t)0);	}
	hash_for_each_possible(OBJ_TBL, current_entry, hlist_ip, destIP) {
		if (current_entry->switchNum == switchNum &&
			current_entry->destIP == destIP && current_entry->destPort == (uint16_t)0) {
			*objHash = current_entry->objHash;
			*pSwitchIP = current_entry->switchIP;
			if(LOGGING){os_WriteLog6("cache hit! SwitchNum=%u, DestIP=%u.%u.%u.%u, DestPort=%u\n", switchNum, *((uint8_t*)&destIP + 0), *((uint8_t*)&destIP + 1), *((uint8_t*)&destIP + 2), *((uint8_t*)&destIP + 3), (uint16_t)0);}
			if(LOGGING){os_WriteLog("ObjID=\n");}
			if(LOGGING){
				for (i=0 ; i<(MOE_HLEN/8) ; i++) {
					os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)*objHash+((i*8))),*((uint8_t*)*objHash+((i*8)+1)),*((uint8_t*)*objHash+((i*8)+2)),*((uint8_t*)*objHash+((i*8)+3)),*((uint8_t*)*objHash+((i*8)+4)),*((uint8_t*)*objHash+((i*8)+5)),*((uint8_t*)*objHash+((i*8)+6)),*((uint8_t*)*objHash+((i*8)+7)));
				}
			}
			
			return 1;
		}
	}

	
	return 0;
}

static uint32_t moe_GetOriginIPFromSrcIP(uint32_t switchNum, uint32_t srcIP, uint16_t srcPort, uint8_t** objHash, uint32_t* originIP)
{
	_OE* current_entry = NULL;
	uint32_t mnIP = srcIP;
	
	if (srcPort != (uint16_t)0 && (srcPort < (uint16_t)32768 || srcPort > (uint16_t)61000)) {
		if(LOGGING){os_WriteLog6("Searching cache. SwitchNum=%u, SrcIP=%u.%u.%u.%u, SrcPort=%u\n", switchNum, *((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3), srcPort);}
		
		hash_for_each_possible(OBJ_TBL, current_entry, hlist_ip, mnIP) {
			if (current_entry->switchNum == switchNum &&
				current_entry->mnIP == mnIP && current_entry->destPort == srcPort) {
				*originIP = current_entry->destIP;
				if(LOGGING){os_WriteLog6("cache hit! SwitchNum=%u, OriginalIP=%u.%u.%u.%u, SrcPort=%u\n", switchNum, *((uint8_t*)originIP + 0), *((uint8_t*)originIP + 1), *((uint8_t*)originIP + 2), *((uint8_t*)originIP + 3), srcPort);}
				
				return 1;
			}
		}
	}


	current_entry = NULL;
	//destPort == 0
	if(LOGGING){os_WriteLog6("Searching cache. SwitchNum=%u, SrcIP=%u.%u.%u.%u, SrcPort=%u\n", switchNum, *((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3), (uint32_t)0);}
	hash_for_each_possible(OBJ_TBL, current_entry, hlist_ip, mnIP) {
		if (current_entry->switchNum == switchNum &&
			current_entry->mnIP == mnIP && current_entry->destPort == (uint16_t)0) {
			*originIP = current_entry->destIP;
			if(LOGGING){os_WriteLog6("cache hit! SwitchNum=%u, OriginalIP=%u.%u.%u.%u, SrcPort=%u\n", switchNum, *((uint8_t*)originIP + 0), *((uint8_t*)originIP + 1), *((uint8_t*)originIP + 2), *((uint8_t*)originIP + 3), (uint16_t)0);}
			
			return 1;
		}
	}
	return 0;
}

static uint32_t moe_GetObjectFromHash(uint32_t switchNum, uint8_t* objHash, uint32_t* pDestIP)
{
	_OE* current_entry = NULL;
	int i = 0;
	if(LOGGING){os_WriteLog1("Searching cache. SwitchNum=%u\n", switchNum);}
	if(LOGGING){os_WriteLog("ObjID=\n");}
	if(LOGGING){
		for (i=0 ; i<(MOE_HLEN/8) ; i++) {
			os_WriteLog8("%02x%02x%02x%02x%02x%02x%02x%02x\n", *((uint8_t*)objHash+((i*8))),*((uint8_t*)objHash+((i*8)+1)),*((uint8_t*)objHash+((i*8)+2)),*((uint8_t*)objHash+((i*8)+3)),*((uint8_t*)objHash+((i*8)+4)),*((uint8_t*)objHash+((i*8)+5)),*((uint8_t*)objHash+((i*8)+6)),*((uint8_t*)objHash+((i*8)+7)));
		}
	}
	current_entry = NULL;
	hash_for_each_possible(OBJ_REV_TBL, current_entry, hlist_hash, *(uint64_t*)objHash) {
		if (current_entry->switchNum == switchNum && memcmp(current_entry->objHash, objHash, HASH_LEN) == 0) {
			
			*pDestIP = current_entry->mnIP;
			if(LOGGING){os_WriteLog5("cache hit! SwitchNum=%u, DestIP=%u.%u.%u.%u\n", switchNum, *((uint8_t*)pDestIP + 0), *((uint8_t*)pDestIP + 1), *((uint8_t*)pDestIP + 2), *((uint8_t*)pDestIP + 3));}
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
			if (current_entry->hlist_hash.next == NULL && current_entry->hlist_hash.pprev == NULL)
				kfree(current_entry);
			else
				moe_DeleteObjectHash(switchNum, current_entry->objHash);
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
			if (current_entry->hlist_ip.next == NULL && current_entry->hlist_ip.pprev == NULL)
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
			if (moe_CheckHeader(entry->vp, entry->skb) == -1) continue;
			rcu_read_lock();
			ovs_dp_process_received_packet(entry->vp, entry->skb);
			rcu_read_unlock();
			previous = entry;
		}
	}
	if (previous != NULL) {
		list_del(&previous->list);
		kfree(previous); previous = NULL;
	}
}
// End of MoE Support

static void ovs_vport_record_error(struct vport *,
				   enum vport_err_type err_type);

/* List of statically compiled vport implementations.  Don't forget to also
 * add yours to the list at the bottom of vport.h. */
static const struct vport_ops *vport_ops_list[] = {
	&ovs_netdev_vport_ops,
	&ovs_internal_vport_ops,
#if IS_ENABLED(CONFIG_NET_IPGRE_DEMUX)
	&ovs_gre_vport_ops,
	&ovs_gre64_vport_ops,
#endif
	&ovs_vxlan_vport_ops,
	&ovs_lisp_vport_ops,
};

/* Protected by RCU read lock for reading, ovs_mutex for writing. */
static struct hlist_head *dev_table;
#define VPORT_HASH_BUCKETS 1024

/**
 *	ovs_vport_init - initialize vport subsystem
 *
 * Called at module load time to initialize the vport subsystem.
 */
int ovs_vport_init(void)
{
	dev_table = kzalloc(VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dev_table)
		return -ENOMEM;

	// LOHan: Initialization
	os_CreateIPCSocket();
	hash_init(OBJ_TBL);
    hash_init(OBJ_REV_TBL);
	if(LOGGING){os_WriteLog("--- OvS with MoE has successfully been loaded. --- \n");}
	{int i; for (i = 0; i < SWITCH_NUMS; i++) SW_TYPES[i] = SWITCHTYPE_IMS;}
    {int i; for (i = 0; i < SWITCH_NUMS; i++) { STAT_TIMES[i].tv_sec = STAT_TIMES[i].tv_usec = 0; STAT_NEW_UES[i] = 0; }}
	ipc_SendMessage(0, OPCODE_BOOTUP, 0, NULL);
	do_gettimeofday(&START_TIME);
	os_mySrand(START_TIME.tv_usec % 100);
	//debug_file = debugfs_create_file_size("mmap_example", 0644, NULL, NULL, &IPC_mmfops, PAGE_SIZE * 1024);
	// End of Initialization
	return 0;
}

/**
 *	ovs_vport_exit - shutdown vport subsystem
 *
 * Called at module exit time to shutdown the vport subsystem.
 */
void ovs_vport_exit(void)
{
	kfree(dev_table);
	// LOHan: Clean-up
	os_CloseIPCSocket();
	moe_CleanUp();
	//debugfs_remove(debug_file);
}

static struct hlist_head *hash_bucket(struct net *net, const char *name)
{
	unsigned int hash = jhash(name, strlen(name), (unsigned long) net);
	return &dev_table[hash & (VPORT_HASH_BUCKETS - 1)];
}

/**
 *	ovs_vport_locate - find a port that has already been created
 *
 * @name: name of port to find
 *
 * Must be called with ovs or RCU read lock.
 */
struct vport *ovs_vport_locate(struct net *net, const char *name)
{
	struct hlist_head *bucket = NULL;
	bucket = hash_bucket(net, name);
	struct vport *vport;

	hlist_for_each_entry_rcu(vport, bucket, hash_node)
		if (!strcmp(name, vport->ops->get_name(vport)) &&
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
 * ovs_vport_free().
 */
struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			      const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size = 0;
	int i = 0;

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

	if (ovs_vport_set_upcall_portids(vport, parms->upcall_portids))
		return ERR_PTR(-EINVAL);

	vport->percpu_stats = alloc_percpu(struct pcpu_sw_netstats);
	if (!vport->percpu_stats) {
		kfree(vport);
		return ERR_PTR(-ENOMEM);
	}

	for_each_possible_cpu(i) {
		struct pcpu_sw_netstats *vport_stats;
		vport_stats = per_cpu_ptr(vport->percpu_stats, i);
		u64_stats_init(&vport_stats->syncp);
	}

	spin_lock_init(&vport->stats_lock);

	return vport;
}

/**
 *	ovs_vport_free - uninitialize and free vport
 *
 * @vport: vport to free
 *
 * Frees a vport allocated with ovs_vport_alloc() when it is no longer needed.
 *
 * The caller must ensure that an RCU grace period has passed since the last
 * time @vport was in a datapath.
 */
void ovs_vport_free(struct vport *vport)
{
	kfree((struct vport_portids __force *)vport->upcall_portids);
	free_percpu(vport->percpu_stats);
	kfree(vport);
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
	struct vport *vport ;
	int err = 0;
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(vport_ops_list); i++) {
		if (vport_ops_list[i]->type == parms->type) {
			struct hlist_head *bucket;

			vport = vport_ops_list[i]->create(parms);
			if (IS_ERR(vport)) {
				err = PTR_ERR(vport);
				goto out;
			}

			bucket = hash_bucket(ovs_dp_get_net(vport->dp),
					     vport->ops->get_name(vport));
			hlist_add_head_rcu(&vport->hash_node, bucket);
			return vport;
		}
	}

	err = -EAFNOSUPPORT;

out:
	return ERR_PTR(err);
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
 * Detaches @vport from its datapath and destroys it.  It is possible to fail
 * for reasons such as lack of memory.  ovs_mutex must be held.
 */
void ovs_vport_del(struct vport *vport)
{
	ASSERT_OVSL();

	hlist_del_rcu(&vport->hash_node);
	vport->ops->destroy(vport);
}

/**
 *	ovs_vport_set_stats - sets offset device stats
 *
 * @vport: vport on which to set stats
 * @stats: stats to set
 *
 * Provides a set of transmit, receive, and error stats to be added as an
 * offset to the collected data when stats are retrieved.  Some devices may not
 * support setting the stats, in which case the result will always be
 * -EOPNOTSUPP.
 *
 * Must be called with ovs_mutex.
 */
void ovs_vport_set_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	spin_lock_bh(&vport->stats_lock);
	vport->offset_stats = *stats;
	spin_unlock_bh(&vport->stats_lock);
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
	int i;

	/* We potentially have 3 sources of stats that need to be
	 * combined: those we have collected (split into err_stats and
	 * percpu_stats), offset_stats from set_stats(), and device
	 * error stats from netdev->get_stats() (for errors that happen
	 * downstream and therefore aren't reported through our
	 * vport_record_error() function).
	 * Stats from first two sources are merged and reported by ovs over
	 * OVS_VPORT_ATTR_STATS.
	 * netdev-stats can be directly read over netlink-ioctl.
	 */

	spin_lock_bh(&vport->stats_lock);

	*stats = vport->offset_stats;

	stats->rx_errors	+= vport->err_stats.rx_errors;
	stats->tx_errors	+= vport->err_stats.tx_errors;
	stats->tx_dropped	+= vport->err_stats.tx_dropped;
	stats->rx_dropped	+= vport->err_stats.rx_dropped;

	spin_unlock_bh(&vport->stats_lock);

	for_each_possible_cpu(i) {
		const struct pcpu_sw_netstats *percpu_stats;
		struct pcpu_sw_netstats local_stats;
		unsigned int start;

		percpu_stats = per_cpu_ptr(vport->percpu_stats, i);

		do {
			start = u64_stats_fetch_begin_irq(&percpu_stats->syncp);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_irq(&percpu_stats->syncp, start));

		stats->rx_bytes		+= local_stats.rx_bytes;
		stats->rx_packets	+= local_stats.rx_packets;
		stats->tx_bytes		+= local_stats.tx_bytes;
		stats->tx_packets	+= local_stats.tx_packets;
	}
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

static void vport_portids_destroy_rcu_cb(struct rcu_head *rcu)
{
	struct vport_portids *ids = container_of(rcu, struct vport_portids,
						 rcu);

	kfree(ids);
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
int ovs_vport_set_upcall_portids(struct vport *vport,  struct nlattr *ids)
{
	struct vport_portids *old, *vport_portids;

	if (!nla_len(ids) || nla_len(ids) % sizeof(u32))
		return -EINVAL;

	old = ovsl_dereference(vport->upcall_portids);

	vport_portids = kmalloc(sizeof *vport_portids + nla_len(ids),
				GFP_KERNEL);
	if (!vport_portids)
		return -ENOMEM;

	vport_portids->n_ids = nla_len(ids) / sizeof(u32);
	vport_portids->rn_ids = reciprocal_value(vport_portids->n_ids);
	nla_memcpy(vport_portids->ids, ids, nla_len(ids));

	rcu_assign_pointer(vport->upcall_portids, vport_portids);

	if (old)
		call_rcu(&old->rcu, vport_portids_destroy_rcu_cb);

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
			       ids->n_ids * sizeof(u32), (void *) ids->ids);
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
u32 ovs_vport_find_upcall_portid(const struct vport *p, struct sk_buff *skb)
{
	struct vport_portids *ids;
	u32 hash;

	ids = rcu_dereference(p->upcall_portids);

	if (ids->n_ids == 1 && ids->ids[0] == 0)
		return 0;

	hash = skb_get_hash(skb);
	return ids->ids[hash - ids->n_ids * reciprocal_divide(hash, ids->rn_ids)];
}

// LOHan: MoE Support
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
	if (++STAT_NEW_UES[switchNum] == 1000) {
		if(LOGGING){os_WriteLog1("SwitchNum=%u, 1K new UEs are connected.\n", switchNum);}
		STAT_NEW_UES[switchNum] = 0;
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

//jaehee & jaehyun modified  2017-04-15
static int32_t moe_AddHeader(struct sk_buff *skb, uint32_t destIP, uint8_t* hashed, uint32_t newIP)
{
	uint8_t* data = NULL;
	uint16_t len = 0, temp = 0;

	if(LOGGING){os_WriteLog("Adding header operation.\n");}
	if (skb_cow_head(skb, MOE_HLEN) < 0)
		return -1;
	skb_push(skb, MOE_HLEN);
	/* Move the mac addresses to the beginning of the new header. */
	memmove(skb->data, skb->data + MOE_HLEN, ETH_HLEN + IP_HLEN);
	data = skb->data + ETH_HLEN;

	memcpy(data + 0, (void*)"\x4E", 1);
	len = ntohs(*(uint16_t*)(data + 2));
	len = htons(len + MOE_HLEN);
	memcpy(data + 2, (void*)&len, 2);
	memcpy(data + 10, (void*)"\x0000", 2);
	memcpy(data + 16, (void*)&newIP, sizeof(newIP));
	memcpy(data + IP_HLEN + 0, (void*)"\x00", 1);
	memcpy(data + IP_HLEN + 1, (void*)"\x18", 1);
	memcpy(data + IP_HLEN + 2, (void*)"\x0000", 2);
	memcpy(data + IP_HLEN + 4, hashed, HASH_LEN);

	temp = htons(CalculateIPChecksum(data, IP_HLEN + MOE_HLEN));
	memcpy(data + 10, (void*)&temp, 2);
	return 0;
}

static int32_t moe_RemoveHeader(struct sk_buff *skb, uint32_t newIP, int is_tcp)
{
	uint8_t* data = NULL;
	uint16_t len = 0, temp = 0;
    uint16_t tcp_check = 0;
	struct pseudo_header psh;
	int psize = 0;
	char *pseudogram = NULL;
	if(LOGGING){os_WriteLog("Removing header operation.\n");}
	memmove(skb->data + MOE_HLEN, skb->data, ETH_HLEN + IP_HLEN);
	skb_pull(skb, MOE_HLEN);
	data = skb->data + ETH_HLEN;

	memcpy(data + 0, (void*)"\x45", 1);
	len = ntohs(*(uint16_t*)(data + 2));
	len = htons(len - MOE_HLEN);
	memcpy(data + 2, (void*)&len, 2);
	memcpy(data + 10, (void*)"\x0000", 2);
	memcpy(data + 16, (void*)&newIP, sizeof(newIP));
	temp = htons(CalculateIPChecksum(data, IP_HLEN));
	memcpy(data + 10, (void*)&temp, 2);

	
    if (is_tcp){

		if(LOGGING){os_WriteLog("received tcp segment\n");}
		memcpy(data + IP_HLEN + 16, (void*)"\x0000",2);  //checksum = 0
		
		
		memcpy(&psh.source_address,(uint32_t*)(data + 12), 4); 
		memcpy(&psh.dest_address, (uint32_t*)(data + 16), 4);
		if(LOGGING){os_WriteLog1("ip saddr=%x\n",psh.source_address);}
		if(LOGGING){os_WriteLog1("ip daddr=%x\n",psh.dest_address);}
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(ntohs(len) - IP_HLEN);
		psize = sizeof(struct pseudo_header) + ntohs(len) - IP_HLEN;
		pseudogram = kmalloc(psize,GFP_KERNEL);

		memcpy(pseudogram, (char*) &psh, sizeof (struct pseudo_header));
		memcpy(pseudogram + sizeof(struct pseudo_header), data + IP_HLEN, ntohs(len) - IP_HLEN);
		tcp_check = csum((unsigned short*) pseudogram, psize);

		memcpy(data + IP_HLEN + 16, (void*)&tcp_check, sizeof(tcp_check));
		if(LOGGING){os_WriteLog1("tcp checksum=%x\n",tcp_check);}
		kfree(pseudogram);
		
		/*
		struct iphdr *iph;
        struct tcphdr *tcph;
        int tcplen = ntohs(len) - IP_HLEN;
		if(LOGGING){os_WriteLog1("tcp length=%d\n",tcplen);}
        iph = (struct iphdr *)data;
        tcph = (struct tcphdr *)(data + IP_HLEN);
        tcph->check = 0;
        tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char *)tcph, tcplen, 0));
		if(LOGGING){os_WriteLog1("ip saddr=%x\n",iph->saddr);}
		if(LOGGING){os_WriteLog1("ip daddr=%x\n",iph->daddr);}
		if(LOGGING){os_WriteLog1("tcp checksum=%x\n",tcph->check);}*/
	}

	
	return 0;
}
/*
static int32_t moe_RemoveHeader(struct sk_buff *skb, uint32_t newIP)
{
	uint8_t* data;
	uint16_t len, temp;
	uint16_t* port;
	if(LOGGING){os_WriteLog("Removing header operation.\n");}
	memmove(skb->data + MOE_HLEN, skb->data, ETH_HLEN + IP_HLEN);
	skb_pull(skb, MOE_HLEN);
	data = skb->data + ETH_HLEN;

	memcpy(data + 0, (void*)"\x45", 1);
	len = ntohs(*(uint16_t*)(data + 2));
	len = htons(len - MOE_HLEN);
	memcpy(data + 2, (void*)&len, 2);
	memcpy(data + 10, (void*)"\x0000", 2);
	memcpy(data + 16, (void*)&newIP, sizeof(newIP));
	
	
	
	port = ntohs(*(uint16_t*)(data + IP_HLEN + 2));
	if(LOGGING){os_WriteLog1("Replaced header dstPort=%u.\n",port);}

	temp = htons(CalculateIPChecksum(data, IP_HLEN));
	memcpy(data + 10, (void*)&temp, 2);
	
	
	return 0;
}*/




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
//jaehee & jaehyun modified  --- end

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
		//if(LOGGING){os_WriteLog6("Switch MAC=%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);}
		if (addr[0] == 0x20 && addr[1] == 0x00 && addr[2] == 0x00 && addr[3] == 0x00)
			return (uint8_t)(addr[4]+1);
	}
	return switchNum;
}

static int32_t moe_CheckHeader(struct vport *vp, struct sk_buff *skb)
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
	uint32_t newIP = 0;
	uint8_t dstPortByteArr[2] = {0,0};
	//uint8_t srcPortByteArr[2];
	uint32_t* ptrSrcIP = NULL;
	uint32_t originalIP = 0;
    uint8_t dstIPisSWIP = 0;
    int i=0;
	
	uint8_t* hashed = NULL;
	
	switchNum = moe_GetSwitchNum(skb);  if (switchNum > SWITCH_NUMS) return DO_FORWARD;
	switchType = SW_TYPES[switchNum-1];   if (switchType != SWITCHTYPE_ES) return DO_FORWARD;

	data = skb->data;
	if (data[ETH_ALEN+0] == 0x10 && data[ETH_ALEN+1] == 0x00 && data[ETH_ALEN+2] == 0x00 && data[ETH_ALEN+3] == 0x00) senderType = SENDERTYPE_UE;
	if (data[ETH_ALEN+0] == 0x20 && data[ETH_ALEN+1] == 0x00 && data[ETH_ALEN+2] == 0x00 && data[ETH_ALEN+3] == 0x00) senderType = SENDERTYPE_SW;
	if (senderType == SENDERTYPE_NONE) return DO_FORWARD;

	protocol = ntohs(*(uint16_t*)(data + ETH_ALEN*2));  if (protocol != ETH_P_IP && protocol != ETH_P_ARP) return DO_FORWARD;
	data += ETH_HLEN;
	
	if (protocol == ETH_P_ARP && senderType == SENDERTYPE_UE) {
		moe_CheckNewUE(switchNum, protocol, data);
		if(LOGGING){os_WriteLog("New UE.\n");}
	}

	else if (protocol == ETH_P_IP) {
		IHL = *(uint8_t*)data;          if (IHL != 0x45 && IHL != 0x4E) return DO_FORWARD; //4B(SHA1) -> 4E(SHA256)
		srcIP = *(uint32_t*)(data + 12);	// Do not use 'ntohl'
		ptrSrcIP = (uint32_t*)(data + 12);
		dstIP = *(uint32_t*)(data + 16);	// Do not use 'ntohl'
		
        for (i=0 ; i<SWITCH_NUMS ; i++){
            if(dstIP==SWITCHS_IP[i]) {
                 dstIPisSWIP = 1;
                 break;
            }
        }
		if (senderType==SENDERTYPE_UE && !dstIPisSWIP) {
			if(LOGGING){os_WriteLog3("Check header. Switch num=%u, type=%u, Sender type=%u\n", switchNum, switchType, senderType);}

			if(LOGGING){os_WriteLog8("New packet. Source IP=%u.%u.%u.%u, Destination IP=%u.%u.%u.%u\n", 
					*((uint8_t*)&srcIP + 0), *((uint8_t*)&srcIP + 1), *((uint8_t*)&srcIP + 2), *((uint8_t*)&srcIP + 3), 
			*((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3));}
		}
		if (dstIP == 0 || dstIP == 0xFFFFFFFF) return DO_FORWARD;
		totalLen = ntohs(*(uint16_t*)(data + 2));
		tp_protocol = *(data + 9);

		
		// --------------------------------------------------------------------------------
		// ICMP Header Addition Operation
		// --------------------------------------------------------------------------------
		if (tp_protocol == IPPROTO_ICMP) {
			if(LOGGING){os_WriteLog("ICMP packet.\n");}
			if (IHL == 0x45 && (totalLen - IP_HLEN >= 18) && ((dstIP&0x00ffffff)!=(SWITCHS_IP[switchNum-1]&0x00ffffff)) && dstIP != 16777343 && dstIP != SWITCHS_IP[switchNum-1]) {
					//normal IP packet
					//dstIP is not 127.0.0.1 and not this switch's ip 
					//host is in other subnet
				data += IP_HLEN;
				//if (data[0] == 0x08 && data[1] == 0x10); // Type (ECHO_REQUEST) and Code
					//ipc_SendMessage(switchNum, OPCODE_INFORM_CONNECTION, srcIP, data + 8); // 170327 Jaehee
				

				if (!moe_GetObjectFromIP(switchNum, dstIP, 0, &hashed, &newIP)) { // If it doesn't exist,
					dstPortByteArr[1] = 0;
					dstPortByteArr[0] = 0;
					// Send a request message to the upper layer
					ipc_SendMessage(switchNum, OPCODE_GET_HASH, dstIP, dstPortByteArr); 
					moe_SaveSKB(switchNum, dstIP, vp, skb);
					return DO_NOT_FORWARD;
					
				}
				if(LOGGING){os_WriteLog9("Switch num=%u, Original IP=%u.%u.%u.%u, New IP=%u.%u.%u.%u\n", switchNum,
					*((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3),
				*((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3));}
				
				
				if (newIP == 0) {return DO_FORWARD;}
				
				return moe_AddHeader(skb, dstIP, hashed, newIP);
			
			}
			
		// --------------------------------------------------------------------------------
		// ICMP Header Removal Operation
		// --------------------------------------------------------------------------------
			
			if (IHL == 0x45) {
				return DO_FORWARD;
			}
			else if (senderType == SENDERTYPE_SW && IHL == 0x4E) {
				hashed = data + IP_HLEN + 4;
				if (!moe_GetObjectFromHash(switchNum, hashed, &newIP)) { // If it doesn't exist,
					// Send a request message to the upper layer
					ipc_SendMessage(switchNum, OPCODE_GET_IP, dstIP, hashed);
					moe_SaveSKB(switchNum, dstIP, vp, skb);
					return DO_NOT_FORWARD;
				}
				if(LOGGING){os_WriteLog9("Switch num=%u, Received IP=%u.%u.%u.%u, Host IP=%u.%u.%u.%u\n", switchNum,
					*((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3),
				*((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3));}
				if (newIP == 0) {
					return DO_FORWARD;
				}
					
				return moe_RemoveHeader(skb, newIP, (tp_protocol == IPPROTO_TCP)?1:0);
			
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
			moe_CheckNewUE(switchNum, protocol, data);
			if(LOGGING){os_WriteLog("New UE.\n");}
			return DO_NOT_FORWARD;
		}

		// --------------------------------------------------------------------------------
		// Header Addition Operation
		// --------------------------------------------------------------------------------
		if (senderType == SENDERTYPE_UE && IHL == 0x45) {
			hashed = NULL;
			// Check entry in order to append an MoE header
			/*if (!moe_GetObjectFromIP(switchNum, dstIP, 0, &hashed, &newIP)) { // If it doesn't exist,
				// Send a request message to the upper layer
				ipc_SendMessage(switchNum, OPCODE_GET_HASH, dstIP, 0);
				moe_SaveSKB(switchNum, dstIP, vp, skb);
				return DO_NOT_FORWARD;
			}*/
			if (srcIP != 16777343 && srcIP != SWITCHS_IP[switchNum-1] && moe_GetOriginIPFromSrcIP(switchNum, srcIP, srcPort, &hashed, &originalIP)) {
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
					return DO_NOT_FORWARD;
				} else {
					dstPortByteArr[0] = 0;
					dstPortByteArr[1] = 0;
					ipc_SendMessage(switchNum, OPCODE_GET_HASH, dstIP, dstPortByteArr); 
					moe_SaveSKB(switchNum, dstIP, vp, skb);
					return DO_NOT_FORWARD;
				}
				// 170327 Jaehee
			}
			if(LOGGING){os_WriteLog10("Switch num=%u, Original IP=%u.%u.%u.%u, dstPort=%u, New IP=%u.%u.%u.%u\n", switchNum,
				*((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3), dstPort,
			*((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3));}
			
			
			if (newIP == 0) {return DO_FORWARD;}
			
			return moe_AddHeader(skb, dstIP, hashed, newIP);
		}

		// --------------------------------------------------------------------------------
		// Header Removal Operation
		// --------------------------------------------------------------------------------
		else if (senderType == SENDERTYPE_SW && IHL == 0x4E) {
			hashed = data + IP_HLEN + 4;
			if (!moe_GetObjectFromHash(switchNum, hashed, &newIP)) { // If it doesn't exist,
				// Send a request message to the upper layer
				ipc_SendMessage(switchNum, OPCODE_GET_IP, dstIP, hashed);
				moe_SaveSKB(switchNum, dstIP, vp, skb);
				return DO_NOT_FORWARD;
			}
			if(LOGGING){os_WriteLog10("Switch num=%u, Received IP=%u.%u.%u.%u, dstPort=%u, Host IP=%u.%u.%u.%u\n", switchNum,
				*((uint8_t*)&dstIP + 0), *((uint8_t*)&dstIP + 1), *((uint8_t*)&dstIP + 2), *((uint8_t*)&dstIP + 3), dstPort,
			*((uint8_t*)&newIP + 0), *((uint8_t*)&newIP + 1), *((uint8_t*)&newIP + 2), *((uint8_t*)&newIP + 3));}
			if (newIP == 0) {
				return DO_FORWARD;
			}

			
			if (tp_protocol == IPPROTO_UDP) { 
				if(LOGGING){os_WriteLog("received udp segment\n");}
				*(uint16_t*)(data + IP_HLEN + MOE_HLEN + 6) = (uint16_t)0;	
			
				uint16_t udp_check = CalculateUDPChecksum(srcIP, newIP, srcPort, dstPort, 
					data + IP_HLEN + MOE_HLEN + UDP_HLEN, ntohs(*(uint16_t*)(data + IP_HLEN + MOE_HLEN + 4)) - UDP_HLEN);
	
				memcpy(data + IP_HLEN + MOE_HLEN + 6, (void*)&udp_check, sizeof(udp_check));
				if(LOGGING){os_WriteLog1("udp checksum=%x\n",udp_check);}
					
			} else if (tp_protocol == IPPROTO_TCP) { 
				*(uint16_t*)(data + IP_HLEN + MOE_HLEN + 16) = (uint16_t)0;
			}
				
			return moe_RemoveHeader(skb, newIP, (tp_protocol == IPPROTO_TCP)?1:0);
			
		}
	}

	return 0;
}
// End of MoE Support

/**
 *	ovs_vport_receive - pass up received packet to the datapath for processing
 *
 * @vport: vport that received the packet
 * @skb: skb that was received
 * @tun_key: tunnel (if any) that carried packet
 *
 * Must be called with rcu_read_lock.  The packet cannot be shared and
 * skb->data should point to the Ethernet header.  The caller must have already
 * called compute_ip_summed() to initialize the checksumming fields.
 */
void ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
		       struct ovs_key_ipv4_tunnel *tun_key)
{
	struct pcpu_sw_netstats *stats;
	// LOHan: Statistics Support
	/*uint8_t switchNum = moe_GetSwitchNum(skb);
	do_gettimeofday(&START_TIME);*/

	stats = this_cpu_ptr(vport->percpu_stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	OVS_CB(skb)->tun_key = tun_key;
	// LOHan: Load Balancing Support
	/*if (switchNum == 7) {
		uint8_t randnum = os_myRand() % 16;
		if (randnum >= 8) {
			uint8_t* data = skb->data;
			if (data[ETH_ALEN+0] == 0x10 && data[ETH_ALEN+1] == 0x00 && data[ETH_ALEN+2] == 0x00 && data[ETH_ALEN+3] == 0x00)
			if (moe_CheckHeader(vport, skb) == -1) return;
		}
	}
	else */if (moe_CheckHeader(vport, skb) == -1) return;
	ovs_dp_process_received_packet(vport, skb);
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
}

/**
 *	ovs_vport_send - send a packet on a device
 *
 * @vport: vport on which to send the packet
 * @skb: skb to send
 *
 * Sends the given packet and returns the length of data sent.  Either ovs
 * lock or rcu_read_lock must be held.
 */
int ovs_vport_send(struct vport *vport, struct sk_buff *skb)
{
	int sent = vport->ops->send(vport, skb);

	if (likely(sent > 0)) {
		struct pcpu_sw_netstats *stats;

		stats = this_cpu_ptr(vport->percpu_stats);

		u64_stats_update_begin(&stats->syncp);
		stats->tx_packets++;
		stats->tx_bytes += sent;
		u64_stats_update_end(&stats->syncp);
	} else if (sent < 0) {
		ovs_vport_record_error(vport, VPORT_E_TX_ERROR);
		kfree_skb(skb);
	} else
		ovs_vport_record_error(vport, VPORT_E_TX_DROPPED);

	return sent;
}

/**
 *	ovs_vport_record_error - indicate device error to generic stats layer
 *
 * @vport: vport that encountered the error
 * @err_type: one of enum vport_err_type types to indicate the error type
 *
 * If using the vport generic stats layer indicate that an error of the given
 * type has occurred.
 */
static void ovs_vport_record_error(struct vport *vport,
				   enum vport_err_type err_type)
{
	spin_lock(&vport->stats_lock);

	switch (err_type) {
	case VPORT_E_RX_DROPPED:
		vport->err_stats.rx_dropped++;
		break;

	case VPORT_E_RX_ERROR:
		vport->err_stats.rx_errors++;
		break;

	case VPORT_E_TX_DROPPED:
		vport->err_stats.tx_dropped++;
		break;

	case VPORT_E_TX_ERROR:
		vport->err_stats.tx_errors++;
		break;
	}

	spin_unlock(&vport->stats_lock);
}

static void free_vport_rcu(struct rcu_head *rcu)
{
	struct vport *vport = container_of(rcu, struct vport, rcu);

	ovs_vport_free(vport);
}

void ovs_vport_deferred_free(struct vport *vport)
{
	if (!vport)
		return;

	call_rcu(&vport->rcu, free_vport_rcu);
}
