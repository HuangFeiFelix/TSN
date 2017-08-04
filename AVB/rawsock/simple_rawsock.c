#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "simple_rawsock.h"

unsigned char glob_l2_dest_addr[] = { 0x91, 0xE0, 0xF0, 0x00, 0x0e, 0x80 };

// Get information about an interface
int simpleAvbCheckInterface(const char *ifname, if_info_t *info)
{
	if (!ifname || !info) {
		printf("Checking interface; invalid arguments\n");
		return 0;
	}

	// zap the result struct
	memset(info, 0, sizeof(if_info_t));

	strncpy(info->name, ifname, 6);

	// open a throw-away socket - used for our ioctls
	int sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk == -1) {
		printf("Checking interface; socket open failed\n");
		return 0;
	}

	// set the name of the interface in the ioctl request struct
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	// First check if the interface is up
	//  (also proves that the interface exists!)
	int r = ioctl(sk, SIOCGIFFLAGS, &ifr);
	if (r != 0) {
		printf("Checking interface; ioctl(SIOCGIFFLAGS) failed\n");
		close(sk);
		return 0;
	}

	if (!(ifr.ifr_flags&IFF_UP)) {
		printf("Checking interface; interface is not up: %s\n", ifname);
		close(sk);
		return 0;
	}

	// get index for interface
	r = ioctl(sk, SIOCGIFINDEX, &ifr);
	if (r != 0) {
		printf("Checking interface; ioctl(SIOCGIFINDEX) failed\n");
		close(sk);
    return 0;
	}
	info->index = ifr.ifr_ifindex;

	// get the MAC address for the interface
	r = ioctl(sk, SIOCGIFHWADDR, &ifr);
	if (r != 0) {
		printf("Checking interface; ioctl(SIOCGIFHWADDR) failed\n");
		close(sk);
		return 0;
	}
	memcpy(&info->mac.ether_addr_octet, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	// get the MTU for the interface
	r = ioctl(sk, SIOCGIFMTU, &ifr);
	if (r != 0) {
		printf("Checking interface; ioctl(SIOCGIFMTU) failed\n");
		close(sk);
		return 0;
	}
	info->mtu = ifr.ifr_mtu;

	// close the temporary socket
	close(sk);
	return 1;
}

void* simpleRawsockOpen(simple_rawsock_t *rawsock, const char *ifname, int rx_mode, int tx_mode, uint16_t ethertype, uint32_t frame_size, uint32_t num_frames){

  baseRawsockOpen(&rawsock->base, ifname, rx_mode, tx_mode, ethertype, frame_size, num_frames);

  rawsock->sock = -1;

	// Get info about the network device
  if(!simpleAvbCheckInterface(ifname, &(rawsock->base.ifInfo))){
    printf("Creating rawsock: bad interface name: %s\n",ifname);
    free(rawsock);
    return NULL;
  }

	// Deal with frame size.
if (rawsock->base.frameSize == 0) {
	// use interface MTU as max frames size, if none specified
	rawsock->base.frameSize = rawsock->base.ifInfo.mtu + ETH_HLEN + VLAN_HLEN;
}
else if (rawsock->base.frameSize > rawsock->base.ifInfo.mtu + ETH_HLEN + VLAN_HLEN) {
	printf("Creating raswsock; requested frame size exceeds MTU\n");
	free(rawsock);
	return NULL;
}
rawsock->base.frameSize = TPACKET_ALIGN(rawsock->base.frameSize);

// Prepare default Ethernet header.
	rawsock->base.ethHdrLen = sizeof(eth_hdr_t);
	//memset(&(rawsock->base.ethHdr.notag.dhost), 0xFF, ETH_ALEN);
	memcpy(rawsock->base.ethHdr.notag.dhost, glob_l2_dest_addr,ETH_ALEN);
	memcpy(&(rawsock->base.ethHdr.notag.shost), &(rawsock->base.ifInfo.mac), ETH_ALEN);
	rawsock->base.ethHdr.notag.ethertype = htons(rawsock->base.ethertype);

	// Create socket
	rawsock->sock = socket(PF_PACKET, SOCK_RAW, htons(rawsock->base.ethertype));
	if (rawsock->sock == -1) {
		printf("Creating rawsock; opening socket error\n");
		simpleRawsockClose(rawsock);
		return NULL;
	}

	// Allow address reuse
	int temp = 1;
	if(setsockopt(rawsock->sock, SOL_SOCKET, SO_REUSEADDR, &temp, sizeof(int)) < 0) {
		printf("Creating rawsock; failed to set reuseaddr\n");
		simpleRawsockClose(rawsock);
		return NULL;
	}

	// Bind to interface
	struct sockaddr_ll my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sll_family = PF_PACKET;
	my_addr.sll_protocol = htons(rawsock->base.ethertype);
	my_addr.sll_ifindex = rawsock->base.ifInfo.index;

	if (bind(rawsock->sock, (struct sockaddr*)&my_addr, sizeof(my_addr)) == -1) {
		printf("Creating rawsock; bind socket error\n");
		simpleRawsockClose(rawsock);
		return NULL;
	}


	// fill virtual functions table
	rawsock_cb_t *cb = &rawsock->base.cb;
	cb->close = simpleRawsockClose;
	cb->getTxFrame = simpleRawsockGetTxFrame;
	cb->txSetMark = simpleRawsockTxSetMark;
	cb->txSetHdr = simpleRawsockTxSetHdr;
	cb->txFrameReady = simpleRawsockTxFrameReady;
	cb->getRxFrame = simpleRawsockGetRxFrame;
	cb->rxMulticast = simpleRawsockRxMulticast;
	cb->getSocket = simpleRawsockGetSocket;

	return rawsock;
}

// Close the rawsock
void simpleRawsockClose(void *pvRawsock)
{
	simple_rawsock_t *rawsock = (simple_rawsock_t*)pvRawsock;

	if (rawsock) {
		// close the socket
		if (rawsock->sock != -1) {
			close(rawsock->sock);
			rawsock->sock = -1;
		}
	}

	baseRawsockClose(rawsock);
}

// Get a buffer from the ring to use for TX
uint8_t* simpleRawsockGetTxFrame(void *pvRawsock, int blocking, unsigned int *len)
{
	simple_rawsock_t *rawsock = (simple_rawsock_t*)pvRawsock;

	if (!VALID_TX_RAWSOCK(rawsock)) {
		printf("Getting TX frame; bad arguments\n");
		return NULL;
	}
//	if (rawsock->buffersOut >= rawsock->frameCount) {
//		printf("Getting TX frame; too many TX buffers in use\n");
//		return NULL;
//	}


	uint8_t *pBuffer = rawsock->txBuffer;

	// Remind client how big the frame buffer is
	if (len)
		*len = rawsock->base.frameSize;

	return  pBuffer;
}

// Set the Firewall MARK on the socket
// The mark is used by FQTSS to identify AVTP packets in kernel.
// FQTSS creates a mark that includes the AVB class and stream index.
int simpleRawsockTxSetMark(void *pvRawsock, int mark)
{
	simple_rawsock_t *rawsock = (simple_rawsock_t*)pvRawsock;
	int retval = 0;

	if (!VALID_TX_RAWSOCK(rawsock)) {
		printf("Setting TX mark; invalid argument passed\n");
		return 0;
	}

	if (setsockopt(rawsock->sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
		printf("Setting TX mark; setsockopt failed\n");
	}
	else {
		//printf("SO_MARK=%d OK\n", mark);
		retval = 1;
	}
	return retval;
}

// Pre-set the ethernet header information that will be used on TX frames
int simpleRawsockTxSetHdr(void *pvRawsock, hdr_info_t *pHdr)
{
	simple_rawsock_t *rawsock = (simple_rawsock_t*)pvRawsock;

	int ret = baseRawsockTxSetHdr(pvRawsock, pHdr);
	if (ret && pHdr->vlan) {
		// set the class'es priority on the TX socket
		// (required by Telechips platform for FQTSS Credit Based Shaper to work)
		uint32_t pcp = pHdr->vlan_pcp;
		if (setsockopt(rawsock->sock, SOL_SOCKET, SO_PRIORITY, (char *)&pcp, sizeof(pcp)) < 0) {
			printf("stcRawsockTxSetHdr; SO_PRIORITY setsockopt failed \n");
			return 0;
		}
	}
	return ret;
}

// Release a TX frame, and send it
int simpleRawsockTxFrameReady(void *pvRawsock, uint8_t *pBuffer, unsigned int len, uint64_t timeNsec)
{
	simple_rawsock_t *rawsock = (simple_rawsock_t*)pvRawsock;

	if (!VALID_TX_RAWSOCK(rawsock)) {
		printf("Marking TX frame ready; invalid argument\n");
		return 0;
	}

	if (timeNsec) {
		//IF_LOG_INTERVAL(1000) AVB_LOG_WARNING("launch time is unsupported in simple_rawsock");
	}

	int flags = MSG_DONTWAIT;
	send(rawsock->sock, pBuffer, len, flags);
	return 1;
}

// Get a RX frame
uint8_t* simpleRawsockGetRxFrame(void *pvRawsock, uint32_t timeout, unsigned int *offset, unsigned int *len)
{
	simple_rawsock_t *rawsock = (simple_rawsock_t*)pvRawsock;
	if (!VALID_RX_RAWSOCK(rawsock)) {
		printf("Getting RX frame; invalid arguments\n");
		return NULL;
	}
//	if (rawsock->buffersOut >= rawsock->frameCount) {
//		printf("Too many RX buffers in use");
//		AVB_TRACE_EXIT(AVB_TRACE_RAWSOCK_DETAIL);
//		return NULL;
//	}

	int flags = 0;

	uint8_t *pBuffer = rawsock->rxBuffer;
	*offset = 0;
	*len = recv(rawsock->sock, pBuffer, rawsock->base.frameSize, flags);

	if (*len == -1) {
		printf("error");
		return NULL;
	}

	return pBuffer;
}

// Setup the rawsock to receive multicast packets
int simpleRawsockRxMulticast(void *pvRawsock, int add_membership, const uint8_t addr[ETH_ALEN])
{
	simple_rawsock_t *rawsock = (simple_rawsock_t*)pvRawsock;
	if (!VALID_RX_RAWSOCK(rawsock)) {
		printf("Setting multicast; invalid arguments\n");
		return 0;
	}

	struct ether_addr mcast_addr;
	memcpy(mcast_addr.ether_addr_octet, addr, ETH_ALEN);

	// Fill in the structure for the multicast ioctl
	struct packet_mreq mreq;
	memset(&mreq, 0, sizeof(struct packet_mreq));
	mreq.mr_ifindex = rawsock->base.ifInfo.index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	memcpy(&mreq.mr_address, &mcast_addr.ether_addr_octet, ETH_ALEN);

	// And call the ioctl to add/drop the multicast address
	int action = (add_membership ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP);
	if (setsockopt(rawsock->sock, SOL_PACKET, action,
					(void*)&mreq, sizeof(struct packet_mreq)) < 0) {
		printf("Setting multicast; setsockopt(%s) failed\n",
					   (add_membership ? "PACKET_ADD_MEMBERSHIP" : "PACKET_DROP_MEMBERSHIP"));
		return 0;
	}

	// In addition to adding the multicast membership, we also want to
	//	add a packet filter to restrict the packets that we'll receive
	//	on this socket.  Multicast memeberships are global - not
	//	per-socket, so without the filter, this socket would receieve
	//	packets for all the multicast addresses added by all other
	//	sockets.
	//
	if (add_membership)
	{
		// Here's the template packet filter code.
		// It was produced by running:
		//   tcpdump -dd ether dest host 91:e0:01:02:03:04
		struct sock_filter bpfCode[] = {
			{ 0x20, 0, 0, 0x00000002 },
			{ 0x15, 0, 3, 0x01020304 },   // last 4 bytes of dest mac
			{ 0x28, 0, 0, 0x00000000 },
			{ 0x15, 0, 1, 0x000091e0 },   // first 2 bytes of dest mac
			{ 0x06, 0, 0, 0x0000ffff },
			{ 0x06, 0, 0, 0x00000000 }
		};

		// We need to graft our multicast dest address into bpfCode
		uint32_t tmp; uint8_t *buf = (uint8_t*)&tmp;
		memcpy(buf, mcast_addr.ether_addr_octet + 2, 4);
		bpfCode[1].k = ntohl(tmp);
		memset(buf, 0, 4);
		memcpy(buf + 2, mcast_addr.ether_addr_octet, 2);
		bpfCode[3].k = ntohl(tmp);

		// Now wrap the filter code in the appropriate structure
		struct sock_fprog filter;
		memset(&filter, 0, sizeof(filter));
		filter.len = 6;
		filter.filter = bpfCode;

		// And attach it to our socket
		if (setsockopt(rawsock->sock, SOL_SOCKET, SO_ATTACH_FILTER,
						&filter, sizeof(filter)) < 0) {
			printf("Setting multicast; setsockopt(SO_ATTACH_FILTER) failed\n");
		}
	}
	else {
		if (setsockopt(rawsock->sock, SOL_SOCKET, SO_DETACH_FILTER, NULL, 0) < 0) {
			printf("Setting multicast; setsockopt(SO_DETACH_FILTER) failed\n");
		}
	}
	return 1;
}

// Get the socket used for this rawsock; can be used for poll/select
int  simpleRawsockGetSocket(void *pvRawsock)
{
	simple_rawsock_t *rawsock = (simple_rawsock_t*)pvRawsock;
	if (!rawsock) {
		printf("Getting socket; invalid arguments\n");
		return -1;
	}
	return rawsock->sock;
}
