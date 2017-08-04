#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef RAWSOCK_IMPL_H
#define RAWSOCK_IMPL_H

#include "openavb_rawsock.h"

#define ETHERTYPE_8021Q 0x8100
#define VLAN_HLEN	4

typedef struct {
	void (*setRxSignalMode)(void* rawsock, int rxSignalMode);
	void (*close)(void* rawsock);
	int (*getSocket)(void* rawsock);
	int (*getAddr)(void* rawsock, uint8_t addr[ETH_ALEN]);
	uint8_t* (*getRxFrame)(void* rawsock, uint32_t usecTimeout, uint32_t* offset, uint32_t* len);
	int (*rxParseHdr)(void* rawsock, uint8_t* pBuffer, hdr_info_t* pInfo);
	int (*relRxFrame)(void* rawsock, uint8_t* pFrame);
	int (*rxMulticast)(void* rawsock, int add_membership, const uint8_t buf[ETH_ALEN]);
	int (*rxAVTPSubtype)(void* rawsock, uint8_t subtype);
	int (*txSetHdr)(void* rawsock, hdr_info_t* pInfo);
	int (*txFillHdr)(void* rawsock, uint8_t* pBuffer, uint32_t* hdrlen);
	int (*txSetMark)(void* rawsock, int prio);
	uint8_t* (*getTxFrame)(void* rawsock, int blocking, uint32_t* size);
	int (*relTxFrame)(void* rawsock, uint8_t* pBuffer);
	int (*txFrameReady)(void* rawsock, uint8_t* pFrame, uint32_t len, uint64_t timeNsec);
	int (*send)(void* rawsock);
	int (*txBufLevel)(void* rawsock);
	int (*rxBufLevel)(void* rawsock);
	unsigned long (*getTXOutOfBuffers)(void* pvRawsock);
	unsigned long (*getTXOutOfBuffersCyclic)(void* pvRawsock);
} rawsock_cb_t;

typedef struct {
	uint8_t dhost[ETH_ALEN];
	uint8_t shost[ETH_ALEN];
	uint16_t  ethertype;
}eth_hdr_t;


typedef struct {
	u_int16_t	tpip;
	u_int16_t	bits;
}vlan_tag_t;

typedef struct {
	uint8_t dhost[ETH_ALEN];
	uint8_t shost[ETH_ALEN];
	vlan_tag_t vlan;
	uint16_t  ethertype;
}eth_vlan_hdr_t;

typedef struct base_rawsock {
	// implementation callbacks
	rawsock_cb_t cb;

	// interface info
	if_info_t ifInfo;

	// saved Ethernet header for TX frames
	union {
		eth_hdr_t      notag;
		eth_vlan_hdr_t tagged;
	} ethHdr;
	unsigned ethHdrLen;

	// Ethertype for TX/RX frames
	unsigned ethertype;

	// size of ethernet frame
	int frameSize;

	// TX-RX usage of the socket
  int txMode;

  int rxMode;

} base_rawsock_t;

#define VALID_RAWSOCK(s) ((s) != NULL)
#define VALID_TX_RAWSOCK(s) (VALID_RAWSOCK(s) && ((base_rawsock_t*)s)->txMode)
#define VALID_RX_RAWSOCK(s) (VALID_RAWSOCK(s) && ((base_rawsock_t*)s)->rxMode)

void* baseRawsockOpen(base_rawsock_t* rawsock, const char *ifname, int rx_mode, int tx_mode, uint16_t ethertype, uint32_t frame_size, uint32_t num_frames);
void baseRawsockClose(void* rawsock);
int baseRawsockTxSetHdr(void *pvRawsock, hdr_info_t *pHdr);
int baseRawsockTxFillHdr(void *pvRawsock, uint8_t *pBuffer, unsigned int *hdrlen);
int baseRawsockGetAddr(void *pvRawsock, uint8_t addr[ETH_ALEN]);
int baseRawsockRxParseHdr(void *pvRawsock, uint8_t *pBuffer, hdr_info_t *pInfo);

#endif //RAWSOCK_IMPL_H
