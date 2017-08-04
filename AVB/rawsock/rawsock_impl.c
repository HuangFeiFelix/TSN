#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "rawsock_impl.h"

void baseRawsockSetRxSignalMode(void *rawsock, int rxSignalMode) {}
int baseRawsockGetSocket(void *rawsock) { return -1; }
uint8_t *baseRawsockGetRxFrame(void *rawsock, uint32_t usecTimeout, uint32_t *offset, uint32_t *len) { return NULL; }
int baseRawsockRelRxFrame(void *rawsock, uint8_t *pFrame) { return 0; }
int baseRawsockRxMulticast(void *rawsock, int add_membership, const uint8_t buf[]) { return 0; }
int baseRawsockRxAVTPSubtype(void *rawsock, uint8_t subtype) { return 0; }
int baseRawsockTxSetMark(void *rawsock, int prio) { return 0; }
uint8_t *baseRawsockGetTxFrame(void *rawsock, int blocking, uint32_t *size) { return NULL; }
int baseRawsockRelTxFrame(void *rawsock, uint8_t *pBuffer) { return 0; }
int baseRawsockTxFrameReady(void *rawsock, uint8_t *pFrame, uint32_t len, uint64_t timeNsec) { return 0; }
int baseRawsockSend(void *rawsock) { return -1; }
int baseRawsockTxBufLevel(void *rawsock) { return -1; }
int baseRawsockRxBufLevel(void *rawsock) { return -1; }
unsigned long baseRawsockGetTXOutOfBuffers(void *pvRawsock) { return 0; }
unsigned long baseRawsockGetTXOutOfBuffersCyclic(void *pvRawsock) { return 0; }

void* baseRawsockOpen(base_rawsock_t* rawsock, const char *ifname, int rx_mode, int tx_mode, uint16_t ethertype, uint32_t frame_size, uint32_t num_frames){

  rawsock->rxMode = rx_mode;
  rawsock->txMode = tx_mode;
  rawsock->frameSize = frame_size;
  rawsock->ethertype = ethertype;


  // fill virtual functions table
  rawsock_cb_t *cb = &rawsock->cb;
	cb->setRxSignalMode = baseRawsockSetRxSignalMode;
	cb->close = baseRawsockClose;
	cb->getSocket = baseRawsockGetSocket;
	cb->getAddr = baseRawsockGetAddr;
	cb->getRxFrame = baseRawsockGetRxFrame;
	cb->rxParseHdr = baseRawsockRxParseHdr;
	cb->relRxFrame = baseRawsockRelRxFrame;
	cb->rxMulticast = baseRawsockRxMulticast;
	cb->rxAVTPSubtype = baseRawsockRxAVTPSubtype;
	cb->txSetHdr = baseRawsockTxSetHdr;
	cb->txFillHdr = baseRawsockTxFillHdr;
	cb->txSetMark = baseRawsockTxSetMark;
	cb->getTxFrame = baseRawsockGetTxFrame;
	cb->relTxFrame = baseRawsockRelTxFrame;
	cb->txFrameReady = baseRawsockTxFrameReady;
	cb->send = baseRawsockSend;
	cb->txBufLevel = baseRawsockTxBufLevel;
	cb->rxBufLevel = baseRawsockRxBufLevel;
	cb->getTXOutOfBuffers = baseRawsockGetTXOutOfBuffers;
	cb->getTXOutOfBuffersCyclic = baseRawsockGetTXOutOfBuffersCyclic;

  return rawsock;
}

void baseRawsockClose(void *rawsock)
{
	// free the state struct
	free(rawsock);
}

// Pre-set the ethernet header information that will be used on TX frames
int baseRawsockTxSetHdr(void *pvRawsock, hdr_info_t *pHdr)
{
	base_rawsock_t *rawsock = (base_rawsock_t*)pvRawsock;

	if (!VALID_TX_RAWSOCK(rawsock)) {
		printf("Setting TX header; invalid argument\n");
		return 0;
	}
	// source address
	if (pHdr->shost) {
		memcpy(&(rawsock->ethHdr.notag.shost), pHdr->shost, ETH_ALEN);
	}
	// destination address
	if (pHdr->dhost) {
		memcpy(&(rawsock->ethHdr.notag.dhost), pHdr->dhost, ETH_ALEN);
	}

	// VLAN tag?
	if (!pHdr->vlan) {
		// No, set ethertype in normal location
		rawsock->ethHdr.notag.ethertype = htons(rawsock->ethertype);
		// and set ethernet header length
		rawsock->ethHdrLen = sizeof(eth_hdr_t);
	}
	else {
		// Add VLAN tag

		// Build bitfield with vlan_pcp and vlan_vid.
		// I think CFI bit is alway 0
		
		uint16_t bits = 0;
		bits |= (pHdr->vlan_pcp << 13) & 0xE000;
		bits |= pHdr->vlan_vid & 0x0FFF;

		// Create VLAN tag
		rawsock->ethHdr.tagged.vlan.tpip = htons(ETHERTYPE_VLAN);
		rawsock->ethHdr.tagged.vlan.bits = htons(bits);
		rawsock->ethHdr.tagged.ethertype = htons(rawsock->ethertype);
		// and set ethernet header length
		rawsock->ethHdrLen = sizeof(eth_vlan_hdr_t);
	}
	return 1;
}

// Copy the pre-set header to the outgoing frame
int baseRawsockTxFillHdr(void *pvRawsock, uint8_t *pBuffer, unsigned int *hdrlen)
{
	base_rawsock_t *rawsock = (base_rawsock_t*)pvRawsock;
	if (!rawsock) {
		printf("Filling TX header; invalid argument");
		return 0;
	}
	// Copy the default Ethernet header into the buffer
	if (hdrlen)
		*hdrlen = rawsock->ethHdrLen;
	memcpy((char*)pBuffer, &(rawsock->ethHdr), rawsock->ethHdrLen);

	return 0;
}

// Get the ethernet address of the interface
int baseRawsockGetAddr(void *pvRawsock, uint8_t addr[ETH_ALEN])
{
	base_rawsock_t *rawsock = (base_rawsock_t*)pvRawsock;
	if (!rawsock) {
		printf("Getting address; invalid arguments");
		return 0;
	}

	memcpy(addr, &rawsock->ifInfo.mac.ether_addr_octet, ETH_ALEN);
	return 1;
}

// Parse the ethernet frame header.  Returns length of header, or -1 for failure
int baseRawsockRxParseHdr(void *pvRawsock, uint8_t *pBuffer, hdr_info_t *pInfo)
{
	eth_hdr_t *eth_hdr = (eth_hdr_t*)pBuffer;
	pInfo->dhost = eth_hdr->dhost;
	pInfo->shost = eth_hdr->shost;
	pInfo->ethertype = ntohs(eth_hdr->ethertype);
	int hdrLen = sizeof(eth_hdr_t);

	if (pInfo->ethertype == ETHERTYPE_8021Q) {
		pInfo->vlan = 1;
		// TODO extract vlan_vid and vlan_pcp
		hdrLen += 4;
	}
	return hdrLen;
}


/////////////////////////////////////////////////////////////////////////////

void openavbSetRxSignalMode(void *pvRawsock, int rxSignalMode)
{
	((base_rawsock_t*)pvRawsock)->cb.setRxSignalMode(pvRawsock, rxSignalMode);
}

void openavbRawsockClose(void *pvRawsock)
{
	((base_rawsock_t*)pvRawsock)->cb.close(pvRawsock);
}

uint8_t *openavbRawsockGetTxFrame(void *pvRawsock, int blocking, unsigned int *len)
{
	uint8_t *ret = ((base_rawsock_t*)pvRawsock)->cb.getTxFrame(pvRawsock, blocking, len);
	return ret;
}

int openavbRawsockTxSetMark(void *pvRawsock, int mark)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.txSetMark(pvRawsock, mark);
	return ret;
}

int openavbRawsockTxSetHdr(void *pvRawsock, hdr_info_t *pHdr)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.txSetHdr(pvRawsock, pHdr);
	return ret;
}

int openavbRawsockTxFillHdr(void *pvRawsock, uint8_t *pBuffer, unsigned int *hdrlen)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.txFillHdr(pvRawsock, pBuffer, hdrlen);
	return ret;
}

int openavbRawsockRelTxFrame(void *pvRawsock, uint8_t *pBuffer)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.relTxFrame(pvRawsock, pBuffer);
	return ret;
}

int openavbRawsockTxFrameReady(void *pvRawsock, uint8_t *pBuffer, unsigned int len, uint64_t timeNsec)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.txFrameReady(pvRawsock, pBuffer, len, timeNsec);
	return ret;
}

int openavbRawsockSend(void *pvRawsock)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.send(pvRawsock);
	return ret;
}

int openavbRawsockTxBufLevel(void *pvRawsock)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.txBufLevel(pvRawsock);
	return ret;
}

int openavbRawsockRxBufLevel(void *pvRawsock)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.rxBufLevel(pvRawsock);
	return ret;
}

uint8_t *openavbRawsockGetRxFrame(void *pvRawsock, uint32_t timeout, unsigned int *offset, unsigned int *len)
{
	uint8_t *ret = ((base_rawsock_t*)pvRawsock)->cb.getRxFrame(pvRawsock, timeout, offset, len);
	return ret;
}

int openavbRawsockRxParseHdr(void *pvRawsock, uint8_t *pBuffer, hdr_info_t *pInfo)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.rxParseHdr(pvRawsock, pBuffer, pInfo);
	return ret;
}

int openavbRawsockRelRxFrame(void *pvRawsock, uint8_t *pBuffer)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.relRxFrame(pvRawsock, pBuffer);
	return ret;
}

int openavbRawsockRxMulticast(void *pvRawsock, int add_membership, const uint8_t addr[ETH_ALEN])
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.rxMulticast(pvRawsock, add_membership, addr);
	return ret;
}

int openavbRawsockRxAVTPSubtype(void *pvRawsock, uint8_t subtype)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.rxAVTPSubtype(pvRawsock, subtype);
	return ret;
}

int openavbRawsockGetSocket(void *pvRawsock)
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.getSocket(pvRawsock);
	return ret;
}

int openavbRawsockGetAddr(void *pvRawsock, uint8_t addr[ETH_ALEN])
{
	int ret = ((base_rawsock_t*)pvRawsock)->cb.getAddr(pvRawsock, addr);
	return ret;
}

unsigned long openavbRawsockGetTXOutOfBuffers(void *pvRawsock)
{
	unsigned long ret = ((base_rawsock_t*)pvRawsock)->cb.getTXOutOfBuffers(pvRawsock);
	return ret;
}

unsigned long openavbRawsockGetTXOutOfBuffersCyclic(void *pvRawsock)
{
	unsigned long ret = ((base_rawsock_t*)pvRawsock)->cb.getTXOutOfBuffersCyclic(pvRawsock);
	return ret;
}

void openavbGetSourceAddress(void *pvRawsock, unsigned char *glob_station_addr){
  base_rawsock_t *rawsock = (base_rawsock_t*)pvRawsock;
  memcpy(glob_station_addr,&(rawsock->ethHdr.tagged.shost),ETH_ALEN);
}
