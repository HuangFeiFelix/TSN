#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>

#ifndef SIMPLE_RAWSOCK_H
#define SIMPLE_RAWSOCK_H

#include "rawsock_impl.h"

typedef struct {
	base_rawsock_t base;

	// the underlying socket
	int sock;

	// buffer for sending frames
	uint8_t txBuffer[1518];

	// buffer for receiving frames
  uint8_t rxBuffer[1518];
} simple_rawsock_t;

int simpleAvbCheckInterface(const char *ifname, if_info_t *info);

// Open a rawsock for TX or RX
void* simpleRawsockOpen(simple_rawsock_t *rawsock, const char *ifname, int rx_mode, int tx_mode, uint16_t ethertype, uint32_t frame_size, uint32_t num_frames);

// Close the rawsock
void simpleRawsockClose(void *pvRawsock);

// Get a buffer from the simple to use for TX
uint8_t* simpleRawsockGetTxFrame(void *pvRawsock, int blocking, unsigned int *len);

// Set the Firewall MARK on the socket
// The mark is used by FQTSS to identify AVTP packets in kernel.
// FQTSS creates a mark that includes the AVB class and stream index.
int simpleRawsockTxSetMark(void *pvRawsock, int mark);

// Pre-set the ethernet header information that will be used on TX frames
int simpleRawsockTxSetHdr(void *pvRawsock, hdr_info_t *pHdr);

// Release a TX frame, and mark it as ready to send
int simpleRawsockTxFrameReady(void *pvRawsock, uint8_t *pBuffer, unsigned int len, uint64_t timeNsec);

// Get a RX frame
uint8_t* simpleRawsockGetRxFrame(void *pvRawsock, uint32_t timeout, unsigned int *offset, unsigned int *len);

// Setup the rawsock to receive multicast packets
int simpleRawsockRxMulticast(void *pvRawsock, int add_membership, const uint8_t addr[ETH_ALEN]);

// Get the socket used for this rawsock; can be used for poll/select
int  simpleRawsockGetSocket(void *pvRawsock);

#endif
