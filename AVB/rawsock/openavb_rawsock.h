#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/ethernet.h>

#ifndef RAWSOCK_H
#define RAWSOCK_H 1

#define OPENAVB_RAWSOCK_NONBLOCK  	(0)
#define OPENAVB_RAWSOCK_BLOCK		(-1)

// Structure to hold information about a network interface
typedef struct {
	char name[6];
	struct ether_addr mac;
	int index;
	int mtu;
} if_info_t;

// Structure to hold fields from Ethernet header
// Used to set information to be added to TX frames,
//  or to return info parsed from RX frames.
typedef struct {
	uint8_t *shost;		// Source MAC address
	uint8_t *dhost; 		// Destination MAC address
	uint16_t ethertype;	// Ethernet type (protocol)
	int vlan;		// Include VLAN header?
	uint8_t  vlan_pcp;	// VLAN Priority Code Point
	uint8_t vlan_vid;	// VLAN ID
} hdr_info_t;

void *openavbRawsockOpen(const char *ifname_uri, int rx, int tx, uint16_t ethertype, uint32_t frame_size, uint32_t num_frames);

// TX FUNCTIONS
//
// Setup the header that we'll use on TX Ethernet frames.
// Called once during intialization.
int openavbRawsockTxSetHdr(void *rawsock, hdr_info_t *pInfo);

// Get a buffer to hold a frame for transmission.
// Returns pointer to frame (or NULL).
uint8_t *openavbRawsockGetTxFrame(void *rawsock,		// rawsock handle
						   int blocking,	// TRUE blocks until frame buffer is available.
						   uint32_t *size);		// size of the frame buffer

// Copy the pre-set Ethernet header into the frame
int openavbRawsockTxFillHdr(void *rawsock, uint8_t  *pBuffer, uint32_t *hdrlen);

// Submit a frame and mark it "ready to send"
int openavbRawsockTxFrameReady(void *rawsock,	// rawsock handle
							uint8_t *pFrame, 	// pointer to frame buffer
							uint32_t len,	// length of frame to send
							uint64_t timeNsec);	// launch time (in gPTP wall clock)

int openavbRawsockSend(void *rawsock);

// Close the raw socket and release associated resources.
void openavbRawsockClose(void *rawsock);

// Add (or drop) membership in link-layer multicast group
int openavbRawsockRxMulticast(void *rawsock, int add_membership, const uint8_t buf[ETH_ALEN]);

// Get a received frame.
// Returns pointer to received frame, or NULL
uint8_t *openavbRawsockGetRxFrame(void *rawsock,	// rawsock handle
						 uint32_t usecTimeout,   // timeout (microseconds)
						 					// or use OPENAVB_RAWSOCK_BLOCK/NONBLOCK
						 uint32_t *offset,	// offset of frame in the frame buffer
						 uint32_t *len);		// returns length of received frame

// Parse the frame header.  Returns length of header, or -1 for failure
int openavbRawsockRxParseHdr(void* rawsock, uint8_t *pBuffer, hdr_info_t *pInfo);

// Release the received frame for re-use.
int openavbRawsockRelRxFrame(void *rawsock, uint8_t *pFrame);

void openavbGetSourceAddress(void *rawsock, unsigned char *glob_station_addr);

#endif //RAWSOCK_H
