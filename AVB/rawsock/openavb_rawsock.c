#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>

#include "openavb_rawsock.h"
#include "simple_rawsock.h"

void *openavbRawsockOpen(const char *ifname_uri, int rx, int tx, uint16_t ethertype, uint32_t frame_size, uint32_t num_frames){   //tx = 1, rx = 0

  const char* ifname = ifname_uri;
  //char protocol[6] = "simple";

  void *pvRawsock = NULL;

  printf("Using simple implementation\n");
  simple_rawsock_t *rawsock = calloc(1,sizeof(simple_rawsock_t));
  if(!rawsock){
    printf("Creating rawsock: malloc failed\n");
    return NULL;
  }

  pvRawsock = simpleRawsockOpen(rawsock,ifname,rx,tx,ethertype,frame_size,num_frames);

  return pvRawsock;

}
