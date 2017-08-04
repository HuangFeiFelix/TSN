#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <glib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if.h>

#include "../common/avb.h"
#include "../mrpd/talker_mrp_client.h"

#include "../rawsock/openavb_rawsock.h"

//Common usage: ./obj/rawsock_tx -i eth0 -t 8944 -r 8000 -s 1 -c 1 -m 1 -l 100

#define MAX_NUM_FRAMES 100
#define NANOSECONDS_PER_SECOND    (1000000000ULL)
#define TIMESPEC_TO_NSEC(ts) ((uint64_t)ts.tv_sec * (uint64_t)NANOSECONDS_PER_SECOND) + (uint64_t)ts.tv_nsec

#define RAWSOCK_TX_MODE_FILL  (0)
#define RAWSOCK_TX_MODE_SEQ   (1)

#define CHANNELS (1)
#define L2_SAMPLES_PER_FRAME (6)
#define L2_PACKET_IPG (125000)
#define PKT_SZ (100)

#define GAIN (0.5)
#define XMIT_DELAY (200000000) /* us */
#define RENDER_DELAY (XMIT_DELAY+2000000)	/* us */
#define SRC_CHANNELS (2)


static char* interface = NULL;
static int ethertype = -1;
static int txRate = 8000;
static int reportSec = 1;

typedef long double FrequencyRatio;
volatile int *halt_tx_sig;//Global variable for signal handler

unsigned char glob_station_addr[] = { 0, 0, 0, 0, 0, 0 };
unsigned char glob_stream_id[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
/* IEEE 1722 reserved address */
unsigned char glob_l2_dest_addr2[] = { 0x91, 0xE0, 0xF0, 0x00, 0x0e, 0x80 };

void sigint_handler(int signum)
{
	printf("got SIGINT\n");
	*halt_tx_sig = signum;
}

static GOptionEntry entries[] =
{
  { "interface", 'i', 0, G_OPTION_ARG_STRING, &interface, "network interface", "NAME"},
  { "ethertype", 't', 0, G_OPTION_ARG_INT,    &ethertype, "ethernet protocol", "NUM"},
  { NULL }
};

void gensine32(int32_t * buf, unsigned count)
{
	long double interval = (2 * ((long double)M_PI)) / count;
	unsigned i;
	for (i = 0; i < count; ++i) {
		buf[i] =
		    (int32_t) (MAX_SAMPLE_VALUE * sinl(i * interval) * GAIN);
	}
}

int get_samples(unsigned count, int32_t * buffer)
{
	static int init = 0;
	static int32_t samples_onechannel[100];
	static unsigned index = 0;

	if (init == 0) {
		gensine32(samples_onechannel, 100);
		init = 1;
	}

	while (count > 0) {
		int i;
		for (i = 0; i < SRC_CHANNELS; ++i) {
			*(buffer++) = samples_onechannel[index];
		}
		index = (index + 1) % 100;
		--count;
	}

	return 0;
}

int main(int argc, char* argv[]){
  GError *error = NULL;
  GOptionContext *context;

	uint8_t *pBuf, *pData, *pHeader0_l2;
	uint32_t buflen, hdrlen;
	hdr_info_t hdr;
	seventeen22_header *l2_header0;
	six1883_header *l2_header1;
	six1883_sample *sample;
	int rc = 0;
	struct mrp_talker_ctx *ctx = malloc(sizeof(struct mrp_talker_ctx));
	gPtpTimeData td;
	uint16_t seqnum = 0;
	unsigned total_samples = 0;
	int32_t sample_buffer[L2_SAMPLES_PER_FRAME * SRC_CHANNELS];
	char *rawsock_mmap = NULL;
	int rawsock_shm_fd = -1;
	struct mrp_domain_attr *class_a = malloc(sizeof(struct mrp_domain_attr));
	struct mrp_domain_attr *class_b = malloc(sizeof(struct mrp_domain_attr));

	struct timespec now_local_timespec;
	uint64_t now_local, now_8021as;
	uint64_t update_8021as;
	unsigned delta_8021as, delta_local;
	uint8_t dest_addr[6];
	uint64_t time_stamp;
	u_int64_t last_time;
	int i;

  context = g_option_context_new("- rawsock listener");
  g_option_context_add_main_entries(context, entries, NULL);
  if (!g_option_context_parse(context, &argc, &argv, &error))
  {
          printf("error: %s\n", error->message);
          exit(1);
  }

  if(interface == NULL || ethertype < 0){
    printf("error: must specify network interface and ethertype\n");
    exit(2);
  }

	/**
	*Apertura del socket raw
	**/
	void *rs = openavbRawsockOpen(interface, 0, 1, ethertype, 0, MAX_NUM_FRAMES);
	if(!rs){
		printf("error: failed to open raw socket (are you root?)\n");
		exit(3);
	}


	/**
	*SRP
	**/

	//Inicialización
 	rc = mrp_talker_client_init(ctx);
  if (rc) {
    printf("MRP talker client initialization failed\n");
    return errno;
  }

  halt_tx_sig = &ctx->halt_tx;

	//Creación del thread que se queda a la espera de recepción de mensajes de control provenientes del demonio MRPD
  rc = mrp_connect(ctx);
	if (rc) {
		printf("socket creation failed\n");
		return errno;
	}

  signal(SIGINT, sigint_handler);

	memcpy( dest_addr, glob_l2_dest_addr2, sizeof(dest_addr));

	//Petición de la base de datos de registro de MSRP
	//En caso de no encontrar ningún dominio válido inicializa el dominio por defecto
	//En teoría el dominio debería registrarlo previamente un switch intermedio
  rc = mrp_get_domain(ctx,class_a,class_b);
  if (rc) {
		rc = mrp_initialize_domain(ctx,class_a,class_b);
		if(rc){
			return EXIT_FAILURE;
		}
	}
	else{
		printf("detected domain Class A PRIO=%d VID=%04x...\n",class_a->priority,
		       class_a->vid);
		printf("detected domain Class B PRIO=%d VID=%04x...\n",class_b->priority,
				 	  class_b->vid);
	}


	//Reporta el estado del dominio (Dominio por defecto de la clase a
  rc = mrp_register_domain(class_a, ctx);
	if (rc) {
		printf("mrp_register_domain failed\n");
		return EXIT_FAILURE;
	}

	/*rc = mrp_join_vlan(class_a, ctx);
	if (rc) {
		printf("mrp_join_vlan failed\n");
		return EXIT_FAILURE;
	}*/

	/**
	*SRP
	**/

	//Enable Qav// FQTSS
	//igb_set_class_bandwidth((&igb_dev, 125000/L2_PACKET_IPG, 0, PKT_SZ - 22, 0);


	/**
	*Definición de los campos de la cabecera de la trama ethernet + VLAN (DA, SA, TPID, PCP, CFI, VID)
	**/
	openavbGetSourceAddress(rs,glob_station_addr);

	memset(glob_stream_id, 0, sizeof(glob_stream_id));
	memcpy(glob_stream_id, glob_station_addr, sizeof(glob_station_addr));

	memset(&hdr, 0, sizeof(hdr_info_t));
	//PCP y VID en función de la clase
	hdr.vlan = 1;
	hdr.vlan_pcp = ((ctx->domain_class_a_priority << 13 | ctx->domain_class_a_vid)) >> 8;
	hdr.vlan_vid = ((ctx->domain_class_a_priority << 13 | ctx->domain_class_a_vid)) & 0xFF;
	openavbRawsockTxSetHdr(rs, &hdr);

  pBuf = (uint8_t*)openavbRawsockGetTxFrame(rs,1,&buflen);
  if(!pBuf){
    printf("failed to get TX frame buffer\n");
    exit(4);
  }

	//DA, SA y TPID definidos a la hora de inicializar el socket raw
  openavbRawsockTxFillHdr(rs, pBuf, &hdrlen);

	/**
	*Definición de los campos de la cabecera de la trama ethernet + VLAN (DA, SA, TPID, PCP, CFI, VID)
	**/

  pHeader0_l2 = pBuf + hdrlen;

	/**
	*Definición de los campos de la cabecera 1722 y 61883 (Según los estándares)
	**/
	l2_header0 = (seventeen22_header *)((char *)pHeader0_l2);
	l2_header0->cd_indicator = 0;
	l2_header0->subtype = 0;
	l2_header0->sid_valid = 1;
	l2_header0->version = 0;
	l2_header0->reset = 0;
	l2_header0->reserved0 = 0;
	l2_header0->gateway_valid = 0;
	l2_header0->reserved1 = 0;
	l2_header0->timestamp_uncertain = 0;
	memset(&(l2_header0->stream_id), 0, sizeof(l2_header0->stream_id));
	memcpy(&(l2_header0->stream_id), glob_station_addr,
			sizeof(glob_station_addr));
	l2_header0->length = htons(32);
	l2_header1 = (six1883_header *) (l2_header0 + 1);
	l2_header1->format_tag = 1;
	l2_header1->packet_channel = 0x1F;
	l2_header1->packet_tcode = 0xA;
	l2_header1->app_control = 0x0;
	l2_header1->reserved0 = 0;
	l2_header1->source_id = 0x3F;
	l2_header1->data_block_size = 1;
	l2_header1->fraction_number = 0;
	l2_header1->quadlet_padding_count = 0;
	l2_header1->source_packet_header = 0;
	l2_header1->reserved1 = 0;
	l2_header1->eoh = 0x2;
	l2_header1->format_id = 0x10;
	l2_header1->format_dependent_field = 0x02;
	l2_header1->syt = 0xFFFF;

	/**
	*Definición de los campos de la cabecera 1722 y 61883 (Según los estándares)
	**/

  hdrlen = hdrlen + sizeof(seventeen22_header) + sizeof(six1883_header);
	buflen = hdrlen + (L2_SAMPLES_PER_FRAME * CHANNELS * sizeof(six1883_sample));
	pData = pBuf + hdrlen;

	/**
	*SRP
	**/
	//NEW a stream-> se informa de un nuevo stream
	/*
 * subtract 16 bytes for the MAC header/Q-tag - pktsz is limited to the
 * data payload of the ethernet frame.
 *
 * IPG is scaled to the Class (A) observation interval of packets per 125 usec.
 */
	fprintf(stderr, "advertising stream ...\n");
	rc = mrp_advertise_stream(glob_stream_id, dest_addr,
							buflen - 16,
							L2_PACKET_IPG / 125000,
							3900,ctx);

	if (rc) {
		printf("mrp_advertise_stream failed\n");
		return EXIT_FAILURE;
	}

	//A la espera de que se conecte un nuevo receptor
	fprintf(stderr, "awaiting a listener ...\n");
	rc = mrp_await_listener(glob_stream_id, ctx);
	if (rc) {
		printf("mrp_await_listener failed\n");
		return EXIT_FAILURE;
	}

	ctx->listeners = 1;
	printf("got a listener ...\n");
	ctx->halt_tx = 0;

	/**
	*SRP
	**/

	/**
	*gPTP
	**/
	//Inicializar el acceso a la memoria compartida con la que nos comunicamos con el demonio gPTP
	if(-1 == gptpinit(&rawsock_shm_fd, &rawsock_mmap)) {
		fprintf(stderr, "GPTP init failed.\n");
		return EXIT_FAILURE;
	}

	//Realizar lectura del timestamp
	if (-1 == gptpscaling(rawsock_mmap, &td)) {
	fprintf(stderr, "GPTP scaling failed.\n");
	return EXIT_FAILURE;
}

	//Sustituida función de igb_get_wallclock( &igb_dev, &now_local, NULL )
	clock_gettime(CLOCK_REALTIME, &now_local_timespec);
	now_local = TIMESPEC_TO_NSEC(now_local_timespec);

	update_8021as = td.local_time - td.ml_phoffset;
	delta_local = (unsigned)(now_local - td.local_time);
	delta_8021as = (unsigned)(td.ml_freqoffset * delta_local);
	now_8021as = update_8021as + delta_8021as;

	last_time = now_local + XMIT_DELAY;
	time_stamp = now_8021as + RENDER_DELAY;

	/**
	*gPTP
	**/

	rc = nice(-20);


	struct timespec now;
	static uint64_t packetIntervalNSec = 0;
	static uint64_t nextCycleNSec = 0;
	static uint32_t packetCnt = 0;
	static uint64_t nextReportInterval = 0;

	packetIntervalNSec = NANOSECONDS_PER_SECOND / txRate;
	clock_gettime(CLOCK_MONOTONIC, &now);
	nextCycleNSec = TIMESPEC_TO_NSEC(now);
	nextReportInterval = TIMESPEC_TO_NSEC(now) + (NANOSECONDS_PER_SECOND * reportSec);
	//Bucle infinito mientras exista algún receptor
	while (ctx->listeners && !ctx->halt_tx) {

		uint32_t timestamp_l;
		//Función para calcular las muestras de un seno
		get_samples( L2_SAMPLES_PER_FRAME, sample_buffer );

		last_time += L2_PACKET_IPG;
		l2_header0->seq_number = seqnum++;

		if (seqnum % 4 == 0)
			l2_header0->timestamp_valid = 0;

		else
			l2_header0->timestamp_valid = 1;

		timestamp_l = time_stamp;
		l2_header0->timestamp = htonl(timestamp_l);
		time_stamp += L2_PACKET_IPG;
		l2_header1->data_block_continuity = total_samples;
		total_samples += L2_SAMPLES_PER_FRAME*CHANNELS;

		sample = (six1883_sample*) pData;

		for (i = 0; i < L2_SAMPLES_PER_FRAME * CHANNELS; ++i) {
			uint32_t tmp = htonl(sample_buffer[i]);
			sample[i].label = 0x40;
			memcpy(&(sample[i].value), &(tmp),
				   sizeof(sample[i].value));
		}

		//Transmición del frame mediante el rawsocket
		openavbRawsockTxFrameReady(rs, pBuf, buflen, 0);

		packetCnt++;

		nextCycleNSec += packetIntervalNSec;
		clock_gettime(CLOCK_MONOTONIC, &now);
		uint64_t nowNSec = TIMESPEC_TO_NSEC(now);;

		if (nowNSec > nextReportInterval) {
			printf("TX Packets: %d\n", packetCnt);
			packetCnt = 0;
			nextReportInterval = nowNSec + (NANOSECONDS_PER_SECOND * reportSec);
		}

		if (nowNSec < nextCycleNSec) {
			usleep((nextCycleNSec - nowNSec) / 1000);
		}
	}

	rc = nice(0);
	if (ctx->halt_tx == 0)
		printf("listener left ...\n");
	ctx->halt_tx = 1;
	rc = mrp_unadvertise_stream
			(glob_stream_id, dest_addr, PKT_SZ - 16, L2_PACKET_IPG / 125000,
			 3900, ctx);
	if (rc)
		 printf("mrp_unadvertise_stream failed\n");

	//disable Qav// FQTSS
	//igb_set_class_bandwidth(&igb_dev, 0, 0, 0, 0);

	rc = mrp_disconnect(ctx);
	if (rc)
		printf("mrp_disconnect failed\n");

	free(ctx);
	free(class_a);
	free(class_b);

	rc = gptpdeinit(&rawsock_shm_fd, &rawsock_mmap);

	pthread_exit(NULL);

  openavbRawsockClose(rs);

  return 0;
}
