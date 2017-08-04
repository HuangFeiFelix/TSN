#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <glib.h>
#include <netinet/ether.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <pcap/pcap.h>
#include <sndfile.h>

#include "../rawsock/openavb_rawsock.h"
#include "../mrpd/listener_mrp_client.h"

// Common usage with VTAG 0x8100:				./rawsock_rx -i eth0 -t 33024 -d 1 -s 1
// Common usage without VTAG 0x22F0:			./rawsock_rx -i eth0 -t 8944 -d 1 -s 1

#define NANOSECONDS_PER_SECOND    (1000000000ULL)
#define MAX_NUM_FRAMES 10
#define TIMESPEC_TO_NSEC(ts) (((uint64_t)ts.tv_sec * (uint64_t)NANOSECONDS_PER_SECOND) + (uint64_t)ts.tv_nsec)

#define CHANNELS (1)

#define ETHERNET_HEADER_SIZE (18)
#define SEVENTEEN22_HEADER_PART1_SIZE (4)
#define STREAM_ID_SIZE (8)
#define SEVENTEEN22_HEADER_PART2_SIZE (10)
#define SIX1883_HEADER_SIZE (10)
#define HEADER_SIZE (ETHERNET_HEADER_SIZE		\
			+ SEVENTEEN22_HEADER_PART1_SIZE \
			+ STREAM_ID_SIZE		\
			+ SEVENTEEN22_HEADER_PART2_SIZE \
			+ SIX1883_HEADER_SIZE)
#define SAMPLES_PER_SECOND (48000)
#define SAMPLES_PER_FRAME (6)

struct ethernet_header{
	u_char dst[6];
	u_char src[6];
	u_char stuff[4];
	u_char type[2];
};

//static int bRunning = TRUE;

struct mrp_listener_ctx *ctx_sig;

pcap_t* glob_pcap_handle;
u_char glob_ether_type[] = { 0x22, 0xf0 };
SNDFILE* glob_snd_file;

static char* interface = NULL;
static int ethertype = -1;
static char* macaddr_s = NULL;
static int dumpFlag = 0;
static int reportSec = 1;

struct timespec now;
static uint32_t packetCnt = 0;
static uint64_t nextReportInterval = 0;

static GOptionEntry entries[] =
{
  { "interface", 'i', 0, G_OPTION_ARG_STRING, &interface, "network interface",               "NAME" },
  { "ethertype", 't', 0, G_OPTION_ARG_INT,    &ethertype, "ethernet protocol",               "NUM" },
  { "mac",       'a', 0, G_OPTION_ARG_STRING, &macaddr_s, "MAC address",                     "MAC" },
  { "dump",      'd', 0, G_OPTION_ARG_INT,    &dumpFlag,  "Dump packets (1=yes, 0=no)",      "DUMP" },
  { "rptsec",    's', 0, G_OPTION_ARG_INT,    &reportSec, "report interval in seconds",      "RPTSEC" },
  { NULL }
};

void pcap_callback(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet)
{
	unsigned char* test_stream_id;
	struct ethernet_header* eth_header;
	uint32_t *buf;
	uint32_t frame[2] = { 0 , 0 };
	int i;
	struct mrp_listener_ctx *ctx = (struct mrp_listener_ctx*) args;
	(void) packet_header; /* unused */

	clock_gettime(CLOCK_MONOTONIC, &now);
	uint64_t nowNSec = TIMESPEC_TO_NSEC(now);;

	if (reportSec > 0) {
			if (nowNSec > nextReportInterval) {
				printf("RX Packets: %d\n", packetCnt);
				packetCnt = 0;
				nextReportInterval = nowNSec + (NANOSECONDS_PER_SECOND * reportSec);
			}
		}

#if DEBUG
	fprintf(stdout,"Got packet.\n");
#endif /* DEBUG*/

	eth_header = (struct ethernet_header*)(packet);

#if DEBUG
	fprintf(stdout,"Ether Type: 0x%02x%02x\n", eth_header->type[0], eth_header->type[1]);
#endif /* DEBUG*/

	if (0 == memcmp(glob_ether_type,eth_header->type,sizeof(eth_header->type)))
	{
		test_stream_id = (unsigned char*)(packet + ETHERNET_HEADER_SIZE + SEVENTEEN22_HEADER_PART1_SIZE);

#if DEBUG
		fprintf(stderr, "Received stream id: %02x%02x%02x%02x%02x%02x%02x%02x\n ",
			     test_stream_id[0], test_stream_id[1],
			     test_stream_id[2], test_stream_id[3],
			     test_stream_id[4], test_stream_id[5],
			     test_stream_id[6], test_stream_id[7]);
#endif /* DEBUG*/

		if (0 == memcmp(test_stream_id, ctx->stream_id, sizeof(STREAM_ID_SIZE)))
		{

#if DEBUG
			fprintf(stdout,"Stream ids matched.\n");
#endif /* DEBUG*/
			buf = (uint32_t*) (packet + HEADER_SIZE);
			for(i = 0; i < SAMPLES_PER_FRAME * CHANNELS; i += 2)
			{
				memcpy(&frame[0], &buf[i], sizeof(frame));

				frame[0] = ntohl(frame[0]);   /* convert to host-byte order */
				frame[1] = ntohl(frame[1]);
				frame[0] &= 0x00ffffff;       /* ignore leading label */
				frame[1] &= 0x00ffffff;
				frame[0] <<= 8;               /* left-align remaining PCM-24 sample */
				frame[1] <<= 8;
				
				sf_writef_int(glob_snd_file, (const int *)frame, 1);
			}
		}
	}
}

void sigint_handler(int signum)
{
	int ret;

	fprintf(stdout,"Received signal %d:leaving...\n", signum);

	if (0 != ctx_sig->talker) {
		ret = send_leave(ctx_sig);
		if (ret)
			printf("send_leave failed\n");
	}

	if (2 > ctx_sig->control_socket)
	{
		close(ctx_sig->control_socket);
		ret = mrp_disconnect(ctx_sig);
		if (ret)
			printf("mrp_disconnect failed\n");
	}

//#if PCAP
	if (NULL != glob_pcap_handle)
	{
		pcap_breakloop(glob_pcap_handle);
		pcap_close(glob_pcap_handle);
	}
//#endif /* PCAP */

//#if LIBSND
	sf_write_sync(glob_snd_file);
	sf_close(glob_snd_file);
//#endif /* LIBSND */
}

int main(int argc, char* argv[])
{
  char file_name[] = "received.wav";
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program comp_filter_exp;
  char filter_exp[100];
	GError *error = NULL;
	GOptionContext *context;


	context = g_option_context_new("- rawsock listenr");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error))
	{
		printf("error: %s\n", error->message);
		exit(1);
	}

	if (interface == NULL || ethertype == -1) {
		printf("error: must specify network interface and ethertype\n");
		exit(2);
	}

  int rc;
  struct mrp_listener_ctx *ctx = malloc(sizeof(struct mrp_listener_ctx));
  struct mrp_domain_attr *class_a = malloc(sizeof(struct mrp_domain_attr));
  struct mrp_domain_attr *class_b = malloc(sizeof(struct mrp_domain_attr));
  ctx_sig = ctx;
  signal(SIGINT, sigint_handler);

	/**
	*SRP
	**/
	//Inicialización
  rc = mrp_listener_client_init(ctx);
	if (rc)
	{
		printf("failed to initialize global variables\n");
		return EXIT_FAILURE;
	}
	//Creación del socket de control para comunicarse con el demonio MRPD
  if (create_socket(ctx))
  {
    fprintf(stderr, "Socket creation failed.\n");
    return errno;
  }

	//Creación del thread que se queda a la espera de la recepción de mensajes provenientes del demonio MRPD
  rc = mrp_monitor(ctx);
  if (rc)
  {
    printf("failed creating MRP monitor thread\n");
    return EXIT_FAILURE;
  }

	//Petición de la base de datos de registro de MSRP
	//En caso de no encontrar ningún dominio válido inicializa el dominio por defecto
	//En teoría el dominio debería registrarlo previamente un switch intermedio
  rc=mrp_get_domain(ctx, class_a, class_b);
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

	//Reporta el estado del dominio (Dominio por defecto de la clase a)
	rc = report_domain_status(class_a,ctx);
	if (rc) {
		printf("report_domain_status failed\n");
		return EXIT_FAILURE;
	}

  /*rc = join_vlan(class_a, ctx);
	if (rc) {
		printf("join_vlan failed\n");
		return EXIT_FAILURE;
	}*/

	//A la espera de nuevos emisores
	fprintf(stdout,"Waiting for talker...\n");
	await_talker(ctx);

	//Report a listener status
  rc = send_ready(ctx);
	if (rc) {
		printf("send_ready failed\n");
		return EXIT_FAILURE;
	}

	/**
	*SRP
	**/

  SF_INFO* sf_info = (SF_INFO*)malloc(sizeof(SF_INFO));
	memset(sf_info, 0, sizeof(SF_INFO));

	sf_info->samplerate = SAMPLES_PER_SECOND;
	sf_info->channels = CHANNELS;
	sf_info->format = SF_FORMAT_WAV | SF_FORMAT_PCM_24;

	if (0 == sf_format_check(sf_info))
	{
		fprintf(stderr, "Wrong format.");
		return EXIT_FAILURE;
	}

	if (NULL == (glob_snd_file = sf_open(file_name, SFM_WRITE, sf_info)))
	{
		fprintf(stderr, "Could not create file.");
		return EXIT_FAILURE;
	}
	fprintf(stdout,"Created file called %s\n", file_name);

  /** session, get session handler */
	/* take promiscuous vs. non-promiscuous sniffing? (0 or 1) */
	glob_pcap_handle = pcap_open_live(interface, BUFSIZ, 1, -1, errbuf);
	if (NULL == glob_pcap_handle)
	{
		fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
		return EXIT_FAILURE;
	}
	/* compile and apply filter */
	sprintf(filter_exp,"ether dst %02x:%02x:%02x:%02x:%02x:%02x",ctx->dst_mac[0],ctx->dst_mac[1],ctx->dst_mac[2],ctx->dst_mac[3],ctx->dst_mac[4],ctx->dst_mac[5]);
	if (-1 == pcap_compile(glob_pcap_handle, &comp_filter_exp, filter_exp, 0, PCAP_NETMASK_UNKNOWN))
	{
		fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(glob_pcap_handle));
		return EXIT_FAILURE;
	}

	if (-1 == pcap_setfilter(glob_pcap_handle, &comp_filter_exp))
	{
		fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(glob_pcap_handle));
		return EXIT_FAILURE;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);
	nextReportInterval = TIMESPEC_TO_NSEC(now) + (NANOSECONDS_PER_SECOND * reportSec);

	/** loop forever and call callback-function for every received packet */
	pcap_loop(glob_pcap_handle, -1, pcap_callback, (u_char*)ctx);

  free(ctx);
  free(class_a);
  free(class_b);

  return 0;
}
