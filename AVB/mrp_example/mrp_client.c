#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "../mrpd/talker_mrp_client.h"

int main(int argc, char* argv[]){

	int rc = 0;
  struct mrp_talker_ctx *ctx = malloc(sizeof(struct mrp_talker_ctx));
  struct mrp_domain_attr *class_a = malloc(sizeof(struct mrp_domain_attr));
	struct mrp_domain_attr *class_b = malloc(sizeof(struct mrp_domain_attr));

  rc = mrp_talker_client_init(ctx);
  if (rc) {
    printf("MRP talker client initialization failed\n");
    return errno;
  }

  rc = mrp_connect(ctx);
	if (rc) {
		printf("socket creation failed\n");
		return errno;
	}

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

  rc = mrp_register_domain(class_a, ctx);
  if (rc) {
    printf("mrp_register_domain failed\n");
    return EXIT_FAILURE;
  }

  return 0;
}
