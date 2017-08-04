objects_tx = ./obj/openavb_rawsock.o ./obj/simple_rawsock.o\
 ./obj/rawsock_impl.o ./obj/avb.o ./obj/talker_mrp_client.o

objects_rx = ./obj/openavb_rawsock.o ./obj/simple_rawsock.o\
 ./obj/rawsock_impl.o ./obj/avb.o ./obj/listener_mrp_client.o


flags = -Wall -lsndfile -lpcap `pkg-config --cflags --libs glib-2.0`

all: rawsock_tx rawsock_rx mrp_client

rawsock_rx: $(objects_rx)
	gcc ../tx_rx_example/rawsock_rx.c $(flags) $(objects_rx) -o ./obj/rawsock_rx -lpthread -lm -lrt

rawsock_tx: $(objects_tx)
	gcc ../tx_rx_example/rawsock_tx.c $(flags) $(objects_tx) -o ./obj/rawsock_tx -lpthread -lm -lrt

mrp_client:
	gcc ../mrp_example/mrp_client.c ./obj/talker_mrp_client.o -o ./obj/mrp_client -lpthread

./obj/openavb_rawsock.o:
	gcc -Wall -c ../rawsock/openavb_rawsock.c -o ./obj/openavb_rawsock.o

./obj/simple_rawsock.o:
	gcc -Wall -c ../rawsock/simple_rawsock.c -o ./obj/simple_rawsock.o

./obj/rawsock_impl.o:
	gcc -Wall -c ../rawsock/rawsock_impl.c -o ./obj/rawsock_impl.o

./obj/avb.o:
	gcc -Wall -c ../common/avb.c -o ./obj/avb.o

./obj/talker_mrp_client.o:
	gcc -Wall -c ../mrpd/talker_mrp_client.c -o ./obj/talker_mrp_client.o

./obj/listener_mrp_client.o:
	gcc -Wall -c ../mrpd/listener_mrp_client.c -o ./obj/listener_mrp_client.o

clean:
	rm ./obj/*.o ./obj/rawsock_tx ./obj/rawsock_rx

.PHONY : clean
