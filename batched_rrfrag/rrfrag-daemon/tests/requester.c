#include <question.h>
#include <dns_message.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//char *ipaddr = "127.0.0.1";
char *ipaddr = "10.10.0.3"; // TODO
char *port = "53";

int
get_socket(struct addrinfo **addr) {
	struct addrinfo hints, *res;
	int fd;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	getaddrinfo(ipaddr, port, &hints, &res);

	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	int size = 2 * 1024 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, (socklen_t)sizeof(int));
	if (connect(fd, res->ai_addr, res->ai_addrlen) == -1) {
		return -1;
	}
	*addr = res;
	return fd;
}


int
main(int argc, char **argv) {
	// Make a query for our specifically large RR
	printf("Starting...\n");
	sleep(10);
	Question *q;
	create_question(&q, "www.google.com.", 1, 2);
	// TODO create OPT record to enable EDNS(0) and set udp size to make sense
	uint16_t flags = 0; // QUERY bit set
	DNSMessage *msg;
	create_dnsmessage(&msg, 4321, flags, 1, 0, 0, 0, &q, NULL, NULL, NULL);
	size_t byte_len = 0;
	unsigned char *msg_bytes = NULL;
	dnsmessage_to_bytes(msg, &msg_bytes, &byte_len);
	DNSMessage *respon_msg;
	// Send it
	struct addrinfo *addr;
	int fd = get_socket(&addr);
	if (fd == -1) {
		printf("Failed to get socket for some reason...\n");
		return -1;
	}
	printf("byte_len: %lu\n", byte_len);
	printf("Sending...");
	fflush(stdout);
	if (send(fd, msg_bytes, byte_len, 0) <= 0) {
		printf("Failed to send.\n");
		return -1;
	}
	printf("Done\n");
	fflush(stdout);
	// Wait for response
	printf("Waiting...");
	fflush(stdout);
	size_t buffsize = 2 * 1024 * 1024;
	unsigned char recv_bytes[buffsize]; // Just make sure it's big enough...
	ssize_t recv_bytes_len = recv(fd, recv_bytes, buffsize, 0);
	if (recv_bytes_len == -1) {
		close(fd);
		perror("recv");
		return -1;
	}
	close(fd);
	printf("Done\n");
	fflush(stdout);
	if (recv_bytes_len < 0) {
		printf("Failed to receive something\n");
		return -1;
	} else if (recv_bytes_len == 0) {
		printf("Connection closed.\n");
		return -1;
	}
	printf("bytes_recvd: %lu\n", recv_bytes_len);
	fflush(stdout);
	bytes_to_dnsmessage(recv_bytes, recv_bytes_len, &respon_msg);
	// Sanity check that the response is what it should be
	ResourceRecord *rr;
	unsigned char rdata[2048];
	for (int i = 0; i < 2048; i++) {
		rdata[i] = i;
	}
	create_rr(&rr, "www.google.com.", 2, 1, 1234, 2048, rdata);
	PackedRR **answers = malloc(sizeof(PackedRR *) * 1);
	create_packedrr(rr, answers);
	DNSMessage *testmsg;
	create_dnsmessage(&testmsg, 4321, 1 << 15, 0, 1, 0, 0, NULL, answers, NULL, NULL);
	if (dnsmessage_is_equal(testmsg, respon_msg)) {
		printf("Dns message received and is equal\n");
		return 0;
	} else {
		printf("dnsmessage comparison failed\n");
		fflush(stdout);
		printf("recv_bytes_len: %lu\n", recv_bytes_len);
		/*
		size_t test_len;
		unsigned char *test_bytes;
		dnsmessage_to_bytes(testmsg, &test_bytes, &test_len);
		for (uint16_t i = 0; i < recv_bytes_len; i++) {
			if (test_bytes[i] != recv_bytes[i]) {
				printf("Bytes didn't match at position: %hu, t: %x, r: %x\n", i, test_bytes[i], recv_bytes[i]);
			} else {
				printf("Iteration: %hu\n", i);
			}
			fflush(stdout);
		}
		*/
		return -1;
	}
}
