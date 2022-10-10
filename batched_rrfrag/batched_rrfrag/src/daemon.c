#include <linux/module.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <poll.h>
#include <math.h>
#include <dns_message.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <assert.h>
#include <map.h>

#define RRFRAGHEADER 15 // 14 for the fields, + 1 for the name
#define RRHEADER 10
#define DNSMESSAGEHEADER DNSHEADERSIZE
uint32_t MAXUDP = 1232;
uint32_t our_addr;
uint32_t is_resolver = false;

int rrfs_copied = 0;
bool BYPASS = false;

char *
itoa(uint16_t in) {
	char *res = NULL;
	int num_bytes = snprintf(NULL, 0, "%hu", in) + 1;
	res = malloc(sizeof(char) * num_bytes);
	snprintf(res, num_bytes , "%hu", in);
	return res;
}

void
ERROR(void) {
	assert(false);
}


// TODO it would be nice to have a nice way to "guess" a string of bytes
// is likely a dns message. I guess the simplest way would be to make sure
// the length of the byte string is at least
// min(header_size) + qd_count * min(rr_size) + an_count * min(rr_size) + nscount * min(rr_size) + ar_count * min(rr_size)


#define BLOCKSIZE 32

#define BLOCKRECVD 0
#define BLOCKFREE -1
#define BLOCKWAITING 1

typedef struct PartialRR {
	unsigned char *bytes;
	size_t rrsize;
	size_t bytes_received;
	bool is_complete;
	uint16_t rrid; // 0 will represent an uninitalized PartialRR. There must be no rr's with rrid 0
	size_t blocks_received;
	size_t expected_blocks;
	int8_t *block_markers; // -1 == not requested, 0 == received, 1 == requested but not received
} PartialRR;

int
init_partialrr(PartialRR **prr) {
	assert(*prr == NULL);
	PartialRR *_prr = malloc(sizeof(PartialRR));
	if (_prr == NULL) {
		return -1;
	}
	_prr->bytes = NULL;
	_prr->rrsize = 0;
	_prr->bytes_received = 0;
	_prr->is_complete = false;
	_prr->rrid = 0;
	_prr->blocks_received = 0;
	_prr->expected_blocks = 0;
	_prr->block_markers = NULL;
	*prr = _prr;
	return 0;
}

typedef struct PartialDNSMessage {
	sem_t lock;
	uint16_t identification;
	bool identification_set;
	uint16_t flags;
	bool flags_set;
	uint16_t qdcount;
	bool qdcount_set;
	uint16_t ancount;
	bool ancount_set;
	uint16_t nscount;
	bool nscount_set;
	uint16_t arcount;
	bool arcount_set;
	Question **question_section;
	uint16_t questions_done;
	PartialRR **answers_section;
	uint16_t answers_done;
	PartialRR **authoritative_section;
	uint16_t authoritative_done;
	PartialRR **additional_section;
	uint16_t additionals_done;
} PartialDNSMessage;

bool
init_partialdnsmessage(PartialDNSMessage **msg) {
	PartialDNSMessage *m = *msg;
	if (m == NULL) {
		m = malloc(sizeof(PartialDNSMessage));
	}
	sem_init(&(m->lock), 0, 1);
	m->identification_set = false;
	m->flags_set = false;
	m->qdcount_set = false;
	m->ancount_set = false;
	m->nscount_set = false;
	m->arcount_set = false;
	m->questions_done = false;
	m->answers_done = false;
	m->authoritative_done = false;
	m->additionals_done = false;
	m->question_section = NULL;
	m->answers_section = NULL;
	m->authoritative_section = NULL;
	m->additional_section = NULL;
	m->qdcount = 0;
	m->ancount = 0;
	m->nscount = 0;
	m->arcount = 0;
	*msg = m;
	return true;
}

bool
section_is_done(PartialRR **section, uint16_t section_count) {
	bool res = true;
	for (uint16_t i = 0; i < section_count; i++) {
		res = res && (section[i]->blocks_received == section[i]->expected_blocks);
	}
	return res;
}

PartialRR *
find_partialrr(PartialDNSMessage *pm, uint16_t rrid, uint8_t *section) {
	if (pm == NULL) {
		return NULL;
	}
	for (uint16_t i = 0; i < pm->ancount; i++) {
		if (pm->answers_section[i]->rrid == rrid) {
			*section = 0;
			return pm->answers_section[i];
		}
	}
	for (uint16_t i = 0; i < pm->nscount; i++) {
		if (pm->authoritative_section[i]->rrid == rrid) {
			*section = 1;
			return pm->authoritative_section[i];
		}
	}
	for (uint16_t i = 0; i < pm->arcount; i++) {
		if (pm->additional_section[i]->rrid == rrid) {
			*section = 2;
			return pm->additional_section[i];
		}
	}
	return NULL;
}

void
copy_section(PartialDNSMessage *pm, PackedRR **msgsection, uint16_t sec_len, uint8_t section) {
	for (uint16_t i = 0; i < sec_len; i++) {
		//printf("i:%d\n", i);
		//fflush(stdout);
		if (msgsection[i]->isRRFrag) {
			RRFrag *rrfrag = msgsection[i]->data.rrfrag;
			uint16_t rrid = rrfrag->rrid;
			uint32_t curidx = rrfrag->curidx;
			uint16_t fragsize = rrfrag->fragsize;
			uint8_t section;
			// Find the associated record somewhere in the partialDNSMessage
			PartialRR *prr = find_partialrr(pm, rrid, &section);
			if (prr->rrid == 0) {
				prr->rrid = rrid;
			}
			// Sanity check that we aren't overwriting anything we shouldn't.
			uint16_t blockidx = curidx / (double)BLOCKSIZE;
			uint16_t lastblockidx = blockidx + ceil(fragsize / (double)BLOCKSIZE);
			uint16_t totalblocks = ceil(rrfrag->rrsize / (double)BLOCKSIZE);
			if (prr->block_markers == NULL) {
				prr->block_markers = malloc(sizeof(int8_t) * totalblocks);
				for (uint16_t j = 0; j < totalblocks; j++) {
					prr->block_markers[j] = BLOCKFREE;
				}
				prr->expected_blocks = totalblocks;
			}
			if (prr->bytes == NULL) {
				prr->bytes = malloc(sizeof(unsigned char) * rrfrag->rrsize);
				if (prr->bytes == NULL) {
					printf("Error allocating bytes in prr\n");
					fflush(stdout);
					exit(-1);
				}
				prr->rrsize = rrfrag->rrsize;
			}
			for (uint16_t j = blockidx; j < lastblockidx; j++) {
				if (prr->block_markers[j] == BLOCKRECVD) {
					printf("block wasn't waiting for data\n");
					ERROR();
				}
			}
			memcpy(prr->bytes + rrfrag->curidx, rrfrag->fragdata, rrfrag->fragsize);
			for (uint16_t j = blockidx; j < lastblockidx; j++) {
				prr->block_markers[j] = BLOCKRECVD;
			}
			prr->blocks_received += lastblockidx - blockidx;
			prr->bytes_received += rrfrag->fragsize;
			if (prr->expected_blocks == prr->blocks_received) {
				prr->is_complete = true;
				for (uint16_t j = 0; j < prr->expected_blocks; j++) {
					assert(prr->block_markers[j] == BLOCKRECVD);
				}
				if (section == 0) {
					// answer section
					pm->answers_done++;
				} else if (section == 1) {
					// authoritative section
					pm->authoritative_done++;
				} else if (section == 2) {
					// additional section
					pm->additionals_done++;
				} else {
					ERROR();
				}
			}
		} else {
			ResourceRecord *rr = msgsection[i]->data.rr;
			size_t outlen;
			unsigned char *out;
			rr_to_bytes(rr, &out, &outlen);
			PartialRR **prrs;
			uint16_t prrs_len;
			uint16_t *rrs_done;
			if (section == 0) {
				// answer section
				prrs = pm->answers_section;
				prrs_len = pm->ancount;
				rrs_done = &(pm->answers_done);
			} else if (section == 1) {
				// authoritative section
				prrs = pm->authoritative_section;
				prrs_len = pm->nscount;
				rrs_done = &(pm->authoritative_done);
			} else if (section == 2) {
				// additional section
				prrs = pm->additional_section;
				prrs_len = pm->arcount;
				rrs_done = &(pm->additionals_done);
			} else {
				ERROR();
			}
			for (uint16_t j = 0; j < prrs_len; j++) {
				if (!prrs[j]->is_complete && prrs[j]->rrid == 0) {
					prrs[j]->bytes = malloc(outlen);
					prrs[j]->bytes_received = outlen;
					prrs[j]->rrsize = outlen;
					memcpy(prrs[j]->bytes, out, outlen);
					free(out);
					prrs[j]->is_complete = true;
					(*rrs_done)++;
					break;
				}
			}
		}
	}	
}


/*
void
copy_section(PartialRR **section, size_t section_len, uint16_t *records_done, PackedRR **mSection, size_t m_len) {
	assert(section_len >= m_len);
	for (uint16_t i = 0; i < m_len; i++) {
		// if we get a non-rrfrag, just copy the whole thing
		// otherwise copy the associated blocks
		if (mSection[i]->isRRFrag) {
			RRFrag *rrfrag = mSection[i]->data.rrfrag;
			uint64_t rrid = rrfrag->rrid;
			uint16_t curidx = rrfrag->curidx;
			assert(curidx % BLOCKSIZE == 0);
			//assert(rrfrag->fragsize <= BLOCKSIZE);
			uint16_t j = 0;
			// TODO, fix this crap so that it looks for rrid first, then other
			// open spots if it can't find it
			while (j < section_len && rrid != section[j]->rrid) {
				j++;
			}
			if (rrid != section[j]->rrid) {
				j = 0;
				while (section[j]->is_complete
						|| (!section[j]->is_complete 
							&& (section[j]->rrid != 0))) {
					j++;
				}
			}
			assert(j < section_len);
			if (section[j]->rrid == 0) {
				section[j]->rrsize = mSection[i]->data.rrfrag->rrsize;
				section[j]->expected_blocks = ceil(section[j]->rrsize / (double) BLOCKSIZE);
				section[j]->rrid = rrid;
				section[j]->block_markers = malloc(sizeof(int32_t) * section[j]->expected_blocks);
				section[j]->bytes = malloc(sizeof(unsigned char) * section[j]->rrsize);
				for (int k = 0; k < section[j]->expected_blocks; k++) {
					section[j]->block_markers[k] = BLOCKFREE;
				}

			}
			for (int k = 0; k < ceil(rrfrag->fragsize / (double) BLOCKSIZE); k++) {
				if (section[j]->block_markers[(curidx / BLOCKSIZE) + k]
						== BLOCKRECVD) {
					assert("error, tried overwriting a block we've already received" == false);	
				}
				section[j]->block_markers[(curidx / BLOCKSIZE) + k] = BLOCKRECVD;
			}
			memcpy(section[j]->bytes + curidx, rrfrag->fragdata, rrfrag->fragsize);
			section[j]->recvd_blocks += ceil((float)rrfrag->fragsize / BLOCKSIZE);
			if (section[j]->recvd_blocks == section[j]->expected_blocks) {
				(*records_done)++;
				section[j]->is_complete = true;
			}
		} else {
			ResourceRecord *rr = mSection[i]->data.rr;
			size_t outlen;
			unsigned char *out;
			rr_to_bytes(rr, &out, &outlen);
			for (uint16_t j = 0; j < section_len; j++) {
				if (!section[j]->is_complete && section[j]->rrid == 0) {
					section[j]->bytes = malloc(outlen);
					section[j]->bytes_len = outlen;
					memcpy(section[j]->bytes, out, outlen);
					free(out);
					(*records_done)++;
					section[j]->is_complete = true;
					break;
				}
			}
		}
	}

}
*/

void
copy_message_contents(PartialDNSMessage *data, DNSMessage *msg) {
	//printf("pre wait\n");
	//fflush(stdout);
	sem_wait(&(data->lock));
	//printf("post wait\n");
	//fflush(stdout);
	if (!data->identification_set) {
		data->identification = msg->identification;
		data->identification_set = true;
	}
	if (!data->flags_set) {
		data->flags = msg->flags;
		data->flags_set = true;
	}
	if (!data->qdcount_set) {
		data->qdcount = msg->qdcount;
		data->qdcount_set = true;
	}
	if (!data->ancount_set) {
		data->ancount = msg->ancount;
		data->ancount_set = true;
	}
	if (!data->nscount_set) {
		data->nscount = msg->nscount;
		data->nscount_set = true;
	}
	if (!data->arcount_set) {
		data->arcount = msg->arcount;
		data->arcount_set = true;
	}
	if (data->question_section == NULL && msg->qdcount != 0) {
		data->question_section = malloc(sizeof(Question *) * data->qdcount);
		for (uint16_t i = 0; i < msg->qdcount; i++) {
			data->question_section[i] = NULL;
			assert(msg->question_section[i]->qtype != RRFRAG);
			clone_question(msg->question_section[i], data->question_section + i);
			//init_partialrr(data->answers_section + i);

			//if (msg->answers_section[i]->isRRFrag) {
			//	data->answers_section[i]->rrid = msg->answers_section[i]->data.rrfrag->rrid;
			//}
		}
	}
	if (data->answers_section == NULL && msg->ancount != 0) {
		data->answers_section = malloc(sizeof(PartialRR *) * data->ancount);
		for (uint16_t i = 0; i < msg->ancount; i++) {
			data->answers_section[i] = NULL;
			init_partialrr(data->answers_section + i);
			if (msg->answers_section[i]->isRRFrag) {
				data->answers_section[i]->rrid = msg->answers_section[i]->data.rrfrag->rrid;
			}
		}
	}
	if (data->authoritative_section == NULL && msg->nscount != 0) {
		data->authoritative_section = malloc(sizeof(PartialRR *) * data->nscount);
		for (uint16_t i = 0; i < data->nscount; i++) {
			data->authoritative_section[i] = NULL;
			init_partialrr(data->authoritative_section + i);
			if (msg->authoritative_section[i]->isRRFrag) {
				data->authoritative_section[i]->rrid = msg->authoritative_section[i]->data.rrfrag->rrid;
			}
		}
	}
	if (data->additional_section == NULL && msg->arcount != 0) {
		data->additional_section = malloc(sizeof(PartialRR *) * data->arcount);
		for (uint16_t i = 0; i < data->arcount; i++) {
			data->additional_section[i] = NULL;
			init_partialrr(data->additional_section + i);
			if (msg->additional_section[i]->isRRFrag) {
				data->additional_section[i]->rrid = msg->additional_section[i]->data.rrfrag->rrid;
			}
		}
	}
	//printf("pre copy_section\n");
	//fflush(stdout);
	copy_section(data, msg->answers_section, msg->ancount, 0);
	//printf("1\n");
	//fflush(stdout);
	copy_section(data, msg->authoritative_section, msg->nscount, 1);
	//printf("2\n");
	//fflush(stdout);
	copy_section(data, msg->additional_section, msg->arcount, 2);
	//printf("3\n");
	//fflush(stdout);
	sem_post(&(data->lock));
}

bool
message_complete(PartialDNSMessage *msg) {
	sem_wait(&(msg->lock));
	bool res = ((msg->ancount == msg->answers_done && msg->ancount_set)
			&& (msg->nscount == msg->authoritative_done && msg->nscount_set)
			&& (msg->arcount == msg->additionals_done && msg->arcount_set));
	sem_post(&(msg->lock));
	return res;
}

bool
message_complete_soon(PartialDNSMessage *msg) {
	sem_wait(&(msg->lock));
	bool res = true;
	if (!(msg->ancount_set && msg->nscount_set &&msg->arcount_set)) {
		return false;
	}
	for (int i = 0; i < msg->ancount; i++) {
		PartialRR *prr = msg->answers_section[i];
		if (prr->is_complete) continue;
		if (prr->rrid == 0) {
			sem_post(&(msg->lock));
			return false;
		}
		for (int j = 0; j < prr->expected_blocks; j++) {
			res = (res && ((prr->block_markers[j] == BLOCKWAITING)
				   || (prr->block_markers[j] == BLOCKRECVD)));
			if (!res) {
				sem_post(&(msg->lock));
				return res;
			}
		}
	}
	for (int i = 0; i < msg->nscount; i++) {
		PartialRR *prr = msg->authoritative_section[i];
		if (prr->is_complete) continue;
		if (prr->rrid == 0) {
			sem_post(&(msg->lock));
			return false;
		}
		for (int j = 0; j < prr->expected_blocks; j++) {
			res = (res && ((prr->block_markers[j] == BLOCKWAITING)
				   || (prr->block_markers[j] == BLOCKRECVD)));
			if (!res) {
				sem_post(&(msg->lock));
				return res;
			}
		}
	}
	for (int i = 0; i < msg->arcount; i++) {
		PartialRR *prr = msg->additional_section[i];
		if (prr->is_complete) continue;
		if (prr->rrid == 0) {
			sem_post(&(msg->lock));
			return false;
		}
		for (int j = 0; j < prr->expected_blocks; j++) {
			res = (res && ((prr->block_markers[j] == BLOCKWAITING)
				   || (prr->block_markers[j] == BLOCKRECVD)));
			if (!res) {
				sem_post(&(msg->lock));
				return false;
			}
		}
	}
	sem_post(&(msg->lock));
	return res;
}

uint16_t
frags_requested(PartialRR **section, uint16_t section_len) {
	uint16_t res = 0;
	for (int i = 0; i < section_len; i++) {
		PartialRR *prr = section[i];
		if (prr->is_complete && prr->rrid == 0) {
			continue;
		}
		if (prr->is_complete) {
			res += 1;
			continue;
		}
		if (prr->rrid == 0) {
			continue;
		}
		bool is_requested = true;
		for (int j = 0; j < prr->expected_blocks; j++) {
			is_requested =  (is_requested && ((prr->block_markers[j] == BLOCKRECVD) ||
			    				(prr->block_markers[j] == BLOCKWAITING)));
			if (!is_requested) {
				break;
			}
		}
		if (is_requested) res += 1;
	}
	return res;
}

#define OPT 41

bool
update_max_udp(DNSMessage *msg, uint16_t new_size) {
	bool res = false;
	// First we need to find opt. It's always located in
	// the additional section.
	uint16_t arcount = msg->arcount;
	for (uint16_t i = 0; i < arcount; i++) {
		ResourceRecord *rr = msg->additional_section[i]->data.rr;
		if (rr->type == OPT) {
			rr->clas = new_size; // the class field in opt is used for max UDP size
			res = true;
			break;
		}
	}
	return res;
}


bool
construct_intermediate_message(DNSMessage *in, DNSMessage **out) {
	clone_dnsmessage(in, out);
	return update_max_udp(*out, 65535U);
}


uint64_t
calculate_size_needed(DNSMessage *msg) {
	uint64_t total_size = 12; // Start at 12 to include header size
	for (uint16_t i = 0; i < msg->qdcount; i++) {
		// Should never get here, so let's error
		assert("We should never get here because we aren't handling queries" == false);
	}

	for (uint16_t i = 0; i < msg->ancount; i++) {
		if (msg->answers_section[i]->isRRFrag) {
			total_size += msg->answers_section[i]->data.rrfrag->rrsize;
		} else {
			unsigned char *tmp_res;
			size_t out_len;
			rr_to_bytes(msg->answers_section[i]->data.rr, &tmp_res, &out_len);
			total_size += out_len;
			free(tmp_res);
		}
	}

	for (uint16_t i = 0; i < msg->nscount; i++) {
		if (msg->authoritative_section[i]->isRRFrag) {
			total_size += msg->authoritative_section[i]->data.rrfrag->rrsize;
		} else {
			unsigned char *tmp_res;
			size_t out_len;
			rr_to_bytes(msg->authoritative_section[i]->data.rr, &tmp_res, &out_len);
			total_size += out_len;
			free(tmp_res);
		}

	}

	for (uint16_t i = 0; i < msg->arcount; i++) {
		if (msg->additional_section[i]->isRRFrag) {
			total_size += msg->additional_section[i]->data.rrfrag->rrsize;
		} else {
			unsigned char *tmp_res;
			size_t out_len;
			rr_to_bytes(msg->additional_section[i]->data.rr, &tmp_res, &out_len);
			total_size += out_len;
			free(tmp_res);
		}

	}
	return total_size;
}


// From The Practice of Programming
uint16_t
hash_16bit(unsigned char *in, size_t in_len) {
	uint16_t h;
	unsigned char *p = in;

	h = 0;
	for (size_t i = 0; i < in_len; i++) {
		h = 37 * h + p[i];
	}
	return h;
}


void
insert_rrfrag(DNSMessage *msg, size_t i, RRFrag *rrfrag) {
	if (i < msg->ancount) {
		free(msg->answers_section[i]->data.rr);
		msg->answers_section[i]->data.rrfrag = malloc(sizeof(rrfrag));
		clone_rrfrag(rrfrag, &(msg->answers_section[i]->data.rrfrag));
		msg->answers_section[i]->isRRFrag = true;
	}
	else if (i < (msg->ancount + msg->nscount)) {
		i -= msg->ancount;
		free(msg->authoritative_section[i]->data.rr);
		msg->authoritative_section[i]->data.rrfrag = malloc(sizeof(rrfrag));
		clone_rrfrag(rrfrag, &(msg->authoritative_section[i]->data.rrfrag));
		msg->authoritative_section[i]->isRRFrag = true;
	}
	else if (i < (msg->ancount + msg->nscount + msg->arcount)) {
		i -= (msg->ancount + msg->nscount);
		free(msg->additional_section[i]->data.rr);
		msg->additional_section[i]->data.rrfrag = malloc(sizeof(rrfrag));
		clone_rrfrag(rrfrag, &(msg->additional_section[i]->data.rrfrag));
		msg->additional_section[i]->isRRFrag = true;
	}
}


typedef struct shared_map {
	sem_t lock;
	hashmap *map;
} shared_map;

shared_map responder_cache;
hashmap *requester_state;
shared_map connection_info;

typedef struct conn_info {
	int fd;
	void *transport_header;
	bool is_tcp;
	struct iphdr *iphdr;
} conn_info;

void
init_shared_map(shared_map *map) {
	sem_init(&(map->lock), 0, 1);
	map->map = hashmap_create();
}

void
create_generic_socket(uint32_t dest_addr, uint16_t dest_port, bool is_tcp, int *out_fd) {
	struct sockaddr_in addrinfo;
	addrinfo.sin_family = AF_INET;
	addrinfo.sin_addr.s_addr = dest_addr;
	int sock_type = -1;
	if (is_tcp) {
		sock_type = SOCK_STREAM;
	} else {
		sock_type = SOCK_DGRAM;
	}
	addrinfo.sin_port = dest_port;
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addrinfo.sin_addr, ip, INET_ADDRSTRLEN);
	char *port = itoa(ntohs(addrinfo.sin_port));
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = sock_type;
	getaddrinfo(ip, port, &hints, &res);
	int fd = socket(addrinfo.sin_family, sock_type, 0);
	if (fd < 0) {
		printf("Error creating socket to send rrfrag\n");
		exit(-1);
	}
	connect(fd, res->ai_addr, res->ai_addrlen);
	*out_fd = fd;
}

void
generic_close(int *fd) {
	close(*fd);
}

void
generic_send(int fd, unsigned char *bytes, size_t byte_len) {
	int bytes_sent = send(fd, bytes, byte_len, 0);
	if (bytes_sent != byte_len) {
		printf("Error! Didn't send enough.\n");
		exit(-1);
	}
}

void
generic_recv(int fd, unsigned char *buff, size_t *bufflen) {
	// TODO, add error checking.
	*bufflen = recv(fd, buff, *bufflen, 0);
	
}
// The internal packet functions are to get around an issue
// where netfilter queue prevents packets between the daemon
// and dns server from being sent. There is probably a better
// way to do this, but I can't find it right now.
// Need to figure out a good way to clean up this map.

bool
is_internal_packet(struct iphdr *iphdr) {
	return (!is_resolver &&(iphdr->saddr == our_addr && iphdr->daddr == our_addr));
}


// If we get an internal message that looks like an DNSMessage, then we can assume
// it is passing information between the daemon and either the requester or receiver

bool
internal_send(int fd, unsigned char *bytes, size_t byte_len,
		struct iphdr *iphdr, void *transport_header, uint16_t question_hash, bool is_tcp) {
	generic_send(fd, bytes, byte_len);
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	socklen_t len = sizeof(sin);
	if (getsockname(fd, (struct sockaddr *)&sin, &len) == -1) {
		perror("getsockname");
		exit(-1);
	}
	uint16_t src_port;
	src_port = ntohs(sin.sin_port);
	conn_info *ci = malloc(sizeof(conn_info));
	ci->fd = fd;
	ci->is_tcp = is_tcp;
	if (is_tcp) {
		ci->transport_header = malloc(sizeof(struct tcphdr));
		memcpy(ci->transport_header, transport_header, sizeof(struct tcphdr));
	} else {
		ci->transport_header = malloc(sizeof(struct udphdr));
		memcpy(ci->transport_header, transport_header, sizeof(struct udphdr));
	}
	ci->iphdr = malloc(sizeof(struct iphdr));
	memcpy(ci->iphdr, iphdr, sizeof(struct iphdr));
	fflush(stdout);
	uintptr_t test;
	uint64_t *question_hash_port = malloc(sizeof(uint64_t));
	memset(question_hash_port, 0, sizeof(uint64_t));
	uint32_t *qh = (uint32_t *)question_hash_port;
	*qh = question_hash;
	*(qh + 1) = src_port;
	if (hashmap_get(connection_info.map, question_hash_port, sizeof(uint64_t), (uintptr_t *)&test)) {
		printf("Something is already there...\n");
		fflush(stdout);
		assert(false);
		exit(-1);
	}
	//fflush(stdout);
	// TODO might be worth using question_hash || source port to make it more specific. For now, not a concern
	hashmap_set(connection_info.map, question_hash_port, sizeof(uint64_t), (uintptr_t)ci);
	if (!hashmap_get(connection_info.map, question_hash_port, sizeof(uint64_t), (uintptr_t *)&ci)) {
		printf("Failed to add connection info to hashmap\n");
		fflush(stdout);
		exit(-1);
	}
	return true;
}

// Going to need to use raw sockets when responding to an rrfrag request
// so that the sorce destination and ports match up

uint16_t
csum(uint16_t *ptr, int32_t nbytes) {
	int32_t sum;
	uint16_t oddbyte;
	uint16_t answer;

	sum = 0;
	while (nbytes > 1) {
		sum += htons(*ptr);
		ptr++;
		nbytes -= 2;
	}
	if (nbytes==1) {
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (int16_t)~sum;

	return answer;
}

bool
create_raw_socket(int *fd) {
	int _fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (_fd < 0) {
		return false;
	}
	*fd = _fd;
	return true;
}


bool
raw_socket_send(int fd, unsigned char *payload, size_t payload_len, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, bool is_tcp) {
	unsigned char *datagram;
	if (is_tcp) {
       		datagram = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + (sizeof(char) * payload_len));
	} else {
       		datagram = malloc(sizeof(struct iphdr) + sizeof(struct udphdr) + (sizeof(char) * payload_len));
	}
	// IP header
	struct iphdr *iph = (struct iphdr *)datagram;

	unsigned char *data;
	if (is_tcp) {
		data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	} else {
		data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	}

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	if (is_tcp) {
		iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
	} else {
		iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
	}
	iph->tot_len = htons(iph->tot_len);
	memcpy(data, payload, payload_len);
	iph->id = htons(1234); // TODO, actually figure out how to set this properly
	iph->frag_off = 0;
	iph->ttl = 255;
	if (is_tcp) {
		iph->protocol = IPPROTO_TCP;
	} else {
		iph->protocol = IPPROTO_UDP;
	}
	iph->check = 0;
	iph->saddr = saddr;
	iph->daddr = daddr;
	// IP checksum
	iph->check = csum((uint16_t *)datagram, sizeof(struct iphdr));
	iph->check = htons(iph->check);
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dport);
	sin.sin_addr.s_addr = daddr;
	
	unsigned char *tphdr = datagram + sizeof(struct iphdr);
	if (is_tcp) {
		struct tcphdr *tcph = (struct tcphdr *)tphdr;
		tcph->source = htons(sport);
		tcph->dest = htons(dport);
		tcph->seq = 0;
		tcph->ack_seq = 0;
		tcph->doff = 5;
		tcph->fin = 0;
		tcph->syn = 1;
		tcph->rst = 0;
		tcph->psh = 0;
		tcph->ack = 0;
		tcph->urg = 0;
		tcph->window = htons(5840);
		tcph->check = 0;
		tcph->urg_ptr = 0;

		// TODO TCP checksum
	} else {
		struct udphdr *udph = (struct udphdr *)tphdr;
		udph->source = sport;
		udph->dest = dport;
		udph->check = 0;
		udph->len = htons(payload_len + sizeof(struct udphdr));
	}

	int value = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value))) {
		perror("Error setting IP_HDRINCL");
		exit(-1);
	}

	if (sendto(fd, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		//printf("message size: %u\n", ntohs(iph->tot_len));
		//fflush(stdout);
		perror("raw socket failed to send");
		return false;
	}
	// we don't need to wait for a response for these, so just close the socket.
	close(fd);
	return true;
}

bool
handle_internal_packet(struct nfq_q_handle *qh, uint32_t id,
			struct iphdr *iphdr, uint64_t *question_hash_port,
			unsigned char *outbuff, size_t *outbuff_len) {
	assert(is_internal_packet(iphdr));
	uint32_t verdict = NF_ACCEPT;
	if (!nfq_set_verdict(qh, id, verdict, 0, NULL)) {
		printf("Failed to accept internal packet\n");
		fflush(stdout);
		exit(-1);
	}

	// We need to get the file descriptor from a previous cb, so get it from
	// a hashtable based on the dest (original socket's source port)
	// if there is something there, receive it, otherwise just return
	conn_info *ci;
	int fd;
	//printf("Looking up original port for question_hash: %lu\n", *question_hash_port);
	//fflush(stdout);
	if (!hashmap_get(connection_info.map, question_hash_port, sizeof(uint64_t), (uintptr_t *)&ci)) {
		//printf("Didn't find the connection_info we needed\n");
		//fflush(stdout);
		return false;
	}
	fd = ci->fd;
	//printf("mapped port: %d, fd: %d\n", ntohs(((struct udphdr *)ci->transport_header)->source), ci->fd);
	struct pollfd ufd;
	memset(&ufd, 0, sizeof(struct pollfd));
	ufd.fd = fd;
	ufd.events = POLLIN;
	int rv = poll(&ufd, 1, 0); // TODO can probably make this smaller or non-existent
	if (rv == -1) {
		perror("Failed to poll");
		fflush(stdout);
		exit(-1);
	} else if (rv == 0) {
		// This must be an "outgoing" internal message
		// so we just need to accept
		// printf("Must be an outgoing message, fd: %d\n", fd);
		return false;
	} else {
		if (ufd.revents & POLLIN) {
			*outbuff_len = recv(fd, outbuff, *outbuff_len, 0);
			// TODO, probably don't want to remove this here until we get the port initial headers out of it
//			hashmap_remove(connection_info.map, &og_src_port, sizeof(uint16_t));
			return true;
		} else {
			printf("poll returned on an event we don't care about\n");
			exit(-1);
		}
	}
}

void
internal_close(int fd, uint64_t question_hash_port) {
	hashmap_remove(connection_info.map, &question_hash_port, sizeof(uint64_t));
	generic_close(&fd);
}


void
get_rrfrags(DNSMessage *msg, uint8_t section, uint16_t *num_rrfrags, RRFrag ***rrfrags) {
	// 0 == answer section
	// 1 == authoritative section
	// 2 == additional section
	PackedRR **packed_section = NULL;
	size_t section_size = 0;
	if (section == 0) {
		packed_section = msg->answers_section;
		section_size = msg->ancount;
	} else if (section == 1) {
		packed_section = msg->authoritative_section;
		section_size = msg->nscount;
	} else if (section == 2) {
		packed_section = msg->additional_section;
		section_size = msg->arcount;
	} else {
		printf("Failed in get_rrfrags\n");
		fflush(stdout);
		ERROR();
	}
	uint16_t rrfrag_count = 0;
	for (uint16_t i = 0; i < section_size; i++) {
		if (packed_section[i]->isRRFrag) {
			rrfrag_count++;
		}
	}
	RRFrag **_rrfrags = malloc(sizeof(RRFrag *) * rrfrag_count);
	rrfrag_count = 0;
	for (uint16_t i = 0; i < section_size; i++) {
		if (packed_section[i]->isRRFrag) {
			clone_rrfrag(packed_section[i]->data.rrfrag, _rrfrags + rrfrag_count++);
		}
	}
	*rrfrags = _rrfrags;
	*num_rrfrags = rrfrag_count;
}

void
partial_to_dnsmessage(PartialDNSMessage *in, DNSMessage **out) {
	assert(message_complete(in));

	Question **questions = in->question_section;
	
	PackedRR **answers = malloc(sizeof(PackedRR *) * in->ancount);
	for (uint16_t i = 0; i < in->ancount; i++) {
		ResourceRecord *rr;
		size_t bytes_processed;
		if (bytes_to_rr(in->answers_section[i]->bytes, in->answers_section[i]->rrsize, &bytes_processed, &rr) != 0) {
			printf("Failed to make rr from received bytes\n");
			fflush(stdout);
			exit(-1);
		}
		create_packedrr(rr, answers + i);
	}
	PackedRR **authoritative = malloc(sizeof(PackedRR *) * in->nscount);
	for (uint16_t i = 0; i < in->nscount; i++) {
		ResourceRecord *rr = NULL;
		size_t bytes_processed;
		if (bytes_to_rr(in->authoritative_section[i]->bytes, in->authoritative_section[i]->rrsize, &bytes_processed, &rr) != 0) {
			printf("Failed to make rr from received bytes\n");
			fflush(stdout);
			exit(-1);
		}
		create_packedrr(rr, authoritative + i);
	}
	PackedRR **additional = malloc(sizeof(PackedRR *) * in->arcount);
	for (uint16_t i = 0; i < in->arcount; i++) {
		ResourceRecord *rr;
		size_t bytes_processed;
		if (bytes_to_rr(in->additional_section[i]->bytes, in->additional_section[i]->rrsize, &bytes_processed, &rr) != 0) {
			printf("Failed to make rr from received bytes\n");
			fflush(stdout);
			exit(-1);
		}
		create_packedrr(rr, additional + i);
	}
	DNSMessage *msg;
	create_dnsmessage(&msg, in->identification, in->flags, in->qdcount, in->ancount, in->nscount, in->arcount, questions, answers, authoritative, additional);
	//dnsmessage_to_string(msg);
	*out = msg;
}


void
pack_section(PackedRR ***packed_rrfrags, PartialRR **section, uint16_t section_len, uint16_t section_start, uint16_t *rrfrag_count, uint16_t *rrids_to_complete, uint16_t rrs_not_complete, uint16_t *cur_message_size) {
	uint16_t cursize = *cur_message_size;
	PackedRR **rrfrags = malloc(sizeof(PackedRR *) * rrs_not_complete);
	uint16_t _rrfrag_count = 0;
	for (uint16_t i = section_start; (i < rrs_not_complete) && cursize < MAXUDP; i++) {
		RRFrag *rrf;
		uint16_t rrid = rrids_to_complete[i];
		PartialRR *prr = NULL;
		for (uint16_t j = 0; j < section_len; j++) {
			if (section[j]->rrid == rrid) {
				prr = section[j];
				break;
			}
		}
		assert(prr != NULL);
		// Find the first block that we haven't requested yet and use that to determine
		// curidx and fragsize to request
		ssize_t curidx = -1;
		size_t numblocks = 0;
		//size_t numblocksrecvdreq = 0;
		for (size_t j = 0; j < prr->expected_blocks; j++) {
			if (prr->block_markers[j] == BLOCKFREE
					&& curidx == -1) {
				curidx = j;
				numblocks++;
			} else if (prr->block_markers[j] == BLOCKFREE
					&& curidx != -1) {
				numblocks++;
			}
		}
		if (curidx == -1) continue;
		size_t lastblocksize = prr->rrsize % BLOCKSIZE;
		if (lastblocksize == 0) lastblocksize = BLOCKSIZE;

		size_t canfit = abs(MAXUDP - cursize);
		size_t numblockscanfit = floor((float)canfit / BLOCKSIZE);
		
		if (numblockscanfit >= numblocks) {
			// ask for all
			uint16_t fragsize = numblocks * BLOCKSIZE;
			if (fragsize > prr->rrsize - (curidx * BLOCKSIZE)) {
				fragsize = prr->rrsize - (curidx * BLOCKSIZE);
			}
			if (create_rrfrag(&rrf, fragsize, curidx * BLOCKSIZE, prr->rrsize, prr->rrid, NULL) != 0) {
				printf("Error making rrfrag for follow up request\n");
				ERROR();
			}
			cursize += ((numblocks - 1) * BLOCKSIZE) + lastblocksize - RRHEADER + RRFRAGHEADER;
			if (create_packedrr(rrf, rrfrags + _rrfrag_count) != 0) {
				printf("Error creating packedrr 1\n");
				fflush(stdout);
				ERROR();
			}
			for (int j = curidx; j < curidx + numblocks; j++) {
				prr->block_markers[j] = BLOCKWAITING;
			}
			_rrfrag_count++;
		} else if (numblockscanfit > 0) {
			// ask for what we can
			uint16_t fragsize = numblockscanfit * BLOCKSIZE;
			if (create_rrfrag(&rrf, fragsize, curidx * BLOCKSIZE, prr->rrsize, prr->rrid, NULL) != 0) {
				printf("Error making rrfrag for follow up request\n");
				ERROR();
			}
			cursize += (numblockscanfit * BLOCKSIZE) - RRHEADER + RRFRAGHEADER;
			if (create_packedrr(rrf, rrfrags + _rrfrag_count) != 0) {
				printf("Error creating packedrr 1\n");
				fflush(stdout);
				ERROR();
			}
			for (int j = curidx; j < curidx + numblockscanfit; j++) {
				prr->block_markers[j] = BLOCKWAITING;
			}
			_rrfrag_count++;
			*packed_rrfrags = rrfrags;
			*cur_message_size = cursize;
			*rrfrag_count = _rrfrag_count;
			return;
		} else {
			// Pack RRFrags and return
			*packed_rrfrags = rrfrags;
			*cur_message_size = cursize;
			*rrfrag_count = _rrfrag_count;
			return;
		}
	}
	*packed_rrfrags = rrfrags;
	*cur_message_size = cursize;
	*rrfrag_count = _rrfrag_count;

}

void
refresh_hashmap(hashmap **map);

void
requester_thread(DNSMessage *msg, struct iphdr *iphdr, void *transport_header, bool is_tcp) {

	// 1) Copy the contents of the received message into the partial message
	// 	- Initialize if needed.
	// 2) Figure out what we still need
	// 	- Loop through each section finding messages we still need
	// 	  to complete
	// 	- Construct a new query that contains a subset of the RRFrags
	// 	  we need.
	// 	- send the query as if it was from the original process.
	
	//printf("requester_thread\n");
	//fflush(stdout);
	// Step 1
	uint16_t id = msg->identification;
	PartialDNSMessage *pm;
	if (!hashmap_get(requester_state, &id, sizeof(uint16_t), (uintptr_t *)&pm)) {
		printf("Failed to find a pm when we really should have...\n");
		fflush(stdout);
		uint16_t *_id = malloc(sizeof(uint16_t));
		*_id = msg->identification;
		init_partialdnsmessage(&pm);
		hashmap_set(requester_state, _id, sizeof(uint16_t), (uintptr_t)pm);
	}
	//printf("pre copy\n");
	//fflush(stdout);
	copy_message_contents(pm, msg);
	//printf("post copy\n");
	//fflush(stdout);
	if (message_complete(pm)) {
		// We are done! Send the reconstructed message to the requester
		//printf("message complete!\n");
		//fflush(stdout);
		int fd;
		size_t bytelen;
		unsigned char *bytes;
		DNSMessage *tosend;
		if (!create_raw_socket(&fd)) {
			printf("Error creating raw socket to send completed partial messaged\n");
			ERROR();
		}
		partial_to_dnsmessage(pm, &tosend);
		// SHouldn't need to do this since the original response should have this bit set anyway
		tosend->flags = tosend->flags | ((1 << 15));
		if (dnsmessage_to_bytes(tosend, &bytes, &bytelen) != 0) {
			printf("Error converting final dns message to bytes\n");
			ERROR();
		}
		if (is_tcp) {
			raw_socket_send(fd, bytes, bytelen, iphdr->saddr, iphdr->daddr, ((struct tcphdr *)transport_header)->source, ((struct tcphdr *)transport_header)->dest, is_tcp);
		} else {
			//printf("Sending complete message\n");
			//fflush(stdout);
			raw_socket_send(fd, bytes, bytelen, iphdr->saddr, iphdr->daddr, ((struct udphdr *)transport_header)->source, ((struct udphdr *)transport_header)->dest, is_tcp);
		}
		generic_close(&fd);
		return;
	} else if (message_complete_soon(pm)) {
		// We've requested everything we need to request and just need to wait.
		//printf("Message will be complete soon!\n");
		return;
	}

	// Step 2
	
	uint16_t an_not_complete = 0;
	uint16_t *an_rrids_to_complete = NULL;
	for (uint16_t i = 0; i < pm->ancount; i++) {
		if (!pm->answers_section[i]->is_complete) {
			an_not_complete++;
		} else {
		}
	}
	if (an_not_complete != 0) {
		an_rrids_to_complete = malloc(sizeof(uint16_t) * an_not_complete);
	}
	int j = 0;
	for (uint16_t i = 0; i < pm->ancount; i++) {
		if (!pm->answers_section[i]->is_complete && pm->answers_section[i]->rrid != 0) {
			an_rrids_to_complete[j] = pm->answers_section[i]->rrid;
			j++;
		}
	}
	uint16_t ns_not_complete = 0;
	uint16_t *ns_rrids_to_complete = NULL;
	for (uint16_t i = 0; i < pm->nscount; i++) {
		if (!pm->authoritative_section[i]->is_complete) {
			ns_not_complete++;
		}
	}
	if (ns_not_complete != 0) {
		ns_rrids_to_complete = malloc(sizeof(uint16_t) * ns_not_complete);
	}
	j = 0;
	for (uint16_t i = 0; i < pm->nscount; i++) {
		if (!pm->authoritative_section[i]->is_complete && pm->authoritative_section[i]->rrid != 0) {
			ns_rrids_to_complete[j] = pm->authoritative_section[i]->rrid;
			j++;
		}
	}
	uint16_t ar_not_complete = 0;
	uint16_t *ar_rrids_to_complete = NULL;
	for (uint16_t i = 0; i < pm->arcount; i++) {
		if (!pm->additional_section[i]->is_complete) {
			ar_not_complete++;
		}
	}
	if (ar_not_complete != 0) {
		ar_rrids_to_complete = malloc(sizeof(uint16_t) * ar_not_complete);
	}
	j = 0;
	for (uint16_t i = 0; i < pm->arcount; i++) {
		if (!pm->additional_section[i]->is_complete && pm->additional_section[i]->rrid != 0) {
			ar_rrids_to_complete[j] = pm->additional_section[i]->rrid;
			j++;
		}
	}
	uint16_t an_frags_requested = frags_requested(pm->answers_section, pm->ancount);
	uint16_t ns_frags_requested = frags_requested(pm->authoritative_section, pm->nscount);
	uint16_t ar_frags_requested = frags_requested(pm->additional_section, pm->arcount);
	//printf("an_frags_requested: %hu; an_not_complete: %hu\n", an_frags_requested, an_not_complete);
	//printf("ns_frags_requested: %hu; ns_not_complete: %hu\n", ns_frags_requested, ns_not_complete);
	//printf("ar_frags_requested: %hu; ar_not_complete: %hu\n", ar_frags_requested, ar_not_complete);
	while ((an_frags_requested < an_not_complete) ||
		(ns_frags_requested < ns_not_complete) ||
		(ar_frags_requested < ar_not_complete)) {
		//printf("an_frags_requested: %hu; an_not_complete: %hu\n", an_frags_requested, an_not_complete);
		//printf("ns_frags_requested: %hu; ns_not_complete: %hu\n", ns_frags_requested, ns_not_complete);
		//printf("ar_frags_requested: %hu; ar_not_complete: %hu\n", ar_frags_requested, ar_not_complete);
		uint16_t cur_message_size = DNSMESSAGEHEADER;
		PackedRR **an_rrfrags = NULL;
		uint16_t an_rrfrag_count = 0;
		PackedRR **ns_rrfrags = NULL;
		uint16_t ns_rrfrag_count = 0;
		PackedRR **ar_rrfrags = NULL;
		uint16_t ar_rrfrag_count = 0;
		pack_section(&an_rrfrags, pm->answers_section, pm->ancount, an_frags_requested, &an_rrfrag_count, an_rrids_to_complete, an_not_complete, &cur_message_size);
		pack_section(&ns_rrfrags, pm->authoritative_section, pm->nscount, ns_frags_requested, &ns_rrfrag_count, ns_rrids_to_complete, ns_not_complete, &cur_message_size);
		pack_section(&ar_rrfrags, pm->additional_section, pm->arcount, ar_frags_requested, &ar_rrfrag_count, ar_rrids_to_complete, ar_not_complete, &cur_message_size);
		an_frags_requested = frags_requested(pm->answers_section, pm->ancount);
		ns_frags_requested = frags_requested(pm->authoritative_section, pm->nscount);
		ar_frags_requested = frags_requested(pm->additional_section, pm->arcount);
		uint16_t final_size = an_rrfrag_count + ns_rrfrag_count + ar_rrfrag_count;
		assert(final_size > 0);
		PackedRR **final_section = malloc(sizeof(PackedRR *) * final_size);
		for (uint16_t i = 0; i < an_rrfrag_count; i++) {
			clone_packedrr(an_rrfrags[i], final_section + i);
		}
		for (uint16_t i = 0; i < ns_rrfrag_count; i++) {
			clone_packedrr(ns_rrfrags[i], final_section + i + an_rrfrag_count);
		}
		for (uint16_t i = 0; i < ar_rrfrag_count; i++) {
			clone_packedrr(ar_rrfrags[i], final_section + i + an_rrfrag_count + ns_rrfrag_count);
		}
		if (an_rrfrags != NULL)
			free(an_rrfrags);
		if (ns_rrfrags != NULL)
			free(ns_rrfrags);
		if (ar_rrfrags != NULL)
			free(ar_rrfrags);

		DNSMessage *req_msg;
		Question *q;
		create_question(&q, "",  108, 1);
		if (create_dnsmessage(&req_msg, msg->identification, 0, 1, 0, 0, final_size, &q, NULL, NULL, final_section) != 0) {
			printf("Error making DNSMessage asking for more rrfrags\n");
			ERROR();
		}
		//dnsmessage_to_string(req_msg);
		int fd;
		unsigned char *bytes;
		size_t bytelen;
		if (!create_raw_socket(&fd)) {
			printf("Failed to make raw socket to ask for more rrfrags\n");
			ERROR();
		}
		if (dnsmessage_to_bytes(req_msg, &bytes, &bytelen) != 0) {
			printf("Failed to convert dnsmessage asking for more rrfrags to bytes\n");
			ERROR();
		}
		if (is_tcp) {
			raw_socket_send(fd, bytes, bytelen, iphdr->daddr, iphdr->saddr, ((struct tcphdr *)transport_header)->dest, ((struct tcphdr *)transport_header)->source, is_tcp);
		} else {
			//printf("Sending message...\n");
			raw_socket_send(fd, bytes, bytelen, iphdr->daddr, iphdr->saddr, ((struct udphdr *)transport_header)->dest, ((struct udphdr *)transport_header)->source, is_tcp);
		}
	}
	//printf("Sent all messages\n");
	//fflush(stdout);
}

void
responding_thread_start(DNSMessage *imsg, struct iphdr *iphdr, void *transport_hdr, bool is_tcp) {
	// open socket using the same protocol as used for the request
	int fd;
	//uint32_t src_ipaddr = iphdr->saddr;
	uint32_t dst_ipaddr = iphdr->daddr;
	//uint16_t src_port;
	uint16_t dst_port;
	if (is_tcp) {
		//src_port = ((struct tcphdr *)transport_hdr)->source;
		dst_port = ((struct tcphdr *)transport_hdr)->dest;
	} else {
		//src_port = ((struct udphdr *)transport_hdr)->source;
		dst_port = ((struct udphdr *)transport_hdr)->dest;
	}
	unsigned char *imsg_bytes;
	size_t imsg_size;
	//unsigned char recvd[1232]; // Maybe make this bigger just to be safe.
	//size_t recvd_len;
	dnsmessage_to_bytes(imsg, &imsg_bytes, &imsg_size);
	uint16_t question_hash;
	if (imsg->qdcount == 1) /* it should always be one */ {
		unsigned char *qout;
		size_t qout_size;
		question_to_bytes(imsg->question_section[0], &qout, &qout_size);
		question_hash = hash_16bit(qout, qout_size);
	} else {
		assert(false);
	}
	create_generic_socket(dst_ipaddr, dst_port, is_tcp, &fd);
	internal_send(fd, imsg_bytes, imsg_size, iphdr, transport_hdr, question_hash, is_tcp);
	destroy_dnsmessage(&imsg);
}


void
insert_into_state(ResourceRecord *rr, uint16_t *rrids, size_t *rrcount, size_t *rrsize) {
	size_t _rrcount = *rrcount;
	size_t _rrsize = *rrsize;
	unsigned char *rrout;
	size_t rr_outlen;
	rr_to_bytes(rr, &rrout, &rr_outlen);
	uint16_t hash = hash_16bit(rrout, rr_outlen);
	ResourceRecord *out;
	_rrsize += rr_outlen;
	sem_wait(&(responder_cache.lock));
	if (!hashmap_get(responder_cache.map, &hash, sizeof(uint16_t), (uintptr_t *)&out)) {
		uint16_t *_hash = malloc(sizeof(uint16_t));
		*_hash = hash;
		ResourceRecord *crr;
		if (clone_rr(rr, &crr) != 0) {
			printf("Failed to clone rr before inserting into hashtable\n");
			ERROR();
		}
		//printf("adding hash to hashmap: %hu\n", *_hash);
		//printf("adding rr to hashmap:\n%s\n", rr_to_string(rr));
		hashmap_set(responder_cache.map, _hash, sizeof(uint16_t), (uintptr_t)crr);
		rrids[_rrcount++] = hash;
		//rrsizes[rrcount++] = rr_outlen;
	} else {
		if (rr_is_equal(rr, out)) {
			// it's already in our hashmap, so just continue
			sem_post(&(responder_cache.lock));
			rrids[_rrcount++] = hash;;
			*rrcount = _rrcount;
			*rrsize = _rrsize;
			return;
		}
		hash++;
		while(hashmap_get(responder_cache.map, &hash, sizeof(uint16_t), (uintptr_t *)&out)) {
			hash++;
		}
		uint16_t *_hash = malloc(sizeof(uint16_t));
		*_hash = hash;
		hashmap_set(responder_cache.map, _hash, sizeof(uint16_t), (uintptr_t)rr);
		rrids[_rrcount++] = hash;
		//rrsizes[rrcount++] = rr_outlen;
	}
	sem_post(&(responder_cache.lock));
	*rrcount = _rrcount;
	*rrsize = _rrsize;
}

void
insert_into_state_and_construct_map(DNSMessage* msg, size_t max_size) {
	size_t total_records = msg->ancount + msg->nscount + msg->arcount;
	uint16_t *rrids = malloc(sizeof(uint16_t) * total_records);
	size_t rrcount = 0;
	size_t rrsize = DNSMESSAGEHEADER;
	//size_t rrsizes = malloc(sizeof(size_t) * total_records);

	// We won't fragment questions since they are very small, but we must include them in
	// responses, and must account for their size when calculating FRAGSIZEs
	
	for (int i = 0; i < msg->qdcount; i++) {
		size_t q_len;
		unsigned char *q_bytes;
		question_to_bytes(msg->question_section[i], &q_bytes, &q_len);
		free(q_bytes);
		rrsize += q_len;
	}
	
	// Answers
	for (int i = 0; i < msg->ancount; i++) {
		ResourceRecord *rr = msg->answers_section[i]->data.rr;
		insert_into_state(rr, rrids, &rrcount, &rrsize);
	}

	// Authoritative
	for (int i = 0; i < msg->nscount; i++) {
		ResourceRecord *rr = msg->authoritative_section[i]->data.rr;
		insert_into_state(rr, rrids, &rrcount, &rrsize);
	}

	// Additional Section (make sure to not add opt)
	for (int i = 0; i < msg->arcount; i++) {
		ResourceRecord *rr = msg->additional_section[i]->data.rr;
		insert_into_state(rr, rrids, &rrcount, &rrsize);
	}

	
	size_t cur_size = rrsize;
	//printf("pre look cur_size: %lu\n", cur_size);
	while (cur_size > max_size - DNSMESSAGEHEADER) {
		//printf("in cur_size loop insert_into_state_and_construct_map\n");
		//printf("rrcount0 : %lu\n", rrcount);
		//fflush(stdout);
		size_t cur_max = 0;
		//cur_size = rrsize;
		//uint32_t hash = rrids[0];
		uint16_t hash;
		ResourceRecord *rr;
		size_t idx = 0;
		for (int i = 0; i < rrcount; i++) {
			uint16_t cur_hash = rrids[i];
			//printf("hash: %hu\n", cur_hash);
			//fflush(stdout);
			if (cur_hash == 0) {
				continue;
			}
			//printf("pre hashmap get\n");
			//fflush(stdout);
			if (!hashmap_get(responder_cache.map, &cur_hash, sizeof(uint16_t), (uintptr_t *)&rr)) {
				printf("RRID: %hu, type: %hu\n", hash, rr->type);
				fflush(stdout);
				assert("[ERROR]Couldn't find rr with that rrid" == false);
			}
			//printf("post hashmap get\n");
			//fflush(stdout);
			if (rr->rdsize > cur_max) {
				cur_max = rr->rdsize;
				hash = cur_hash;
				//size = rrsizes[i];
				idx = i;
			}
		}
		//printf("post forloop\n");
		//fflush(stdout);
		//hash = rrids[idx];
		if (!hashmap_get(responder_cache.map, &hash, sizeof(uint16_t), (uintptr_t *)&rr)){
			printf("rrid: %hu\n", hash);
			fflush(stdout);
			assert("[ERROR]Couldn't find rr with that rrid" == false);
		}
		// mark rrfrag as compressed.
		rrids[idx] = 0;
		// TODO might be a bug here. Might end up adding an unneeded rrfrag
		if ((cur_size - rr->rdsize) >= max_size - DNSMESSAGEHEADER) {
			// make an rrfrag with fragsize 0
			RRFrag *rrfrag;
			unsigned char *bytes;
			size_t out_len;
			rr_to_bytes(rr, &bytes, &out_len);
			//printf("Fragmenting:\n %s\n", rr_to_string(rr));
			//printf("out_len: %lu\n", out_len);
			//fflush(stdout);
			create_rrfrag(&rrfrag, 0, 0, out_len, hash, NULL);
			free(bytes);
			insert_rrfrag(msg, idx, rrfrag);
			cur_size -= out_len;
			cur_size += RRFRAGHEADER;
		} else {
			// How much do we have to work with?
			size_t cs = abs(cur_size + (RRFRAGHEADER - RRHEADER - rr->name_byte_len) - (max_size - DNSMESSAGEHEADER));
			//printf("name_byte_len: %lu\n", rr->name_byte_len);
			//printf("rdsize: %hu\n", rr->rdsize);
			//printf("difference: %lu\n", cs);
			//printf("cur_size: %lu\n", cur_size);
			//printf("max_size: %lu\n", max_size);
			if (cs > rr->rdsize) {
				cs = 0;
			} else {
				cs = rr->rdsize - cs;
			}
			double numblocks = ((double)cs) / ((double)BLOCKSIZE);
			//printf("new fragsize: %lu\n", cs);
			//printf("numblocks: %lf\n", numblocks);
			RRFrag *rrfrag;
			unsigned char *bytes;
			size_t out_len;
			rr_to_bytes(rr, &bytes, &out_len);
			//printf("==========out_len: %lu\n", out_len);
			uint16_t fragsize = floor(numblocks) * BLOCKSIZE;
			//printf("fragsize: %hu\n", fragsize);
			if (cs > 0) {
				create_rrfrag(&rrfrag, fragsize, 0, out_len, hash, bytes);
				cur_size -= out_len;
			} else {
				create_rrfrag(&rrfrag, fragsize, 0, 0, hash, NULL);
				cur_size -= out_len;
			}
			free(bytes);
			insert_rrfrag(msg, idx, rrfrag);
			rrfrag_to_bytes(rrfrag, &bytes, &out_len);
			free(bytes);
			cur_size += out_len;
			//printf("post cur_size: %lu\n", cur_size);
			/*
			double maxblocks = ((double)cs / BLOCKSIZE;
			printf("maxblocks: %lu\n", maxblocks);
			fflush(stdout);
			// make rrfrag of fragsize maxblocks
			RRFrag *rrfrag;
			unsigned char *bytes;
			size_t out_len;
			rr_to_bytes(rr, &bytes, &out_len);
			uint16_t fragsize = floor(maxblocks) * BLOCKSIZE;
			create_rrfrag(&rrfrag, fragsize, 0, out_len, hash, bytes);
			free(bytes);
			insert_rrfrag(msg, idx, rrfrag);
			cur_size -= out_len;
			rrfrag_to_bytes(rrfrag, &bytes, &out_len);
			free(bytes);
			cur_size += out_len;
			*/
			// if we get to this case, we're done and can just break out of our loop
			break;
		}
	}
	//printf("cursize: %lu, maxsize: %lu DNSHEADER %u\n", cur_size, max_size, DNSHEADERSIZE); 

}



void
responding_thread_end(struct iphdr *iphdr, void *transport_hdr, bool is_tcp,
			unsigned char *recvd, size_t recvd_len, uint64_t *question_hash_port,
			int fd) {
	internal_close(fd, *question_hash_port);
	DNSMessage *recvd_msg;
	// Probably what's best is to have a centralized hashmap that we index using RRIDs
	// when we get a response from the name server containing all the RRs we add them
	// to the hash table. If there is something already there, just increase the proposed
	// RRID by one until we find a blank spot. Keep a note of these RRIDs for reassembly
	if (bytes_to_dnsmessage(recvd, recvd_len, &recvd_msg) != 0) {
		assert("Failed to build dnsmessage from response to imsg" == false);
	}
	//dnsmessage_to_string(recvd_msg);
	// Finally we can make our new DNSMessage and send it back to who we got it from.
	insert_into_state_and_construct_map(recvd_msg, MAXUDP);
	fd = -1;
	unsigned char *msg_bytes;
	size_t byte_len;
	//dnsmessage_to_string(recvd_msg);
	dnsmessage_to_bytes(recvd_msg, &msg_bytes, &byte_len);
	destroy_dnsmessage(&recvd_msg);
	create_raw_socket(&fd);
	if (is_tcp) {
		raw_socket_send(fd, msg_bytes, byte_len, iphdr->daddr, iphdr->saddr, ((struct tcphdr *)transport_hdr)->dest, ((struct tcphdr *)transport_hdr)->source, is_tcp);
	} else {
		if (byte_len > MAXUDP) {
			printf("byte_len: %lu, MAXUDP: %u, difference: %lu\n", byte_len, MAXUDP, byte_len - (size_t)MAXUDP);
			assert(byte_len <= MAXUDP);
		}
		raw_socket_send(fd, msg_bytes, byte_len, iphdr->daddr, iphdr->saddr, ((struct udphdr *)transport_hdr)->dest, ((struct udphdr *)transport_hdr)->source, is_tcp);

	}
	close(fd);
}


uint32_t
process_dns_message(struct nfq_q_handle *qh, uint32_t id, unsigned char *payload, size_t payloadLen, struct iphdr *iphdr, void *transport_header, bool is_tcp) {
	unsigned char *pkt_content;
	DNSMessage *msg;

	uint32_t saddr = iphdr->saddr;
	uint32_t daddr = iphdr->daddr;
	uint16_t sport;
	uint16_t dport;
	if (is_tcp) {
		sport = ((struct tcphdr *)transport_header)->source;
		sport = ntohs(sport);
		dport = ((struct tcphdr *)transport_header)->dest;
		dport = ntohs(dport);
	} else {
		sport = ((struct udphdr *)transport_header)->source;
		sport = ntohs(sport);
		dport = ((struct udphdr *)transport_header)->dest;
		dport = ntohs(dport);
	}

	size_t msgSize = payloadLen;
    	if (is_tcp) {
		pkt_content = payload + sizeof(struct tcphdr) + sizeof(struct iphdr);
		msgSize -= sizeof(struct tcphdr) + sizeof(struct iphdr);
	} else {
		pkt_content = payload + sizeof(struct udphdr) + sizeof(struct iphdr);
		msgSize -= sizeof(struct udphdr) + sizeof(struct iphdr);
	}
	if (!looks_like_dnsmessage(pkt_content, msgSize)) {
		printf("[Warning]This doesn't look like a dnsmessage\n");
		fflush(stdout);
		return NF_ACCEPT;
	}
	int rc = bytes_to_dnsmessage(pkt_content, msgSize, &msg);
	//printf("msgSize: %lu\n", msgSize);
	//fflush(stdout);
	if (rc != 0) {
		printf("[Error]Failed to convert bytes to dns_message\n");
		ERROR();
	}
	if (is_tcp) return NF_ACCEPT;
	assert(!is_tcp);
	//printf("==========================\n");
	//fflush(stdout);
	//dnsmessage_to_string(msg);
	//printf("==========================\n");
	//fflush(stdout);
	if (is_internal_packet(iphdr)) {
		size_t outbuff_len = 65355; // Need to account for large messages because of SPHINCS+
		unsigned char outbuff[outbuff_len];
		uint64_t *question_hash_port = malloc(sizeof(uint64_t));
		memset(question_hash_port, 0, sizeof(uint64_t));
		if (msg->qdcount == 1) /* it should always be one */ {
			unsigned char *qout;
			size_t qout_size;
			question_to_bytes(msg->question_section[0], &qout, &qout_size);
			uint32_t *question_hash = (uint32_t *)question_hash_port;
			*question_hash = hash_16bit(qout, qout_size);
			*(question_hash + 1) = dport;
		} else {
			assert(false);
		}
		/*
		uint16_t og_port;
		if (sport == 53) {
			og_port = dport;
		} else {
			og_port = sport;
		}
		*/
		if (handle_internal_packet(qh, id, iphdr, question_hash_port, outbuff, &outbuff_len) && dport != 53) {
			conn_info *ci;
			// TODO lock
			if (!hashmap_get(connection_info.map, question_hash_port, sizeof(uint64_t), (uintptr_t *)&ci)) {
				printf("Failed to get ci\n");
				fflush(stdout);
				return NF_ACCEPT;
			}
			responding_thread_end(ci->iphdr, ci->transport_header, ci->is_tcp,
						outbuff, outbuff_len, question_hash_port, ci->fd);
		} else {
			return NF_ACCEPT;
		}
		return 0xFFFF;
	
	}
	if (dport != 53 && sport != 53) {
		printf("[Warning]Non-standard dns port. Likely not dns message so ignoring.\n");
		return  NF_ACCEPT;
	}
	// Might not be able to handle the responder side =/ Issues include:
	// 	1) Passing super large resource records to the daemon because of EDNS0 size limits
	// 	2) How do I give meaning to RRIDs? Would need to read all of the resource records anyway
	// 	   in order to assign them an RRID. This feels like overstepping as a daemon, and just being
	// 	   a DNS server... Probably makes more sense to bake it in
	// This daemon is being designed to run in its own container
	// so we can't rely our_addr. Instead using a list of addrs
	// that we are acting in front of.
	if (is_query(msg)) {
		// If we are sending the packet, and the packet
		// is a query, then there is nothing for us to
		// do yet...
		if (saddr == our_addr && dport == 53) {
			// depending on how routing works, we might need check if it's communication between this machine or not
			//
			// We should also log the identifier for the purpose of preventing resource exhaustion
			// however this won't prevent a middle man from modifying an advertised RRFRAG's size
			// and causing the system to allocate way too much memory... um, hm.
			// I guess you could use some sort of max cap depending on what the record is, and what it contains
			// DNSKEYS and RRSIGS can be based on the algorithm being used. So the worst case memory usage would
			// be Requests * max(max(RRSIG_SIZE), max(DNSKEY_SIZE))
			
			uint16_t *id = malloc(sizeof(uint16_t));
			*id = msg->identification;
			// init id's entry in hashmap to NULL. When we get the first response
			// then we can allocate space based on advertized value
			// no point taking up space until we know we need it.
			uintptr_t out;
			if (!hashmap_get(requester_state, id, sizeof(uint16_t), &out) ) {
				PartialDNSMessage *pmsg = NULL;
				init_partialdnsmessage(&pmsg);
				hashmap_set(requester_state, id, sizeof(uint16_t), (uintptr_t)pmsg);
			}
			return NF_ACCEPT;
		} else if (daddr == our_addr && dport == 53) {
			// parse query for rrfrags, if none
			// just pass it on, since this is a normal request
			if (contains_rrfrag(msg)) {
				// For now, I'm not going to cache, but in the future we should.
				// First construct on DNS query to send dns server that will retrieve
				// all of the whole resource records we need. Should be able to just make the
				// advertised size huge, but that won't work for RRs larger than what EDNS supports.
				// In that case the server will *need* to implement RRFrags on their side.
				// For now, if the RRs needed are already in memory, just use those instead of querying the
				// DNS server


				// Make a new thread to handle sending and receiving data to send, and request RRs from
				// responder
				// This is strictly because I'm lazy and just want to store the result of the above query in memory
				// and not implement a real caching system.

				// For now, I think I'm going to have a hashmap that output that uses rrids for keys, then
				// the value is the RR. I guess it's kind of like caching, but currently it won't expire

				// Once that thread receives the data it needs, it should send using the received RRFrags
				// to determine what to respond with.

				// We should drop all packets that have RRFrags as we are intercepting them
				
				uint16_t num_rrfrags;
				RRFrag **rrfrags;
				PackedRR **rrfrags_to_send;
				get_rrfrags(msg, 2, &num_rrfrags, &rrfrags);
				rrfrags_to_send = malloc(sizeof(RRFrag *) * num_rrfrags);
				for (uint16_t i = 0; i < num_rrfrags; i++) {
					RRFrag *rrf = rrfrags[i];
					uint16_t rrid = rrf->rrid;
					uint32_t curidx = rrf->curidx;
					uint32_t fragsize = rrf->fragsize;
					// TODO acquire locks to be safe
					ResourceRecord *rr;
					if (!hashmap_get(responder_cache.map, &rrid, sizeof(uint16_t), (uintptr_t *)&rr)) {
						printf("Failed to find a rr with that rrid... shouldn't happen\n");
						fflush(stdout);
						exit(-1);
					}
					unsigned char *rrbytes;
					size_t rrbyte_len;
					rr_to_bytes(rr, &rrbytes, &rrbyte_len);
					RRFrag *_rrf;
					if (create_rrfrag(&_rrf, fragsize, curidx, rrf->rrsize, rrf->rrid, rrbytes + curidx) != 0) {
						assert("Failed to make new rrfrag" == false);
					}
					free(rrbytes);
					create_packedrr(_rrf, rrfrags_to_send + i);
					
				}
				DNSMessage *resp;
				uint16_t flags = msg->flags;
				flags = (flags | (1 << 15)); // mark message as response
				if (create_dnsmessage(&resp, msg->identification, flags, 0, num_rrfrags, 0, 0, NULL, rrfrags_to_send, NULL, NULL) != 0) {
					assert("Failed to make dnsmessage containing rrfrags" == false);
				}
				unsigned char *msgbytes;
				size_t msgbyte_len;
				dnsmessage_to_bytes(resp, &msgbytes, &msgbyte_len);
				int out_fd;
				if (!create_raw_socket(&out_fd)) {
					printf("Failed to make raw socket to respond to rrfrag request\n");
					fflush(stdout);
					ERROR();
				}
				if (is_tcp) {
					raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->daddr, iphdr->saddr, ((struct tcphdr *)transport_header)->dest, ((struct tcphdr *)transport_header)->source, is_tcp);
				} else {
					raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->daddr, iphdr->saddr, ((struct udphdr *)transport_header)->dest, ((struct udphdr *)transport_header)->source, is_tcp);
				}
				generic_close(&out_fd);
				free(msgbytes);
				/*
				create_generic_socket(saddr, sport, is_tcp, &out_fd);
				generic_send(out_fd, msgbytes, msgbyte_len);
				generic_close(&out_fd);
				free(msgbytes);
				*/
				return NF_DROP;
			} else if (!is_resolver) {
				// Should be able to get away with just updating the udp max size in opt
				// TODO there is a bug here, but for now this isn't a problem.
				// need to only update udp size when sending to our own machine, this currently
				// does it to all messages
				DNSMessage *iquery;
				construct_intermediate_message(msg, &iquery);
				//return NF_ACCEPT;
				responding_thread_start(iquery, iphdr, transport_header, is_tcp);
				return NF_DROP;
			} else {
				return NF_ACCEPT;
			}
		}
	} else {
		if (daddr == our_addr && sport == 53) {
			if (contains_rrfrag(msg)) {
				uint16_t id = msg->identification;
				PartialDNSMessage *data;
				if (hashmap_get(requester_state, &id, sizeof(uint16_t), (uintptr_t *)&data)) {
					//copy_message_contents(data, msg);
					if (!message_complete(data)) {
						//printf("pre requester_thread\n");
						//fflush(stdout);
						requester_thread(msg, iphdr, transport_header, is_tcp);
						//printf("post requester_thread\n");
						//fflush(stdout);
					}
					return NF_DROP;
				} else {
					return NF_DROP;
					// if we get here, then this is a malicious message and we should drop.
				}
			} else {
				// If this doesn't contain an rrfrag, we have nothing to do, so remove
				// id from hashmap and accept.
				uint16_t id = msg->identification;
				hashmap_remove(requester_state, &id, sizeof(uint16_t));
				return NF_ACCEPT;
			}
		} else if (daddr == our_addr && dport == 53) {
			// Since we are using queries to ask for RRFrags, this should never happen
			printf("We should never have to process a non-query directed at port 53\n");
			fflush(stdout);
			ERROR();
		} else if (saddr == our_addr && sport == 53) {
			return NF_ACCEPT;
		} else {
			printf("Fell through...\n");
			ERROR();
		}
	}

	return NF_ACCEPT;
}

uint32_t
process_tcp(struct nfq_q_handle *qh, uint32_t id, struct iphdr *ipv4hdr, unsigned char *payload, size_t payloadLen) {
	struct tcphdr *tcphdr = (struct tcphdr *)((char *)payload + sizeof(*ipv4hdr));
	uint16_t src_port = ntohs(tcphdr->source);
	uint16_t dst_port = ntohs(tcphdr->dest);
	//printf("tcp: <src: %u:%hu, dest: %u:%hu, total size: %lu>\n", ipv4hdr->saddr, src_port, ipv4hdr->daddr, dst_port, payloadLen);
	//fflush(stdout);
	return NF_ACCEPT;
	return process_dns_message(qh, id, payload, payloadLen, ipv4hdr, tcphdr, true);
}

uint32_t
process_udp(struct nfq_q_handle *qh, uint32_t id, struct iphdr *ipv4hdr, unsigned char *payload, size_t payloadLen) {
	struct udphdr *udphdr = (struct udphdr *)((char *)payload + sizeof(*ipv4hdr));
	uint16_t src_port = ntohs(udphdr->source);
	uint16_t dst_port = ntohs(udphdr->dest);
	//printf("<src: %u:%hu, dest: %u:%hu, total size: %lu>\n", ipv4hdr->saddr, src_port, ipv4hdr->daddr, dst_port, payloadLen);
	//fflush(stdout);
	if (BYPASS) {
		return NF_ACCEPT;
	}
	return process_dns_message(qh, id, payload, payloadLen, ipv4hdr, udphdr, false);
}



uint32_t
process_packet(struct nfq_q_handle *qh, struct nfq_data *data, uint32_t **verdict) {
	// For the sake of testing getting this to work in docker containers
	// this is just going to print packet header info if it's a packet
	// addressed to this machine

	size_t payloadLen = 0;
	unsigned char *payload = NULL;
	struct iphdr *ipv4hdr;
	struct icmphdr *icmphdr;
	uint32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	payloadLen = nfq_get_payload(data, &payload);
	ipv4hdr = (struct iphdr *)payload;
	ph = nfq_get_msg_packet_hdr(data);
	id = ntohl(ph->packet_id);

	uint32_t dst_ip = ipv4hdr->daddr;
	uint32_t src_ip = ipv4hdr->saddr;
	uint32_t res;
	if (dst_ip == our_addr || src_ip == our_addr) {
		if (ipv4hdr->protocol == IPPROTO_TCP) {
			res = process_tcp(qh, id, ipv4hdr, payload, payloadLen);
		} else if (ipv4hdr->protocol == IPPROTO_UDP) {
			res = process_udp(qh, id, ipv4hdr, payload, payloadLen);
		} else if (ipv4hdr->protocol == IPPROTO_ICMP) {
			icmphdr = (struct icmphdr *)((char *)payload + sizeof(*ipv4hdr));
			//printf("<type: %hhu, code: %hhu src: %u dest: %u>\n", icmphdr->type, icmphdr->code, ipv4hdr->saddr, ipv4hdr->daddr);
		} else {
			res = NF_ACCEPT;
		}
	} else if (ipv4hdr->protocol == IPPROTO_UDP) {
		struct udphdr *udphdr = (struct udphdr *)((char *)payload + sizeof(*ipv4hdr));
		uint16_t src_port = ntohs(udphdr->source);
		uint16_t dst_port = ntohs(udphdr->dest);
		//printf("<src: %u:%hu, dest: %u:%hu, total size: %lu>\n", ipv4hdr->saddr, src_port, ipv4hdr->daddr, dst_port, payloadLen);
		res = NF_DROP;
	} else {
		//printf("Packet type: %hhu\n", ipv4hdr->protocol);
		if (ipv4hdr->protocol == IPPROTO_ICMP) {
			icmphdr = (struct icmphdr *)((char *)payload + sizeof(*ipv4hdr));
			//printf("<type: %hhu, code: %hhu src: %u dest: %u>\n", icmphdr->type, icmphdr->code, ipv4hdr->saddr, ipv4hdr->daddr);
			res = NF_DROP;
		} else {
			res = NF_ACCEPT;
		}
	}
	**verdict = res;
	if (res == 0xFFFF) {
		return 0;
	}
	return id;

}

static int 
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	uint32_t verdict;
	uint32_t *verdict_p = &verdict;
	uint32_t id = process_packet(qh, nfa, &verdict_p);
	if (*verdict_p == 0xFFFF) {
		//printf("Got singal to not submit a verdict\n");
		//fflush(stdout);
		return 0;
	}
	verdict = *verdict_p;
	if (verdict == NF_DROP) {
		//printf("dropping packet\n");
		//fflush(stdout);
	}
	if (verdict == NF_ACCEPT) {
		//printf("accepting packet\n");
		//fflush(stdout);
	}
	if (nfq_set_verdict(qh, id, verdict, 0, NULL) < 0) {
		printf("Verdict error\n");
		fflush(stdout);
		exit(-1);
	}
	return 0;
}

int
get_addr(char *ipaddr) {
	inet_pton(AF_INET, ipaddr, &our_addr);
	return 0;
}

void
free_key(void *key, size_t ksize, uintptr_t value, void *usr) {
	free(key);
}


void
refresh_shared_map(shared_map **map) {
	if (map == NULL) return;
	shared_map *m = *map;
	if (m != NULL) {
		sem_wait(&(m->lock));
		hashmap_iterate(m->map, free_key, NULL);
		hashmap_free(m->map);
		m->map = hashmap_create();
		sem_post(&(m->lock));
	} else {
		init_shared_map(m);
	}
	*map = m;
}

void
refresh_hashmap(hashmap **map) {
	if (map == NULL) return;
	hashmap *m = *map;
	if (m != NULL) {
		hashmap_iterate(m, free_key, NULL);
		hashmap_free(m);
	}
	m = hashmap_create();
	*map = m;
}

void
refresh_state(void) {
	shared_map *rcp;
	shared_map *cip;
	rcp = &responder_cache;
	cip = &connection_info;
	refresh_shared_map(&rcp);
	refresh_shared_map(&cip);
	refresh_hashmap(&requester_state);
}




int
main(int argc, char **argv) {
	char *ipaddr;
	if (argc < 2 || argc > 5) {
		printf("Wrong number of arguments.\n");
		return -1;
	}
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--is_resolver") == 0){
			printf("Is a resolver\n");
			is_resolver = true;
		} else if (strcmp(argv[i], "--bypass") == 0) {
			printf("bypassing daemon\n");
			BYPASS = true;
		} else if (strcmp(argv[i], "--maxudp") == 0) {
			i++;
			MAXUDP = atoi(argv[i]);
			printf("Using maxudp: %u\n", MAXUDP);
		} else {
			ipaddr = argv[i];
		}
	}
	printf("Starting daemon...\n");
	size_t buff_size = 0xffff;
	char buf[buff_size];
	int fd;
	/* get this machine's ip address from ioctl */
	if (get_addr(ipaddr) != 0) return -1;
	/* Create and initialize handle for netfilter_queue */
	struct nfq_handle *h = nfq_open();
	init_shared_map(&responder_cache);
	init_shared_map(&connection_info);
	requester_state = hashmap_create();
	if (!h) {
		printf("Failed getting h\n");
		return -1;
	}
	if (nfq_bind_pf(h, AF_INET) < 0) {
		printf("Failed to bind\n");
		return -1;
	}
	struct nfq_q_handle *qh;
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		printf("Failed to make queue\n");
		return -1;
	}
	if ((nfq_set_mode(qh, NFQNL_COPY_PACKET, buff_size)) == -1) {
		printf("Failed to tune queue\n");
		return -1;
	}
	fd = nfq_fd(h);
	printf("Listening...\n");
	fflush(stdout);
	for(;;) {
		int rv;
		struct pollfd ufd;
		memset(&ufd, 0, sizeof(struct pollfd));
		ufd.fd = fd;
		ufd.events = POLLIN;
		rv = poll(&ufd, 1, 0); // If we time out, then reset hashtable?
		if (rv < 0) {
			printf("Failed to poll nfq\n");
			return -1;
		} else if (rv == 0) {
			// Timed out
			// If we haven't received any packets in 10 seconds, it's safe to assume we should reset state.
			// This won't work well in large scale operations, but this is just a proof of concept
			//refresh_state();
		} else {
			rv = recv(fd, buf, sizeof(buf), 0);
			if (rv < 0) {
				printf("failed to receive a thing\n");
				return -1;
			}
			nfq_handle_packet(h, buf, rv);
		}
	}
	
	return 0;
}
