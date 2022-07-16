#ifndef __DNS_MESSAGE__

#define __DNS_MESSAGE__


#include <resource_record.h>
#include <question.h>
#include <rrfrag.h>
#include <packedrr.h>
#include <stdbool.h>

#define DNSHEADERSIZE 12


typedef struct DNSMessage {
	uint16_t identification;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	Question **question_section;
	PackedRR **answers_section;
	PackedRR **authoritative_section;
	PackedRR **additional_section;
} DNSMessage;

int
destroy_dnsmessage(DNSMessage **msg);

int
create_dnsmessage(DNSMessage **out, uint16_t identification, uint16_t flags, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount, Question **questions, PackedRR **answers_section, PackedRR **authoritative_section, PackedRR **additional_section);

int
bytes_to_dnsmessage(unsigned char *in, size_t in_len, DNSMessage **out);

int
dnsmessage_to_bytes(DNSMessage *in, unsigned char **out, size_t *out_len);

int
clone_dnsmessage(DNSMessage *in, DNSMessage **out);

char *
dnsmessage_to_string(DNSMessage *in);

bool
is_query(DNSMessage *in);

bool
looks_like_dnsmessage(unsigned char *in, size_t in_len);

bool
contains_rrfrag(DNSMessage *msg);

bool
dnsmessage_is_equal(DNSMessage *lhs, DNSMessage *rhs);

#endif /* __DNS_MESSAGE__ */
