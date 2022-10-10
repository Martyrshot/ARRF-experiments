#ifndef __RESOURCE_RECORD__

#define __RESOURCE_RECORD__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct ResourceRecord {
	char *name;
	uint16_t type;
	uint16_t clas;
	uint32_t ttl;
	uint16_t rdsize;
	unsigned char *rdata;
	// These need to be last so we maintain the byte structure of Resource Records and RRFrags
	// since we cast between them in a few places
	unsigned char *name_bytes;
	size_t name_byte_len;
} ResourceRecord;


int
bytes_to_dnsname(unsigned char *in, char **name, size_t *name_len, size_t *bytes_processed, size_t in_len);

int
dnsname_to_bytes(char *name, size_t name_len, unsigned char **out, size_t *out_len);

int
destroy_rr(ResourceRecord **rr);

int
create_rr(ResourceRecord **out, char *name, unsigned char *name_bytes, size_t name_byte_len, uint16_t type, uint16_t clas, uint32_t ttl, uint16_t rdsize, unsigned char *rdata);

int
bytes_to_rr(unsigned char *in, size_t in_len, size_t *bytes_processed, ResourceRecord **out);

int
rr_to_bytes(ResourceRecord *in, unsigned char **out, size_t *out_len);

int
clone_rr(ResourceRecord *in, ResourceRecord **out);

bool
rr_is_equal(ResourceRecord *lhs, ResourceRecord *rhs);

char *
rr_to_string(ResourceRecord *rr);
#endif // __RESOURCE_RECORD__
