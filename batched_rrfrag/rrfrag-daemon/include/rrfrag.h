#ifndef __RRFRAG_H__

#define __RRFRAG_H__

#define RRFRAG 108 // This is just after the "experiemntal" ids and is currently unused



#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
typedef struct RRFrag {
	char *name;
	uint16_t type; // Should always be RRFRAG but keeping so it's consistent with RRs
	uint16_t fragsize;
	uint32_t curidx;
	uint32_t rrsize;
	uint16_t rrid;
	unsigned char *fragdata;
} RRFrag;

int
destroy_rrfrag(RRFrag **rrfrag);

int
create_rrfrag(RRFrag **out, uint16_t fragsize, uint32_t curidx, uint32_t rrsize, uint16_t rrid, unsigned char *fragdata);

int
bytes_to_rrfrag(unsigned char *in, size_t in_len, size_t *bytes_processed, bool is_query, RRFrag **out);

int
rrfrag_to_bytes(RRFrag *in, unsigned char **out, size_t *out_len);

int
clone_rrfrag(RRFrag *in, RRFrag **out);

bool
rrfrag_is_equal(RRFrag *lhs, RRFrag *rhs);

char *
rrfrag_to_string(RRFrag *rrfrag);

// TODO dangerous, add length checks
bool
bytes_look_like_rrfrag(unsigned char *in);


#endif /* __RRFRAG_H__ */
