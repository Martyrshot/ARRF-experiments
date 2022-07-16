#ifndef __PACKEDRR_H__

#define __PACKEDRR_H__

#include <resource_record.h>
#include <rrfrag.h>
#include <stdbool.h>

typedef union RR {
	ResourceRecord *rr;
	RRFrag *rrfrag;
} RR;

typedef struct PackedRR {
	bool isRRFrag;
	RR data;
} PackedRR;

// PackedRR functions. A PackedRR is used to store a Resource record and RRFRAG
// in the same place since they are shaped slightly differently.

int
destroy_packedrr(PackedRR **prr);

// in should either be a ResourceRecord or an RRFrag
int
create_packedrr(void *in, PackedRR **out);

int
clone_packedrr(PackedRR *in, PackedRR **out);

int
bytes_to_packedrr(unsigned char *in, size_t in_len, size_t *bytes_processed, bool is_query, PackedRR **out);

int
packedrr_to_bytes(PackedRR *in, unsigned char **out, size_t *in_len);

char *
packedrr_to_string(PackedRR *prr);

bool
packedrr_is_equal(PackedRR *lhs, PackedRR *rhs);


#endif // __PACKEDRR_H__
