#include <rrfrag.h>
#include <resource_record.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

int
destroy_rrfrag(RRFrag **rrfrag) {
	if (rrfrag == NULL) {
		return 0;
	}
	RRFrag *_rrfrag = *rrfrag;
	if (_rrfrag == NULL) {
		return 0;
	}
	if (_rrfrag->name != NULL) {
		free(_rrfrag->name);
	}
	if (_rrfrag->fragdata != NULL) {
		free(_rrfrag->fragdata);
	}
	free(_rrfrag);
	*rrfrag = NULL;
	return 0;
}

int
create_rrfrag(RRFrag **out, uint16_t fragsize, uint32_t curidx, uint32_t rrsize, uint16_t rrid, unsigned char *fragdata) {
	RRFrag *res = malloc(sizeof(RRFrag));
	if (res == NULL) {
		printf("RRFrag malloc failed.\n");
		return -1;
	}
	res->name = malloc(2);
	strncpy(res->name, ".", 2);

	res->type = RRFRAG;
	res->fragsize = fragsize;
	res->curidx = curidx;
	res->rrsize = rrsize;
	res->rrid = rrid;
	if (fragdata != NULL) {
		res->fragdata = malloc(res->fragsize);
		memcpy(res->fragdata, fragdata, res->fragsize);
	} else {
		res->fragdata = NULL;
	}
	*out = res;
	return 0;
}

int
bytes_to_rrfrag(unsigned char *in, size_t in_len, size_t *bytes_processed, bool is_query, RRFrag **out) {
	RRFrag *res = malloc(sizeof(RRFrag));
	if (res == NULL) {
		printf("Error bytes_to_rrfrag\n");
		return -1;
	}
	unsigned char *cur_pos = in;

	int name_byte_len = 0;
	while (in[name_byte_len] != 0) {
		name_byte_len++;
	}
	name_byte_len += 1;
	assert(name_byte_len == 1);
	*bytes_processed = 1;
	res->name = ".";

	cur_pos = cur_pos + *bytes_processed;
	in_len = in_len - *bytes_processed;
	// get type, and ensure it's an RRFrag. If not, then back out with special error
	res->type = *(uint16_t *)cur_pos;
	res->type = ntohs(res->type);
	if (res->type != RRFRAG) {
		free(res);
		printf("Not an RRFRAG");
		fflush(stdout);
		return -3;
	}
	cur_pos += 2;
	*bytes_processed += 2;
	res->fragsize = *(uint16_t *)cur_pos;
	res->fragsize = ntohs(res->fragsize);
	cur_pos += 2;
	*bytes_processed += 2;

	res->curidx = *(uint32_t *)cur_pos;
	res->curidx = ntohl(res->curidx);
	cur_pos += 4;
	*bytes_processed += 4;

	res->rrsize = *(uint32_t *)cur_pos;
	res->rrsize = ntohl(res->rrsize);
	cur_pos += 4;
	*bytes_processed += 4;

	res->rrid = *(uint16_t *)cur_pos;
	res->rrid = ntohs(res->rrid);
	cur_pos += 2;
	*bytes_processed += 2;
	if (!is_query) {
		res->fragdata = malloc(sizeof(unsigned char) * res->fragsize);
		memcpy(res->fragdata, cur_pos, res->fragsize);
		*bytes_processed += res->fragsize;
	} else {
		res->fragdata = NULL;
	}
	*out = res;
	return 0;
}

int rrfrag_to_bytes(RRFrag *in, unsigned char **out, size_t *out_len) {
	unsigned char *bytes = NULL;
	unsigned char *cur_pos = NULL;

	uint16_t type;
	uint16_t fragsize;
	uint32_t curidx;
	uint32_t rrsize;
	uint16_t rrid;


	assert(in->type == RRFRAG);
	*out_len = 0;
	if (in->fragdata != NULL) {
		bytes = malloc(1 + 2 + 2 + 4 + 4 + 2 + in->fragsize);
	} else {
		bytes = malloc(1 + 2 + 2 + 4 + 4 + 2);
	}
	if (bytes == NULL) {
		return -1;
	}

	cur_pos = bytes;
	cur_pos[0] = 0;
	cur_pos += 1;

	type = htons(in->type);
	memcpy(cur_pos, &type, 2);
	cur_pos += 2;

	fragsize = htons(in->fragsize);
	memcpy(cur_pos, &fragsize, 2);
	cur_pos += 2;

	curidx = htonl(in->curidx);
	memcpy(cur_pos, &curidx, 4);
	cur_pos += 4;

	rrsize = htonl(in->rrsize);
	memcpy(cur_pos, &rrsize, 4);
	cur_pos += 4;
	rrid = htons(in->rrid);
	memcpy(cur_pos, &rrid, 2);
	cur_pos += 2;
	if (in->fragdata != NULL) {
		memcpy(cur_pos, in->fragdata, in->fragsize);
		*out_len = in->fragsize;
	} else {
		*out_len = 0;
	}	
	*out_len += 1 + 2 + 2 + 4 + 4 + 2;
	*out = bytes;
	return 0;
}


int
clone_rrfrag(RRFrag *in, RRFrag **out) {
	int rc = 0;
	RRFrag *res = malloc(sizeof(RRFrag));
	res->name = malloc(2);
	strcpy(res->name, ".");
	res->type = in->type;
	res->fragsize = in->fragsize;
	res->curidx = in->curidx;
	res->rrsize = in->rrsize;
	res->rrid = in->rrid;
	if (in->fragdata != NULL) {
		res->fragdata = malloc(sizeof(unsigned char) * res->fragsize);
		memcpy(res->fragdata, in->fragdata, res->fragsize);
	} else {
		// This occurs in queries
		res->fragdata = NULL;
	}
	*out = res;
	return rc;
}

bool
rrfrag_is_equal(RRFrag *lhs, RRFrag *rhs) {
	bool nameCheck = (strcmp(lhs->name, rhs->name) == 0);
	bool typeCheck = (lhs->type == rhs->type);
	bool fragsizeCheck = (lhs->fragsize == rhs->fragsize);
	bool curidxCheck = (lhs->curidx == rhs->curidx);
	bool rrsizeCheck = (lhs->rrsize == rhs->rrsize);
	if (!rrsizeCheck) return false;
	bool rridCheck = (lhs->rrid == rhs->rrid);
	if (lhs->fragdata != NULL && rhs->fragdata == NULL) return false;
	if (lhs->fragdata == NULL && rhs->fragdata != NULL) return false;
	bool fragdataCheck;
	if (lhs->fragdata == NULL) {
		fragdataCheck = true;
	} else {
		fragdataCheck = (memcmp(lhs->fragdata, rhs->fragdata, lhs->fragsize) == 0);
	}
	return (nameCheck && typeCheck && fragsizeCheck && curidxCheck && rrsizeCheck && rridCheck && fragdataCheck);
}

char *
rrfrag_to_string(RRFrag *rrfrag) {
	char *res = NULL;
	size_t wanted_to_write = 0;

	if (rrfrag == NULL) return NULL;
	size_t str_len = snprintf(NULL, 0, "RRFrag:\n\tNAME: %s\n\tTYPE: %hu\n\tFRAGSIZE: %hu\n\tCURIDX: %u\n\tRRSIZE: %u\n\tRRID: %hu\n\tFRAGDATA: *OMITTED*\n", rrfrag->name, rrfrag->type, rrfrag->fragsize, rrfrag->curidx, rrfrag->rrsize, rrfrag->rrid) + 1;
	res = malloc((sizeof(char) * str_len));
	wanted_to_write = snprintf(res, str_len, "RRFrag:\n\tNAME: %s\n\tTYPE: %hu\n\tFRAGSIZE: %hu\n\tCURIDX: %u\n\tRRSIZE: %u\n\tRRID: %hu\n\tFRAGDATA: *OMITTED*\n", rrfrag->name, rrfrag->type, rrfrag->fragsize, rrfrag->curidx, rrfrag->rrsize, rrfrag->rrid);
	if (wanted_to_write >= str_len) {
		printf("String buffer too small\n");
		free(res);
		res = NULL;
	}
	return res;
}


bool
bytes_look_like_rrfrag(unsigned char *in) {
	uint16_t type;
	if (in == NULL) {
		return false;
	}
	size_t i = 0;
	while(in[i] != 0) {
		i++;
	}
	i++;
	type = *(uint16_t *)(in + i);
	type = ntohs(type);
	return (type == RRFRAG);
}
