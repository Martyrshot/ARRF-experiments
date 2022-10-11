#include <resource_record.h>
#include <rrfrag.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <assert.h>


int
bytes_to_dnsname(unsigned char *in, char **name, size_t *name_len, size_t *bytes_processed, size_t in_len) {
	int i = 0;
	char *_name = NULL;
	size_t label_len = 0;
	char *tmp_name = NULL;
	size_t name_size = in_len + 1;
	tmp_name = malloc(name_size);
	if (tmp_name == NULL) {
		printf("Failed to malloc tmp_name\n");
		fflush(stdout);
		return -1;
	}
	while ((i < in_len) && in[i] != 0) {
		label_len = in[i];
		if (label_len + i > in_len) {
			free(tmp_name);
			// Is a pointer name, so fill our struct with a human readable name
			int j = 0;
			while(in[j] != 0) j++;
			*name = malloc(strlen("POINTER NAME") + 1);
			strcpy(*name, "POINTER NAME");
			*bytes_processed = j;
			return 0;
		}
		for (size_t j = 0; j < label_len; j++) {
			tmp_name[i + j] = in[i + j + 1];
		}
		tmp_name[i + label_len] = '.';
		i += label_len + 1;
	}
	if (i > in_len) {
		printf("i > in_len\n");
		fflush(stdout);
		return -1;
	}
	if (i == 0) {
		tmp_name[i] = '.';
	} else if ((in_len - i) != 0) {
		_name = tmp_name;
		tmp_name = malloc((i * sizeof(char)) + 1);
		if (tmp_name == NULL) {
			printf("failed to reallocate tmp_name\n");
			fflush(stdout);
			return -1;
		}
		strncpy(tmp_name, _name, i);
		free(_name);
	}
	*name_len = i + 1;
	*bytes_processed = i + 1;
	if (i == 0) {
		i++;
	}
	tmp_name[i] = '\0';
	*name = tmp_name;
	return 0;
}


int
dnsname_to_bytes(char *name, size_t name_len, unsigned char **out, size_t *out_len) {
	size_t i = 0;
	size_t label_len = 0;
	unsigned char *tmp_out = NULL;
	tmp_out = malloc(name_len * sizeof(unsigned char) + 1);
	while (i < name_len) {
		size_t j = i;
		while (j < name_len) {
			if (name[j] == '.') {
				break;
			}
			j++;
		}
		label_len = j - i;
		if (label_len == 0) {
			goto exit;
		}
		tmp_out[i] = label_len;
		i++;
		for (size_t k = i; k < j + 1; k++) {
			tmp_out[k] = name[k-1];
		}
		i += label_len;
	}
exit:
	tmp_out[i] = 0;
	*out_len = ++i;
	*out = tmp_out;
	return 0;
}


int
destroy_rr(ResourceRecord **rr) {
	if (rr == NULL) {
		return 0;
	}
	ResourceRecord *_rr = *rr;
	if (_rr == NULL) {
		return 0;
	}
	if (_rr->name != NULL)
		free(_rr->name);
	if (_rr->name_bytes != NULL)
		free(_rr->name_bytes);
	if (_rr->rdata != NULL)
		free(_rr->rdata);
	free(_rr);
	*rr = NULL;
	return 0;
}

int
create_rr(ResourceRecord **out, char *name, unsigned char *name_bytes, size_t name_byte_len, uint16_t type, uint16_t clas, uint32_t ttl, uint16_t rdsize, unsigned char *rdata) {
	ResourceRecord *rr = malloc(sizeof(ResourceRecord));
	if (rr == NULL) {
		return -1;
	}
	size_t name_len = strlen(name);
	rr->name = malloc((sizeof(char) * name_len) + 1);
	if (rr->name == NULL) {
		printf("rrname malloc error\n");
		destroy_rr(&rr);
		return -1;
	}
	memcpy(rr->name, name, name_len + 1);
	rr->name_bytes = malloc(name_byte_len);
	memcpy(rr->name_bytes, name_bytes, name_byte_len);
	rr->name_byte_len = name_byte_len;
	rr->type = type;
	rr->clas = clas;
	rr->ttl = ttl;
	rr->rdsize = rdsize;
	rr->rdata = malloc(rr->rdsize);
	if (rr->rdata == NULL) {
		printf("rdata malloc error\n");
		destroy_rr(&rr);
		return -1;
	}
	memcpy(rr->rdata, rdata, rdsize);
	*out = rr;
	return 0;
}

int
bytes_to_rr(unsigned char *in, size_t in_len, size_t *bytes_processed, ResourceRecord **out) {
	int rc = 0;
	ResourceRecord *rr = malloc(sizeof(ResourceRecord));
	char *name;
	size_t name_len = 0;
	unsigned char *cur_pos = in;
	// get name
	// find the length of the byte field
	size_t name_byte_len = 0;
	while (in[name_byte_len] != 0) {
		name_byte_len++;
	}
	name_byte_len += 1;
	rc = bytes_to_dnsname(cur_pos, &name, &name_len, bytes_processed, name_byte_len);
	if (rc != 0) {
		printf("Failed to make bytename\n");
		fflush(stdout);
		goto end;
	}
	rr->name = name;
	
	if (*bytes_processed != 0) {
		rr->name_bytes = malloc(*bytes_processed);
		memcpy(rr->name_bytes, in, *bytes_processed);
	} else {
		assert("Should never happen\n");
	}
	rr->name_byte_len = *bytes_processed;
	cur_pos = cur_pos + *bytes_processed;
	in_len = in_len - *bytes_processed;
	// get type
	rr->type = *(uint16_t *)cur_pos;
	rr->type = ntohs(rr->type);
	if (rr->type == RRFRAG) {
		printf("tried to make rr from rrfrag\n");
		fflush(stdout);
		destroy_rr(&rr);
		return -3;
	}
	cur_pos = cur_pos + 2;
	in_len = in_len - 2;
	*bytes_processed += 2;
	// get class
	rr->clas = *(uint16_t *)cur_pos;
	rr->clas = ntohs(rr->clas);
	cur_pos = cur_pos + 2;
	in_len = in_len - 2;
	*bytes_processed += 2;
	// get ttl
	rr->ttl = *(uint32_t *)cur_pos;
	rr->ttl = ntohl(rr->ttl);
	cur_pos = cur_pos + 4;
	in_len = in_len - 4;
	*bytes_processed += 4;

	// get rdsize
	rr->rdsize = *(uint16_t *)cur_pos;
	rr->rdsize = ntohs(rr->rdsize);
	cur_pos = cur_pos + 2;
	in_len = in_len - 2;
	*bytes_processed += 2;

	if (rr->rdsize > in_len) {
		printf("rr->rdsize: %hu, in_len: %lu flipped rdsize:%hu\n", rr->rdsize, in_len, ntohs(rr->rdsize));
		printf("ERROR: rdsize larger than supplied bytes\n");
		rc = -1;
		goto end;
	}
	
	// get rdata
	rr->rdata = malloc(sizeof(unsigned char) * rr->rdsize);
	memcpy(rr->rdata, cur_pos, rr->rdsize);
	*bytes_processed += rr->rdsize;
	*out = rr;
end:
	return rc;
}

int
rr_to_bytes(ResourceRecord *in, unsigned char **out, size_t *out_len) {
	int rc = 0;
	unsigned char *bytes = NULL;
	unsigned char *cur_pos = NULL;
	unsigned char *name = NULL;
	uint16_t type = 0;
	uint16_t clas = 0;
	uint32_t ttl = 0;
	uint16_t rdsize = 0;
	bytes = malloc(in->name_byte_len + 2 + 2 + 4 + 2 + in->rdsize);
	if (bytes == NULL) {
		rc = -1;
		goto end;
	}
	cur_pos = bytes;
	memcpy(cur_pos, in->name_bytes, in->name_byte_len);
	cur_pos = cur_pos + in->name_byte_len;

	type = htons(in->type);
	memcpy(cur_pos, &type, 2);
	cur_pos = cur_pos + 2;
	
	clas = htons(in->clas);
	memcpy(cur_pos, &clas, 2);
	cur_pos = cur_pos + 2;

	ttl = htonl(in->ttl);
	memcpy(cur_pos, &ttl, 4);
	cur_pos = cur_pos + 4;

	rdsize = htons(in->rdsize);
	memcpy(cur_pos, &rdsize,2);
	cur_pos = cur_pos + 2;
	if (in->rdsize != 0) {
		memcpy(cur_pos, in->rdata, in->rdsize);
		*out_len = in->name_byte_len + 2 + 2 + 4 + 2 + in->rdsize;
	} else {
		*out_len = in->name_byte_len + 2 + 2 + 4 + 2;
	}
	*out = bytes;
	free(name);
end:
	return rc;

}


int
clone_rr(ResourceRecord *in, ResourceRecord **out) {
	int rc = 0;
	ResourceRecord *res = malloc(sizeof(ResourceRecord));
	if (res == NULL) {
		printf("Failed to malloc for res in clone rr\n");
		fflush(stdout);
		exit(-1);
	}
	res->name = malloc((sizeof(char) * strlen(in->name)) + 1);
	if (res->name == NULL) {
		printf("Failed to malloc for res->name in clone rr\n");
		exit(-1);
	}
	strcpy(res->name, in->name);
	res->name_bytes = malloc(in->name_byte_len);
	memcpy(res->name_bytes, in->name_bytes, in->name_byte_len);
	res->name_byte_len = in->name_byte_len;
	res->type = in->type;
	res->clas = in->clas;
	res->ttl = in->ttl;
	res->rdsize = in->rdsize;
	res->rdata = malloc(sizeof(unsigned char) * res->rdsize);
	memcpy(res->rdata, in->rdata, res->rdsize);
	*out = res;
	return rc;
}

bool
rr_is_equal(ResourceRecord *lhs, ResourceRecord *rhs) {
	bool nameCheck = true;
	// if the name_bytes are the same, we're happy
	if (lhs->name_byte_len != rhs->name_byte_len) return false;
	for (int i = 0; i < lhs->name_byte_len; i++) {
		nameCheck = nameCheck && (lhs->name_bytes[i] == rhs->name_bytes[i]);
	}
	bool typeCheck = (lhs->type == rhs->type);
	bool classCheck = (lhs->clas == rhs->clas);
	bool ttlCheck = (lhs->ttl == rhs->ttl);
	bool rdsizeCheck = (lhs->rdsize == rhs->rdsize);
	if (!rdsizeCheck) return false;
	bool rdataCheck = (memcmp(lhs->rdata, rhs->rdata, lhs->rdsize) == 0);
	return (nameCheck && typeCheck && classCheck && ttlCheck && rdsizeCheck && rdataCheck);
}

char *
rr_to_string(ResourceRecord *rr) {
	char *res = NULL;
	size_t wanted_to_write = 0;
	
	if (rr == NULL) return NULL;
	size_t str_len;
	if (rr->type == 41/* OPT */) {
		str_len = snprintf(NULL, 0, "Resource Record:\n\tName: %s\n\tType: %hu\n\tClass: %hu\n\tExtended RCODE || version: ", rr->name, rr->type, rr->clas);
		str_len += 32;
		str_len += 1;
		str_len += snprintf(NULL, 0, "\trdsize: %hu\n\trdata: ", rr->rdsize);
	} else {
		str_len = snprintf(NULL, 0, "Resource Record:\n\tName: %s\n\tType: %hu\n\tClass: %hu\n\tTTL: %u\n\tRDSIZE: %hu\n\tRDATA: ", rr->name, rr->type, rr->clas, rr->ttl, rr->rdsize);
	}
	for (int i = 0; i < rr->rdsize; i++) {
		str_len += snprintf(NULL, 0, "%hhX ", rr->rdata[i]);
	}
	str_len = str_len + /* \n */1 + /* \0 */1;
	res = malloc((sizeof(char) * str_len));
	if (res == NULL) {
		printf("Error malloc\n");
		return NULL;
	}
	if (rr->type != 41 /* OPT */) {
		wanted_to_write = snprintf(res, str_len, "Resource Record:\n\tName: %s\n\tType: %hu\n\tClass: %hu\n\tTTL: %u\n\tRDSIZE: %hu\n\tRDATA: ", rr->name, rr->type, rr->clas, rr->ttl, rr->rdsize);
	} else {
		wanted_to_write = snprintf(res, str_len, "Resource Record:\n\tName: %s\n\tType: %hu\n\tClass: %hu\n\tExtended RCODE || version: ", rr->name, rr->type, rr->clas);
		uint8_t tmp = rr->ttl;
		uint16_t mask = 1 << 15;
		char bits[33];
		char *cur_bit = bits;
		char tmp_bit[2];
		for (int i = 0; i < 16; i++) {
			int wanted_to_write = snprintf(tmp_bit, 3, "%u ", tmp&mask ? 1 : 0);
			if (wanted_to_write > 3) {
				assert("didn't get to write everything we wanted..." == false);
			}
			tmp = tmp << 1;
			strcat(cur_bit, tmp_bit);
			cur_bit += 2;
		}
		strncat(res, bits, str_len);
		strncat(res, "\n", str_len);
		size_t str_left = str_len - strlen(res);
		char *cur_pos = res + strlen(res);
		snprintf(cur_pos, str_left, "\trdsize: %hu\n\trdata: ", rr->rdsize);

	}
	if (wanted_to_write >= str_len) {
		printf("Not enough space to make the string.\n");
		free(res);
		return NULL;
	}

	for(size_t i = 0; i < rr->rdsize; i++) {
		char byte[4];
		wanted_to_write = snprintf(byte, 4, "%hhX ", rr->rdata[i]);
		if (wanted_to_write >=  4) {
			printf("Ran out of room for rdata, wanted: %lu\n", wanted_to_write);
			free(res);
			return NULL;
		}
		strncat(res, byte, 4);
		str_len -= wanted_to_write;
	}
	if (str_len == 0) {
		printf("Error!\n");
	}
	
	strncat(res, "\n", 2);
	return res;
}
