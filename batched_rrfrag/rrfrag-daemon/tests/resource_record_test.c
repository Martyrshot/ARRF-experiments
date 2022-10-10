#include <resource_record.h>
#include <question.h>
#include <rrfrag.h>
#include <packedrr.h>
#include <dns_message.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int
test_dnsnames(void) {
	char *in_names[4] = {"www.google.ca.", "google.ca.", "ca.", "."};
	int rc;
	for (size_t i = 0; i < 4; i++) {
		char *name;
		size_t name_len;
		size_t bytes_processed;
		unsigned char *out;
		size_t out_len;
		rc = dnsname_to_bytes(in_names[i], strlen(in_names[i]), &out, &out_len);
		if (i == 0) {
			printf("%hhx%c%c%c%hhx%c%c%c%c%c%c%u%c%c%hhx\n", out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[8], out[9], out[10], out[11], out[12], out[13], out[14]);
			bytes_to_dnsname(out, &name, &name_len, &bytes_processed, out_len);
			printf("bytes processed: %zu\n", bytes_processed);
			printf("0: %s out_len: %zu\n", name, name_len);
		} else if (i == 1) {
			printf("%hhx%c%c%c%c%c%c%hhx%c%c%hhx\n", out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[8], out[9], out[10]);
			bytes_to_dnsname(out, &name, &name_len, &bytes_processed, out_len);
			printf("bytes processed: %zu\n", bytes_processed);
			printf("1: %s out_len %zu\n", name, name_len);
		} else if (i == 2) {
			printf("%hhx%c%c%hhx\n", out[0], out[1], out[2], out[3]);
			bytes_to_dnsname(out, &name, &name_len, &bytes_processed, out_len);
			printf("bytes processed: %zu\n", bytes_processed);
			printf("2: %s out_len: %zu\n", name, name_len);
		} else if (i == 3) {
			printf("%hhx\n", out[0]);
			bytes_to_dnsname(out, &name, &name_len, &bytes_processed, out_len);
			printf("bytes processed: %zu\n", bytes_processed);
			printf("3: %s out_len: %zu\n", name, name_len);
		}
	}
	return rc;
}


int
test_rr(void) {
	int rc = 0;

	char *name = "www.google.com.";
	uint16_t type = 1;
	uint16_t clas = 2;
	uint32_t ttl = 1234;
	uint16_t rdsize = 3;
	unsigned char rdata[3] = {0x00, 0x01, 0x02};
	unsigned char *bytes = NULL;
	size_t byte_len;
	ResourceRecord *rr = NULL;
	ResourceRecord *rr2 = NULL;
	rc = create_rr(&rr, name, type, clas, ttl, rdsize, rdata);

	if (rc != 0) goto end;
	char *rr_str = rr_to_string(rr);
	printf("%s",rr_str);
	free(rr_str);
	rc = rr_to_bytes(rr, &bytes, &byte_len);
	if (rc != 0) {
		destroy_rr(&rr);
		goto end;
	}
	destroy_rr(&rr);
	rc = bytes_to_rr(bytes, byte_len, &byte_len, &rr);
	if (rc != 0) {
		free(bytes);
		goto end;
	}
	rc = clone_rr(rr, &rr2);
	if (rc != 0) {
		destroy_rr(&rr);
		goto end;
	}
	if (!rr_is_equal(rr, rr2)) {
		printf("Failed equality check when it shouldn't have\n");
		rc = -1;
		goto end;
	}
	rr2->clas = 3;
	if (rr_is_equal(rr, rr2)) {
		printf("Passed equality check when it shouldn't have\n");
		rc = -1;
		goto end;
	}
	rr_str = rr_to_string(rr);
	printf("%s", rr_str);
	free(rr_str);
	

end:
	return rc;
}


int
test_question(void) {
	int rc;
	unsigned char *bytes;
	size_t byte_len;
	size_t bytes_processed;
	char *qname = "www.google.com.";
	Question *q = NULL;
	char *q_str;
	rc = create_question(&q, qname, 1, 2);
	if (rc != 0) {
		goto end;
	}
	rc = question_to_bytes(q, &bytes, &byte_len);
	printf("bl: %lu\n", byte_len);
	if (rc != 0) {
		destroy_question(&q);
		goto end;
	}
	q_str = question_to_string(q);
	printf("%s", q_str);
	destroy_question(&q);
	rc = bytes_to_question(bytes, byte_len, &bytes_processed, &q);
	printf("bl: %lu, bp: %lu\n", byte_len, bytes_processed);
	if (rc != 0) {
		free(bytes);
		goto end;
	}
	q_str = question_to_string(q);
	printf("%s", q_str);
	free(bytes);
	destroy_question(&q);
end:
	return rc;
}


int
test_rrfrag(void) {
	int rc;
	RRFrag *rrfrag;
	RRFrag *rrfrag2;
	unsigned char *bytes;
	size_t bytes_processed;
	size_t byte_len;
	char *name = ".";
	uint16_t fragsize = 2;
	uint32_t curidx = 0;
	uint32_t rrsize = 2;
	uint16_t rrid = 4567;
	unsigned char *fragdata = malloc(sizeof(unsigned char) * 2);
	fragdata[0] = 0x08;
	fragdata[1] = 0x09;
	rc = create_rrfrag(&rrfrag, name, fragsize, curidx, rrsize, rrid, fragdata);
	free(fragdata);
	if (rc != 0) {
		goto end;
	}
	rc = rrfrag_to_bytes(rrfrag, &bytes, &byte_len);
	if (rc != 0) {
		destroy_rrfrag(&rrfrag);
		goto end;
	}
	destroy_rrfrag(&rrfrag);
	rc = bytes_to_rrfrag(bytes, byte_len, &bytes_processed, &rrfrag);
	if (rc != 0) {
		printf("failed bytes to rrfrag\n");
		fflush(stdout);
		free(bytes);
		goto end;
	}
	printf("%s\n", rrfrag_to_string(rrfrag));
	
	rc = clone_rrfrag(rrfrag, &rrfrag2);
	if (rc != 0) {
		destroy_rrfrag(&rrfrag);
		goto end;
	}
	if (!rrfrag_is_equal(rrfrag, rrfrag2)) {
		printf("Failed rrfrag equality check when it shouldn't have\n");
		rc = -1;
		goto end;
	}
	rrfrag2->curidx = 3;
	if (rrfrag_is_equal(rrfrag, rrfrag2)) {
		printf("Passed rrfrag equality check when it shouldn't have\n");
		rc = -1;
		goto end;
	}

	if (bytes_look_like_rrfrag(bytes)) {
		printf("Correctly identified an rrfrag from bytes\n");
	} else {
		printf("Failed to identify an rrfrag from bytes\n");
	}
	free(bytes);
	ResourceRecord *rr;
	unsigned char rdata = 0x08;
	rc = create_rr(&rr, name, 0, 1, 123, 1, &rdata);
	if (rc != 0) {
		goto end;
	}
	rc = rr_to_bytes(rr, &bytes, &byte_len);
	if (rc != 0) {
		destroy_rr(&rr);
		goto end;
	}
	if (!bytes_look_like_rrfrag(bytes)) {
		printf("Correctly identified bytes weren't an rrfrag\n");
	} else {
		printf("Failed to identify that bytes weren't an rrfrag\n");
	}
end:
	return rc;
}

int
test_packedrr(void) {
	int rc;
	
	ResourceRecord *rr;
	RRFrag *rrfrag;
	PackedRR *prr_rr;
	PackedRR *prr_rrfrag;
	unsigned char *bytes;
	size_t byte_len;
	size_t bytes_processed;
	unsigned char rdata[3] = {0x00, 0x01, 0x02};
	unsigned char fragdata[3] = {0x02, 0x01, 0x00};
	create_rr(&rr, "www.google.com.", 0x01, 0x02, 1234, 3, rdata);
	create_rrfrag(&rrfrag, "www.google.com.", 2, 0, 3, 123, fragdata);
	rc = create_packedrr((void *)rr, &prr_rr);
	if (rc != 0) {
		goto end;
	}
	rc = create_packedrr((void *)rrfrag, &prr_rrfrag);
	if (rc != 0) {
		goto end;
	}
	if (prr_rr->isRRFrag) {
		printf("packedrr reporting as rrfrag\n");
	}
	if (!prr_rrfrag ->isRRFrag) {
		printf("packedrrfrag not reporting as rrfrag\n");
	}
	rc = packedrr_to_bytes(prr_rr, &bytes, &byte_len);
	if (rc != 0) {
		goto end;
	}
	rc = destroy_packedrr(&prr_rr);
	if (rc != 0) {
		goto end;
	}
	bytes_to_packedrr(bytes, byte_len, &bytes_processed, &prr_rr);
	if (prr_rr->isRRFrag) {
		printf("packedrr reporting as rrfrag\n");
	}
	printf("%s", rr_to_string(prr_rr->data.rr));
	destroy_packedrr(&prr_rr);
	destroy_packedrr(&prr_rrfrag);
end:
	return rc;
}


int
test_dnsmessage(void) {
	printf("testing dnsmessage\n");
	printf("================================\n");
	int rc = 0;
	DNSMessage *msg0;
	Question **questions = malloc(sizeof(Question *) * 1);
	PackedRR **answers = malloc(sizeof(PackedRR *) * 3);
	PackedRR **authorities = NULL; // Empty section
	PackedRR **additionals = malloc(sizeof(PackedRR *) * 2);
	unsigned char data[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
	ResourceRecord *rr0;
	ResourceRecord *rr1;
	ResourceRecord *rr2;
	ResourceRecord *rr3;
	RRFrag *rrfrag0;
	create_question(questions + 0, "www.google.com.", 1, 2);
	create_rr(&rr0, "1.google.com.", 0, 1, 2, 1, data);
	create_rr(&rr1, "2.google.com.", 0, 1, 2, 2, data);
	create_rr(&rr2, "3.google.com.", 0, 1, 2, 3, data);
	create_rr(&rr3, "4.google.com.", 0, 1, 2, 4, data);
	create_rrfrag(&rrfrag0, ".", 5, 0, 5, 1234, data);

	create_packedrr(rr0, answers + 0);
	create_packedrr(rr1, answers + 1);
	create_packedrr(rr2, answers + 2);
	create_packedrr(rr3, additionals + 0);
	create_packedrr(rrfrag0, additionals + 1);
	create_dnsmessage(&msg0, 4321, 0x5, 1, 3, 0, 2, questions, answers, authorities, additionals);
	dnsmessage_to_string(msg0);
	unsigned char *bytes;
	size_t byte_len;
	dnsmessage_to_bytes(msg0, &bytes, &byte_len);
	destroy_dnsmessage(&msg0);
	bytes_to_dnsmessage(bytes, byte_len, &msg0);
	dnsmessage_to_string(msg0);
	return rc;


}

int
main(int argc, char **argv) {
	int rc;
	
	rc = test_dnsnames();
	if (rc < 0) {
		printf("Failed test_dnsnames\n");
		goto end;
	}
	
	rc = test_rr();
	if (rc < 0) {
		printf("Failed test_rr\n");
		goto end;
	}
	
	rc = test_question();
	if (rc < 0) {
		printf("Failed test_question\n");
		goto end;
	}
	rc = test_rrfrag();
	if (rc < 0) {
		printf("Failed test_frag\n");
		goto end;
	}
	rc = test_packedrr();
	if (rc < 0) {
		printf("Failed test_packedrr\n");
		goto end;
	}
	rc = test_dnsmessage();
	if (rc < 0) {
		printf("Failed test_packedrr\n");
		goto end;
	}
end:
	return rc;
}
