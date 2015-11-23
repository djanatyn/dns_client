#ifndef __DNS_STRUCTS_H__
#define __DNS_STRUCTS_H__

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} DNS_header;

typedef struct {
  size_t length;
  uint16_t qtype;
  uint16_t qclass;
  char qname[];
} DNS_question;

DNS_header *create_request_header() {
  srandom(time(NULL));

  DNS_header *header = malloc(sizeof(DNS_header));
  memset(header,0,sizeof(DNS_header));

  header->id = random();

  header->flags |= htons(0x0100); /* bitmask to turn on recursion desired */
  header->qdcount = htons(1);     /* one query (currently) */
  
  return header;
}

DNS_question *create_question(const char *hostname) {
  DNS_question *question = malloc(sizeof(DNS_question) + strlen(hostname) + 2);

  // the amount of memory needed to QNAME label of an FQDN of length n
  // characters is always n + 2.
  // 
  // there is an initial length prefix added to the first string of
  // characters, as well as an additional null byte at the end.
  question->length = strlen(hostname) + 2;
  question->qtype  = htons(1);
  question->qclass = htons(1);

  char *token;
  const char delim[2] = ".";

  char *hostname_dup = strdup(hostname);
  token = strtok(hostname_dup, delim);

  char *qname_p = &question->qname[0];
  while(token != NULL) {
    size_t len = strlen(token);

    *qname_p = len;               /* set first byte to the length of the string */
    qname_p++;                    /* move forward one byte */
    strncpy(qname_p, token, len); /* copy string to buffer */
    qname_p += len;               /* increment pointer to null byte */

    token = strtok(NULL,delim);   /* get another token */
  }

  free(hostname_dup);
  return question;
}

size_t build_packet(DNS_header *header, DNS_question *question, unsigned char **packet) {
  size_t header_s = sizeof(DNS_header);
  size_t question_s = question->length + sizeof(question->qtype) + sizeof(question->qclass);
  size_t length = header_s + question_s;

  *packet = malloc(length);

  // copy into packet byte array
  int offset = 0;
  memcpy(*packet + offset, header, sizeof(DNS_header));
  offset += sizeof(DNS_header);
  memcpy(*packet + offset, question->qname, question->length);
  offset += question->length;
  memcpy(*packet + offset, &question->qtype, sizeof(question->qtype)); 
  offset += sizeof(question->qtype);
  memcpy(*packet + offset, &question->qclass, sizeof(question->qclass)); 

  return length;
}

void parse_packet(size_t query_length, unsigned char *packet) {
  unsigned char *responsep = packet + query_length;

  DNS_header *response_header = malloc(sizeof(DNS_header));
  memcpy(response_header, packet, sizeof(DNS_header));

  int resource_records = ntohs(response_header->ancount);
  printf("resource records returned: %d\n", resource_records);

  // parse NAME in RR
  while(*responsep) {
    if (*responsep == 0xc0) {
      printf("found pointer!\n");
      uint16_t offset = ntohs(*(uint16_t *)responsep) & 0x3fff ; /* remove pointer bits */
      break;
    }
  }

  free(response_header);
}

#endif
