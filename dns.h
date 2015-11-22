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

  return question;
}

size_t build_packet(DNS_header *header, DNS_question *question, char **packet) {
  size_t length = sizeof(DNS_header) + sizeof(DNS_question) + question->length;
  *packet = malloc(length);

  // copy into packet byte array
  char *offset = *packet;
  memcpy(offset, header, sizeof(DNS_header));
  offset += sizeof(DNS_header);
  memcpy(offset, question->qname, question->length);
  offset += question->length;
  memcpy(offset, &question->qtype, sizeof(question->qtype)); 
  offset += sizeof(question->qtype);
  memcpy(offset, &question->qclass, sizeof(question->qclass)); 

  return length;
}

#endif