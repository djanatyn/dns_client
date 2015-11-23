#ifndef __DNS_STRUCTS_H__
#define __DNS_STRUCTS_H__

#include <stdint.h>
#include <stdlib.h>

#define MAX_HOSTNAME_LENGTH 64
#define BUFLEN 512

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

DNS_header *create_request_header(); 
DNS_question *create_question(const char *hostname);

size_t build_packet(DNS_header *header, DNS_question *question, unsigned char **packet);

void parse_packet(size_t query_length, unsigned char *packet);
const char *parse_label(unsigned char *packet, uint16_t offset);

#endif
