#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

#include "dns.h"

const char *address_types[16] = {
  "A",
  "NS",
  "MD",
  "MF",
  "CNAME",
  "SOA",
  "MB",
  "MG",
  "MR",
  "NULL",
  "WKS",
  "PTR",
  "HINFO",
  "MINFO",
  "MX",
  "TXT"};

const char *address_classes[4] = {
  "IN",
  "CS",
  "CH",
  "HS"};

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

    *qname_p = len;                   /* set first byte to the length of the string */
    qname_p++;                        /* move forward one byte */
    strncpy(qname_p, token, len + 1); /* copy string to buffer; add 1 for null byte! */
    qname_p += len;                   /* increment pointer to null byte */

    token = strtok(NULL,delim);       /* get another token */
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
  const char *hostname;
  unsigned char *responsep = packet + query_length;

  DNS_header *response_header = malloc(sizeof(DNS_header));
  memcpy(response_header, packet, sizeof(DNS_header));

  int resource_records = ntohs(response_header->ancount);
  printf("resource records returned: %d\n", resource_records);

  int record_count = 0;
  while(record_count < resource_records && *responsep) {
    if(record_count) {
      printf("\n");
    }

    // check for pointer
    if (*responsep == 0xc0) {
      uint16_t offset = ntohs(*(uint16_t *)responsep) & 0x3fff ; /* remove pointer bits */
      hostname = parse_label(packet, offset);
    } else {
      hostname = parse_label(packet, query_length);
    }

    printf("%-10s %s\n", ">> FQDN:", hostname); 
    responsep += strlen((const char *)responsep);

    uint16_t type = ntohs(*(uint16_t *)responsep);
    printf("%-10s %s\n", ">> TYPE:", address_types[type - 1]);
    responsep += 2;

    uint16_t class = ntohs(*(uint16_t *)responsep);
    printf("%-10s %s\n", ">> TYPE:", address_classes[class - 1]);
    responsep += 2;

    uint32_t ttl = ntohs(*(uint32_t *)responsep);
    printf("%-10s %u\n", ">> TTL:", ttl);
    responsep += 4;

    uint16_t rdlength = ntohs(*(uint16_t *)responsep);
    printf("%-10s %hu\n", ">> RDLENGTH:", rdlength);
    responsep += 2;

    printf("%-10s", ">> RDATA");
    for(int i = 0; i < rdlength; i++) {
      if(i) {
        putchar('.');
      }

      printf("%d", *responsep);
      responsep++;
    }
    putchar('\n');
    record_count++;
    free((void *)hostname);
  }

  free(response_header);
}

const char *parse_label(unsigned char *packet, uint16_t offset) {
  size_t packet_label_length = strlen((const char *)&packet[offset]);
  char *string = calloc(packet_label_length, sizeof(char));

  unsigned char *labelp = &packet[offset];
  int i = 0; /* index var for position in string */

  while(*labelp) {
    if(i) {
      string[i++] = '.'; // add a dot if we're not at the beginning of the string
    }
    memcpy(string + i, labelp + 1, *labelp); /* copy the bytes following the length prefix */
    i += *labelp;                            /* increment string index by length prefix */
    labelp += *labelp + 1;                   /* increment labelp to the next length prefix byte */
  }

  return (const char *)string;
}
