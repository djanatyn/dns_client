#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"


void die(char *s) {
  perror(s);
  exit(1);
}

void write_buffer(unsigned char *buffer, size_t len, const char *filename) {
  FILE *fp = fopen(filename,"w");
  if(fp == NULL) {
    die("unable to open file");
  }

  if(fwrite(buffer, sizeof(char), len, fp) == -1) {
    die("error opening file");
  }

  fclose(fp);
}

int main(int argc, char *argv[]) {

  char hostname[MAX_HOSTNAME_LENGTH + 1];
  unsigned char response[BUFLEN];
  unsigned char *packet;

  const char response_output_file[] = "out/response.payload";
  const char query_output_file[] = "out/query.payload";

  int sockfd;
  struct sockaddr_in google_addr;
  unsigned int slen = sizeof(google_addr);
  int rlen;

  // parse command line options
  if(argc != 2) {
    printf("usage: %s <hostname>\n", argv[0]);
    return 1;
  }

  // check length of hostname
  if(strlen(argv[1]) > MAX_HOSTNAME_LENGTH) {
    printf("hostname must be less than %d characters\n", MAX_HOSTNAME_LENGTH);
    return 1;
  }

  // strcpy woooo (this is maybe unecessary)
  strcpy(hostname, argv[1]);

  printf(">> Querying hostname: %s\n", hostname);

  // create socket
  if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    die("could not create socket");
  }

  // create address for google's DNS server
  google_addr.sin_family = AF_INET;
  google_addr.sin_port   = htons(53);
  google_addr.sin_addr.s_addr = inet_addr("8.8.8.8");
  memset(&google_addr.sin_zero, 0, sizeof(google_addr.sin_zero));

  // generate UDP payload
  DNS_header *header = create_request_header(); 
  DNS_question *question = create_question(hostname);
  size_t packet_length = build_packet(header, question, &packet);

  // write packet
  write_buffer(packet, packet_length, query_output_file);

  free(header);
  free(question);

  // tell google hello
  if (sendto(sockfd, packet, packet_length, 0, (struct sockaddr *) &google_addr, slen) == -1) {
    die("error sending to google");
  }
  printf(">> Waiting for response...\n");

  if ((rlen = recvfrom(sockfd, response, BUFLEN, 0, (struct sockaddr *) &google_addr, &slen)) == -1) {
    die("error receiving from google");
  }
  printf(">> %d bytes received.\n", rlen);

  // write packet
  write_buffer(response, rlen, response_output_file);

  // start parsing the response
  printf(">> Parsing response...\n\n");
  parse_packet(packet_length, response);
  free(packet);

  return 0;
}
