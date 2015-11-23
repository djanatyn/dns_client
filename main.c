#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <stdbool.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"

#define MAX_HOSTNAME_LENGTH 64
#define BUFLEN 512

void die(char *s) {
  perror(s);
  exit(1);
}

int main(int argc, char *argv[]) {

  char hostname[MAX_HOSTNAME_LENGTH + 1];
  unsigned char response[BUFLEN];
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

  printf("Querying hostname: %s\n\n", hostname);

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
  unsigned char *packet;
  size_t packet_length = build_packet(header, question, &packet);
  free(header);
  free(question);

  printf("writing query to %s\n", query_output_file);
  FILE *qp = fopen(query_output_file,"w");
  fwrite(packet, sizeof(char), packet_length, qp);
  fclose(qp);

  // tell google hello
  if (sendto(sockfd, packet, packet_length, 0, (struct sockaddr *) &google_addr, slen) == -1) {
    die("error sending to google");
  }

  printf("waiting for response...\n");

  if ((rlen = recvfrom(sockfd, response, BUFLEN, 0, (struct sockaddr *) &google_addr, &slen)) == -1) {
    die("error receiving from google");
  }

  printf("\n%d bytes received\n", rlen);

  printf("writing response to %s\n", response_output_file);
  FILE *rp = fopen(response_output_file,"w");
  fwrite(response, sizeof(char), rlen, rp);
  fclose(rp);

  // start parsing the response
  printf("parsing response...\n\n");

  parse_packet(packet_length, response);

  free(packet);

  return 0;
}
