#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_HOSTNAME_LENGTH 64
#define BUFLEN 512
#define REQUEST_LENGTH 42

void die(char *s) {
  perror(s);
  exit(1);
}

int main(int argc, char *argv[]) {

  char hostname[MAX_HOSTNAME_LENGTH];
  char request[BUFLEN];
  char response[BUFLEN];

  int sockfd;
  struct sockaddr_in google_addr;
  int slen = sizeof(google_addr);
  int rlen;

  // read DNS request into request
  FILE *fp = fopen("dns_request","r");
  if (fp != NULL) {
    fread(request, sizeof(char), BUFLEN, fp);
  }

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

  // tell google hello
  if (sendto(sockfd, request, REQUEST_LENGTH, 0, (struct sockaddr *) &google_addr, slen) == -1) {
    die("error sending to google");
  }

  if ((rlen = recvfrom(sockfd, response, BUFLEN, 0, (struct sockaddr *) &google_addr, &slen)) == -1) {
    die("error receiving from google");
  }
  
  printf("%d bytes received\n\n", rlen);

  fwrite(response, sizeof(char), rlen, stdout);
  exit(0);
}
