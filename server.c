#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <map>
#include <vector>
#include "./rand.h"
# ifdef _WIN32
#  include <memory.h>
# endif
#include <openssl/seed.h>

const unsigned char userKey[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15} ;

char* base;

char* end;

int main(void)
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

unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };

  unsigned char ciphertext[16];

  SEED_KEY_SCHEDULE kd;

  SEED_set_key(userKey,&kd);

uint64_t min_time = rdtsc();

  srand(min_time);

  int sockfd = 0,n = 0;

unsigned  char recvBuff[16];

  struct sockaddr_in serv_addr;

  memset(recvBuff, '0' ,sizeof(recvBuff));

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0))< 0)

    {
      printf("\n Error : Could not create socket \n");
      return 1;

    }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(5000);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0)

    {
      printf("\n Error : Connect Failed \n");
      return 1;

    }

while (read(sockfd, recvBuff, sizeof(recvBuff)) > 0){

   for (size_t j = 0; j < 16; ++j)

    plaintext[j] = rand() % 256;

       SEED_encrypt(plaintext,ciphertext, &kd);

      write(sockfd,ciphertext ,sizeof (ciphertext));

}

close(fd);
  munmap(base, map_size);
  fflush(stdout);
  return 0;
}
