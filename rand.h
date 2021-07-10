#ifndef CACHEUTILS_H
#define CACHEUTILS_H

#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))


unsigned long long rdtsc() {
	unsigned long long a, d;
	asm volatile ("mfence");
	asm volatile ("rdtsc" : "=a" (a), "=d" (d));
	a = (d<<32) | a;
	
	asm volatile ("mfence");
	return a;
}



#endif


