#include "isa.h"
int main()
{
	void* m=shm1();
	memset(m,0,32);
	void* m=shm2();
	return memset(m,0,MEM_SIZE);
}