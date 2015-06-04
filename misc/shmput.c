#include "isa.h"
int main()
{
	int i;
	byte_t* m=shm2();
	for(i=2048;i<2048+32;i++)
	{
		m[i]=i%32;
	}
	return 0;
}