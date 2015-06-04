#include "isa.h"
int main()
{
	byte_t* m=shm1();
	int i;
	memset(m,0,sizeof(system_status));
	m=shm2();
	printf("SMEM Contents:\n");
	for(i=0;i<MEM_SIZE;i++)
	{
		if(m[i]!=0)
			printf("%d:%x\n",i,m[i]);
	}
	printf("SMEM Cleared.\n");
	return memset(m,0,MEM_SIZE);
}