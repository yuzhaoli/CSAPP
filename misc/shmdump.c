#include "isa.h"
int main()
{
	system_status* sm=shm1();
	int i;
	printf("Status:\n");
	printf("hasMessage:%d\n", sm->hasMessage);
	printf("msgAddr:%x\n", sm->msgAddr);
	printf("pid:%d %d %d %d\n", sm->pid[0],sm->pid[1],sm->pid[2],sm->pid[3]);
	
	byte_t* m=(byte_t*) shm2();
	printf("SMEM Contents:\n");
	for(i=0;i<MEM_SIZE;i++)
	{
		if(m[i]!=0)
			printf("%d:%x\n",i,m[i]);
	}
	return 0;
}