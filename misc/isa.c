#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "isa.h"

//for flie locking:
#include <fcntl.h>
#include <unistd.h>
#ifndef lockfile
#define lockfile "/var/lock/CSAPP_testset.lock"
#endif

/* Are we running in GUI mode? */
extern int gui_mode;

/* Bytes Per Line = Block size of memory */
#define BPL 32
//kAc Marked at 21:00, 5.16
//这个结构表示了每个寄存器的名称，标号
//保留
struct {
    char *name;
    int id;
} reg_table[REG_ERR+1] = 
{
    {"%eax",   REG_EAX},
    {"%ecx",   REG_ECX},
    {"%edx",   REG_EDX},
    {"%ebx",   REG_EBX},
    {"%esp",   REG_ESP},
    {"%ebp",   REG_EBP},
    {"%esi",   REG_ESI},
    {"%edi",   REG_EDI},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_ERR},
    {"----",  REG_NONE},
    {"----",  REG_ERR}
};

//kAc Marked at 21:00, 5.16
//Name->标号
//保留
reg_id_t find_register(char *name)
{
    int i;
    for (i = 0; i < REG_NONE; i++)
	if (!strcmp(name, reg_table[i].name))
	    return reg_table[i].id;
    return REG_ERR;
}
//kAc Marked at 21:00, 5.16
//标号->Name
//保留
char *reg_name(reg_id_t id)
{
    if (id >= 0 && id < REG_NONE)
	return reg_table[id].name;
    else
	return reg_table[REG_NONE].name;
}

//kAc Marked at 21:00, 5.16
//通过标号判断寄存器的合法性
//保留
/* Is the given register ID a valid program register? */
int reg_valid(reg_id_t id)
{
  return id >= 0 && id < REG_NONE && reg_table[id].id == id;
}
//kAc Marked at 21:00, 5.16
//所有的指令
//需要添加指令
instr_t instruction_set[] = 
{
    {"nop",    HPACK(I_NOP, F_NONE), 1, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    {"halt",   HPACK(I_HALT, F_NONE), 1, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    {"rrmovl", HPACK(I_RRMOVL, F_NONE), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    /* Conditional move instructions are variants of RRMOVL */
    {"cmovle", HPACK(I_RRMOVL, C_LE), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmovl", HPACK(I_RRMOVL, C_L), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmove", HPACK(I_RRMOVL, C_E), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmovne", HPACK(I_RRMOVL, C_NE), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmovge", HPACK(I_RRMOVL, C_GE), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"cmovg", HPACK(I_RRMOVL, C_G), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    /* arg1hi indicates number of bytes */
    {"irmovl", HPACK(I_IRMOVL, F_NONE), 6, I_ARG, 2, 4, R_ARG, 1, 0 },
    {"rmmovl", HPACK(I_RMMOVL, F_NONE), 6, R_ARG, 1, 1, M_ARG, 1, 0 },
    {"mrmovl", HPACK(I_MRMOVL, F_NONE), 6, M_ARG, 1, 0, R_ARG, 1, 1 },
    {"addl",   HPACK(I_ALU, A_ADD), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"subl",   HPACK(I_ALU, A_SUB), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"andl",   HPACK(I_ALU, A_AND), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    {"xorl",   HPACK(I_ALU, A_XOR), 2, R_ARG, 1, 1, R_ARG, 1, 0 },
    /* arg1hi indicates number of bytes */
    {"jmp",    HPACK(I_JMP, C_YES), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jle",    HPACK(I_JMP, C_LE), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jl",     HPACK(I_JMP, C_L), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"je",     HPACK(I_JMP, C_E), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jne",    HPACK(I_JMP, C_NE), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jge",    HPACK(I_JMP, C_GE), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"jg",     HPACK(I_JMP, C_G), 5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"call",   HPACK(I_CALL, F_NONE),    5, I_ARG, 1, 4, NO_ARG, 0, 0 },
    {"ret",    HPACK(I_RET, F_NONE), 1, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    {"pushl",  HPACK(I_PUSHL, F_NONE) , 2, R_ARG, 1, 1, NO_ARG, 0, 0 },
    {"popl",   HPACK(I_POPL, F_NONE) ,  2, R_ARG, 1, 1, NO_ARG, 0, 0 },
    {"iaddl",  HPACK(I_IADDL, F_NONE), 6, I_ARG, 2, 4, R_ARG, 1, 0 },
    {"leave",  HPACK(I_LEAVE, F_NONE), 1, NO_ARG, 0, 0, NO_ARG, 0, 0 },
    /* test&set is similar to mrmovl */
    {"testset",   HPACK(I_TESTSET, F_NONE) , 6, M_ARG, 1, 0, R_ARG, 1, 1 },

    /* For allocation instructions, arg1hi indicates number of bytes */
    {".byte",  0x00, 1, I_ARG, 0, 1, NO_ARG, 0, 0 },
    {".word",  0x00, 2, I_ARG, 0, 2, NO_ARG, 0, 0 },
    {".long",  0x00, 4, I_ARG, 0, 4, NO_ARG, 0, 0 },
    {NULL,     0   , 0, NO_ARG, 0, 0, NO_ARG, 0, 0 }
};
//kAc Marked at 21:00, 5.16
//不合法指令
//保留
instr_t invalid_instr =
    {"XXX",     0   , 0, NO_ARG, 0, 0, NO_ARG, 0, 0 };
//kAc Marked at 21:00, 5.16
//名字->指令ID
//保留
instr_ptr find_instr(char *name)
{
    int i;
    for (i = 0; instruction_set[i].name; i++)
	if (strcmp(instruction_set[i].name,name) == 0)
	    return &instruction_set[i];
    return NULL;
}

//kAc Marked at 21:00, 5.16
//指令ID->名字
//保留
/* Return name of instruction given its encoding */
char *iname(int instr) {
    int i;
    for (i = 0; instruction_set[i].name; i++) {
	if (instr == instruction_set[i].code)
	    return instruction_set[i].name;
    }
    return "<bad>";
}


instr_ptr bad_instr()
{
    return &invalid_instr;
}


#define L1line (8)
#define L1size (16*L1line)

cache_line L1Cache[L1size];
/*
  Started IPC section!
  shm1: for IPC, using struct IPCaddr
  shm2: the "memory"
*/
void* shm1(){
	int shmid;
	const int SHMSZ=sizeof(system_status);
    char *shm;
    if ((shmid = shmget(SHMKEY1, SHMSZ, IPC_CREAT | 0666)) < 0) {
        perror("shmget");
        exit(1);
    }
    if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
        perror("shmat");
        exit(1);
    }
    return shm;
}
void* shm2(){
	int shmid;
	const int SHMSZ=MEM_SIZE;
    char *shm;
    if ((shmid = shmget(SHMKEY2, SHMSZ, IPC_CREAT | 0666)) < 0) {
        perror("shmget");
        exit(1);
    }
    if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
        perror("shmat");
        exit(1);
    }
    return shm;
}
system_status *SYS;
#ifdef CORE0
const int coreid=0;
const int IS_MULTICORE=1;
#endif
#ifdef CORE1
const int coreid=1;
const int IS_MULTICORE=1;
#endif
#ifndef CORE0
#ifndef CORE1
	const int coreid=-1;
	const int IS_MULTICORE=0;
#endif
#endif
/*typedef struct {
	//each consists of 1 word
  char hasMessage;
  int msgAddr;
  int msgVal;
  int pid[4];//pid position for each core; core=2?
} system_status;*/
void take_msg()
{
	int addr=SYS->msgAddr;
	int cont=SYS->msgVal;
	int lpos=addr%L1size;
	if(L1Cache[lpos].isValid==1 && L1Cache[lpos].myAddr==addr)
	{
		L1Cache[lpos].myContent=cont;
		L1Cache[lpos].isDirty=0;
		//do mem update!
	}
	else
	{
		//update miss; do nothing.
	}
	SYS->hasMessage=0;
}
int peer_pid()
{
	int pid=0;
	if(coreid==0)pid=SYS->pid[1];
	if(coreid==1)pid=SYS->pid[0];
	return pid;
}
void sig_send(){
	int ret;
	ret = kill(peer_pid(),SIGUSR1);
	printf("signal sent; ret : %d\n",ret);
}
void send_msg(int addr, int value)
{
	//while(SYS->hasMessage)
	//{
	//	take_msg();usleep(1);
	//}
	//SYS->hasMessage=1;
	while(__sync_lock_test_and_set(&SYS->hasMessage,1)){
		take_msg();usleep(1);
	}
	//assert hasMessage=1
	if(SYS->hasMessage!=1)
	{
		printf("Test&Set failed?\n");exit(1);
	}
	if(peer_pid()==0){SYS->hasMessage=0;return;}//no one to receive the message...
	SYS->msgAddr=addr;
	SYS->msgVal=value;
	sig_send();
	while(SYS->hasMessage==1)
	{
		usleep(10);
	}
}

void sig_handler(int signo)
{
    if (signo == SIGUSR1)
	{
        printf("received SIGUSR1\n");
		while(SYS->hasMessage)take_msg();
	}
}

void IPC_start()
{
	if(IS_MULTICORE==0)return;
	int pid=getpid();
	
	printf("Initializing Multicore mode; I'm core#%d, pid#%d\n",coreid,pid);
	SYS=shm1();
	SYS->pid[coreid]=pid;
	
	
    if (signal(SIGUSR1, sig_handler) == SIG_ERR)
	{
        printf("\nCan't register listener for SIGUSR1??\n");
		exit(-1);
	}
	
	//debug!!
	//send_msg(1024+coreid*4,0xff);
}

//kAc Marked at 21:00, 5.16
//得到一个初始化过的内存，共计len个byte
//分配一段内存
//待定
mem_t init_mem(int len)
{
    mem_t result = (mem_t) malloc(sizeof(mem_rec));
    len = ((len+BPL-1)/BPL)*BPL;
    result->len = len;
	if(len>32)//not register
	{
		//result->L1cache=(cache_line*) calloc(L1size,sizeof(cache_line));
		memset(L1Cache,0,sizeof(L1Cache));
		//this is the initialization of a CPU!
		result->contents=(byte_t *) shm2();
	}
	else
	{
		result->contents = (byte_t *) calloc(len, 1);
		IPC_start();
	}
    return result;
}

//kAc Marked at 21:00, 5.16
//将一段内存清零
//待定
void clear_mem(mem_t m)
{
    memset(m->contents, 0, m->len);
	memset(L1Cache,0,sizeof(L1Cache));
}
//kAc Marked at 21:00, 5.16
//释放一段内存
//待定
void free_mem(mem_t m)
{
	int i;
    //if((byte_t *)m->contents != (byte_t *)shm2())
	//	free((void *) m->contents);
	if(m->len==32)
		free((void *) m->contents);
	else
	if((byte_t *)m->contents == (byte_t *)shm2())
	{
		//cache write-back!
		printf("Freeing SHMEM; writing back L1 cache...\n");
		for(i=0;i<L1size;i++)
		{
			if(L1Cache[i].isValid && L1Cache[i].isDirty)
				m->contents[L1Cache[i].myAddr]=L1Cache[i].myContent;
		}
	}
	//do not free the shared-memory pointer!
    free((void *) m);
}
//kAc Marked at 21:00, 5.16
//两片内存复制
//待定
/*
mem_t copy_mem(mem_t oldm)//for backup only; copy into raw mem
{
	mem_t newm = (mem_t) malloc(sizeof(mem_rec));
	int len=oldm->len;
    len = ((len+BPL-1)/BPL)*BPL;
    newm->len = len;
    newm->contents = (byte_t *) calloc(len, 1);
    memcpy(newm->contents, oldm->contents, oldm->len);
    return newm;
}*/
//kAc Marked at 21:00, 5.16
//比较两片内存，并将结果存至outfile
//待定
bool_t diff_mem(mem_t oldm, mem_t newm, FILE *outfile)
{
    word_t pos;
    int len = MEM_SIZE;//oldm->len;
    bool_t diff = FALSE;
    //if (newm->len < len)
	//len = newm->len;
    for (pos = 0; (!diff || outfile) && pos < len; pos += 4) {
        word_t ov = 0;  word_t nv = 0;
	//get_word_val(oldm, pos, &ov);
	//get_word_val(newm, pos, &nv);
	//will be affected by L1 cache...
	ov=oldm->contents[pos];
	nv=newm->contents[pos];
	if (nv != ov) {
	    diff = TRUE;
	    if (outfile)
		fprintf(outfile, "0x%.4x:\t0x%.8x\t0x%.8x\n", pos, ov, nv);
	}
    }
    return diff;
}

//kAc Marked at 21:00, 5.16
//16进制char->int
//保留
int hex2dig(char c)
{
    if (isdigit((int)c))
	return c - '0';
    if (isupper((int)c))
	return c - 'A' + 10;
    else
	return c - 'a' + 10;
}

//kAc Marked at 21:00, 5.16
//使用文件初始化内存
//待定
#define LINELEN 4096
int load_mem(mem_t m, FILE *infile, int report_error)
{
    /* Read contents of .yo file */
    char buf[LINELEN];
    char c, ch, cl;
    int byte_cnt = 0;
    int lineno = 0;
    word_t bytepos = 0;
    int empty_line = 1;
    int addr = 0;
    char hexcode[15];

#ifdef HAS_GUI
    /* For display */
    int line_no = 0;
    char line[LINELEN];
#endif /* HAS_GUI */   

    int index = 0;

    while (fgets(buf, LINELEN, infile)) {
	int cpos = 0;
	empty_line = 1;
	lineno++;
	/* Skip white space */
	while (isspace((int)buf[cpos]))
	    cpos++;

	if (buf[cpos] != '0' ||
	    (buf[cpos+1] != 'x' && buf[cpos+1] != 'X'))
	    continue; /* Skip this line */      
	cpos+=2;

	/* Get address */
	bytepos = 0;
	while (isxdigit((int)(c=buf[cpos]))) {
	    cpos++;
	    bytepos = bytepos*16 + hex2dig(c);
	}

	while (isspace((int)buf[cpos]))
	    cpos++;

	if (buf[cpos++] != ':') {
	    if (report_error) {
		fprintf(stderr, "Error reading file. Expected colon\n");
		fprintf(stderr, "Line %d:%s\n", lineno, buf);
		fprintf(stderr,
			"Reading '%c' at position %d\n", buf[cpos], cpos);
	    }
	    return 0;
	}

	addr = bytepos;

	while (isspace((int)buf[cpos]))
	    cpos++;

	index = 0;

	/* Get code */
	while (isxdigit((int)(ch=buf[cpos++])) && 
	       isxdigit((int)(cl=buf[cpos++]))) {
	    byte_t byte = 0;
	    if (bytepos >= m->len) {
		if (report_error) {
		    fprintf(stderr,
			    "Error reading file. Invalid address. 0x%x\n",
			    bytepos);
		    fprintf(stderr, "Line %d:%s\n", lineno, buf);
		}
		return 0;
	    }
	    byte = hex2dig(ch)*16+hex2dig(cl);
//kAc Marked at 21:00, 5.16
//潜在的被修改的地方
	    m->contents[bytepos++] = byte;
	    byte_cnt++;
	    empty_line = 0;
	    hexcode[index++] = ch;
	    hexcode[index++] = cl;
	}
	/* Fill rest of hexcode with blanks */
	for (; index < 12; index++)
	    hexcode[index] = ' ';
	hexcode[index] = '\0';

#ifdef HAS_GUI
	if (gui_mode) {
	    /* Now get the rest of the line */
	    while (isspace((int)buf[cpos]))
		cpos++;
	    cpos++; /* Skip over '|' */
	    
	    index = 0;
	    while ((c = buf[cpos++]) != '\0' && c != '\n') {
		line[index++] = c;
	    }
	    line[index] = '\0';
	    if (!empty_line)
		report_line(line_no++, addr, hexcode, line);
	}
#endif /* HAS_GUI */ 
    }
    return byte_cnt;
}

int load_mem_raw(mem_t m, FILE *infile, int report_error)//for backup diff; no GUI considerations
{
    /* Read contents of .yo file */
    char buf[LINELEN];
    char c, ch, cl;
    int byte_cnt = 0;
    int lineno = 0;
    word_t bytepos = 0;

    int index = 0;

    while (fgets(buf, LINELEN, infile)) {
	int cpos = 0;
	lineno++;
	/* Skip white space */
	while (isspace((int)buf[cpos]))
	    cpos++;

	if (buf[cpos] != '0' ||
	    (buf[cpos+1] != 'x' && buf[cpos+1] != 'X'))
	    continue; /* Skip this line */      
	cpos+=2;

	/* Get address */
	bytepos = 0;
	while (isxdigit((int)(c=buf[cpos]))) {
	    cpos++;
	    bytepos = bytepos*16 + hex2dig(c);
	}

	while (isspace((int)buf[cpos]))
	    cpos++;

	if (buf[cpos++] != ':') {
	    if (report_error) {
		fprintf(stderr, "Error reading file. Expected colon\n");
		fprintf(stderr, "Line %d:%s\n", lineno, buf);
		fprintf(stderr,
			"Reading '%c' at position %d\n", buf[cpos], cpos);
	    }
	    return 0;
	}

	while (isspace((int)buf[cpos]))
	    cpos++;

	index = 0;

	/* Get code */
	while (isxdigit((int)(ch=buf[cpos++])) && 
	       isxdigit((int)(cl=buf[cpos++]))) {
	    byte_t byte = 0;
	    if (bytepos >= m->len) {
		if (report_error) {
		    fprintf(stderr,
			    "Error reading file. Invalid address. 0x%x\n",
			    bytepos);
		    fprintf(stderr, "Line %d:%s\n", lineno, buf);
		}
		return 0;
	    }
	    byte = hex2dig(ch)*16+hex2dig(cl);
//kAc Marked at 21:00, 5.16
//潜在的被修改的地方
	    m->contents[bytepos++] = byte;
	    byte_cnt++;
		index+=2;
	}
	/* Fill rest of hexcode with blanks */
    }
    return byte_cnt;
}

//kAc Marked at 21:00, 5.16
//得到m在pos位置的byte，放到dest，如果越界则返回FALSE
//修改
//bool_t get_byte_val(mem_t m, word_t pos, byte_t *dest)
//{
//    if (pos < 0 || pos >= m->len)
//	return FALSE;
//    *dest = m->contents[pos];
//    return TRUE;
//}
bool_t get_byte_val(mem_t m, word_t pos, byte_t *dest)
{
	word_t cache_pos=pos%L1size;
	word_t pi,p0;
    if (pos < 0 || pos >= m->len)
	return FALSE;
	if(m->len<=32)//is register
	{
		*dest = m->contents[pos];
		return TRUE;
	}
	
	if(L1Cache[cache_pos].isValid==1 && L1Cache[cache_pos].myAddr==pos)//hit?
	{
		*dest=L1Cache[cache_pos].myContent;
	}
	else//miss
	{
		//before eviction, need to write-back
		p0=L1line*(pos/L1line);
		for(pi=p0;pi<p0+L1line;pi++)
		{
			cache_pos=pi%L1size;
			if(L1Cache[cache_pos].isValid==1 && L1Cache[cache_pos].isDirty==1)
			{
				m->contents[ 
					L1Cache[cache_pos].myAddr
				]=L1Cache[cache_pos].myContent;
			}
			L1Cache[cache_pos].isDirty=0;
			L1Cache[cache_pos].isValid=1;
			L1Cache[cache_pos].myAddr=pi;
			L1Cache[cache_pos].myContent=m->contents[pi];
		}
		
		cache_pos=pos%L1size;
		*dest=L1Cache[cache_pos].myContent;
	}
    return TRUE;
}

//kAc Marked at 21:00, 5.16
//得到m在pos位置的word，放到dest，如果越界则返回FALSE
//修改

bool_t get_word_val(mem_t m, word_t pos, word_t *dest)
{
    int i;
    word_t val;
    if (pos < 0 || pos + 4 > m->len)
	return FALSE;
    val = 0;
    for (i = 0; i < 4; i++)
	//val = val | m->contents[pos+i]<<(8*i);
	{
		byte_t curr;
		get_byte_val(m, pos+i, &curr);
		val = val | curr<<(8*i);
	}
    *dest = val;
    return TRUE;
}

//kAc Marked at 21:00, 5.16
//修改m在pos位置的byte为val，如果越界则返回FALSE
//修改
//bool_t set_byte_val(mem_t m, word_t pos, byte_t val)
//{
//    if (pos < 0 || pos >= m->len)
//	return FALSE;
//    m->contents[pos] = val;
//    return TRUE;
//}
bool_t set_byte_val(mem_t m, word_t pos, byte_t val)
{
	word_t cache_pos=pos%L1size;
    if (pos < 0 || pos >= m->len)
	return FALSE;
	if(m->len<=32)//is register
	{
		m->contents[pos] = val;
		return TRUE;
	}
	
	if(L1Cache[cache_pos].isValid==1 && L1Cache[cache_pos].myAddr==pos)//hit?
	{
		//broadcast? only when clean->dirty! or always! (note: it's possible that A read, A write, dirty, then B read, then A write (should also broadcast here); )
		L1Cache[cache_pos].isDirty=1;
		L1Cache[cache_pos].myContent=val;
		send_msg(pos,val);
		//broadcast??
	}
	else
	{
		//before eviction, need to write-back; no need to writeback whole cacheline!
		if(L1Cache[cache_pos].isValid==1 &&L1Cache[cache_pos].isDirty==1)
		{
			m->contents[ 
				L1Cache[cache_pos].myAddr
			]=L1Cache[cache_pos].myContent;
		}
		
		cache_pos=pos%L1size;
		
		//fill a byte, or a line? 16?
		L1Cache[cache_pos].isDirty=1;
		L1Cache[cache_pos].isValid=1;
		L1Cache[cache_pos].myAddr=pos;
		//also need to broadcast
		L1Cache[cache_pos].myContent=val;
		send_msg(pos,val);
	}
    return TRUE;
}

//test&set
bool_t testset_byte_val(mem_t m, byte_t pos, byte_t *dest)
{
	int fd;
	struct flock fl = {F_WRLCK, SEEK_SET,   0,      0,     0 };
	
    if (pos < 0 || pos >= m->len)
	return FALSE;

	fd = open(lockfile, O_CREAT | O_RDWR);
    fcntl(fd, F_SETLKW, &fl);
	//*dest = m->contents[pos];
    //m->contents[pos] = 1;
	get_byte_val(m,pos,dest);
	set_byte_val(m,pos,1);
	
	fl.l_type = F_UNLCK;
    fcntl(fd, F_SETLK, &fl);
    return TRUE;
}
//kAc Marked at 21:00, 5.16
//修改m在pos位置的word为val，如果越界则返回FALSE
//修改
bool_t set_word_val(mem_t m, word_t pos, word_t val)
{
    int i;
    if (pos < 0 || pos + 4 > m->len)
	return FALSE;
    for (i = 0; i < 4; i++) {
	//m->contents[pos+i] = val & 0xFF;
	set_byte_val(m, pos+i, val & 0xFF);
	val >>= 8;
    }
    return TRUE;
}
//kAc Marked at 21:00, 5.16
//将m中的内容输出到outfile中
//从pos位置开始输出，共len个bit
//待定

void dump_memory(FILE *outfile, mem_t m, word_t pos, int len)
{
    int i, j;
    while (pos % BPL) {
	pos --;
	len ++;
    }

    len = ((len+BPL-1)/BPL)*BPL;

    if (pos+len > m->len)
	len = m->len-pos;

    for (i = 0; i < len; i+=BPL) {
	word_t val = 0;
	fprintf(outfile, "0x%.4x:", pos+i);
	for (j = 0; j < BPL; j+= 4) {
	    get_word_val(m, pos+i+j, &val);
	    fprintf(outfile, " %.8x", val);
	}
    }
}
mem_t raw_init_mem(int len)
{
    mem_t result = (mem_t) malloc(sizeof(mem_rec));
    len = ((len+BPL-1)/BPL)*BPL;
    result->len = len;
	result->contents=calloc(len,1);
	return result;
}
//kAc Marked at 21:00, 5.16
//关于寄存器file的操作
//保留
mem_t init_reg()
{
    return raw_init_mem(32);
}

void free_reg(mem_t r)
{
    free_mem(r);
}

mem_t copy_reg(mem_t oldr)
{
	mem_t newm = raw_init_mem(oldr->len);
    memcpy(newm->contents, oldr->contents, oldr->len);
    return newm;
}

bool_t diff_reg(mem_t oldr, mem_t newr, FILE *outfile)
{
    word_t pos;
    int len = oldr->len;
    bool_t diff = FALSE;
    if (newr->len < len)
	len = newr->len;
    for (pos = 0; (!diff || outfile) && pos < len; pos += 4) {
        word_t ov = 0;
        word_t nv = 0;
	get_word_val(oldr, pos, &ov);
	get_word_val(newr, pos, &nv);
	if (nv != ov) {
	    diff = TRUE;
	    if (outfile)
		fprintf(outfile, "%s:\t0x%.8x\t0x%.8x\n",
			reg_table[pos/4].name, ov, nv);
	}
    }
    return diff;
}

word_t get_reg_val(mem_t r, reg_id_t id)
{
    word_t val = 0;
    if (id >= REG_NONE)
	return 0;
    get_word_val(r,id*4, &val);
    return val;
}

void set_reg_val(mem_t r, reg_id_t id, word_t val)
{
    if (id < REG_NONE) {
	set_word_val(r,id*4,val);
#ifdef HAS_GUI
	if (gui_mode) {
	    signal_register_update(id, val);
	}
#endif /* HAS_GUI */
    }
}
     
void dump_reg(FILE *outfile, mem_t r) {
    reg_id_t id;
    for (id = 0; reg_valid(id); id++) {
	fprintf(outfile, "   %s  ", reg_table[id].name);
    }
    fprintf(outfile, "\n");
    for (id = 0; reg_valid(id); id++) {
	word_t val = 0;
	get_word_val(r, id*4, &val);
	fprintf(outfile, " %x", val);
    }
    fprintf(outfile, "\n");
}

struct {
    char symbol;
    int id;
} alu_table[A_NONE+1] = 
{
    {'+',   A_ADD},
    {'-',   A_SUB},
    {'&',   A_AND},
    {'^',   A_XOR},
    {'?',   A_NONE}
};

char op_name(alu_t op)
{
    if (op < A_NONE)
	return alu_table[op].symbol;
    else
	return alu_table[A_NONE].symbol;
}

word_t compute_alu(alu_t op, word_t argA, word_t argB)
{
    word_t val;
    switch(op) {
    case A_ADD:
	val = argA+argB;
	break;
    case A_SUB:
	val = argB-argA;
	break;
    case A_AND:
	val = argA&argB;
	break;
    case A_XOR:
	val = argA^argB;
	break;
    default:
	val = 0;
    }
    return val;
}

cc_t compute_cc(alu_t op, word_t argA, word_t argB)
{
    word_t val = compute_alu(op, argA, argB);
    bool_t zero = (val == 0);
    bool_t sign = ((int)val < 0);
    bool_t ovf;
    switch(op) {
    case A_ADD:
        ovf = (((int) argA < 0) == ((int) argB < 0)) &&
  	       (((int) val < 0) != ((int) argA < 0));
	break;
    case A_SUB:
        ovf = (((int) argA > 0) == ((int) argB < 0)) &&
	       (((int) val < 0) != ((int) argB < 0));
	break;
    case A_AND:
    case A_XOR:
	ovf = FALSE;
	break;
    default:
	ovf = FALSE;
    }
    return PACK_CC(zero,sign,ovf);
    
}

char *cc_names[8] = {
    "Z=0 S=0 O=0",
    "Z=0 S=0 O=1",
    "Z=0 S=1 O=0",
    "Z=0 S=1 O=1",
    "Z=1 S=0 O=0",
    "Z=1 S=0 O=1",
    "Z=1 S=1 O=0",
    "Z=1 S=1 O=1"};

char *cc_name(cc_t c)
{
    int ci = c;
    if (ci < 0 || ci > 7)
	return "???????????";
    else
	return cc_names[c];
}

/* Status types */

char *stat_names[] = { "BUB", "AOK", "HLT", "ADR", "INS", "PIP" };

char *stat_name(stat_t e)
{
    if (e < 0 || e > STAT_PIP)
	return "Invalid Status";
    return stat_names[e];
}

/**************** Implementation of ISA model ************************/

state_ptr new_state(int memlen)
{
    state_ptr result = (state_ptr) malloc(sizeof(state_rec));
    result->pc = 0;
    result->r = init_reg();
    result->m = init_mem(memlen);
    result->cc = DEFAULT_CC;
    return result;
}

void free_state(state_ptr s)
{
    free_reg(s->r);
    free_mem(s->m);
    free((void *) s);
}
/*
state_ptr copy_state(state_ptr s) {
    state_ptr result = (state_ptr) malloc(sizeof(state_rec));
    result->pc = s->pc;
    result->r = copy_reg(s->r);
    result->m = copy_mem(s->m);
    result->cc = s->cc;
    return result;
}

bool_t diff_state(state_ptr olds, state_ptr news, FILE *outfile) {
    bool_t diff = FALSE;

    if (olds->pc != news->pc) {
	diff = TRUE;
	if (outfile) {
	    fprintf(outfile, "pc:\t0x%.8x\t0x%.8x\n", olds->pc, news->pc);
	}
    }
    if (olds->cc != news->cc) {
	diff = TRUE;
	if (outfile) {
	    fprintf(outfile, "cc:\t%s\t%s\n", cc_name(olds->cc), cc_name(news->cc));
	}
    }
    if (diff_reg(olds->r, news->r, outfile))
	diff = TRUE;
    if (diff_mem(olds->m, news->m, outfile))
	diff = TRUE;
    return diff;
}*/


/* Branch logic */
bool_t cond_holds(cc_t cc, cond_t bcond) {
    bool_t zf = GET_ZF(cc);
    bool_t sf = GET_SF(cc);
    bool_t of = GET_OF(cc);
    bool_t jump = FALSE;
    
    switch(bcond) {
    case C_YES:
	jump = TRUE;
	break;
    case C_LE:
	jump = (sf^of)|zf;
	break;
    case C_L:
	jump = sf^of;
	break;
    case C_E:
	jump = zf;
	break;
    case C_NE:
	jump = zf^1;
	break;
    case C_GE:
	jump = sf^of^1;
	break;
    case C_G:
	jump = (sf^of^1)&(zf^1);
	break;
    default:
	jump = FALSE;
	break;
    }
    return jump;
}


/* Execute single instruction.  Return status. */
//kAc Marked at 21:00, 5.16
//执行一步
//修改

stat_t step_state(state_ptr s, FILE *error_file)
{
    word_t argA, argB;
    byte_t byte0 = 0;
    byte_t byte1 = 0;
    itype_t hi0;
    alu_t  lo0;
    reg_id_t hi1 = REG_NONE;
    reg_id_t lo1 = REG_NONE;
    bool_t ok1 = TRUE;
    word_t cval = 0;
    word_t okc = TRUE;
    word_t val, dval;
    bool_t need_regids;
    bool_t need_imm;
    word_t ftpc = s->pc;  /* Fall-through PC */

    if (!get_byte_val(s->m, ftpc, &byte0)) {
	if (error_file)
	    fprintf(error_file,
		    "PC = 0x%x, Invalid instruction address\n", s->pc);
	return STAT_ADR;
    }
    ftpc++;

    hi0 = HI4(byte0);
    lo0 = LO4(byte0);

    need_regids =
	(hi0 == I_RRMOVL || hi0 == I_ALU || hi0 == I_PUSHL ||
	 hi0 == I_POPL || hi0 == I_IRMOVL || hi0 == I_RMMOVL ||
	 hi0 == I_MRMOVL || hi0 == I_TESTSET || hi0 == I_IADDL);

    if (need_regids) {
	ok1 = get_byte_val(s->m, ftpc, &byte1);
	ftpc++;
	hi1 = HI4(byte1);
	lo1 = LO4(byte1);
    }

    need_imm =
	(hi0 == I_IRMOVL || hi0 == I_RMMOVL || hi0 == I_MRMOVL ||
	  hi0 == I_TESTSET ||
	 hi0 == I_JMP || hi0 == I_CALL || hi0 == I_IADDL);

    if (need_imm) {
	okc = get_word_val(s->m, ftpc, &cval);
	ftpc += 4;
    }

    switch (hi0) {
    case I_NOP:
	s->pc = ftpc;
	break;
    case I_HALT:
	return STAT_HLT;
	break;
    case I_RRMOVL:  /* Both unconditional and conditional moves */
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!reg_valid(hi1)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid register ID 0x%.1x\n",
			s->pc, hi1);
	    return STAT_INS;
	}
	if (!reg_valid(lo1)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid register ID 0x%.1x\n",
			s->pc, lo1);
	    return STAT_INS;
	}
	val = get_reg_val(s->r, hi1);
	if (cond_holds(s->cc, lo0))
	  set_reg_val(s->r, lo1, val);
	s->pc = ftpc;
	break;
    case I_IRMOVL:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!okc) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address",
			s->pc);
	    return STAT_INS;
	}
	if (!reg_valid(lo1)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid register ID 0x%.1x\n",
			s->pc, lo1);
	    return STAT_INS;
	}
	set_reg_val(s->r, lo1, cval);
	s->pc = ftpc;
	break;
    case I_RMMOVL:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!okc) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_INS;
	}
	if (!reg_valid(hi1)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid register ID 0x%.1x\n",
			s->pc, hi1);
	    return STAT_INS;
	}
	if (reg_valid(lo1)) 
	    cval += get_reg_val(s->r, lo1);
	val = get_reg_val(s->r, hi1);
	if (!set_word_val(s->m, cval, val)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid data address 0x%x\n",
			s->pc, cval);
	    return STAT_ADR;
	}
	s->pc = ftpc;
	break;
	case I_TESTSET:
    case I_MRMOVL:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!okc) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction addres\n", s->pc);
	    return STAT_INS;
	}
	if (!reg_valid(hi1)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid register ID 0x%.1x\n",
			s->pc, hi1);
	    return STAT_INS;
	}
	if (reg_valid(lo1)) 
	    cval += get_reg_val(s->r, lo1);
	
	//Use test&set atomic mem access
	if(hi0 == I_TESTSET)
	{
		if (!testset_byte_val(s->m, cval, (byte_t*) &val))
			return STAT_ADR;
	}
	else
	{
		if (!get_word_val(s->m, cval, &val))
			return STAT_ADR;
	}
		
	set_reg_val(s->r, hi1, val);
	s->pc = ftpc;
	break;
    case I_ALU:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	argA = get_reg_val(s->r, hi1);
	argB = get_reg_val(s->r, lo1);
	val = compute_alu(lo0, argA, argB);
	set_reg_val(s->r, lo1, val);
	s->cc = compute_cc(lo0, argA, argB);
	s->pc = ftpc;
	break;
    case I_JMP:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!okc) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (cond_holds(s->cc, lo0))
	    s->pc = cval;
	else
	    s->pc = ftpc;
	break;
    case I_CALL:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!okc) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	val = get_reg_val(s->r, REG_ESP) - 4;
	set_reg_val(s->r, REG_ESP, val);
	if (!set_word_val(s->m, val, ftpc)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid stack address 0x%x\n", s->pc, val);
	    return STAT_ADR;
	}
	s->pc = cval;
	break;
    case I_RET:
	/* Return Instruction.  Pop address from stack */
	dval = get_reg_val(s->r, REG_ESP);
	if (!get_word_val(s->m, dval, &val)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid stack address 0x%x\n",
			s->pc, dval);
	    return STAT_ADR;
	}
	set_reg_val(s->r, REG_ESP, dval + 4);
	s->pc = val;
	break;
    case I_PUSHL:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!reg_valid(hi1)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid register ID 0x%.1x\n", s->pc, hi1);
	    return STAT_INS;
	}
	val = get_reg_val(s->r, hi1);
	dval = get_reg_val(s->r, REG_ESP) - 4;
	set_reg_val(s->r, REG_ESP, dval);
	if  (!set_word_val(s->m, dval, val)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid stack address 0x%x\n", s->pc, dval);
	    return STAT_ADR;
	}
	s->pc = ftpc;
	break;
    case I_POPL:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!reg_valid(hi1)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid register ID 0x%.1x\n", s->pc, hi1);
	    return STAT_INS;
	}
	dval = get_reg_val(s->r, REG_ESP);
	set_reg_val(s->r, REG_ESP, dval+4);
	if (!get_word_val(s->m, dval, &val)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid stack address 0x%x\n",
			s->pc, dval);
	    return STAT_ADR;
	}
	set_reg_val(s->r, hi1, val);
	s->pc = ftpc;
	break;
    case I_LEAVE:
	dval = get_reg_val(s->r, REG_EBP);
	set_reg_val(s->r, REG_ESP, dval+4);
	if (!get_word_val(s->m, dval, &val)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid stack address 0x%x\n",
			s->pc, dval);
	    return STAT_ADR;
	}
	set_reg_val(s->r, REG_EBP, val);
	s->pc = ftpc;
	break;
    case I_IADDL:
	if (!ok1) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address\n", s->pc);
	    return STAT_ADR;
	}
	if (!okc) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid instruction address",
			s->pc);
	    return STAT_INS;
	}
	if (!reg_valid(lo1)) {
	    if (error_file)
		fprintf(error_file,
			"PC = 0x%x, Invalid register ID 0x%.1x\n",
			s->pc, lo1);
	    return STAT_INS;
	}
	argB = get_reg_val(s->r, lo1);
	val = argB + cval;
	set_reg_val(s->r, lo1, val);
	s->cc = compute_cc(A_ADD, cval, argB);
	s->pc = ftpc;
	break;
    default:
	if (error_file)
	    fprintf(error_file,
		    "PC = 0x%x, Invalid instruction %.2x\n", s->pc, byte0);
	return STAT_INS;
    }
    return STAT_AOK;
}
