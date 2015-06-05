CC=gcc
CFLAGS=-Wall -O2
LCFLAGS=-O2
LEX = flex
YACC=bison
LEXLIB = -lfl
YAS=./yas

all: yis yas hcl2c shmclear shmput shmdump 
#yism0 yism1 

# These are implicit rules for making .yo files from .ys files.
# E.g., make sum.yo
.SUFFIXES: .ys .yo
.ys.yo:
	$(YAS) $*.ys

# These are the explicit rules for making yis yas and hcl2c and hcl2v
yas-grammar.o: yas-grammar.c
	$(CC) $(LCFLAGS) -c yas-grammar.c

yas-grammar.c: yas-grammar.lex
	$(LEX) yas-grammar.lex
	mv lex.yy.c yas-grammar.c

isa.o: 
	$(CC) $(CFLAGS) -c isa.c 

yas.o:	
	$(CC) $(CFLAGS) -c yas.c
	
yas: yas-grammar.o isa.o yas.o
	$(CC) $(CFLAGS) yas-grammar.o yas.o isa.o ${LEXLIB} -o yas

yis:
	$(CC) $(CFLAGS) yis.c isa.c -o yis
	
yism0:
	$(CC) $(CFLAGS) -DCORE0 yis.c isa.c -o yism0
	
yism1:
	$(CC) $(CFLAGS) -DCORE1 yis.c isa.c -o yism1

shmclear: isa.h
	$(CC) $(CFLAGS) shmclear.c  isa.c -o shmclear
	
shmput: isa.h
	$(CC) $(CFLAGS) shmput.c  isa.c -o shmput

shmdump: isa.h
	$(CC) $(CFLAGS) shmdump.c  isa.c -o shmdump
	
hcl2c: hcl.tab.c lex.yy.c node.c outgen.c
	$(CC) $(LCFLAGS) node.c lex.yy.c hcl.tab.c outgen.c -o hcl2c

hcl2v: hcl.tab.c lex.yy.c node.c outgen.c
	$(CC) $(LCFLAGS) -DVLOG node.c lex.yy.c hcl.tab.c outgen.c -o hcl2v

hcl2u: hcl.tab.c lex.yy.c node.c outgen.c
	$(CC) $(LCFLAGS) -DUCLID node.c lex.yy.c hcl.tab.c outgen.c -o hcl2u

lex.yy.c: hcl.lex
	$(LEX) hcl.lex

hcl.tab.c: hcl.y
	$(YACC) -d hcl.y

clean:
	rm -f *.o *.yo *.exe yis yas hcl2c mux4 *~ core.* 
	rm -f hcl.tab.c hcl.tab.h lex.yy.c


