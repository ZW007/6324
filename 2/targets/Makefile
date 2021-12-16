CC	:= gcc
CFLAGS	:= -ggdb -Wall
RM	:= rm -f

sources	:= target1.c target2.c target3.c target4.c
targets	:= target1 target2 target3 target4

all: $(targets)

clean:
	$(RM) $(targets) $(source:.c=.o)

