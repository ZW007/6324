#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <unistd.h>
#include <time.h>

void coupon(char * arg)
{
	char name[16];
	char * stuff[4] = {"iPad Air 2", "Surface Pro 3", "iPhone 6", "GALAXY Note 4"};

	strcpy(name, arg);
	printf("Our loyal customer %s:\n", name);
	printf("Use this coupon to redeem your free %s!\n", stuff[rand()%4]);
	printf("Coupon number %d\n\n", rand());
}

int main(int argc, char ** argv)
{
	if (argc < 2) {
		printf("usage: %s your_name\n", argv[0]);
		return 0;
	}

	srand(time(0)); // Initialize random number generator.  use time(0) to get current time
	coupon(argv[1]); //ADDRESS of user input is pushed

	return 0;
}

