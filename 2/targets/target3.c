#include <stdio.h>
#include <string.h>
#include <stdlib.h> // ssystem()
#include <unistd.h>
#include <time.h>
#include <ctype.h>

char *signatures[] = {"sys_open_ports", "sys_module", "write_binaries"};

int is_virus(int argc, char ** argv)
{
        char traffic[64];
        int i, j, len;

        traffic[0] = 0;  //ascii of NULL 
        for (i = 1; i < argc; ++i)
                strcat(traffic, argv[i]);

        for (j = 0; j < 3; ++j) {
                len = strlen(signatures[j]);
                for (i = 0; i < (int)strlen(traffic); ++i)
                        if (strncmp(signatures[j], traffic+i, len) == 0)
                                return 1;
        }

        return 0;
}

int main(int argc, char ** argv)
{
        if (argc < 2) {
                system("echo 'usage: target3 network_traffic_packets'");
                exit(1);
        }

        if (is_virus(argc, argv))
                printf("Alarm! virus founded\n");
        else
                printf("safe.\n");

        return 0;
}


08048474 <is_virus>:
 8048474:	55                   	push   ebp
 8048475:	89 e5                	mov    ebp,esp
 8048477:	83 ec 68             	sub    esp,0x68
 804847a:	c6 45 b8 00          	mov    BYTE PTR [ebp-72],0x0

 804847e:	c7 45 b4 01 00 00 00 	mov    DWORD PTR [ebp-76],0x1
 8048485:	8b 45 b4             	mov    eax,DWORD PTR [ebp-76]
 8048488:	3b 45 08             	cmp    eax,DWORD PTR [ebp+8]
 804848b:	7c 02                	jl     804848f <is_virus+0x1b>
 804848d:	eb 26                	jmp    80484b5 <is_virus+0x41>
 804848f:	8b 45 b4             	mov    eax,DWORD PTR [ebp-76]
 8048492:	8d 14 85 00 00 00 00 	lea    edx,[eax*4]
 8048499:	8b 45 0c             	mov    eax,DWORD PTR [ebp+12]
 804849c:	8b 04 10             	mov    eax,DWORD PTR [eax+edx]
 804849f:	89 44 24 04          	mov    DWORD PTR [esp+4],eax
 80484a3:	8d 45 b8             	lea    eax,[ebp-72]
 80484a6:	89 04 24             	mov    DWORD PTR [esp],eax
 80484a9:	e8 c6 fe ff ff       	call   8048374 <_init+0x6c>
 80484ae:	8d 45 b4             	lea    eax,[ebp-76]
 80484b1:	ff 00                	inc    DWORD PTR [eax]
 80484b3:	eb d0                	jmp    8048485 <is_virus+0x11>
 80484b5:	c7 45 b0 00 00 00 00 	mov    DWORD PTR [ebp-80],0x0
 80484bc:	83 7d b0 02          	cmp    DWORD PTR [ebp-80],0x2
 80484c0:	7e 02                	jle    80484c4 <is_virus+0x50>
 80484c2:	eb 6e                	jmp    8048532 <is_virus+0xbe>
 80484c4:	8b 45 b0             	mov    eax,DWORD PTR [ebp-80]
 80484c7:	8b 04 85 58 97 04 08 	mov    eax,DWORD PTR [eax+134518616]
 80484ce:	89 04 24             	mov    DWORD PTR [esp],eax
 80484d1:	e8 6e fe ff ff       	call   8048344 <_init+0x3c>
 80484d6:	89 45 ac             	mov    DWORD PTR [ebp-84],eax
 80484d9:	c7 45 b4 00 00 00 00 	mov    DWORD PTR [ebp-76],0x0
 80484e0:	8d 45 b8             	lea    eax,[ebp-72]
 80484e3:	89 04 24             	mov    DWORD PTR [esp],eax
 80484e6:	e8 59 fe ff ff       	call   8048344 <_init+0x3c>
 80484eb:	39 45 b4             	cmp    DWORD PTR [ebp-76],eax
 80484ee:	7c 02                	jl     80484f2 <is_virus+0x7e>
 80484f0:	eb 39                	jmp    804852b <is_virus+0xb7>
 80484f2:	8d 45 b8             	lea    eax,[ebp-72]
 80484f5:	89 c2                	mov    edx,eax
 80484f7:	03 55 b4             	add    edx,DWORD PTR [ebp-76]
 80484fa:	8b 4d b0             	mov    ecx,DWORD PTR [ebp-80]
 80484fd:	8b 45 ac             	mov    eax,DWORD PTR [ebp-84]
 8048500:	89 44 24 08          	mov    DWORD PTR [esp+8],eax
 8048504:	89 54 24 04          	mov    DWORD PTR [esp+4],edx
 8048508:	8b 04 8d 58 97 04 08 	mov    eax,DWORD PTR [ecx+134518616]
 804850f:	89 04 24             	mov    DWORD PTR [esp],eax
 8048512:	e8 3d fe ff ff       	call   8048354 <_init+0x4c>
 8048517:	85 c0                	test   eax,eax
 8048519:	75 09                	jne    8048524 <is_virus+0xb0>
 804851b:	c7 45 a8 01 00 00 00 	mov    DWORD PTR [ebp-88],0x1
 8048522:	eb 15                	jmp    8048539 <is_virus+0xc5>
 8048524:	8d 45 b4             	lea    eax,[ebp-76]
 8048527:	ff 00                	inc    DWORD PTR [eax]
 8048529:	eb b5                	jmp    80484e0 <is_virus+0x6c>
 804852b:	8d 45 b0             	lea    eax,[ebp-80]
 804852e:	ff 00                	inc    DWORD PTR [eax]
 8048530:	eb 8a                	jmp    80484bc <is_virus+0x48>
 8048532:	c7 45 a8 00 00 00 00 	mov    DWORD PTR [ebp-88],0x0
 8048539:	8b 45 a8             	mov    eax,DWORD PTR [ebp-88]
 804853c:	c9                   	leave  
 804853d:	c3                   	ret    
