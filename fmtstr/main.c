#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int magic = 0;

int main()
{
    char buf[100];
    setvbuf(stdout,0,2,0);
    puts("please crax me");
    read(0,buf,sizeof(buf));
    printf(buf);
    if(magic == 0xda){
        system("cat ./flag");
    }else if(magic == 0xdeadbeef){
        system("cat ./flag2");
    }else{
        puts("you need be a phd");
    }
    return 0;
}

