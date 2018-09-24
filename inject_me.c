#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main()
{
    int i = 0;
    printf("main addr : 0x%lx\n", (u_int64_t)main);
    printf("Please inject me\n");
    for(i = 0; i < 99999; i++){
        sleep(1);
    }
    return 0;
}