#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

long xor_key = 0x0539053905390539; // @jM`@`\q

// use a sneaky ass name to stop those pesky reverse engineers
void __attribute__((constructor)) __do_global_ctors_aux() 
{
    register int    syscall_no  asm("rax") = 101; // ptrace
    register int    arg1        asm("rdi") = 0;
    register char*  arg2        asm("rsi") = 0;
    register int    arg3        asm("rdx") = 0;
    asm("syscall");
    if (syscall_no == -1) {
        return;
    }
    void *xor_key_segment_ptr = (void *)((long unsigned int)__do_global_ctors_aux & 0xFFFFFFFFFFFFF000) + 0x3000;
    long *xor_key_ptr;
    for (int i = 0; i < 0x100; i += sizeof(long)) {
        xor_key_ptr = xor_key_segment_ptr + i;
        long xor_result = *xor_key_ptr ^ 0x9d56d68360d417fd; // 0x0539053905390539
        if (xor_result == 0x986fd3ba65ed12c4) {
            break;
        }
    }
    *xor_key_ptr = *xor_key_ptr ^ 0x119011901190119; // 0x0420042004200420 YkTaYaEp
}

int main() {
    char input_buf[64];
    char *password = "yoteyeet";
    puts("password pls, no brute forcing:");
    fgets(input_buf, 64, stdin);
    __int128 result;
    result = *(long *)input_buf ^ xor_key;
    sleep(2);
    if (!strcmp((char *)&result, password)) {
        char flag_buf[64];
        FILE *f = fopen("flag.txt", "r");
        fgets(flag_buf, sizeof(flag_buf), f);
        fclose(f);
        printf("nice work, here's the flag! %s", flag_buf);
        return 0;
    }
    puts("that aint it dawg\n");
}