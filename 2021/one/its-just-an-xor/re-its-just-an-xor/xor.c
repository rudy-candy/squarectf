#include <stdio.h>
#include <unistd.h>
#include <windows.h>
#define ulong unsigned long

int main(){
  int iVar1;
  FILE *__stream;
  long in_FS_OFFSET;
  ulong local_b8;
  long local_b0;
  ulong local_a8 [8];
  char local_68 [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  puts("password pls, no brute forcing:");
  fgets((char *)local_a8,0x40,stdin);
  local_b8 = local_a8[0] ^ 0x539053905390539;
  local_b0 = (long)local_b8 >> 0x3f;
  sleep(2);
  iVar1 = strcmp((char *)&local_b8,"yoteyeet");
  if (iVar1 == 0) {
    __stream = fopen("flag.txt","r");
    fgets(local_68,0x40,__stream);
    fclose(__stream);
    printf("nice work, here\'s the flag! %s",local_68);
  }
  else {
    puts("that aint it dawg\n");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    //__stack_chk_fail();
    __stpcpy_chk();
  }
  return 0;
}