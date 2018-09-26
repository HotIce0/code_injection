# code_injection by hotice0
Linux x86_64 inject based on inject

## Usage : `code_injection <pid> <exe>`
## Require : Linux 64bit
## Compile
1. test.c `gcc -fpie -pie -nostdlib -o test test.c` [use -fpie -pie to generate the position independent code] 
2. code_injection.c `gcc -o code_injection code_injection.c`
3. inject_me.c `gcc -o inject_me inject_me.c`

## Demo
1. Terminal 1
```
zg@ubuntu:~/Documents/injection$ ./inject_me 
main addr : 0x5635c62146da
Please inject me
^Z
[1]+  Stopped                 ./inject_me
zg@ubuntu:~/Documents/injection$ ps
  PID TTY          TIME CMD
 2959 pts/1    00:00:00 bash
 3531 pts/1    00:00:00 inject_me
 3532 pts/1    00:00:00 ps
zg@ubuntu:~/Documents/injection$ fg %1
./inject_me
mmap^_^
I am HotIce0
```

2. Terminal 2
```
zg@ubuntu:~/Documents/injection$ sudo ./code_injection 3531 test
the injection code size : 298
successful to attach the specify process
rip : 0x7f319a58a9a4
addr_text : 0x7f319a58a9a4
The specify process was traped
success to write the sepecify elf file to sepecify proc
success to insert injection program
done
```
