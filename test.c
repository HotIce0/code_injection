long _write(long fd, char *buf, unsigned long len)
{
    long ret;
    asm volatile (
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall"
        :
        :"g"(fd), "g"(buf), "g"(len)
    );
    asm("mov %%rax, %0":"=r"(ret));
    return ret;
}
void _exit(long status)
{
    asm(
        "mov $60, %%rax\n"
        "syscall"
        :
        :"r"(status)
    );
}

_start()
{
    _write(1, "I am HotIce0\n", sizeof("I am HotIce0\n"));
    _exit(0);
}