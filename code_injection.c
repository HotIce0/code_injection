#include <features.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <linux/limits.h>

extern int errno;

#define BASE_ADDRESS 0x100000

#define WORD_ALIGN(x) ((x + 7) & ~7)

typedef struct handle
{
    Elf64_Phdr *phdr;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    uint8_t *mem;
    char *exec;
    struct user_regs_struct user_reg;
} handle_t;

void block_print(void * addr, u_int64_t size);
char *get_path_by_pid(pid_t pid);
void pid_block_write(pid_t pid, void *addr_dst, void * p_res, u_int64_t u64_len);
void * pid_block_read(pid_t pid, void *addr_res, u_int64_t u64_len);
Elf64_Addr get_text_segment_addr_by_pid(pid_t pid);

static __always_inline volatile void *evil_mmap(
    void *addr,
    uint64_t length,
    uint64_t port,
    uint64_t flags,
    uint64_t fd,
    uint64_t offset)
{
    long mmap_fd = fd;
    unsigned long mmap_off = offset;
    unsigned long mmap_flag = flags;
    unsigned long ret;
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%r10\n"
        "mov %4, %%r8\n"
        "mov %5, %%r9\n"
        "mov $0x9, %%rax\n"
        "syscall"
        :
        : "g"(addr), "g"(length), "g"(port), "g"(flags), "g"(fd), "g"(offset));
    asm("mov %%rax, %0"
        : "=r"(ret));
    return (void *)ret;
}

__always_inline long _write(long fd, char *buf, unsigned long len)
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

// Injection code run for create engouth memeory to insert the sepecify elf file.
void injection_code(void * addr)//void * addr
{
    addr = (void *)0x100000;
    // Apply for enought memory to inject the elf_program.
    char str[] = {'m', 'm', 'a', 'p', '^', '_', '^', '\n', '\0'};
    if (evil_mmap((void *)addr, 8192, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
        asm volatile (
            "mov $60, %%rax\n"
            "syscall"
            ::
        );
    }else {
        _write(1, str, sizeof(str));
    }
    // Soft breakpoint
    asm volatile ("int3");
}
void foo2(){}

uint64_t get_injection_code_size()
{
    // calculate the injection_code size.
    return (u_int64_t)((u_int8_t *)foo2 - (u_int8_t *)injection_code);
}

// Create injection code.
void *create_injection_code()
{
    void *p_injection_code;
    // apply memory for inject code.
    p_injection_code = malloc(get_injection_code_size());// + 8
    // copy the injection code to destination memory.
    memcpy(p_injection_code, injection_code, get_injection_code_size());

    return p_injection_code;
}

int main(int argn, char **argv, char **envp)
{
    int fd, pid, i, j, stat;
    u_int8_t *p_origin_code;
    void *p_injection_code;
    handle_t h;
    struct stat st;
    u_int64_t addr_text;

    if (argn < 3) {
        printf("Usage: %s <pid> <inserted_program>\n", argv[0]);
        exit(0);
    }

    pid = atoi(argv[1]);
    h.exec = strdup(argv[2]);
    //-------------------------------------------------------------------------
    // Open specify ELF file.
    fd = open(h.exec, O_RDONLY);
    // Read file status.
    if (fstat(fd, &st)) {
        perror("fstat");
        exit(-1);
    }
    h.mem = (u_int8_t *)malloc(WORD_ALIGN(st.st_size));

    if (read(fd, h.mem, st.st_size) < 0) {
        perror("read");
        exit(-1);
    }
    
    // close file
    close(fd);

    h.ehdr = (Elf64_Ehdr *)h.mem;
    h.phdr = (Elf64_Phdr *)(h.mem + h.ehdr->e_phoff);
    h.shdr = (Elf64_Shdr *)(h.mem + h.ehdr->e_shoff);
    
    // // Get address of .text
    // for (i = 0; i < h.ehdr->e_phnum; i++)
    //     if (h.phdr[i].p_type == PT_LOAD && h.phdr[i].p_offset == 0)
    //         addr_text = h.phdr[i].p_vaddr;
    //addr_text = get_text_segment_addr_by_pid(pid);
    // printf("please enter addr of injection code\n");
    // scanf("%lx", &addr_text);

    // Create Injection Code
    p_injection_code = create_injection_code();

    printf("the injection code size : %ld\n", get_injection_code_size());

    //---------------------------------------------------------------------------
    // Attach to the specify process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("PTRACE_ATTACH");
        exit(-1);
    }
    // wait for the STOPSIG
    wait(&stat);

    printf("successful to attach the specify process\n");

    // Get register from the specify process. (For change the %rip to run the injection code) 
    if (ptrace(PTRACE_GETREGS, pid, NULL, &h.user_reg) < 0) {
        perror("PTRACE_GETRES");
        exit(-1);
    }
    printf("rip : 0x%llx\n", h.user_reg.rip);    
    addr_text = h.user_reg.rip;
    printf("addr_text : 0x%lx\n", addr_text);

    // Backup the origin code;
    p_origin_code = (u_int8_t *)pid_block_read(pid, (void *)addr_text, get_injection_code_size());

    // Insert injection code into specify process.
    pid_block_write(pid, (void *)addr_text, p_injection_code, get_injection_code_size());

    // Change the control flow
    //h.user_reg.rip = addr_text;
    // Post parament via register.
    h.user_reg.rdi = BASE_ADDRESS;
    //addr_text = h.user_reg.rip;
    // Set register
    if (ptrace(PTRACE_SETREGS, pid, NULL, &h.user_reg) < 0) {
        perror("PTRACE_SETREGS");
        exit(-1);
    }
    
    // Continue the process to run the injection_code function.
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("PTRACE_CONT");
        exit(-1);
    }
    
    // TRAP(int 3 0xCC)
    wait(&stat);
    if (WIFSTOPPED(stat) && (WSTOPSIG(stat) == SIGTRAP)) {
        printf("The specify process was traped\n");
        // Recovery the injection code meory.
        pid_block_write(pid, (void *)addr_text, p_origin_code, get_injection_code_size());
        
        // Write the executable elf file to the memory start with BASE_ADDRESS.
        pid_block_write(pid, (void *)BASE_ADDRESS, (void *)h.mem, st.st_size);
        printf("2\n");
        printf("success to write the sepecify elf file to sepecify proc\n");
        // Get user register
        if (ptrace(PTRACE_GETREGS, pid, NULL, &h.user_reg) < 0 ) {
            perror("PTRACE_GETREGS");
            exit(-1);
        }
        // Change the control flow to specify process entry point.
        h.user_reg.rip = BASE_ADDRESS + h.ehdr->e_entry;
        if (ptrace(PTRACE_SETREGS, pid, NULL, &h.user_reg) < 0) {
            perror("PTRACE_SETREGS");
            exit(-1);
        }
        // Continue the process
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            perror("PTRACE_CONT");
            exit(-1);
        }
        printf("success to insert injection program\n");
    } else {
        printf("Failed\n");
        exit(-1);
    }
    printf("done\n");
    exit(0);
}

// Write block memory via pid.(ptrace)
void pid_block_write(pid_t pid, void *addr_dst, void * p_res, u_int64_t u64_len)
{
    u_int8_t *p_res_cursor = (u_int8_t *)p_res,
             *p_dst_cursor = (u_int8_t *)addr_dst;
    for (; (u_int8_t *)p_res + u64_len > p_res_cursor;) {
        if (ptrace(PTRACE_POKETEXT, pid, (void *)p_dst_cursor, *(u_int64_t *)p_res_cursor) < 0) {// 64 bits system (1 word = 64bit)
            perror("PTRACE_POKETEXT");
            exit(-1);
        }
        p_res_cursor += sizeof(u_int64_t);
        p_dst_cursor += sizeof(u_int64_t);
    }
}

// Read block memory via pid.(ptrace)
void * pid_block_read(pid_t pid, void *addr_res, u_int64_t u64_len) 
{
    u_int8_t *p_dst_cursor,
             *p_res_cursor,
             *p_dst_cursor_origin;
    p_dst_cursor = p_dst_cursor_origin = (u_int8_t *)malloc(u64_len);
    p_res_cursor = (u_int8_t *)addr_res;
    for (; (u_int8_t *)addr_res + u64_len > p_res_cursor; ) {
        //
        *(u_int64_t *)p_dst_cursor = ptrace(PTRACE_PEEKTEXT, pid, (void *)p_res_cursor, NULL);
        if (errno != 0) {
            perror("PTRACE_PEEKTEXT");
            exit(-1);
        }
        p_res_cursor += sizeof(u_int64_t);
        p_dst_cursor += sizeof(u_int64_t);
    }
    return p_dst_cursor_origin;
}

// get path by pid via read /proc/{pid}/exe soft link path.
char *get_path_by_pid(pid_t pid)
{
    char str_proc_pid_path[PATH_MAX], str_path[PATH_MAX], *p;

    if (snprintf(str_proc_pid_path, PATH_MAX, "/proc/%d/exe", pid) < 0) {
        perror("snprintf");
        exit(-1);
    }
    // readlink to get the path
    if (readlink(str_proc_pid_path, str_path, PATH_MAX) < 0) {
        perror("readlink");
        exit(-1);
    }
    if ((p = strdup(str_path)) == NULL) {
        perror("strdup");
        exit(-1);
    }
    return p;
}

Elf64_Addr get_text_segment_addr_by_pid(pid_t pid) 
{
    Elf64_Addr addr_text;
    char str_proc_pid_path[PATH_MAX];
    FILE *pf;
    if (snprintf(str_proc_pid_path, PATH_MAX, "/proc/%d/maps", pid) < 0) {
        perror("snprintf");
        exit(-1);
    }
    pf = fopen(str_proc_pid_path, "r");
    fscanf(pf, "%lx", &addr_text);
    fclose(pf);
    return addr_text;
}

void block_print(void * addr, u_int64_t size) 
{
    u_int64_t i = 0;
    u_int8_t * cursor = (u_int8_t *)addr;
    printf("addr : %p\n", addr);
    for (i = 0; i < size; i++) {
        if (i % 5 == 0) {
            putchar('\n');
        }
        printf("0x%X ", cursor[i]);
    }
}