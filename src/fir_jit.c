// FIR Bytecode to Assembly Translation Pipeline
// This leverages the existing FIR generation and translates it to assembly
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fpvm/fir_jit.h>

// A cached pointer to the real fork() function from libc
static pid_t (*real_fork)(void) = NULL;

// A replacement for system() that executes a command in a clean child process
int system_no_preload(const char* command) {
    // One-time initialization of the real_fork function pointer.
    if (!real_fork) {
        real_fork = dlsym(RTLD_NEXT, "fork");
        if (!real_fork) {
            fprintf(stderr, "CRITICAL: JIT could not find real fork() function. Aborting.\n");
            abort();
        }
    }

    pid_t pid = real_fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // --- Child Process ---
        // Unset LD_PRELOAD to prevent the child from re-preloading this library.
        if (unsetenv("LD_PRELOAD") != 0) {
            perror("unsetenv failed");
            _exit(127);
        }

        execl("/bin/sh", "sh", "-c", command, NULL);
        
        perror("execl failed");
        _exit(127);
    } else {
        // --- Parent Process ---
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }
        
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "JIT compiler process was terminated by signal %d\n", WTERMSIG(status));
        }
        return -1;
    }
}

void asm_init(asm_gen_t *gen) {
    gen->capacity = 4096;
    gen->code = malloc(gen->capacity);
    gen->size = 0;
    strcpy(gen->code, "");
}

void asm_emit(asm_gen_t *gen, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char temp[1024];
    int len = vsnprintf(temp, sizeof(temp), fmt, args);
    
    if (gen->size + len >= gen->capacity) {
        gen->capacity *= 2;
        gen->code = realloc(gen->code, gen->capacity);
    }
    
    strcat(gen->code, temp);
    gen->size += len;
    va_end(args);
}

// New function to compile assembly from a string and load it
void* compile_and_load_assembly(const char* asm_code) {
    // Create temporary files
    char tmp_s_file[] = "/tmp/jit_asm_XXXXXX.s";
    char tmp_so_file[] = "/tmp/jit_so_XXXXXX.so";
    int fd_s = mkstemps(tmp_s_file, 2);

    if (fd_s == -1) {
        perror("mkstemps for .s");
        return NULL;
    }

    // Write assembly to .s file
    if (write(fd_s, asm_code, strlen(asm_code)) == -1) {
        perror("write to .s file");
        close(fd_s);
        return NULL;
    }
    close(fd_s);

    // Create a unique .so file name as well
    int fd_so = mkstemps(tmp_so_file, 3);
    if (fd_so == -1) {
        perror("mkstemps for .so");
        return NULL;
    }
    close(fd_so);


    // Compile the .s file into a .so file
    char command[512];
    snprintf(command, sizeof(command), "gcc -shared -o %s %s", tmp_so_file, tmp_s_file);

    if (system_no_preload(command) != 0) {
        fprintf(stderr, "Failed to compile assembly\n");
        unlink(tmp_s_file);
        unlink(tmp_so_file);
        return NULL;
    }

    // Load the shared object
    void *handle = dlopen(tmp_so_file, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        unlink(tmp_s_file);
        unlink(tmp_so_file);
        return NULL;
    }

    // Get pointers to the function start and end
    void *jit_func_start = dlsym(handle, "jit_function");
    void *jit_func_end = dlsym(handle, "jit_function_end");

    if (!jit_func_start || !jit_func_end) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        dlclose(handle);
        unlink(tmp_s_file);
        unlink(tmp_so_file);
        return NULL;
    }

    // Calculate size and copy the code
    size_t code_size = jit_func_end - jit_func_start;
    void *executable_mem = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (executable_mem == MAP_FAILED) {
        perror("mmap for executable memory");
        dlclose(handle);
        unlink(tmp_s_file);
        unlink(tmp_so_file);
        return NULL;
    }

    memcpy(executable_mem, jit_func_start, code_size);

    // Unload the library and clean up
    dlclose(handle);
    unlink(tmp_s_file);
    unlink(tmp_so_file);

    return executable_mem;
}

// FIR bytecode walker with assembly generation
void translate_fir_to_assembly(uint8_t *fir_code, size_t code_size, asm_gen_t *gen) {
    asm_emit(gen,
        "# Generated from FIR bytecode (AT&T Syntax)\n"
        "# Register allocation:\n"
        "#   r12 = fpstate pointer\n"
        "#   r13 = mcontext pointer\n"
        "#   r14 = vm stack pointer\n"
        "#   r15 = special struct pointer\n"
        ".text\n"
        ".global jit_function\n"
        "jit_function:\n"
        "    pushq %%rbp\n"
        "    movq %%rsp, %%rbp\n"
        "    pushq %%rbx\n"
        "    pushq %%r12\n"
        "    pushq %%r13\n"
        "    pushq %%r14\n"
        "    pushq %%r15\n"
        "    movq %%rdi, %%r12\n"
        "    movq %%rsi, %%r13\n"
        "    subq $1024, %%rsp\n"
        "    movq %%rsp, %%r14\n"
        "    subq $72, %%rsp\n"
        "    movq %%rsp, %%r15\n"
        "    xorq %%rax, %%rax\n"
        "    movq $8, %%rcx\n"
        "    movq %%r15, %%rdi\n"
        "    rep stosq\n\n"
    );

    uint8_t *pc = fir_code;
    uint8_t *end = fir_code + code_size;

    while (pc < end) {
        uint8_t opcode = *pc++;

        switch (opcode) {
            case fpvm_opcode_fpptr: {
                uint16_t offset = *(uint16_t*)pc;
                pc += sizeof(uint16_t);
                asm_emit(gen,
                    "    # fpptr %d\n"
                    "    leaq %d(%%r12), %%rax\n"
                    "    subq $8, %%r14\n"
                    "    movq %%rax, (%%r14)\n\n",
                    offset, offset
                );
                break;
            }

            case fpvm_opcode_mcptr: {
                uint16_t offset = *(uint16_t*)pc;
                pc += sizeof(uint16_t);
                asm_emit(gen,
                    "    # mcptr %d\n"
                    "    leaq %d(%%r13), %%rax\n"
                    "    subq $8, %%r14\n"
                    "    movq %%rax, (%%r14)\n\n",
                    offset, offset
                );
                break;
            }

            case fpvm_opcode_dup:
                asm_emit(gen,
                    "    # dup\n"
                    "    movq (%%r14), %%rax\n"
                    "    subq $8, %%r14\n"
                    "    movq %%rax, (%%r14)\n\n"
                );
                break;

            case fpvm_opcode_call1s1d: {
                void *func_ptr = *(void**)pc;
                pc += sizeof(void*);
                asm_emit(gen,
                    "    # call1s1d %p\n"
                    "    movq %%r15, %%rdi\n"
                    "    movq (%%r14), %%rsi\n"
                    "    addq $8, %%r14\n"
                    "    movq (%%r14), %%rdx\n"
                    "    addq $8, %%r14\n"
                    "    movq $%p, %%rax\n"
                    "    call *%%rax\n\n",
                    func_ptr, func_ptr
                );
                break;
            }

            case fpvm_opcode_call2s1d: {
                void *func_ptr = *(void**)pc;
                pc += sizeof(void*);
                asm_emit(gen,
                    "    # call2s1d %p\n"
                    "    movq %%r15, %%rdi\n"
                    "    movq (%%r14), %%rsi\n"
                    "    addq $8, %%r14\n"
                    "    movq (%%r14), %%rdx\n"
                    "    addq $8, %%r14\n"
                    "    movq (%%r14), %%rcx\n"
                    "    addq $8, %%r14\n"
                    "    movq $%p, %%rax\n"
                    "    call *%%rax\n\n",
                    func_ptr, func_ptr
                );
                break;
            }

            case fpvm_opcode_call3s1d: {
                void *func_ptr = *(void**)pc;
                pc += sizeof(void*);
                asm_emit(gen,
                    "    # call3s1d %p\n"
                    "    movq %%r15, %%rdi\n"
                    "    movq (%%r14), %%rsi\n"
                    "    addq $8, %%r14\n"
                    "    movq (%%r14), %%rdx\n"
                    "    addq $8, %%r14\n"
                    "    movq (%%r14), %%rcx\n"
                    "    addq $8, %%r14\n"
                    "    movq (%%r14), %%r8\n"
                    "    addq $8, %%r14\n"
                    "    movq $%p, %%rax\n"
                    "    call *%%rax\n\n",
                    func_ptr, func_ptr
                );
                break;
            }

            case fpvm_opcode_ld64:
                asm_emit(gen,
                    "    # ld64\n"
                    "    movq (%%r14), %%rax\n"
                    "    movq (%%rax), %%rbx\n"
                    "    movq %%rbx, (%%r14)\n\n"
                );
                break;

            case fpvm_opcode_iadd:
                asm_emit(gen,
                    "    # iadd\n"
                    "    movq (%%r14), %%rax\n"
                    "    addq $8, %%r14\n"
                    "    addq %%rax, (%%r14)\n\n"
                );
                break;
            
            case fpvm_opcode_imm64: {
                int64_t imm = *(int64_t*)pc;
                pc += sizeof(int64_t);
                asm_emit(gen,
                    "    # imm64 %ld\n"
                    "    subq $8, %%r14\n"
                    "    movq $%ld, (%%r14)\n\n",
                    imm, imm
                );
                break;
            }

            case fpvm_opcode_clspecial:
                asm_emit(gen,
                    "    # clspecial\n"
                    "    xorq %%rax, %%rax\n"
                    "    movq $8, %%rcx\n"
                    "    movq %%r15, %%rdi\n"
                    "    rep stosq\n\n"
                );
                break;

            case fpvm_opcode_setrflags:
                asm_emit(gen,
                    "    # setrflags\n"
                    "    movq (%%r14), %%rax\n"
                    "    addq $8, %%r14\n"
                    "    movq %%rax, (%%r15)\n\n"
                );
                break;

            case fpvm_opcode_done:
                asm_emit(gen,
                    "    # done\n"
                    "    addq $1096, %%rsp\n"
                    "    popq %%r15\n"
                    "    popq %%r14\n"
                    "    popq %%r13\n"
                    "    popq %%r12\n"
                    "    popq %%rbx\n"
                    "    popq %%rbp\n"
                    "    retq\n"
                    ".global jit_function_end\n"
                    "jit_function_end:\n"
                );
                return;

            default:
                asm_emit(gen, "    # unknown opcode %d\n", opcode);
                break;
        }
    }
}

// Public wrapper for translating FIR bytecode to assembly and writing to FILE*
int translate_fir_to_asm(FILE *out, uint8_t *fir_code, size_t code_size) {
    asm_gen_t gen;
    asm_init(&gen);
    translate_fir_to_assembly(fir_code, code_size, &gen);
    // Print the generated assembly to the provided FILE*
    fprintf(out, "%s", gen.code);
    free(gen.code);
    return 0;
}