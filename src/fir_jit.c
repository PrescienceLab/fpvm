// FIR Bytecode to Assembly Translation Pipeline
// This leverages the existing FIR generation and translates it to assembly
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fpvm/fir_jit.h>
#include <stdbool.h>
#include <lightning.h>

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

static jit_state_t* _jit;

// Pool of registers available for vstack values.
// We exclude JIT_R0 entirely — it's always scratch.
// Pool: JIT_R1, JIT_R2, JIT_V0... but V0/V1/V2 are taken by fpstate/mcontext/special
// So pool is just JIT_R1, JIT_R2 = 2 registers
#define VSTACK_REG_DEPTH 2  // JIT_R1, JIT_R2 only
#define MAX_VSTACK_DEPTH 16 

static jit_gpr_t pool_reg(int i) {
    return JIT_R(i + 1);  // pool[0]=R1, pool[1]=R2
}

// Where a vstack value lives
typedef enum { LOC_REG, LOC_SPILL } LocKind;
typedef struct {
    LocKind kind;
    int index;  // pool index if LOC_REG, frame slot index if LOC_SPILL
} Location;

// Allocator state — reset between JIT compilations
static struct {
    Location vstack[MAX_VSTACK_DEPTH];
    int      vsp;                        // index of top, -1 = empty
    bool     reg_used[VSTACK_REG_DEPTH];
    int      spill_hwm;                  // next free spill slot
} ra;

static int vstack_frame;  // frame offset of spill area

static void ra_init() {
    ra.vsp = -1;
    memset(ra.reg_used, 0, sizeof(ra.reg_used));
    ra.spill_hwm = 0;
    vstack_frame = jit_allocai(MAX_VSTACK_DEPTH * 8);
}

// Find a free register in the pool, -1 if none
static int ra_find_free() {
    for (int i = 0; i < VSTACK_REG_DEPTH; i++)
        if (!ra.reg_used[i]) return i;
    return -1;
}

// Allocate a location for a new vstack push.
// Tries a register first, falls back to a frame spill slot.
static Location ra_push() {
    Location loc;
    int idx = ra_find_free();
    if (idx >= 0) {
        ra.reg_used[idx] = true;
        loc = (Location){ LOC_REG, idx };
    } else {
        loc = (Location){ LOC_SPILL, ra.spill_hwm++ };
    }
    ra.vstack[++ra.vsp] = loc;
    return loc;
}

// Pop top location and free its register if it was in one.
static Location ra_pop() {
    Location loc = ra.vstack[ra.vsp--];
    if (loc.kind == LOC_REG)
        ra.reg_used[loc.index] = false;
    return loc;
}

// Peek at top without popping.
static Location ra_peek() {
    return ra.vstack[ra.vsp];
}

// Peek at arbitrary depth without popping. depth=0 is top.
static Location ra_peek_at(int depth) {
    return ra.vstack[ra.vsp - depth];
}

// Emit JIT code to store src register into a location.
static void loc_store(jit_gpr_t src, Location loc) {
    if (loc.kind == LOC_REG) {
        if (pool_reg(loc.index) != src)
            jit_movr(pool_reg(loc.index), src);
    } else {
        jit_stxi(vstack_frame + loc.index * 8, JIT_FP, src);
    }
}

// Emit JIT code to load a location into dst register.
static void loc_load(jit_gpr_t dst, Location loc) {
    if (loc.kind == LOC_REG) {
        if (pool_reg(loc.index) != dst)
            jit_movr(dst, pool_reg(loc.index));
    } else {
        jit_ldxi(dst, JIT_FP, vstack_frame + loc.index * 8);
    }
}

// Ensure a location is in a register, loading into a temp if needed.
// Returns the register containing the value.
// Sets *temp_idx to the pool index of the temp register allocated,
// or -1 if no temp was needed (value was already in a register).
// Caller must free the temp with ra.reg_used[*temp_idx] = false when done.
static jit_gpr_t materialize(Location loc, int *temp_idx) {
    if (loc.kind == LOC_REG) {
        *temp_idx = -1;
        return pool_reg(loc.index);
    }
    // Need a temp register to load the spilled value into
    int idx = ra_find_free();
    assert(idx >= 0 && "no free register for materialize");
    ra.reg_used[idx] = true;
    *temp_idx = idx;
    jit_gpr_t reg = pool_reg(idx);
    jit_ldxi(reg, JIT_FP, vstack_frame + loc.index * 8);
    return reg;
}

jit_fn_t translate_fir_to_lightning(uint8_t *fir_code, size_t code_size) {
    // Jit Initialization
    _jit = jit_new_state();
    jit_prolog();

    jit_node_t *fp_regs_arg   = jit_arg();
    jit_node_t *mcontext_arg  = jit_arg();

    // JIT_V0 = fpstate pointer (callee-saved, survives calls)
    // JIT_V1 = mcontext pointer (callee-saved, survives calls)
    // JIT_V2 = special struct pointer (callee-saved)
    jit_getarg(JIT_V0, fp_regs_arg);
    jit_getarg(JIT_V1, mcontext_arg);

    ra_init();

    // Allocate the "special struct" on the frame (72 bytes = 9 x 8)
    // jit_allocai returns a frame offset.
    int special_frame = jit_allocai(sizeof(op_special_t));
    // jit_movi(JIT_R0, 0);
    // for (int i = 0; i < 9; i++) {
    //     jit_stxi(special_frame + i * 8, JIT_FP, JIT_R0);
    // }
    // offsetof 
    // V2 = address of special struct on frame
    jit_addi(JIT_V2, JIT_FP, special_frame);

    int vdepth = 0;
    
    uint8_t *pc = fir_code;
    uint8_t *end = fir_code + code_size;

    while (pc < end) {
        uint8_t opcode = *pc++;

        switch (opcode) {
            case fpvm_opcode_fpptr: {
                uint16_t offset = *(uint16_t *)pc; pc += 2;
                // Allocate a location for the new value, compute into R0 scratch,
                // then store R0 into wherever the allocator decided to put it
                Location loc = ra_push();
                jit_addi(JIT_R0, JIT_V0, offset);
                loc_store(JIT_R0, loc);
                break;
            }

            case fpvm_opcode_mcptr: {
                uint16_t offset = *(uint16_t *)pc; pc += 2;
                Location loc = ra_push();
                jit_addi(JIT_R0, JIT_V1, offset);
                loc_store(JIT_R0, loc);
                break;
            }

            case fpvm_opcode_dup: {
                // Load top into R0, push a new slot, store R0 there
                Location src = ra_peek();
                Location dst = ra_push();
                loc_load(JIT_R0, src);
                loc_store(JIT_R0, dst);
                break;
            }

            case fpvm_opcode_ld64: {
                // Load the pointer from top into R0, dereference it,
                // store the value back in place (no push/pop, same slot)
                Location top = ra_peek();
                loc_load(JIT_R0, top);
                jit_ldr(JIT_R0, JIT_R0);
                loc_store(JIT_R0, top);
                break;
            }

            case fpvm_opcode_iadd: {
                // Pop two, add, push result
                Location b = ra_pop();
                Location a = ra_pop();
                int ta, tb;
                jit_gpr_t ra_reg = materialize(a, &ta);
                jit_gpr_t rb_reg = materialize(b, &tb);
                // Free temps before pushing result so allocator can reuse registers
                if (tb >= 0) ra.reg_used[tb] = false;
                if (ta >= 0) ra.reg_used[ta] = false;
                Location res = ra_push();
                jit_addr(JIT_R0, ra_reg, rb_reg);
                loc_store(JIT_R0, res);
                break;
            }

            case fpvm_opcode_ext32: {
                int signedExt = *(uint8_t *)pc; pc += 1;
                // Pop one, sign-extend or zero-extend to 64 bits, push result
                Location a = ra_pop();
                int ta;
                jit_gpr_t ra_reg = materialize(a, &ta);
                if (ta >= 0) ra.reg_used[ta] = false;
                Location res = ra_push();
                if (signedExt)
                    jit_extr_i(JIT_R0, ra_reg);
                else
                    jit_extr_ui(JIT_R0, ra_reg);
                loc_store(JIT_R0, res);
                break;
            }

            case fpvm_opcode_ishl: {
                // Pop two, shift-left, push result
                Location b = ra_pop();
                Location a = ra_pop();
                int ta, tb;
                jit_gpr_t ra_reg = materialize(a, &ta);
                jit_gpr_t rb_reg = materialize(b, &tb);
                if (tb >= 0) ra.reg_used[tb] = false;
                if (ta >= 0) ra.reg_used[ta] = false;
                Location res = ra_push();
                jit_lshr(JIT_R0, ra_reg, rb_reg);
                loc_store(JIT_R0, res);
                break;
            }

            case fpvm_opcode_imm64: {
                int64_t imm = *(int64_t *)pc; pc += 8;
                Location loc = ra_push();
                jit_movi(JIT_R0, imm);
                loc_store(JIT_R0, loc);
                break;
            }

            case fpvm_opcode_call2s1d: {
                void *func_ptr = *(void **)pc; pc += sizeof(void *);
                // Load each arg into R0 and push immediately — pushargr captures
                // the value at call time so overwriting R0 after each push is safe
                // Stack: [..., src2, src1, dest] (dest = top)
                jit_prepare();
                    jit_pushargr(JIT_V2);
                    loc_load(JIT_R0, ra_peek_at(0)); jit_pushargr(JIT_R0);  // dest
                    loc_load(JIT_R0, ra_peek_at(1)); jit_pushargr(JIT_R0);  // src1
                    loc_load(JIT_R0, ra_peek_at(2)); jit_pushargr(JIT_R0);  // src2
                    jit_pushargi(0);
                    jit_pushargi(0);
                jit_finishi(func_ptr);
                ra_pop(); ra_pop(); ra_pop();
                break;
            }

            case fpvm_opcode_call1s1d: {
                void *func_ptr = *(void **)pc; pc += sizeof(void *);
                jit_prepare();
                    jit_pushargr(JIT_V2);
                    loc_load(JIT_R0, ra_peek_at(0)); jit_pushargr(JIT_R0);  // dest
                    loc_load(JIT_R0, ra_peek_at(1)); jit_pushargr(JIT_R0);  // src1
                    jit_pushargi(0);
                    jit_pushargi(0);
                    jit_pushargi(0);
                jit_finishi(func_ptr);
                ra_pop(); ra_pop();
                break;
            }

            case fpvm_opcode_call3s1d: {
                void *func_ptr = *(void **)pc; pc += sizeof(void *);
                jit_prepare();
                    jit_pushargr(JIT_V2);
                    loc_load(JIT_R0, ra_peek_at(0)); jit_pushargr(JIT_R0);  // dest
                    loc_load(JIT_R0, ra_peek_at(1)); jit_pushargr(JIT_R0);  // src1
                    loc_load(JIT_R0, ra_peek_at(2)); jit_pushargr(JIT_R0);  // src2
                    loc_load(JIT_R0, ra_peek_at(3)); jit_pushargr(JIT_R0);  // src3
                    jit_pushargi(0);
                jit_finishi(func_ptr);
                ra_pop(); ra_pop(); ra_pop(); ra_pop();
                break;
            }

            case fpvm_opcode_clspecial: {
                // R0 is pure scratch so zeroing it is always safe
                // vstack values live in R1/R2 or frame, never R0
                jit_movi(JIT_R0, 0);
                for (int i = 0; i < 9; i++)
                    jit_stxi(special_frame + i * 8, JIT_FP, JIT_R0);
                break;
            }

            case fpvm_opcode_setrflags: {
                // Pop top, store into special->rflags (slot 0 of special struct)
                Location top = ra_pop();
                loc_load(JIT_R0, top);
                jit_stxi(special_frame, JIT_FP, JIT_R0);
                break;
            }
    
                case fpvm_opcode_done: {
                    jit_ret();
                    goto done;
                }
    
                default:
                    // Unknown opcode — could log or assert
                    break;
        }
    }

    done:
    jit_epilog();
    
    jit_fn_t jit_func = (jit_fn_t)jit_emit();

    // jit_word_t real_code_size;

    // jit_get_code(&real_code_size);  /* query exact size of the code */
    // csh handle;
    // cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    // cs_insn *insn;
    // size_t count = cs_disasm(handle, (const uint8_t*)jit_func, real_code_size, (uint64_t)(jit_func), 0, &insn);
    // printf("Disassembly of JIT-compiled function at %p (size: %zu bytes):\n", jit_func, real_code_size);
    // if (count > 0) {
    //     for (size_t i = 0; i < count; i++) {
    //         printf("0x%"PRIx64":\t%s\t\t%s\n", 
    //               insn[i].address, 
    //               insn[i].mnemonic, 
    //               insn[i].op_str);
    //     }
    //     cs_free(insn, count);  // Free memory when done
    // }
    // cs_close(&handle);  // Clean up when done
    
    jit_clear_state();

    return jit_func;
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
            
            // Can add more immediate sizes as needed
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