// FIR Bytecode to Assembly Translation Pipeline
// This leverages the existing FIR generation and translates it to assembly

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fenv.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <stdarg.h>

#include <fpvm/decoder.h>
#include <fpvm/emulator.h>
#include <fpvm/fpvm_common.h>
#include <fpvm/gc.h>
#include <fpvm/vm.h>
#include <fpvm/util.h>
#include <fpvm/perf.h>
#include <fpvm/trace.h>
#include <fpvm/fpvm_fenv.h>
#include <fpvm/fpvm_math.h>
#include <fpvm/number_system.h>
#include <fpvm/fpvm_magic.h>
#include <fpvm/config.h>

// Expose a public wrapper to translate raw FIR bytecode into assembly
int translate_fir_to_asm(FILE *out, uint8_t *fir_code, size_t code_size);

// Assembly code generator
typedef struct {
    char *code;
    size_t size;
    size_t capacity;
} asm_gen_t;

void asm_init(asm_gen_t *gen) {
    gen->capacity = 4096;
    gen->code = malloc(gen->capacity);
    gen->size = 0;
    strcpy(gen->code, "");
}

void asm_emit(asm_gen_t *gen, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char temp[512];
    int len = vsnprintf(temp, sizeof(temp), fmt, args);
    
    if (gen->size + len >= gen->capacity) {
        gen->capacity *= 2;
        gen->code = realloc(gen->code, gen->capacity);
    }
    
    strcat(gen->code, temp);
    gen->size += len;
    va_end(args);
}

// FIR bytecode walker with assembly generation
void translate_fir_to_assembly(uint8_t *fir_code, size_t code_size, asm_gen_t *gen) {
    asm_emit(gen, 
        "# Generated from FIR bytecode\n"
        "# Register allocation:\n"
        "#   r12 = fpstate pointer (callee-saved)\n"
        "#   r13 = mcontext pointer (callee-saved) \n"
        "#   r14 = vm stack pointer (callee-saved)\n"
        "#   r15 = special struct pointer (callee-saved)\n"
        "#   rbx = temp/scratch (callee-saved)\n"
        ".text\n"
        ".global jit_function\n"
        "jit_function:\n"
        "    # Standard prologue\n"
        "    push rbp\n"
        "    mov rbp, rsp\n"
        "    \n"
        "    # Save callee-saved registers we'll use\n"
        "    push rbx\n"
        "    push r12\n"
        "    push r13\n" 
        "    push r14\n"
        "    push r15\n"
        "    \n"
        "    # Set up our persistent state\n"
        "    mov r12, rdi         # r12 = fpstate\n"
        "    mov r13, rsi         # r13 = mcontext\n"
        "    \n"
        "    # Allocate our stack machine stack\n"
        "    sub rsp, 1024        # stack space (16-byte aligned)\n"
        "    mov r14, rsp         # r14 = our stack pointer\n"
        "    \n"
        "    # Set up special struct (could be on real stack or register)\n"
        "    sub rsp, 64          # space for op_special_t\n"
        "    mov r15, rsp         # r15 = &special\n"
        "    \n"
        "    # Zero the special struct\n"
        "    xor rax, rax\n"
        "    mov rcx, 8           # 64 bytes / 8 = 8 qwords\n"
        "    mov rdi, r15\n"
        "    rep stosq            # zero special struct\n\n"
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
                    "    lea rax, [r12 + %d]  # fpstate + offset\n"
                    "    sub r14, 8           # decrement stack pointer\n"
                    "    mov [r14], rax       # push to stack\n\n",
                    offset, offset
                );
                break;
            }
            
            case fpvm_opcode_mcptr: {
                uint16_t offset = *(uint16_t*)pc;
                pc += sizeof(uint16_t);
                
                asm_emit(gen,
                    "    # mcptr %d\n" 
                    "    lea rax, [r13 + %d]  # mcontext + offset\n"
                    "    sub r14, 8           # decrement stack pointer\n"
                    "    mov [r14], rax       # push to stack\n\n",
                    offset, offset
                );
                break;
            }
            
            case fpvm_opcode_dup:
                asm_emit(gen,
                    "    # dup\n"
                    "    mov rax, [r14]       # load top\n"
                    "    sub r14, 8           # make space\n"
                    "    mov [r14], rax       # push duplicate\n\n"
                );
                break;
                
            case fpvm_opcode_call1s1d: {
                void *func_ptr = *(void**)pc;
                pc += sizeof(void*);
                
                asm_emit(gen,
                    "    # call1s1d %p\n"
                    "    # Set up System V ABI calling convention:\n"
                    "    mov rdi, r15         # special struct\n"
                    "    mov rsi, [r14]       # dest\n"
                    "    add r14, 8\n"
                    "    mov rdx, [r14]       # src1\n" 
                    "    add r14, 8\n"
                    "    mov rax, %p          # function pointer\n"
                    "    call rax\n\n",
                    func_ptr, func_ptr
                );
                break;
            }
            
            case fpvm_opcode_call2s1d: {
                void *func_ptr = *(void**)pc;
                pc += sizeof(void*);
                
                asm_emit(gen,
                    "    # call2s1d %p\n"
                    "    # Set up System V ABI calling convention:\n"
                    "    mov rdi, r15         # special struct\n"
                    "    mov rsi, [r14]       # dest\n"
                    "    add r14, 8\n"
                    "    mov rdx, [r14]       # src1\n"
                    "    add r14, 8\n" 
                    "    mov rcx, [r14]       # src2\n"
                    "    add r14, 8\n"
                    "    mov rax, %p          # function pointer\n"
                    "    call rax\n\n",
                    func_ptr, func_ptr
                );
                break;
            }
            
            case fpvm_opcode_call3s1d: {
                void *func_ptr = *(void**)pc;
                pc += sizeof(void*);
                
                asm_emit(gen,
                    "    # call3s1d %p\n"
                    "    # Set up System V ABI calling convention:\n"
                    "    mov rdi, r15         # special struct\n"
                    "    mov rsi, [r14]       # dest\n"
                    "    add r14, 8\n"
                    "    mov rdx, [r14]       # src1\n"
                    "    add r14, 8\n"
                    "    mov rcx, [r14]       # src2\n" 
                    "    add r14, 8\n"
                    "    mov r8, [r14]        # src3\n"
                    "    add r14, 8\n"
                    "    mov rax, %p          # function pointer\n"
                    "    call rax\n\n",
                    func_ptr, func_ptr
                );
                break;
            }
            
            case fpvm_opcode_done:
                asm_emit(gen,
                    "    # done - restore and return\n"
                    "    add rsp, 1088        # deallocate stack + special (1024 + 64)\n"
                    "    pop r15\n"
                    "    pop r14\n"
                    "    pop r13\n"
                    "    pop r12\n"
                    "    pop rbx\n"
                    "    pop rbp\n"
                    "    ret\n"
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

// Integration with existing FPVM pipeline
int fpvm_jit_compile_from_fir(fpvm_inst_t *fi) {
    // fi->codegen already contains the FIR bytecode from fpvm_vm_x86_compile()
    fpvm_builder_t *builder = (fpvm_builder_t*)fi->codegen;
    
    if (!builder || !builder->code) {
        return -1;
    }
    
    // Translate FIR bytecode to assembly
    asm_gen_t gen;
    asm_init(&gen);
    
    translate_fir_to_assembly(builder->code, builder->offset, &gen);
    
    printf("Generated assembly:\n%s\n", gen.code);
    
    // In a real implementation:
    // 1. Write assembly to temp file
    // 2. Invoke assembler: system("as -64 temp.s -o temp.o")
    // 3. Load object and resolve relocations
    // 4. Copy to executable memory
    // 5. Store function pointer in fi->jit_func
    
    free(gen.code);
    return 0;
}

// Example of what the FIR→Assembly translation looks like
void demonstrate_translation();

void demonstrate_translation() {
    printf("FIR Bytecode → Assembly Translation Example\n");
    printf("==========================================\n\n");
    
    // Simulate FIR bytecode for: addsd %xmm1, %xmm0
    uint8_t fir_code[] = {
        fpvm_opcode_fpptr, 16, 0,        // push &xmm1 (offset 16)
        fpvm_opcode_fpptr, 0, 0,         // push &xmm0 (offset 0) 
        fpvm_opcode_dup,                 // duplicate &xmm0 for dest
        fpvm_opcode_call2s1d,            // call add function
        0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0,  // function pointer (placeholder)
        fpvm_opcode_done
    };
    
    asm_gen_t gen;
    asm_init(&gen);
    
    translate_fir_to_assembly(fir_code, sizeof(fir_code), &gen);
    
    printf("Input FIR:\n");
    printf("  fpptr 16\n");
    printf("  fpptr 0\n"); 
    printf("  dup\n");
    printf("  call2s1d 0x12345678\n");
    printf("  done\n\n");
    
    printf("Output Assembly:\n");
    printf("%s\n", gen.code);
    
    free(gen.code);
}

// Next steps for implementation:
// 1. Modify fpvm_vm_x86_compile() to also generate assembly (or add new function)
// 2. Add assembly compilation and linking 
// 3. Add executable memory management
// 4. Benchmark against interpreter
// 5. Add optimizations (register allocation, instruction combining)

// int main() {
//     demonstrate_translation();
//     return 0;
// }