#include "pin.H"
#include <fstream>
#include <iostream>

#include <capstone/capstone.h>
#include <map>
#include <stdint.h>
#include <unordered_map>
#include <unordered_set>

using namespace std;

class SparseBitmap {
 private:
  static constexpr size_t CHUNK_SIZE = 4096 * 8;  // 4096 bytes = 32768 bits
  using Chunk = std::vector<uint64_t>;
  std::unordered_map<size_t, Chunk> chunks;

  size_t getChunkIndex(size_t bit) const {
    return bit / CHUNK_SIZE;
  }

  size_t getBitOffset(size_t bit) const {
    return (bit % CHUNK_SIZE) / 64;
  }

  size_t getBitPosition(size_t bit) const {
    return bit % 64;
  }

 public:
  void set(size_t bit) {
    size_t chunkIdx = getChunkIndex(bit);
    size_t offset = getBitOffset(bit);
    size_t pos = getBitPosition(bit);

    if (chunks.find(chunkIdx) == chunks.end()) {
      chunks[chunkIdx] = Chunk(CHUNK_SIZE / 64, 0);
    }
    chunks[chunkIdx][offset] |= (uint64_t(1) << pos);
  }

  void clear(size_t bit) {
    size_t chunkIdx = getChunkIndex(bit);
    size_t offset = getBitOffset(bit);
    size_t pos = getBitPosition(bit);

    auto it = chunks.find(chunkIdx);
    if (it != chunks.end()) {
      it->second[offset] &= ~(uint64_t(1) << pos);
      // if (std::all_of(it->second.begin(), it->second.end(), [](uint64_t x) {
      // return x == 0; })) {
      //     chunks.erase(it);
      // }
    }
  }

  bool test(size_t bit) const {
    size_t chunkIdx = getChunkIndex(bit);
    size_t offset = getBitOffset(bit);
    size_t pos = getBitPosition(bit);

    auto it = chunks.find(chunkIdx);
    return it != chunks.end() && (it->second[offset] & (uint64_t(1) << pos));
  }
};

// static std::unordered_map<uintptr_t, bool> float_written;
static SparseBitmap float_written;
static std::unordered_set<uintptr_t> sinks;

static inline uintptr_t quantize(uintptr_t addr) {
  return (addr >> 3);  // the cache line (probably too much)
}

// call this analysis function if the instrumentation finds a memory write
static void floatWrite(uintptr_t ip, uintptr_t target, unsigned short opsize) {
  target = quantize(target);
  float_written.set(target);
}

static void intWrite(uintptr_t ip, uintptr_t target, unsigned short opsize) {
  target = quantize(target);
  float_written.clear(target);
}

static void intRead(uintptr_t ip, uintptr_t target, unsigned short opsize) {
  target = quantize(target);
  if (float_written.test(target)) {
    sinks.insert(ip);
  }
}

// Function to log RBP and RSP
void clearBetweenStackPointers(uintptr_t reg_rbp, uintptr_t reg_rsp) {
  for (uintptr_t i = reg_rbp; i <= reg_rsp; i += 8) {
    float_written.set(quantize(i));
  }
}

static inline bool ends_with(const std::string &value, const std::string &ending) {
  if (ending.size() > value.size()) {
    return false;
  }
  return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

void Instruction(INS ins, void *v) {
  IMG img = IMG_FindByAddress(INS_Address(ins));
  if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
    return;
  }

  if (INS_IsRet(ins)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)clearBetweenStackPointers, IARG_REG_REFERENCE,
        REG_RBP, IARG_REG_REFERENCE, REG_RSP, IARG_END);
    return;
  }

  if (INS_IsBranch(ins) || INS_IsCall(ins)) return;

  bool is_write = INS_IsMemoryWrite(ins);
  bool is_read = INS_IsMemoryRead(ins);
  bool is_xmm = false;

  bool is_float_inst = false;
  std::string mnemonic = INS_Mnemonic(ins);

  if (mnemonic == "MOVQ") {
    // std::string dis = INS_Disassemble(ins);
    auto address = INS_Address(ins);


    bool dst_is_gpr = false;
    bool src_is_xmm = false;
    bool dst_is_invalid = false;
    for (uint32_t i = 0; i < INS_OperandCount(ins); i++) {
      int is_dst = i == INS_OperandCount(ins) - 1;
      if (INS_OperandIsReg(ins, i)) {
        REG reg = INS_OperandReg(ins, i);
        if (REG_is_xmm_ymm_zmm(reg)) {
          if (!is_dst) {
            src_is_xmm = true;
          }
        } else {
          if (is_dst) {
            dst_is_gpr = true;
          }
        }
      } else if (is_dst) {
        dst_is_invalid = true;
      }
    }
    if (dst_is_gpr && src_is_xmm && !dst_is_invalid) {
      // printf("\e[33mHANDLE: %s\e[0m\n", dis.data());
      sinks.insert(address);
    } else {
      // printf("IGNORE: %s\n", dis.data());
    }
  }

  if (mnemonic == "RET") return;

  // This is a pretty hacky way to do this, but hopefully its 'good enough'
  if (ends_with(mnemonic, "PS")) is_float_inst = true;
  if (ends_with(mnemonic, "SS")) is_float_inst = true;
  if (ends_with(mnemonic, "PD")) is_float_inst = true;
  if (ends_with(mnemonic, "SD")) is_float_inst = true;
  if (ends_with(mnemonic, "SD_XMM")) is_float_inst = true;

  for (uint32_t i = 0; i < INS_OperandCount(ins); i++) {
    if (INS_OperandIsReg(ins, i)) {
      REG reg = INS_OperandReg(ins, i);
      if (REG_is_xmm_ymm_zmm(reg)) {
        is_xmm = true;
      }
    }
  }

  if (is_xmm) {
    is_float_inst = true;
  }
  if (is_write and is_xmm and is_float_inst) {
    // record a write of a floating point value (SOURCE)
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)floatWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
        IARG_MEMORYWRITE_SIZE, IARG_END);
  }


  if (is_write and not is_float_inst) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)intWrite, IARG_INST_PTR, IARG_MEMORYWRITE_EA,
        IARG_MEMORYWRITE_SIZE, IARG_END);
  }

  if (is_read and !is_float_inst) {
    // Record a SINK if its a mov inst
    if (mnemonic.find("MOV") == std::string::npos) {
      return;
    }

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)intRead, IARG_INST_PTR, IARG_MEMORYREAD_EA,
        IARG_MEMORYREAD_SIZE, IARG_END);
  }
}

// CALLED AUTOMATICALLY BY PIN ON APPLICATION EXIT.
void Fini(INT32 code, void *v) {
  FILE *out = fopen("mem_patches.csv", "w");
  for (auto sink : sinks) {
    fprintf(out, "0x%zx\n", sink);
  }
  fclose(out);
}

INT32 Usage() {
  cerr << "This tool logs memory operations and corresponding instructions" << endl;
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}

int main(int argc, char *argv[]) {
  PIN_InitSymbols();

  // initialize PIN
  if (PIN_Init(argc, argv)) return Usage();

  // register instruction to be called for instrumentation
  INS_AddInstrumentFunction(Instruction, 0);
  // register Fini to be called on app exit
  PIN_AddFiniFunction(Fini, 0);
  // starts program, never returns
  PIN_StartProgram();
  return 0;
}
