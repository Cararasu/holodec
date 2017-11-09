
#include "X86FunctionAnalyzer.h"
#include "InstrDefinition.h"

using namespace holodec;


holox86::Architecture holox86::x86architecture {"x86", "x86", 64, 8, {
		[] (Binary * binary) {
			static FunctionAnalyzer* analyzer = nullptr;
			if (analyzer == nullptr) {
				printf ("Create New Object\n");
				analyzer = new holox86::X86FunctionAnalyzer (&holox86::x86architecture);
			}
			if (analyzer->canAnalyze (binary)) {
				FunctionAnalyzer* temp = analyzer;
				analyzer = nullptr;
				return temp;
			}
			return (FunctionAnalyzer*) nullptr;
		}
	},
	{
		{0, "rax", H_REG_GPR, nullptr, "rax", 64, 0, true},
		{0, "eax", H_REG_GPR, "rax", "rax", 32, 0, true},
		{0, "ax", H_REG_GPR, "eax", "rax", 16, 0, false},
		{0, "al", H_REG_GPR, "ax", "rax", 8, 0, false},{0, "ah", H_REG_GPR, "ax", "rax", 8, 8, false},
		
		{0, "rbx", H_REG_GPR, nullptr, "rbx", 64, 0, true},
		{0, "ebx", H_REG_GPR, "rbx", "rbx", 32, 0, true},
		{0, "bx", H_REG_GPR, "ebx", "rbx", 16, 0, false},
		{0, "bl", H_REG_GPR, "bx", "rbx", 8, 0, false},{0, "bh", H_REG_GPR, "bx", "rbx", 8, 8, false},
		
		{0, "rcx", H_REG_GPR, nullptr, "rcx", 64, 0, true},
		{0, "ecx", H_REG_GPR, "rcx", "rcx", 32, 0, true},
		{0, "cx", H_REG_GPR, "ecx", "rcx", 16, 0, false},
		{0, "cl", H_REG_GPR, "cx", "rcx", 8, 0, false},{0, "ch", H_REG_GPR, "cx", "rcx", 8, 8, false},
		
		{0, "rdx", H_REG_GPR, nullptr, "rdx", 64, 0, true},
		{0, "edx", H_REG_GPR, "rdx", "rdx", 32, 0, true},
		{0, "dx", H_REG_GPR, "edx", "rdx", 16, 0, false},
		{0, "dl", H_REG_GPR, "dx", "rdx", 8, 0, false},{0, "dh", H_REG_GPR, "dx", "rdx", 8, 8, false},
		
		{0, "r8", H_REG_GPR, nullptr, "r8", 64, 0, true},{0, "r8d", H_REG_GPR, "r8", "r8", 32, 0, true},
		{0, "r8w", H_REG_GPR, "r8d", "r8", 16, 0, false},{0, "r8b", H_REG_GPR, "r8w", "r8", 8, 0, false},
		
		{0, "r9", H_REG_GPR, nullptr, "r9", 64, 0, true},{0, "r9d", H_REG_GPR, "r9", "r9", 32, 0, true},
		{0, "r9w", H_REG_GPR, "r9d", "r9", 16, 0, false},{0, "r9b", H_REG_GPR, "r9w", "r9", 8, 0, false},
		
		{0, "r10", H_REG_GPR, nullptr, "r10", 64, 0, true},{0, "r10d", H_REG_GPR, "r10", "r10", 32, 0, true},
		{0, "r10w", H_REG_GPR, "r10d", "r10", 16, 0, false},{0, "r10b", H_REG_GPR, "r10w", "r10", 8, 0, false},
		
		{0, "r11", H_REG_GPR, nullptr, "r11", 64, 0, true},{0, "r11d", H_REG_GPR, "r11", "r11", 32, 0, true},
		{0, "r11w", H_REG_GPR, "r11d", "r11", 16, 0, false},{0, "r11b", H_REG_GPR, "r11w", "r11", 8, 0, false},
		
		{0, "r12", H_REG_GPR, nullptr, "r12", 64, 0, true},{0, "r12d", H_REG_GPR, "r12", "r12", 32, 0, true},
		{0, "r12w", H_REG_GPR, "r12d", "r12", 16, 0, false},{0, "r12b", H_REG_GPR, "r12w", "r12", 8, 0, false},
		
		{0, "r13", H_REG_GPR, nullptr, "r13", 64, 0, true},{0, "r13d", H_REG_GPR, "r13", "r13", 32, 0, true},
		{0, "r13w", H_REG_GPR, "r13d", "r13", 16, 0, false},{0, "r13b", H_REG_GPR, "r13w", "r13", 8, 0, false},
		
		{0, "r14", H_REG_GPR, nullptr, "r14", 64, 0, true},{0, "r14d", H_REG_GPR, "r14", "r14", 32, 0, true},
		{0, "r14w", H_REG_GPR, "r14d", "r14", 16, 0, false},{0, "r14b", H_REG_GPR, "r14w", "r14", 8, 0, false},
		
		{0, "r15", H_REG_GPR, nullptr, "r15", 64, 0, true},{0, "r15d", H_REG_GPR, "r15", "r15", 32, 0, true},
		{0, "r15w", H_REG_GPR, "r15d", "r15", 16, 0, false},{0, "r15b", H_REG_GPR, "r15w", "r15", 8, 0, false},
		
		{0, "rbp", H_REG_GPR, nullptr, "rbp", 64, 0, true},
		{0, "ebp", H_REG_GPR, "rbp", "rbp", 32, 0, true},
		{0, "bp", H_REG_GPR, "ebp", "rbp", 16, 0, false},{0, "bpl", H_REG_GPR, "bp", "rbp", 8, 0, false},
		
		{0, "rsi", H_REG_GPR, nullptr, "rsi", 64, 0, true},
		{0, "esi", H_REG_GPR, "rsi", "rsi", 32, 0, true},
		{0, "si", H_REG_GPR, "esi", "rsi", 16, 0, false},{0, "sil", H_REG_GPR, "si", "rsi", 8, 0, false},
		
		{0, "rdi", H_REG_GPR, nullptr, "rdi", 64, 0, true},
		{0, "edi", H_REG_GPR, "rdi", "rdi", 32, 0, true},
		{0, "di", H_REG_GPR, "edi", "rdi", 16, 0, false},{0, "dil", H_REG_GPR, "di", "rdi", 8, 0, false},
		
		{0, "rsp", H_REG_GPR, nullptr, "rsp", 64, 0, true},
		{0, "esp", H_REG_GPR, "rsp", "rsp", 32, 0, true},
		{0, "sp", H_REG_GPR, "esp", "rsp", 16, 0, false},{0, "spl", H_REG_GPR, "sp", "rsp", 8, 0, true},
		
		{0, "rip", H_REG_GPR, nullptr, "rip", 64, 0, true},
		{0, "eip", H_REG_GPR, "rip", "rip", 32, 0, true},
		{0, "ip", H_REG_GPR, "eip", "rip", 16, 0, false},{0, "ipl", H_REG_GPR, "ip", "rip", 8, 0, false},
		
		
		{0, "rflags", H_REG_FLAGS, nullptr, "rflags", 64, 0, false},
		{0, "eflags", H_REG_FLAGS, "rflags", "rflags", 32, 0, false},
		{0, "flags", H_REG_FLAGS, "eflags", "rflags", 16, 0, false},
		
		{0, "cf", H_REG_FLAGS, "flags", "rflags", 1, 0, false},
		{0, "pf", H_REG_FLAGS, "flags", "rflags", 1, 2, false},
		{0, "af", H_REG_FLAGS, "flags", "rflags", 1, 4, false},
		{0, "zf", H_REG_FLAGS, "flags", "rflags", 1, 6, false},
		{0, "sf", H_REG_FLAGS, "flags", "rflags", 1, 7, false},
		{0, "tf", H_REG_FLAGS, "flags", "rflags", 1, 8, false},
		{0, "if", H_REG_FLAGS, "flags", "rflags", 1, 9, false},
		{0, "df", H_REG_FLAGS, "flags", "rflags", 1, 10, false},
		{0, "of", H_REG_FLAGS, "flags", "rflags", 1, 11, false},
		{0, "iopl", H_REG_FLAGS, "flags", "rflags", 1, 12, false},
		{0, "nt", H_REG_FLAGS, "flags", "rflags", 1, 14, false},
		
		{0, "rf", H_REG_FLAGS, "eflags", "rflags", 1, 16, false},
		{0, "vm", H_REG_FLAGS, "eflags", "rflags", 1, 17, false},
		{0, "ac", H_REG_FLAGS, "eflags", "rflags", 1, 18, false},
		{0, "vif", H_REG_FLAGS, "eflags", "rflags", 1, 19, false},
		{0, "vip", H_REG_FLAGS, "eflags", "rflags", 1, 20, false},
		{0, "id", H_REG_FLAGS, "eflags", "rflags", 1, 21, false},

		{0, "cs", H_REG_SEGMENT, nullptr, "cs", 16, 0, false},
		{0, "ds", H_REG_SEGMENT, nullptr, "ds", 16, 0, false},
		{0, "ss", H_REG_SEGMENT, nullptr, "ss", 16, 0, false},
		{0, "es", H_REG_SEGMENT, nullptr, "es", 16, 0, false},
		{0, "fs", H_REG_SEGMENT, nullptr, "fs", 16, 0, false},
		{0, "gs", H_REG_SEGMENT, nullptr, "gs", 16, 0, false},

		/*Do we need debug registers? maybe not
				{"dr0", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr1", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr2", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr3", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0},
				{"dr4", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr5", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr6", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr7", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0},
				{"dr8",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr9",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr10",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr11",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0},
				{"dr12",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr13",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr14",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr15",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0},
		*/
		/*Do we need control registers? maybe not
				{"cr0",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr1",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr2",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr3",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0},
				{"cr4",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr5",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr6",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr7",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0},
		*/

//sw,cw,tw,fp_ip,...

		{0, "zmm0", H_REG_VEC, nullptr, "zmm0", 512, 0, true},
		{0, "ymm0", H_REG_VEC, "zmm0", "zmm0", 256, 0, true},
		{0, "xmm0", H_REG_VEC, "zmm0", "ymm0", 128, 0, true},
		
		{0, "zmm1", H_REG_VEC, nullptr, "zmm1", 512, 0, true},
		{0, "ymm1", H_REG_VEC, "zmm1", "zmm1", 256, 0, true},
		{0, "xmm1", H_REG_VEC, "zmm1", "ymm1", 128, 0, true},
		
		{0, "zmm2", H_REG_VEC, nullptr, "zmm2", 512, 0, true},
		{0, "ymm2", H_REG_VEC, "zmm2", "zmm2", 256, 0, true},
		{0, "xmm2", H_REG_VEC, "zmm2", "ymm2", 128, 0, true},
		
		{0, "zmm3", H_REG_VEC, nullptr, "zmm3", 512, 0, true},
		{0, "ymm3", H_REG_VEC, "zmm3", "zmm3", 256, 0, true},
		{0, "xmm3", H_REG_VEC, "zmm3", "ymm3", 128, 0, true},
		
		{0, "zmm4", H_REG_VEC, nullptr, "zmm4", 512, 0, true},
		{0, "ymm4", H_REG_VEC, "zmm4", "zmm4", 256, 0, true},
		{0, "xmm4", H_REG_VEC, "zmm4", "ymm4", 128, 0, true},
		
		{0, "zmm5", H_REG_VEC, nullptr, "zmm5", 512, 0, true},
		{0, "ymm5", H_REG_VEC, "zmm5", "zmm5", 512, 0, true},
		{0, "xmm5", H_REG_VEC, "zmm5", "ymm5", 512, 0, true},
		
		{0, "zmm6", H_REG_VEC, nullptr, "zmm6", 512, 0, true},
		{0, "ymm6", H_REG_VEC, "zmm6", "zmm6", 512, 0, true},
		{0, "xmm6", H_REG_VEC, "zmm6", "ymm6", 512, 0, true},
		
		{0, "zmm7", H_REG_VEC, nullptr, "zmm7", 512, 0, true},
		{0, "ymm7", H_REG_VEC, "zmm7", "zmm7", 512, 0, true},
		{0, "xmm7", H_REG_VEC, "zmm7", "ymm7", 512, 0, true},
		
		{0, "zmm8", H_REG_VEC, nullptr, "zmm8", 512, 0, true},
		{0, "ymm8", H_REG_VEC, "zmm8", "zmm8", 512, 0, true},
		{0, "xmm8", H_REG_VEC, "zmm8", "ymm8", 512, 0, true},
		
		{0, "zmm9", H_REG_VEC, nullptr, "zmm9", 512, 0, true},
		{0, "ymm9", H_REG_VEC, "zmm9", "zmm9", 512, 0, true},
		{0, "xmm9", H_REG_VEC, "zmm9", "ymm9", 512, 0, true},
		
		{0, "zmm10", H_REG_VEC, nullptr, "zmm10", 512, 0, true},
		{0, "ymm10", H_REG_VEC, "zmm10", "zmm10", 512, 0, true},
		{0, "xmm10", H_REG_VEC, "zmm10", "ymm10", 512, 0, true},
		
		{0, "zmm11", H_REG_VEC, nullptr, "zmm11", 512, 0, true},
		{0, "ymm11", H_REG_VEC, "zmm11", "zmm11", 512, 0, true},
		{0, "xmm11", H_REG_VEC, "zmm11", "ymm11", 512, 0, true},
		
		{0, "zmm12", H_REG_VEC, nullptr, "zmm12", 512, 0, true},
		{0, "ymm12", H_REG_VEC, "zmm12", "zmm12", 512, 0, true},
		{0, "xmm12", H_REG_VEC, "zmm12", "ymm12", 512, 0, true},
		
		{0, "zmm13", H_REG_VEC, nullptr, "zmm13", 512, 0, true},
		{0, "ymm13", H_REG_VEC, "zmm13", "zmm13", 512, 0, true},
		{0, "xmm13", H_REG_VEC, "zmm13", "ymm13", 512, 0, true},
		
		{0, "zmm14", H_REG_VEC, nullptr, "zmm14", 512, 0, true},
		{0, "ymm14", H_REG_VEC, "zmm14", "zmm14", 512, 0, true},
		{0, "xmm14", H_REG_VEC, "zmm14", "ymm14", 512, 0, true},
		
		{0, "zmm15", H_REG_VEC, nullptr, "zmm15", 512, 0, true},
		{0, "ymm15", H_REG_VEC, "zmm15", "zmm15", 512, 0, true},
		{0, "xmm15", H_REG_VEC, "zmm15", "ymm15", 512, 0, true},
		
		{0, "zmm15", H_REG_VEC, nullptr, "zmm15", 512, 0, true},
		{0, "zmm16", H_REG_VEC, nullptr, "zmm16", 512, 0, true},
		{0, "zmm17", H_REG_VEC, nullptr, "zmm17", 512, 0, true},
		{0, "zmm18", H_REG_VEC, nullptr, "zmm18", 512, 0, true},
		{0, "zmm19", H_REG_VEC, nullptr, "zmm19", 512, 0, true},
		{0, "zmm20", H_REG_VEC, nullptr, "zmm20", 512, 0, true},
		{0, "zmm21", H_REG_VEC, nullptr, "zmm21", 512, 0, true},
		{0, "zmm22", H_REG_VEC, nullptr, "zmm22", 512, 0, true},
		{0, "zmm23", H_REG_VEC, nullptr, "zmm23", 512, 0, true},
		{0, "zmm24", H_REG_VEC, nullptr, "zmm24", 512, 0, true},
		{0, "zmm25", H_REG_VEC, nullptr, "zmm25", 512, 0, true},
		{0, "zmm26", H_REG_VEC, nullptr, "zmm26", 512, 0, true},
		{0, "zmm27", H_REG_VEC, nullptr, "zmm27", 512, 0, true},
		{0, "zmm28", H_REG_VEC, nullptr, "zmm28", 512, 0, true},
		{0, "zmm29", H_REG_VEC, nullptr, "zmm29", 512, 0, true},
		{0, "zmm30", H_REG_VEC, nullptr, "zmm30", 512, 0, true},
		{0, "zmm31", H_REG_VEC, nullptr, "zmm31", 512, 0, true},

		{0, "st0", H_REG_VEC, nullptr, "st0", 80, 0, true},
		{0, "st1", H_REG_VEC, nullptr, "st1", 80, 0, true},
		{0, "st2", H_REG_VEC, nullptr, "st2", 80, 0, true},
		{0, "st3", H_REG_VEC, nullptr, "st3", 80, 0, true},
		{0, "st4", H_REG_VEC, nullptr, "st4", 80, 0, true},
		{0, "st5", H_REG_VEC, nullptr, "st5", 80, 0, true},
		{0, "st6", H_REG_VEC, nullptr, "st6", 80, 0, true},
		{0, "st7", H_REG_VEC, nullptr, "st7", 80, 0, true},
		
		{0, "mm0", H_REG_VEC, "st0", "st0", 64, 0, true},
		{0, "mm1", H_REG_VEC, "st1", "st1", 64, 0, true},
		{0, "mm2", H_REG_VEC, "st2", "st2", 64, 0, true},
		{0, "mm3", H_REG_VEC, "st3", "st3", 64, 0, true},
		{0, "mm4", H_REG_VEC, "st4", "st4", 64, 0, true},
		{0, "mm5", H_REG_VEC, "st5", "st5", 64, 0, true},
		{0, "mm6", H_REG_VEC, "st6", "st6", 64, 0, true},
		{0, "mm7", H_REG_VEC, "st7", "st7", 64, 0, true},
		
	},
	{
		{
			0,
			"stack",//name
			H_STACK_MEMORY,//what backs the memory
			H_STACKPOLICY_BOTTOM,//where to add new elements
			0, 8, //maxcount(0 = infinite), wordbitsize
			"mem",
			"rsp",//stackptr
			{}
		},
		{
			0,
			"st",
			H_STACK_REGBACKED,
			H_STACKPOLICY_BOTTOM,
			8, 80,
			nullptr,
			nullptr,
			{"st0","st1","st2","st3","st4","st5","st6","st7"}
		},
	},
	{
		{
			0,
			"mem",
			(uint64_t)-1
		}
	},
	{
		/*
		//x86
		{
			"cdecl",//name
			H_CC_STACK_CALLER_SAVED, {"eax", "ecx", "edx"},//saved registers
			{},//register parameters
			nullptr,//register te count of parameters is passed
			{{"eax", "eax", "st0"}, {"edx", "edx", "st0"}}, //return value
			"mem", //backing stack
			H_CC_STACK_R2L//
		},
		{
			"syscall",
			H_CC_STACK_CALLER_SAVED, {"eax", "ecx", "edx"},
			{},
			"al",
			{{"eax", "eax", "eax"}},
			"mem",
			H_CC_STACK_R2L
		},
		{
			"pascal",
			H_CC_STACK_CALLER_SAVED, {},
			{},
			"al",
			{{"eax", "eax", "eax"}},
			"mem",
			H_CC_STACK_L2R
		},
		//x86_64
		{
			"microsoft64",
			H_CC_STACK_CALLER_SAVED, {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"},
			{{"rcx", "rcx", "xmm0", "xmm0", "ymm0"}, {"rdx", "rdx", "xmm1", "xmm1", "ymm1"}, {"r8", "r8", "xmm2", "xmm2", "ymm2"}, {"r9", "r9", "xmm3", "xmm3", "ymm3"}},
			nullptr,
			{{"rax", "rax", "xmm0", "xmm0", "ymm0"}},
			"mem",
			H_CC_STACK_R2L
		},*/
		{
			0, "vectorcall",
			{"rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "cs"},
			{
				{"rcx", H_CC_PARA_INT, 1}, {"rdx", H_CC_PARA_INT, 2}, {"r8", H_CC_PARA_INT, 3}, {"r9", H_CC_PARA_INT, 4},
				{"zmm0", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 1},
				{"zmm1", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 2},
				{"zmm2", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 3},
				{"zmm3", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 4}
			},
			{{"rax", H_CC_PARA_INT, 1}, {"zmm0", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 1}},
			nullptr,
			"stack",
			H_CC_STACK_ADJUST_CALLEE,
			H_CC_STACK_R2L
		},
		{
			0, "amd64",
			{"rbp", "rbx", "r12", "r13", "r14", "r15", "cs"},
			{
				{"rdi", H_CC_PARA_INT, 1}, {"rsi", H_CC_PARA_INT, 2}, {"rdx", H_CC_PARA_INT, 3}, {"rcx", H_CC_PARA_INT, 4}, {"r8", H_CC_PARA_INT, 5}, {"r9", H_CC_PARA_INT, 6},
				{"zmm0", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 1},
				{"zmm1", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 2},
				{"zmm2", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 3},
				{"zmm3", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 4},
				{"zmm4", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 5},
				{"zmm5", H_CC_PARA_FLOAT | H_CC_PARA_VEC128 | H_CC_PARA_VEC256, 6},
				{"cs", 0, 0}
			},
			{{"rax", H_CC_PARA_ALL, 1}, {"rdx", H_CC_PARA_ALL, 2}},
			"rax",
			"stack",
			H_CC_STACK_ADJUST_CALLEE,
			H_CC_STACK_R2L
		},
	},
	{
		{X86_INS_INVALID, "invalid", {}, H_INSTR_TYPE_MOV},
		{X86_INS_MOV, "mov", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVABS, "movabs", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVDQA, "movdqa", {{2, "=(#arg[1],#arg[2])"}}},
		{X86_INS_MOVDQU, "movdqu", {{2, "=(#arg[1],#arg[2])"}}},
		{X86_INS_MOVQ, "movq", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVD, "movd", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{
			X86_INS_MOVBE,
			"movbe", {
				{2, "==(#bsize(#arg[1]),16)", "=(#arg[1],#app(#arg[2][8,8],#arg[2][0,8]))"},
				{2, "==(#bsize(#arg[1]),32)", "=(#arg[1],#app(#arg[2][24,8],#arg[2][16,8],#arg[2][8,8],#arg[2][0,8]))"},
				{2, "==(#bsize(#arg[1]),64)", "=(#arg[1],#app(#arg[2][56,8],#arg[2][48,8],#arg[2][40,8],#arg[2][32,8],#arg[2][24,8],#arg[2][16,8],#arg[2][8,8],#arg[2][0,8]))"}
			}, H_INSTR_TYPE_MOV
		},
		{
			X86_INS_MOVDDUP,
			"movddup", {
				{2, "==(#bsize(#arg[1]),128)", "=(#arg[1],#app(#arg[2],#arg[2]))"},
				{2, "==(#bsize(#arg[1]),64)", "=(#arg[1],#app(#arg[2][0,64],#arg[2][0,64]))"},
			}, H_INSTR_TYPE_MOV
		},
		{
			X86_INS_MOVHPS,
			"movhps", {
				{2, "==(#bsize(#arg[1]),64)", "=(#arg[1],#arg[2][64,64])"},
				{2, "==(#bsize(#arg[1]),128)", "=(#arg[1],#app(#arg[2],#arg[1][64,64]))"},
			}, H_INSTR_TYPE_MOV
		},
		{X86_INS_MOVLHPS, "movlhps", {{2, "=(#arg[1],#app(#arg[1][0,64],#arg[2][0,64]))"}}, H_INSTR_TYPE_MOV},
		{
			X86_INS_MOVLPD,
			"movlpd", {
				{2, "==(#bsize(#arg[1]),64)", "=(#arg[1],#arg[2][0,64])"},
				{2, "==(#bsize(#arg[1]),128)", "=(#arg[1],#app(#arg[2],#arg[1][64,64]))"},
			}, H_INSTR_TYPE_MOV
		},
		{X86_INS_MOVMSKPD, "movskpd", {{2, "=(#arg[1],#app(#arg[2][63],#arg[2][127]))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVMSKPS, "movskps", {{2, "=(#arg[1],#app(#arg[2][31],#arg[2][63],#arg[2][95],#arg[2][127]))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVNTDQA, "movntdqa", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVNTDQ, "movntdq", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVNTI, "movnti", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVNTPD, "movntpd", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVNTPS, "movntps", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVNTSD, "movntsd", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVNTSS, "movntss", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSHDUP, "movshdup", {{2, "=(#arg[1],#app(#arg[2][32,32],#arg[2][32,32],#arg[2][96,32],#arg[2][96,32]))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSLDUP, "movsldup", {{2, "=(#arg[1],#app(#arg[2][0,32],#arg[2][0,32],#arg[2][64,32],#arg[2][64,32]))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSXD, "movsxd", {{2, "=(#arg[1],#sext(#arg[2],#bsize(#arg[1])))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVUPD, "movupd", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVUPS, "movups", {{2, "=(#arg[1],#arg[2])"}}, H_INSTR_TYPE_MOV},

		{X86_INS_LEA, "lea", {{2, "=(#arg[1],#val(#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVE, "cmovz", {{2, "?($zf,=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVNE, "cmovne", {{2, "?(#not($zf),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVA, "cmova", {{2, "?(#and($cf,$zf),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVBE, "cmovbe", {{2, "?(#or($cf,$zf),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVG,	"cmovg", {{2, "?(#and(#not($zf),==($sf,$of)),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVGE, "cmovge", {{2, "?(==($sf,$of),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVL,	"cmovge", {{2, "?(<>($sf,$of),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_CMOVLE,	"cmovle", {{2,  "?(#or($zf,<>($sf,$of)),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		//{X86_INS_CMOVC,{"cmovc", {0, 0, "?($cf) #arg[1] = #arg[2]"}}, H_INSTR_TYPE_MOV, H_INSTR_TYPE_UNKNOWN, H_INSTR_COND_C}},
		//{X86_INS_CMOVNC,{"cmovnc", {0, 0, "?(#not($cf)) #arg[1] = #arg[2]"}}, H_INSTR_TYPE_MOV, H_INSTR_TYPE_UNKNOWN, H_INSTR_COND_NC}},

		{X86_INS_CMOVB,	"cmovb", {{2,  "?($cf,=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVAE,	"cmovae", {{2, "?(#not($cf),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVO,	"cmovo", {{2, "?($of,=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVNO,	"cmovno", {{2, "?(#not($of),=(#arg[1],#arg[2])) "}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVS,	"cmovs", {{2, "?($sf,=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVNS,	"cmovns", {{2, "?(#not($sf),=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVP, "cmovp", {{2, "?($pf,=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_CMOVNP, "cmovp", {{2, "?($pf,=(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_JMP, "jmp", {{1, "#jmp(#arg[1])"}}, H_INSTR_TYPE_JMP, H_INSTR_TYPE_UNKNOWN},

		{X86_INS_JE, "je", {{1, "#cjmp($zf,#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JNE, "jne", {{1, "#cjmp(#not($zf),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JA, "ja", {{1, "#cjmp(#not(#or($cf,$zf)),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JAE, "jae", {{1, "#cjmp(#not($cf),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JB, "jb", {{1, "#cjmp(#not($cf),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JBE, "jbe", {{1, "#cjmp(#or($cf,$zf),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JG, "jg", {{1, "#cjmp(#and(#not($zf),==($sf,$of)),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JGE, "jge", {{1, "#cjmp(==($sf,$of),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JL, "jl", {{1, "#cjmp(<>($sf,$of),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JLE, "jle", {{1, "#cjmp(#or($zf,<>($sf,$of)),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JO, "jo", {{1, "#cjmp($of,#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JNO, "jno", {{1, "#cjmp(#not($of),#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JS, "js", {{1, "#cjmp($sf,#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JNS, "jns", {{1, "#cjmp(#not($sf),#arg[1])"}}, H_INSTR_TYPE_CJMP},

		{X86_INS_JP, "jp", {{1, "#cjmp($pf,#arg[1])"}}, H_INSTR_TYPE_CJMP},
		{X86_INS_JNP, "jnp", {{1, "#cjmp(#not($pf),#arg[1])"}}, H_INSTR_TYPE_CJMP},

		{X86_INS_JCXZ, "jcxz", {{1, "#cjmp(#not($cx),#arg[1])"}}, H_INSTR_TYPE_CJMP, H_INSTR_TYPE_CMP},
		{X86_INS_JECXZ, "jecxz", {{1, "#cjmp(#not($ecx),#arg[1])"}}, H_INSTR_TYPE_CJMP, H_INSTR_TYPE_CMP},
		{X86_INS_JRCXZ, "jrcxz", {{1, "#cjmp(#not($rcx),#arg[1])"}}, H_INSTR_TYPE_CJMP, H_INSTR_TYPE_CMP},


		{X86_INS_XCHG, "xchg", {{2, "#seq(=(#t[1],#arg[1]),=(#arg[1],#arg[2]),=(#arg[2],#t[1]))"}}, H_INSTR_TYPE_XCHG},

		{X86_INS_BSWAP, "bswap", {{1, "=(#arg[1],#app(#arg[1][24,8],#arg[1][16,8],#arg[1][8,8],#arg[1][0,8]))"}}, H_INSTR_TYPE_SWAP},

		{X86_INS_XADD, "xadd", {{2, "#seq(#rec[xchg](#arg[1],#arg[2]),#rec[add](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_XCHG, H_INSTR_TYPE_ADD},


		//X86_INS_CMPXCHG16B,
		{
			X86_INS_CMPXCHG,
			"cmpxchg", {
				{2, "==(#bsize(#arg[1]),8)", "#seq(=($zf,==($al,#arg[1])),=($cf,#c),=($pf,#p),=($af,#a),=($sf,#s),=($of,#o),?($zf,=(#arg[1],#arg[2]),=($al,#arg[1])))"},
				{2, "==(#bsize(#arg[1]),16)", "#seq(=($zf,==($al,#arg[1])),=($cf,#c),=($pf,#p),=($af,#a),=($sf,#s),=($of,#o),?($zf,=(#arg[1],#arg[2]),=($ax,#arg[1])))"},
				{2, "==(#bsize(#arg[1]),32)", "#seq(=($zf,==($eax,#arg[1])),=($cf,#c),=($pf,#p),=($af,#a),=($sf,#s),=($of,#o),?($zf,=(#arg[1],#arg[2]),=($eax,#arg[1])))"},
			}, H_INSTR_TYPE_XCHG, H_INSTR_TYPE_UNKNOWN
		},
		{
			X86_INS_CMPXCHG8B,
			"cmpxchg8g", {
				{2, "#seq(=($zf,==(#app($eax,$edx),#arg[1])),?($zf,=(#arg[1],#app($ebx,$ecx)),#seq(=($eax,#arg[1][0,32]),=($edx,#arg[1][32,32]))))"}
			}, H_INSTR_TYPE_XCHG, H_INSTR_TYPE_UNKNOWN

		},
		{
			X86_INS_CMPXCHG16B,
			"cmpxchg16g", {
				{2, "#seq(=($zf,==(#app($rax,$rdx),#arg[1])),?($zf,=(#arg[1],#app($rbx,$rcx)),#seq(=($rax,#arg[1][0,64]),=($rdx,#arg[1][64,64]))))"}
			}, H_INSTR_TYPE_XCHG, H_INSTR_TYPE_UNKNOWN
		},
		{X86_INS_PUSH, "push", {{1, "#push($stack,#arg[1])"}}, H_INSTR_TYPE_PUSH},
		{X86_INS_POP, "pop", {{1, "=(#arg[1],#pop($stack,#size(#arg[1])))"}}, H_INSTR_TYPE_POP},

		{X86_INS_PUSHAW, "pushad", {{1, "#seq(=(#t[1],$esp),#rec[push]($eax),#rec[push]($ecx),#rec[push]($edx),#rec[push]($edx),#rec[push]($ebx),#rec[push](#t[1]),#rec[push]($ebp),#rec[push]($esi),#rec[push]($edi))"}}, H_INSTR_TYPE_PUSH},
		{X86_INS_PUSHAL, "pusha", {{1, "#seq(=(#t[1],$sp),#rec[push]($ax),#rec[push]($cx),#rec[push]($dx),#rec[push]($dx),#rec[push]($bx),#rec[push](#t[1]),#rec[push]($bp),#rec[push]($si),#rec[push]($di))"}}, H_INSTR_TYPE_PUSH},

		{X86_INS_POPAW, "popad", {{1, "#seq(#rec[pop]($edi),#rec[pop]($esi),#rec[pop]($ebp),=($esp,+($esp,4)),#rec[pop]($ebx),#rec[pop]($edx),#rec[pop]($ecx),#rec[pop]($eax))"}}, H_INSTR_TYPE_PUSH},
		{X86_INS_POPAL, "popa", {{1, "#seq(#rec[pop]($di),#rec[pop]($si),#rec[pop]($bp),=($esp,+($esp,2)),#rec[pop]($bx),#rec[pop]($dx),#rec[pop]($cx),#rec[pop]($ax))"}}, H_INSTR_TYPE_PUSH},

		{X86_INS_RET, "ret", {{0, "#ret"}, {1, "#seq(#pop($stack,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_IRET, "iret", {{0, "#ret"}, {1, "#seq(#pop($stack,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_IRETD, "iretd", {{0, "#ret"}, {1, "#seq(#pop($stack,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_IRETQ, "iretq", {{0, "#ret"}, {1, "#seq(#pop($stack,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_RETF, "retf", {{0, "#ret"}, {1, "#seq(#pop($stack,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_RETFQ, "retfq", {{0, "#ret"}, {1, "#seq(#pop($stack,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},

		{X86_INS_HLT, "hlt", {{0, "#trap"}}},

		{X86_INS_CBW, "cbw", {{0, "=($ax,#sext($al,#bsize($ax)))"}}, H_INSTR_TYPE_EXTEND},
		{X86_INS_CWDE, "cwde", {{0, "=($eax,#ext($ax,#bsize($eax)))"}}, H_INSTR_TYPE_EXTEND},
		{X86_INS_CDQE, "cdqe", {{0, "=($rax,#sext($eax,#bsize($rax)))"}}, H_INSTR_TYPE_EXTEND},

		{X86_INS_CWD, "cwd", {{0, "=($dx,#sext($ax,#bsize($dx)))"}}, H_INSTR_TYPE_EXTEND},
		{X86_INS_CDQ, "cdq", {{0, "=($edx,#sext($eax,#bsize($edx)))"}}, H_INSTR_TYPE_EXTEND},
		{X86_INS_CQO, "cqo", {{0, "=($rdx,#sext($rax,#bsize($rdx)))"}}, H_INSTR_TYPE_EXTEND},

		{X86_INS_MOVSX, "movsx", {{2, "=(#arg[1],#sext(#arg[2],#bsize(#arg[1])))"}}, H_INSTR_TYPE_MOV, H_INSTR_TYPE_EXTEND},
		{X86_INS_MOVZX, "movzx", {{2, "=(#arg[1],#ext(#arg[2],#bsize(#arg[1])))"}}, H_INSTR_TYPE_MOV, H_INSTR_TYPE_EXTEND},

		{X86_INS_ADD, "add", {{2, "#seq(=(#arg[1],+(#arg[1],#arg[2])),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($cf,#c),=($af,#a))"}}, H_INSTR_TYPE_ADD},
		{X86_INS_ADC, "adc", {{2, "#seq(=(#arg[1],+(#arg[1],#arg[2],$cf)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($cf,#c),=($af,#a))"}}, H_INSTR_TYPE_ADD},

		{X86_INS_SUB, "sub", {{2, "#seq(=(#arg[1],-(#arg[1],#arg[2])),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($cf,#c),=($af,#a))"}}, H_INSTR_TYPE_SUB},
		{X86_INS_SBB, "sbb", {{2, "#seq(=(#arg[1],-(#arg[1],#arg[2],$cf)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($cf,#c),=($af,#a))"}}, H_INSTR_TYPE_SUB},

		{X86_INS_ADCX, "adcx", {{2, "#seq(=(#arg[1],+(#arg[1],#arg[2],$cf)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($cf,#c),=($af,#a))"}}, H_INSTR_TYPE_ADD},
		{X86_INS_ADOX, "adox", {{2, "#seq(=(#arg[1],+(#arg[1],#arg[2],$of)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($cf,#c),=($af,#a))"}}, H_INSTR_TYPE_ADD},

		{
			X86_INS_MUL,
			"mul", {
				{1, "==(#bsize(#arg[1]),8)", "#seq(=($ax,*($al,#arg[1])),=($cf,#c),=($of,#o),#undef($sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),16)", "#seq(=(#t[1],*($ax,#arg[1])),=($cf,#c),=($of,#o),=($dx,#t[1][0,16]),=($ax,#t[1][16,16]),#undef($sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),32)", "#seq(=(#t[1],*($eax,#arg[1])),=($cf,#c),=($of,#o),=($edx,#t[1][0,32]),=($eax,#t[1][32,32]),#undef($sf,$zf,$af,$pf))"},
			}, H_INSTR_TYPE_MUL
		},
		{
			X86_INS_IMUL,
			"imul", {
				{1, "==(#bsize(#arg[1]),8)", "#seq(=($ax,*($al,#arg[1])),=($cf,#c),=($of,#o),#undef($zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),16)", "#seq(=(#t[1],*($ax,#arg[1])),=($cf,#c),=($of,#o),=($dx,#t[1][0,16]),=($ax,#t[1][16,16]),#undef($zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),32)", "#seq(=(#t[1],*($eax,#arg[1])),=($cf,#c),=($of,#o),=($edx,#t[1][0,32]),=($eax,#t[1][32,32]),#undef($zf,$af,$pf))"},
				{2, "#seq(=(#arg[1],#smul(#arg[1],#sext(#arg[2],#bsize(#arg[1])))),=($cf,#c),=($of,#o),#undef($zf,$af,$pf))"},
				{3, "#seq(=(#arg[1],#smul(#arg[1],#sext(#arg[3],#bsize(#arg[2])))),=($cf,#c),=($of,#o),#undef($zf,$af,$pf))"},
			}, H_INSTR_TYPE_MUL
		},
		{
			X86_INS_DIV,
			"div", {
				{1, "==(#bsize(#arg[1]),8)", "#seq(=(#t[1],$ax),=($eax,#div(#t[1],#arg[1])),=($edx,#mod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),16)", "#seq(=(#t[1],#app($dx,$ax)),=($eax,#div(#t[1],#arg[1])),=($edx,#mod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),32)", "#seq(=(#t[1],#app($edx,$eax)),=($eax,#div(#t[1],#arg[1])),=($edx,#mod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
			}, H_INSTR_TYPE_DIV
		},
		{
			X86_INS_IDIV,
			"idiv", {
				{1, "==(#bsize(#arg[1]),8)", "#seq(=(#t[1],$ax),=($al,#sdiv(#t[1],#arg[1])),=($ah,#smod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),16)", "#seq(=(#t[1],#app($dx,$ax)),=($ax,#sdiv(#t[1],#arg[1])),=($dx,#smod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),32)", "#seq(=(#t[1],#app($edx,$eax)),=($eax,#sdiv(#t[1],#arg[1])),=($edx,#smod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
			}, H_INSTR_TYPE_DIV
		},
		{X86_INS_NOP, "nop", {{0, "#nop"}, {1, "#nop"}}},

		{X86_INS_INC, "inc", {{1, "#seq(=(#arg[1],+(#arg[1],1)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a))"}}, H_INSTR_TYPE_ADD},
		{X86_INS_DEC, "dec", {{1, "#seq(=(#arg[1],-(#arg[1],1)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a))"}}, H_INSTR_TYPE_SUB},

		{X86_INS_NEG, "neg", {{1, "#seq(=($cf,<>(#arg[1],0)),=(#arg[1],-(0,#arg[1])),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a))"}}, H_INSTR_TYPE_NEG},

		{X86_INS_CMP, "cmp", {{2, "#seq(=(#t[1],#arg[1]),#rec[sub](#t[1],#sext(#arg[2],#bsize(#arg[1]))))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_AND, "and", {{2, "#seq(=(#arg[1],#band(#arg[1],#arg[2])),=($of,0),=($cf,0),=($sf,#s),=($zf,#z),=($pf,#p),#undef($af))"}}, H_INSTR_TYPE_AND},
		{X86_INS_ANDPD, "andpd", {{2, "=(#arg[1],#band(#arg[1],#arg[2]))"}}},
		{X86_INS_ANDPS, "andps", {{2, "=(#arg[1],#band(#arg[1],#arg[2]))"}}},
		{X86_INS_PAND, "pand", {{2, "=(#arg[1],#band(#arg[1],#arg[2]))"}}},
//TODO flags undef checkpoint
		{X86_INS_ANDN, "andn", {{2, "=(#arg[1],#band(#bnot(#arg[1]),#arg[2]))"}}},
		{X86_INS_ANDNPD, "andnpd", {{2, "=(#arg[1],#band(#bnot(#arg[1]),#arg[2]))"}}},
		{X86_INS_ANDNPS, "andnps", {{2, "=(#arg[1],#band(#bnot(#arg[1]),#arg[2]))"}}},
		{X86_INS_PANDN, "pandn", {{2, "#seq(=(#arg[1],#band(#bnot(#arg[1]),#arg[2])),=($of,0),=($cf,0),=($sf,#s),=($zf,#z))"}}},

		{X86_INS_OR, "or", {{2, "#seq(=(#arg[1],#bor(#arg[1],#arg[2])),=($of,0),=($cf,0),=($sf,#s),=($zf,#z),=($pf,#p))"}}, H_INSTR_TYPE_OR},
		{X86_INS_ORPD, "orpd", {{2, "=(#arg[1],#bor(#arg[1],#arg[2]))"}}},
		{X86_INS_ORPS, "orps", {{2, "=(#arg[1],#bor(#arg[1],#arg[2]))"}}},
		{X86_INS_POR, "por", {{2, "=(#arg[1],#bor(#arg[1],#arg[2]))"}}},

		{X86_INS_XOR, "xor", {{2, "#seq(=(#arg[1],#bxor(#arg[1],#arg[2])),=($of,0),=($cf,0),=($sf,#s),=($zf,#z),=($pf,#p))"}}, H_INSTR_TYPE_XOR},
		{X86_INS_XORPD, "xorpd", {{2, "=(#arg[1],#bxor(#arg[1],#arg[2]))"}}},
		{X86_INS_XORPS, "xorps", {{2, "=(#arg[1],#bxor(#arg[1],#arg[2]))"}}},
		{X86_INS_PXOR, "pxor", {{2, "=(#arg[1],#bxor(#arg[1],#arg[2]))"}}},

		{X86_INS_NOT, "not", {{1, "=(#arg[1],#bnot(#arg[1]))"}}, H_INSTR_TYPE_NOT},

		{
			X86_INS_SAR,
			"sar", {
				{1, "#seq(=(#t[1],#sar(#arg[1],1)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
				{2, "#seq(=(#t[1],#sar(#arg[1],#arg[2])),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
			}, H_INSTR_TYPE_SHH
		},

		{
			X86_INS_SHR,
			"shr", {
				{1, "#seq(=(#t[1],#shr(#arg[1],1)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
				{2, "#seq(=(#t[1],#shr(#arg[1],#arg[2])),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"}
			}, H_INSTR_TYPE_SHH
		},

		{
			X86_INS_SAL,
			"sal", {
				{1, "#seq(=(#t[1],#sal(#arg[1],1)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
				{2, "#seq(=(#t[1],#sal(#arg[1],#arg[2])),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"}
			}, H_INSTR_TYPE_SHL
		},

		{
			X86_INS_SHL,
			"shl", {
				{1, "#seq(=(#t[1],#shl(#arg[1],1)),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
				{2, "#seq(=(#t[1],#shl(#arg[1],#arg[2])),=($zf,#z),=($pf,#p),=($sf,#s),=($of,#o),=($af,#a),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"}
			}, H_INSTR_TYPE_SHL
		},

//TODO flags
		{X86_INS_SHRD, "shrd", { {2, "=(#arg[1],#shr(#app(#arg[1],#arg[2]),$cl))"}, {3, "=(#arg[1],#app(#shr(#arg[1],#arg[2]),#arg[3]))"}}, H_INSTR_TYPE_SHH},
		{X86_INS_SHLD, "shld", { {2, "=(#arg[1],#shl(#app(#arg[1],#arg[2]),$cl))"}, {3, "=(#arg[1],#app(#shl(#arg[1],#arg[2]),#arg[3]))"}}, H_INSTR_TYPE_SHL},

//TODO flags for rotates
		{X86_INS_ROR, "ror", {{2, "=(#arg[1],#ror(#arg[1],1))"}, {3, "=(#arg[1],#ror(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_ROR},
		{X86_INS_ROL, "rol", {{2, "=(#arg[1],#rol(#arg[1],1))"}, {3, "=(#arg[1],#rol(#arg[1],#arg[2]))"}}, H_INSTR_TYPE_ROL}, {
			X86_INS_RCR,
			"rcr", {
				{1, "#seq(=(#t[1],#ror(#app(#arg[1],$cf),1)),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
				{2, "#seq(=(#t[1],#ror(#app(#arg[1],$cf),#arg[2])),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"}
			}, H_INSTR_TYPE_ROR
		}, {
			X86_INS_RCL,
			"rcl", {
				{1, "#seq(=(#t[1],#rol(#app(#arg[1],$cf),1)),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
				{2, "#seq(=(#t[1],#rol(#app(#arg[1],$cf),#arg[2])),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"}
			}, H_INSTR_TYPE_ROL
		},

		{X86_INS_BT, "bt", {{2, "=($cf,#arg[1][#arg[2]])"}}, H_INSTR_TYPE_BITTEST},
		{X86_INS_BTS, "bts", {{2, "#seq(=($cf,#arg[1][#arg[2]]),=(#arg[1][#arg[2]],1))"}}, H_INSTR_TYPE_BITTEST, H_INSTR_TYPE_BITSET},
		{X86_INS_BTR, "btr", {{2, "#seq(=($cf,#arg[1][#arg[2]]),=(#arg[1][#arg[2]],0))"}}, H_INSTR_TYPE_BITTEST, H_INSTR_TYPE_BITRESET},
		{X86_INS_BTC, "btc", {{2, "#seq(=($cf,#arg[1][#arg[2]]),=(#arg[1][#arg[2]],#not(#arg[1][#arg[2]])))"}}, H_INSTR_TYPE_BITTEST, H_INSTR_TYPE_CPL},

		{X86_INS_LOOP, "loop", {{1, "#seq(=($ecx,-($ecx,1)),#cjmp(#not($ecx),#arg[1]))"}}, H_INSTR_TYPE_CJMP},


		{X86_INS_LOOPE, "loope", {{1, "#seq(=($ecx,-($ecx,1)),#cjmp(#not(#and($ecx,$zf)),#arg[1]))"}}, H_INSTR_TYPE_CJMP},

		{X86_INS_LOOPNE, "loopne", {{1, "#seq(=($ecx,-($ecx,1)),#cjmp(#not(#and($ecx,#not($zf))),#arg[1]))"}}, H_INSTR_TYPE_CJMP},

		{X86_INS_CALL, "call", {{1, "#call(#arg[1])"}}, H_INSTR_TYPE_CALL},

		{X86_INS_INT, "int", {{1, "#syscall(#arg[1])"}}, H_INSTR_TYPE_SYSCALL, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_INTO, "into", {{"#syscall"}}, H_INSTR_TYPE_SYSCALL, H_INSTR_TYPE_UNKNOWN},

		{X86_INS_BOUND, "bound", {{2, "#seq(=(#t[1],#ld($mem,#arg[2],#size(#arg[2]))),=(#t[2],#ld($mem,+(#arg[2],#size(#arg[1])),#size(#arg[1]))),?(#or(<(#arg[1],#t[1]),>(#arg[1],#t[2])),#trap))"}}},

		{X86_INS_ENTER, "enter", {{1, "#seq(#rec[push]($ebp),#rec[mov]($ebp,$esp),#rec[sub]($esp,#arg[1]))"}}},
		{X86_INS_LEAVE, "leave", {{0, "#seq(#rec[mov]($esp,$ebp),#rec[pop]($ebp))"}}},

		{X86_INS_SETE, "sete", {{1, "=(#arg[1],$zf)"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETNE, "setne", {{1, "=(#arg[1],#not($zf))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETA, "seta", {{1, "=(#arg[1],#not(#or($cf,$zf)))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETAE, "setae", {{1, "=(#arg[1],#not($cf))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETB, "setae", {{1, "=(#arg[1],$cf)"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETBE, "setbe", {{1, "=(#arg[1],#or($cf,$zf))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETG, "setg", {{1, "=(#arg[1],#and(#not($zf),==($sf,$of)))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETGE, "setge", {{1, "=(#arg[1],==($sf,$of))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETL, "setl", {{1, "=(#arg[1],<>($sf,$of))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETLE, "setle", {{1, "=(#arg[1],#or($zf,<>($sf,$of)))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_SETS, "sets", {{1, "=(#arg[1],$sf)"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETNS, "setns", {{1, "=(#arg[1],#not($sf))"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETO, "seto", {{1, "=(#arg[1],$of)"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETNO, "setno", {{1, "=(#arg[1],#not($of))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_SETP, "setp", {{1, "=(#arg[1],$pf)"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SETNP, "setnp", {{1, "=(#arg[1],#not($pf))"}}, H_INSTR_TYPE_MOV},

		{X86_INS_TEST, "test", {{2, "#seq(=(#t[1],#band(#arg[1],#arg[2])),=($cf,0),=($of,0),=($pf,#p),=($zf,#z),=($sf,#s))"}}, H_INSTR_TYPE_AND},

		{X86_INS_BSF, "bsf", {}},
		{X86_INS_BSR, "bsr", {}},
		{X86_INS_CRC32, "crc32", {}},
		{X86_INS_POPCNT, "popcnt", {}},

		{X86_INS_STC, "stc", {{0, "=($cf,1)"}}, H_INSTR_TYPE_BITSET},
		{X86_INS_CLC, "clc", {{0, "=($cf,0)"}}, H_INSTR_TYPE_BITRESET},
		{X86_INS_CMC, "cmc", {{0, "=($cf,#not($cf))"}}, H_INSTR_TYPE_CPL},

		{X86_INS_STD, "std", {{0, "=($df,1)"}}, H_INSTR_TYPE_BITSET},
		{X86_INS_CLD, "cld", {{0, "=($df,0)"}}, H_INSTR_TYPE_BITRESET},

		{X86_INS_LAHF, "lahf", {{0, "=($ah,$eflags)"}}, H_INSTR_TYPE_MOV},
		{X86_INS_SAHF, "sahf", {{0, "=($eflags,$ah)"}}, H_INSTR_TYPE_MOV},

		{X86_INS_PUSHF, "pushf", {{0, "#rec[push]($flags)"}}, H_INSTR_TYPE_PUSH},
		{X86_INS_PUSHFD, "pushfd", {{0, "#rec[push]($eflags)"}}, H_INSTR_TYPE_PUSH},
		{X86_INS_PUSHFQ, "pushfq", {{0, "#rec[push]($rflags)"}}, H_INSTR_TYPE_PUSH},

		{X86_INS_POPF, "popf", {{0, "#rec[pop]($flags)"}}, H_INSTR_TYPE_POP},
		{X86_INS_POPFD, "popfd", {{0, "#rec[pop]($eflags)"}}, H_INSTR_TYPE_POP},
		{X86_INS_POPFQ, "popfq", {{0, "#rec[pop]($rflags)"}}, H_INSTR_TYPE_POP},

		{X86_INS_STI, "sti", {{0, "=($if,1)"}}, H_INSTR_TYPE_BITSET},
		{X86_INS_CLI, "cli", {{0, "=($if,0)"}}, H_INSTR_TYPE_BITRESET},

//TODO
		{X86_INS_AAA, "aaa", {}},
		{X86_INS_AAD, "aad", {}},
		{X86_INS_AAM, "aam", {}},
		{X86_INS_AAS, "aas", {}},
		{X86_INS_DAA, "daa", {}},
		{X86_INS_DAS, "das", {}},

		{X86_INS_FABS, "fabs", {{0, "=($st[0],#fmul($st[0],-1))"}}},
		{X86_INS_ADDPD, "addpd", {{2, "=(#arg[1],#app(#fadd(#arg[1][0,64],#arg[2][0,64]),#fadd(#arg[1][64,64],#arg[2][64,64])))"}}},
		{
			X86_INS_ADDPS,
			"addps", {
				{
					2, "=(#arg[1],#app(#fadd(#arg[1][0,32],#arg[2][0,32]),#fadd(#arg[1][32,32],#arg[2][32,32]),"
					"#fadd(#arg[1][64,32],#arg[2][64,32]),#fadd(#arg[1][96,32],#arg[2][96,32])))"
				}
			}
		},
		{X86_INS_ADDSD, "addsd", {{2, "=(#arg[1],#app(#fadd(#arg[1][0,64],#arg[2][0,64]),#arg[1][64]))"}}},
		{X86_INS_ADDSS, "addss", {{2, "=(#arg[1],#app(#fadd(#arg[1][0,32],#arg[2][0,32]),#arg[1][32]))"}}},
		{X86_INS_ADDSUBPD, "addsubpd", {{2, "=(#arg[1],#app(#fsub(#arg[1][0,64],#arg[2][0,64]),#fadd(#arg[1][64,64],#arg[2][64,64])))"}}},
		{
			X86_INS_ADDSUBPS,
			"addsubps", {
				{
					2, "=(#arg[1],#app(#fsub(#arg[1][0,32],#arg[2][0,32]),#fadd(#arg[1][32,32],#arg[2][32,32]),"
					"#fsub(#arg[1][64,32],#arg[2][64,32]),#fadd(#arg[1][96,32],#arg[2][96,32])))"
				}
			}
		},

		{X86_INS_CVTDQ2PD, "cvtdq2pd", {{2, "=(#arg[1],#app(#fext(#i2f(#arg[2][0,32]),64),#fext(#i2f(#arg[2][32,32]),64)))"}}},
		{X86_INS_CVTDQ2PS, "cvtdq2ps", {{2, "=(#arg[1],#app(#i2f(#arg[2][0,32]),#i2f(#arg[2][32,32]),#i2f(#arg[2][64,32]),#i2f(#arg[2][96,32])))"}}},
		{X86_INS_CVTPD2DQ, "cvtpd2dq", {{2, "=(#arg[1],#app(#f2i(#arg[2][0,32]),#f2i(#arg[2][32,32]),#ext(0,64)))"}}},
		{X86_INS_CVTPD2PS, "cvtpd2ps", {{2, "=(#arg[1],#app(#fext(#arg[2][0,64],32),#fext(#arg[2][64,64],32)))"}}},
		{X86_INS_CVTPS2DQ, "cvtps2dq", {{2, "=(#arg[1],#app(#f2i(#arg[2][0,32]),#f2i(#arg[2][32,32]),#f2i(#arg[2][64,32]),#f2i(#arg[2][96,32])))"}}},
		{X86_INS_CVTPS2PD, "cvtps2pd", {{2, "=(#arg[1],#app(#fext(#arg[2][0,32],64),#fext(#arg[2][32,32],64)))"}}},
		{X86_INS_CVTSD2SI, "cvtsd2si", {{2, "=(#arg[1],#app(#f2i(#arg[2][0,64],32),#arg[1][32]))"}}},
		{X86_INS_CVTSD2SS, "cvtsd2ss", {{2, "=(#arg[1],#app(#fext(#arg[2][0,64],32),#arg[1][32]))"}}},
		{X86_INS_CVTSI2SD, "cvtsi2sd", {{2, "=(#arg[1],#app(#i2f(#arg[2][0,32],64),#arg[1][64]))"}}},
		{X86_INS_CVTSI2SS, "cvtsi2ss", {{2, "=(#arg[1],#app(#i2f(#arg[2][0,32]),#arg[1][32]))"}}},
		{X86_INS_CVTSS2SD, "cvtss2sd", {{2, "=(#arg[1],#app(#fext(#arg[2][0,32],64),#arg[1][64]))"}}},
		{X86_INS_CVTSS2SI, "cvtss2si", {{2, "=(#arg[1],#app(#f2i(#arg[2][0,32]),#arg[1][32]))"}}},
		{X86_INS_CVTTPD2DQ, "cvttpd2dq", {{2, "=(#arg[1],#app(#ext(#f2i(#arg[2][0,64]),32),#ext(#f2i(#arg[2][64,64]),32),#ext(0,64)))"}}},
		{X86_INS_CVTTPS2DQ, "cvttps2dq", {{2, "=(#arg[1],#app(#f2i(#arg[2][0,32]),#f2i(#arg[2][32,32]),#f2i(#arg[2][64,32]),#f2i(#arg[2][96,32])))"}}},
		{X86_INS_CVTTSD2SI, "cvttsd2si", {{2, "=(#arg[1],#app(#f2i(#arg[2][0,64],32),#arg[1][32]))"}}},
		{X86_INS_CVTTSS2SI, "cvttss2si", {{2, "=(#arg[1],#app(#f2i(#arg[2][0,64],32),#arg[1][32]))"}}},

		{X86_INS_AESDECLAST, "aesdeclast", {}, H_INSTR_TYPE_CRYPTO},
		{X86_INS_AESDEC, "aesdec", {}, H_INSTR_TYPE_CRYPTO},
		{X86_INS_AESENCLAST, "aesenclast", {}, H_INSTR_TYPE_CRYPTO},
		{X86_INS_AESENC, "aesenc", {}, H_INSTR_TYPE_CRYPTO},
		{X86_INS_AESIMC, "aesimc", {}, H_INSTR_TYPE_CRYPTO},
		{X86_INS_AESKEYGENASSIST, "aeskeygenassist", {}, H_INSTR_TYPE_CRYPTO},

/*
		{X86_INS_INSB, "insb", {}},
		{X86_INS_INSD, "insd", {}},
		{X86_INS_INSW, "insw", {}},

		{X86_INS_INSB | CUSOM_X86_INSTR_EXTR_REP, "rep insb", {}},
		{X86_INS_INSD | CUSOM_X86_INSTR_EXTR_REP, "rep insd", {}},
		{X86_INS_INSD | CUSOM_X86_INSTR_EXTR_REP, "rep insw", {}},

		{X86_INS_MOVSB, "movsb", {}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSW, "movsw", {}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSD, "movsd", {}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSQ, "movsq", {}, H_INSTR_TYPE_MOV},

		{X86_INS_MOVSB | CUSOM_X86_INSTR_EXTR_REP, "rep movsb", {}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSW | CUSOM_X86_INSTR_EXTR_REP, "rep movsw", {}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSD | CUSOM_X86_INSTR_EXTR_REP, "rep movsd", {}, H_INSTR_TYPE_MOV},
		{X86_INS_MOVSQ | CUSOM_X86_INSTR_EXTR_REP, "rep movsq", {}, H_INSTR_TYPE_MOV},

		{X86_INS_OUTSB, "outsb", {}},
		{X86_INS_OUTSD, "outsd", {}},
		{X86_INS_OUTSW, "outsw", {}},

		{X86_INS_OUTSB | CUSOM_X86_INSTR_EXTR_REP, "rep outsb", {}},
		{X86_INS_OUTSD | CUSOM_X86_INSTR_EXTR_REP, "rep outsd", {}},
		{X86_INS_OUTSW | CUSOM_X86_INSTR_EXTR_REP, "rep outsw", {}},
		 */

		{X86_INS_LODSB, "lodsb", {{2, "#seq(=(#arg[1],#ld($mem,#arg[2],#size(#arg[2]))),?($df,=($rdi,-($rdi,1)),=($rdi,+($rdi,1))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSW, "lodsw", {{2, "#seq(=(#arg[1],#ld($mem,#arg[2],#size(#arg[2]))),?($df,=($rdi,-($rdi,2)),=($rdi,+($rdi,2))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSD, "lodsd", {{2, "#seq(=(#arg[1],#ld($mem,#arg[2],#size(#arg[2]))),?($df,=($rdi,-($rdi,4)),=($rdi,+($rdi,4))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSQ, "lodsq", {{2, "#seq(=(#arg[1],#ld($mem,#arg[2],#size(#arg[2]))),?($df,=($rdi,-($rdi,8)),=($rdi,+($rdi,8))))"}}, H_INSTR_TYPE_LOAD},
		
		{X86_INS_LODSB | CUSOM_X86_INSTR_EXTR_REP, "rep lodsb", {{2, "#rep($rcx,#seq(#rec[lodsb](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSW | CUSOM_X86_INSTR_EXTR_REP, "rep lodsw", {{2, "#rep($rcx,#seq(#rec[lodsw](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSD | CUSOM_X86_INSTR_EXTR_REP, "rep lodsd", {{2, "#rep($rcx,#seq(#rec[lodsd](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSQ | CUSOM_X86_INSTR_EXTR_REP, "rep lodsq", {{2, "#rep($rcx,#seq(#rec[lodsq](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, H_INSTR_TYPE_LOAD},

		{X86_INS_STOSB, "stosb", {{2, "#seq(#st($mem,#arg[2],#arg[1]),?($df,=($rdi,-($rdi,1)),=($rdi,+($rdi,1))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSW, "stosw", {{2, "#seq(#st($mem,#arg[2],#arg[1]),?($df,=($rdi,-($rdi,2)),=($rdi,+($rdi,2))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSD, "stosd", {{2, "#seq(#st($mem,#arg[2],#arg[1]),?($df,=($rdi,-($rdi,4)),=($rdi,+($rdi,4))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSQ, "stosq", {{2, "#seq(#st($mem,#arg[2],#arg[1]),?($df,=($rdi,-($rdi,8)),=($rdi,+($rdi,8))))"}}, H_INSTR_TYPE_STORE},

		{X86_INS_STOSB | CUSOM_X86_INSTR_EXTR_REP, "rep stosb", {{2, "#rep($rcx,#seq(#rec[stosb](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSW | CUSOM_X86_INSTR_EXTR_REP, "rep stosw", {{2, "#rep($rcx,#seq(#rec[stosw](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSD | CUSOM_X86_INSTR_EXTR_REP, "rep stosd", {{2, "#rep($rcx,#seq(#rec[stosd](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSQ | CUSOM_X86_INSTR_EXTR_REP, "rep stosq", {{2, "#rep($rcx,#seq(#rec[stosq](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, H_INSTR_TYPE_STORE},
		
		{X86_INS_CMPSB, "cmpsb", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,1),-($rdi,1))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSW, "cmpsw", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,2),-($rdi,2))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSD, "cmpsd", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,4),-($rdi,4))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSQ, "cmpsq", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,8),-($rdi,8))))"}}, H_INSTR_TYPE_CMP},
		
		{X86_INS_CMPSB | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsb", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[cmpsb](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSW | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsw", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[cmpsw](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSD | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsd", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[cmpsd](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSQ | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsq", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[cmpsq](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_CMPSB | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsb", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[cmpsb](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSW | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsw", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[cmpsw](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSD | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsd", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[cmpsd](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSQ | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsq", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[cmpsq](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_SCASB, "scasb", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),?($df,=($rdi,-($rdi,1)),=($rdi,+($rdi,1))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASW, "scasw", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),?($df,=($rdi,-($rdi,2)),=($rdi,+($rdi,2))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASD, "scasd", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),?($df,=($rdi,-($rdi,4)),=($rdi,+($rdi,4))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASQ, "scasq", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),?($df,=($rdi,-($rdi,8)),=($rdi,+($rdi,8))))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_SCASB | CUSOM_X86_INSTR_EXTR_REPE, "repe scasb", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[scasb](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASW | CUSOM_X86_INSTR_EXTR_REPE, "repe scasw", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[scasw](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASD | CUSOM_X86_INSTR_EXTR_REPE, "repe scasd", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[scasd](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASQ | CUSOM_X86_INSTR_EXTR_REPE, "repe scasq", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[scasq](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_SCASB | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasb", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[scasb](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASW | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasw", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[scasw](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASD | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasd", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[scasd](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASQ | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasq", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[scasq](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, H_INSTR_TYPE_CMP},

//x87
		{X86_INS_FADD, "fadd", {{1, "=($st[0],#fadd($st[0],#fext(#arg[1],#bsize($st[0]))))"}, {2, "=(#arg[1],#fadd(#arg[1],#arg[2]))"}}},
		{X86_INS_FIADD, "fiadd", {{1, "=($st[0],#fadd($st[0],#fext(#arg[1],#bsize($st[0]))))"}}},
		{X86_INS_FADDP, "faddp", {{0, "#push($st,#fadd(#pop($st),#pop($st)))"}, {2, "#seq(=(#arg[1],#fadd(#arg[1],#arg[2])),#pop($st))"}}},

//TODO add missing instructions

	},
};
