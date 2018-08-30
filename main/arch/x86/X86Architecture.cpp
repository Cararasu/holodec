
#include "X86FunctionAnalyzer.h"
#include "../../InstrDefinition.h"

using namespace holodec;


Architecture holox86::x86architecture {"x86", "x86", 8, 8, 8, {
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
		{0, "rax", RegType::eGPR, nullptr, "rax", 64, 0, true},
		{0, "eax", RegType::eGPR, "rax", "rax", 32, 0, true},
		{0, "ax", RegType::eGPR, "eax", "rax", 16, 0, false},
		{0, "al", RegType::eGPR, "ax", "rax", 8, 0, false},{0, "ah", RegType::eGPR, "ax", "rax", 8, 8, false},
		
		{0, "rbx", RegType::eGPR, nullptr, "rbx", 64, 0, true},
		{0, "ebx", RegType::eGPR, "rbx", "rbx", 32, 0, true},
		{0, "bx", RegType::eGPR, "ebx", "rbx", 16, 0, false},
		{0, "bl", RegType::eGPR, "bx", "rbx", 8, 0, false},{0, "bh", RegType::eGPR, "bx", "rbx", 8, 8, false},
		
		{0, "rcx", RegType::eGPR, nullptr, "rcx", 64, 0, true},
		{0, "ecx", RegType::eGPR, "rcx", "rcx", 32, 0, true},
		{0, "cx", RegType::eGPR, "ecx", "rcx", 16, 0, false},
		{0, "cl", RegType::eGPR, "cx", "rcx", 8, 0, false},{0, "ch", RegType::eGPR, "cx", "rcx", 8, 8, false},
		
		{0, "rdx", RegType::eGPR, nullptr, "rdx", 64, 0, true},
		{0, "edx", RegType::eGPR, "rdx", "rdx", 32, 0, true},
		{0, "dx", RegType::eGPR, "edx", "rdx", 16, 0, false},
		{0, "dl", RegType::eGPR, "dx", "rdx", 8, 0, false},{0, "dh", RegType::eGPR, "dx", "rdx", 8, 8, false},
		
		{0, "r8", RegType::eGPR, nullptr, "r8", 64, 0, true},{0, "r8d", RegType::eGPR, "r8", "r8", 32, 0, true},
		{0, "r8w", RegType::eGPR, "r8d", "r8", 16, 0, false},{0, "r8b", RegType::eGPR, "r8w", "r8", 8, 0, false},
		
		{0, "r9", RegType::eGPR, nullptr, "r9", 64, 0, true},{0, "r9d", RegType::eGPR, "r9", "r9", 32, 0, true},
		{0, "r9w", RegType::eGPR, "r9d", "r9", 16, 0, false},{0, "r9b", RegType::eGPR, "r9w", "r9", 8, 0, false},
		
		{0, "r10", RegType::eGPR, nullptr, "r10", 64, 0, true},{0, "r10d", RegType::eGPR, "r10", "r10", 32, 0, true},
		{0, "r10w", RegType::eGPR, "r10d", "r10", 16, 0, false},{0, "r10b", RegType::eGPR, "r10w", "r10", 8, 0, false},
		
		{0, "r11", RegType::eGPR, nullptr, "r11", 64, 0, true},{0, "r11d", RegType::eGPR, "r11", "r11", 32, 0, true},
		{0, "r11w", RegType::eGPR, "r11d", "r11", 16, 0, false},{0, "r11b", RegType::eGPR, "r11w", "r11", 8, 0, false},
		
		{0, "r12", RegType::eGPR, nullptr, "r12", 64, 0, true},{0, "r12d", RegType::eGPR, "r12", "r12", 32, 0, true},
		{0, "r12w", RegType::eGPR, "r12d", "r12", 16, 0, false},{0, "r12b", RegType::eGPR, "r12w", "r12", 8, 0, false},
		
		{0, "r13", RegType::eGPR, nullptr, "r13", 64, 0, true},{0, "r13d", RegType::eGPR, "r13", "r13", 32, 0, true},
		{0, "r13w", RegType::eGPR, "r13d", "r13", 16, 0, false},{0, "r13b", RegType::eGPR, "r13w", "r13", 8, 0, false},
		
		{0, "r14", RegType::eGPR, nullptr, "r14", 64, 0, true},{0, "r14d", RegType::eGPR, "r14", "r14", 32, 0, true},
		{0, "r14w", RegType::eGPR, "r14d", "r14", 16, 0, false},{0, "r14b", RegType::eGPR, "r14w", "r14", 8, 0, false},
		
		{0, "r15", RegType::eGPR, nullptr, "r15", 64, 0, true},{0, "r15d", RegType::eGPR, "r15", "r15", 32, 0, true},
		{0, "r15w", RegType::eGPR, "r15d", "r15", 16, 0, false},{0, "r15b", RegType::eGPR, "r15w", "r15", 8, 0, false},
		
		{0, "rbp", RegType::eGPR, nullptr, "rbp", 64, 0, true},
		{0, "ebp", RegType::eGPR, "rbp", "rbp", 32, 0, true},
		{0, "bp", RegType::eGPR, "ebp", "rbp", 16, 0, false},{0, "bpl", RegType::eGPR, "bp", "rbp", 8, 0, false},
		
		{0, "rsi", RegType::eGPR, nullptr, "rsi", 64, 0, true},
		{0, "esi", RegType::eGPR, "rsi", "rsi", 32, 0, true},
		{0, "si", RegType::eGPR, "esi", "rsi", 16, 0, false},{0, "sil", RegType::eGPR, "si", "rsi", 8, 0, false},
		
		{0, "rdi", RegType::eGPR, nullptr, "rdi", 64, 0, true},
		{0, "edi", RegType::eGPR, "rdi", "rdi", 32, 0, true},
		{0, "di", RegType::eGPR, "edi", "rdi", 16, 0, false},{0, "dil", RegType::eGPR, "di", "rdi", 8, 0, false},
		
		{0, "rsp", RegType::eGPR, nullptr, "rsp", 64, 0, true},
		{0, "esp", RegType::eGPR, "rsp", "rsp", 32, 0, true},
		{0, "sp", RegType::eGPR, "esp", "rsp", 16, 0, false},{0, "spl", RegType::eGPR, "sp", "rsp", 8, 0, true},
		
		{0, "rip", RegType::eGPR, nullptr, "rip", 64, 0, true},
		{0, "eip", RegType::eGPR, "rip", "rip", 32, 0, true},
		{0, "ip", RegType::eGPR, "eip", "rip", 16, 0, false},{0, "ipl", RegType::eGPR, "ip", "rip", 8, 0, false},
		
		{0, "cf", RegType::eFlag, nullptr, "cf", 1, 0, false},
		{0, "pf", RegType::eFlag, nullptr, "pf", 1, 0, false},
		{0, "af", RegType::eFlag, nullptr, "af", 1, 0, false},
		{0, "zf", RegType::eFlag, nullptr, "zf", 1, 0, false},
		{0, "sf", RegType::eFlag, nullptr, "sf", 1, 0, false},
		{0, "tf", RegType::eFlag, nullptr, "tf", 1, 0, false},
		{0, "if", RegType::eFlag, nullptr, "if", 1, 0, false},
		{0, "df", RegType::eFlag, nullptr, "df", 1, 0, false},
		{0, "of", RegType::eFlag, nullptr, "of", 1, 0, false},
		{0, "iopl", RegType::eFlag, nullptr, "iopl", 1, 0, false},
		{0, "nt", RegType::eFlag, nullptr, "nt", 1, 0, false},
		
		{0, "rf", RegType::eFlag, nullptr, "rf", 1, 0, false},
		{0, "vm", RegType::eFlag, nullptr, "vm", 1, 0, false},
		{0, "ac", RegType::eFlag, nullptr, "ac", 1, 0, false},
		{0, "vif", RegType::eFlag, nullptr, "vif", 1, 0, false},
		{0, "vip", RegType::eFlag, nullptr, "vip", 1, 0, false},
		{0, "id", RegType::eFlag, nullptr, "id", 1, 0, false},

		{0, "cs", RegType::eSegment, nullptr, "cs", 16, 0, false},
		{0, "ds", RegType::eSegment, nullptr, "ds", 16, 0, false},
		{0, "ss", RegType::eSegment, nullptr, "ss", 16, 0, false},
		{0, "es", RegType::eSegment, nullptr, "es", 16, 0, false},
		{0, "fs", RegType::eSegment, nullptr, "fs", 16, 0, false},
		{0, "gs", RegType::eSegment, nullptr, "gs", 16, 0, false},

		/*Do we need debug registers? maybe not
				{"dr0", REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr1", REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr2", REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr3", REG_DEBUG, REG_TRACK_VOLATILE, 64, 0},
				{"dr4", REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr5", REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr6", REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr7", REG_DEBUG, REG_TRACK_VOLATILE, 64, 0},
				{"dr8",  REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr9",  REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr10",  REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr11",  REG_DEBUG, REG_TRACK_VOLATILE, 64, 0},
				{"dr12",  REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr13",  REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr14",  REG_DEBUG, REG_TRACK_VOLATILE, 64, 0}, {"dr15",  REG_DEBUG, REG_TRACK_VOLATILE, 64, 0},
		*/
		/*Do we need control registers? maybe not
				{"cr0",  REG_CONTROL, REG_TRACK_VOLATILE, 32, 0}, {"cr1",  REG_CONTROL, REG_TRACK_VOLATILE, 32, 0}, {"cr2",  REG_CONTROL, REG_TRACK_VOLATILE, 32, 0}, {"cr3",  REG_CONTROL, REG_TRACK_VOLATILE, 32, 0},
				{"cr4",  REG_CONTROL, REG_TRACK_VOLATILE, 32, 0}, {"cr5",  REG_CONTROL, REG_TRACK_VOLATILE, 32, 0}, {"cr6",  REG_CONTROL, REG_TRACK_VOLATILE, 32, 0}, {"cr7",  REG_CONTROL, REG_TRACK_VOLATILE, 32, 0},
		*/

//sw,cw,tw,fp_ip,...

		{0, "zmm0", RegType::eVec, nullptr, "zmm0", 512, 0, true},
		{0, "ymm0", RegType::eVec, "zmm0", "zmm0", 256, 0, true},
		{0, "xmm0", RegType::eVec, "zmm0", "ymm0", 128, 0, true},
		
		{0, "zmm1", RegType::eVec, nullptr, "zmm1", 512, 0, true},
		{0, "ymm1", RegType::eVec, "zmm1", "zmm1", 256, 0, true},
		{0, "xmm1", RegType::eVec, "zmm1", "ymm1", 128, 0, true},
		
		{0, "zmm2", RegType::eVec, nullptr, "zmm2", 512, 0, true},
		{0, "ymm2", RegType::eVec, "zmm2", "zmm2", 256, 0, true},
		{0, "xmm2", RegType::eVec, "zmm2", "ymm2", 128, 0, true},
		
		{0, "zmm3", RegType::eVec, nullptr, "zmm3", 512, 0, true},
		{0, "ymm3", RegType::eVec, "zmm3", "zmm3", 256, 0, true},
		{0, "xmm3", RegType::eVec, "zmm3", "ymm3", 128, 0, true},
		
		{0, "zmm4", RegType::eVec, nullptr, "zmm4", 512, 0, true},
		{0, "ymm4", RegType::eVec, "zmm4", "zmm4", 256, 0, true},
		{0, "xmm4", RegType::eVec, "zmm4", "ymm4", 128, 0, true},
		
		{0, "zmm5", RegType::eVec, nullptr, "zmm5", 512, 0, true},
		{0, "ymm5", RegType::eVec, "zmm5", "zmm5", 512, 0, true},
		{0, "xmm5", RegType::eVec, "zmm5", "ymm5", 512, 0, true},
		
		{0, "zmm6", RegType::eVec, nullptr, "zmm6", 512, 0, true},
		{0, "ymm6", RegType::eVec, "zmm6", "zmm6", 512, 0, true},
		{0, "xmm6", RegType::eVec, "zmm6", "ymm6", 512, 0, true},
		
		{0, "zmm7", RegType::eVec, nullptr, "zmm7", 512, 0, true},
		{0, "ymm7", RegType::eVec, "zmm7", "zmm7", 512, 0, true},
		{0, "xmm7", RegType::eVec, "zmm7", "ymm7", 512, 0, true},
		
		{0, "zmm8", RegType::eVec, nullptr, "zmm8", 512, 0, true},
		{0, "ymm8", RegType::eVec, "zmm8", "zmm8", 512, 0, true},
		{0, "xmm8", RegType::eVec, "zmm8", "ymm8", 512, 0, true},
		
		{0, "zmm9", RegType::eVec, nullptr, "zmm9", 512, 0, true},
		{0, "ymm9", RegType::eVec, "zmm9", "zmm9", 512, 0, true},
		{0, "xmm9", RegType::eVec, "zmm9", "ymm9", 512, 0, true},
		
		{0, "zmm10", RegType::eVec, nullptr, "zmm10", 512, 0, true},
		{0, "ymm10", RegType::eVec, "zmm10", "zmm10", 512, 0, true},
		{0, "xmm10", RegType::eVec, "zmm10", "ymm10", 512, 0, true},
		
		{0, "zmm11", RegType::eVec, nullptr, "zmm11", 512, 0, true},
		{0, "ymm11", RegType::eVec, "zmm11", "zmm11", 512, 0, true},
		{0, "xmm11", RegType::eVec, "zmm11", "ymm11", 512, 0, true},
		
		{0, "zmm12", RegType::eVec, nullptr, "zmm12", 512, 0, true},
		{0, "ymm12", RegType::eVec, "zmm12", "zmm12", 512, 0, true},
		{0, "xmm12", RegType::eVec, "zmm12", "ymm12", 512, 0, true},
		
		{0, "zmm13", RegType::eVec, nullptr, "zmm13", 512, 0, true},
		{0, "ymm13", RegType::eVec, "zmm13", "zmm13", 512, 0, true},
		{0, "xmm13", RegType::eVec, "zmm13", "ymm13", 512, 0, true},
		
		{0, "zmm14", RegType::eVec, nullptr, "zmm14", 512, 0, true},
		{0, "ymm14", RegType::eVec, "zmm14", "zmm14", 512, 0, true},
		{0, "xmm14", RegType::eVec, "zmm14", "ymm14", 512, 0, true},
		
		{0, "zmm15", RegType::eVec, nullptr, "zmm15", 512, 0, true},
		{0, "ymm15", RegType::eVec, "zmm15", "zmm15", 512, 0, true},
		{0, "xmm15", RegType::eVec, "zmm15", "ymm15", 512, 0, true},
		
		{0, "zmm16", RegType::eVec, nullptr, "zmm16", 512, 0, true},
		{0, "zmm17", RegType::eVec, nullptr, "zmm17", 512, 0, true},
		{0, "zmm18", RegType::eVec, nullptr, "zmm18", 512, 0, true},
		{0, "zmm19", RegType::eVec, nullptr, "zmm19", 512, 0, true},
		{0, "zmm20", RegType::eVec, nullptr, "zmm20", 512, 0, true},
		{0, "zmm21", RegType::eVec, nullptr, "zmm21", 512, 0, true},
		{0, "zmm22", RegType::eVec, nullptr, "zmm22", 512, 0, true},
		{0, "zmm23", RegType::eVec, nullptr, "zmm23", 512, 0, true},
		{0, "zmm24", RegType::eVec, nullptr, "zmm24", 512, 0, true},
		{0, "zmm25", RegType::eVec, nullptr, "zmm25", 512, 0, true},
		{0, "zmm26", RegType::eVec, nullptr, "zmm26", 512, 0, true},
		{0, "zmm27", RegType::eVec, nullptr, "zmm27", 512, 0, true},
		{0, "zmm28", RegType::eVec, nullptr, "zmm28", 512, 0, true},
		{0, "zmm29", RegType::eVec, nullptr, "zmm29", 512, 0, true},
		{0, "zmm30", RegType::eVec, nullptr, "zmm30", 512, 0, true},
		{0, "zmm31", RegType::eVec, nullptr, "zmm31", 512, 0, true},
		
		{0, "mxcsr", RegType::eFlag, nullptr, "mxcsr", 32, 0, false},
		
		{0, "ie", RegType::eFlag, "mxcsr", "mxcsr", 1, 0, false},
		{0, "de", RegType::eFlag, "mxcsr", "mxcsr", 1, 1, false},
		{0, "ze", RegType::eFlag, "mxcsr", "mxcsr", 1, 2, false},
		{0, "oe", RegType::eFlag, "mxcsr", "mxcsr", 1, 3, false},
		{0, "ue", RegType::eFlag, "mxcsr", "mxcsr", 1, 4, false},
		{0, "pe", RegType::eFlag, "mxcsr", "mxcsr", 1, 5, false},
		{0, "daz", RegType::eFlag, "mxcsr", "mxcsr", 1, 6, false},
		{0, "im", RegType::eFlag, "mxcsr", "mxcsr", 1, 7, false},
		{0, "dm", RegType::eFlag, "mxcsr", "mxcsr", 1, 8, false},
		{0, "zm", RegType::eFlag, "mxcsr", "mxcsr", 1, 9, false},
		{0, "om", RegType::eFlag, "mxcsr", "mxcsr", 1, 10, false},
		{0, "um", RegType::eFlag, "mxcsr", "mxcsr", 1, 11, false},
		{0, "pm", RegType::eFlag, "mxcsr", "mxcsr", 1, 12, false},
		{0, "rnd", RegType::eFlag, "mxcsr", "mxcsr", 2, 13, false},
		{0, "r-", RegType::eFlag, "rnd", "mxcsr", 1, 13, false},
		{0, "r+", RegType::eFlag, "rnd", "mxcsr", 1, 14, false},
		{0, "fz", RegType::eFlag, "mxcsr", "mxcsr", 1, 15, false},

		{0, "st0", RegType::eVec, nullptr, "st0", 80, 0, true},
		{0, "st1", RegType::eVec, nullptr, "st1", 80, 0, true},
		{0, "st2", RegType::eVec, nullptr, "st2", 80, 0, true},
		{0, "st3", RegType::eVec, nullptr, "st3", 80, 0, true},
		{0, "st4", RegType::eVec, nullptr, "st4", 80, 0, true},
		{0, "st5", RegType::eVec, nullptr, "st5", 80, 0, true},
		{0, "st6", RegType::eVec, nullptr, "st6", 80, 0, true},
		{0, "st7", RegType::eVec, nullptr, "st7", 80, 0, true},
		
		{0, "mm0", RegType::eVec, "st0", "st0", 64, 0, true},
		{0, "mm1", RegType::eVec, "st1", "st1", 64, 0, true},
		{0, "mm2", RegType::eVec, "st2", "st2", 64, 0, true},
		{0, "mm3", RegType::eVec, "st3", "st3", 64, 0, true},
		{0, "mm4", RegType::eVec, "st4", "st4", 64, 0, true},
		{0, "mm5", RegType::eVec, "st5", "st5", 64, 0, true},
		{0, "mm6", RegType::eVec, "st6", "st6", 64, 0, true},
		{0, "mm7", RegType::eVec, "st7", "st7", 64, 0, true},
		
	},
	{
		{
			0,
			"stack",//name
			StackType::eMemory,//what backs the memory
			StackPolicy::eBottom,//where to add new elements
			0, 8, //maxcount(0 = infinite), wordbitsize
			"mem",
			"rsp",//stackptr
			{}
		},
		{
			0,
			"st",
			StackType::eRegBacked,
			StackPolicy::eBottom,
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
			static_cast<uint32_t>(-1)
		}
	},
	{
		{0, "parity"}
	},
	{
		/*
		//x86
		{
		"cdecl",//name
		CC_STACK_CALLER_SAVED, {"eax", "ecx", "edx"},//saved registers
		{},//register parameters
		nullptr,//register te count of parameters is passed
		{{"eax", "eax", "st0"}, {"edx", "edx", "st0"}}, //return value
		"mem", //backing stack
		CC_STACK_R2L//
		},
		{
		"syscall",
		CC_STACK_CALLER_SAVED, {"eax", "ecx", "edx"},
		{},
		"al",
		{{"eax", "eax", "eax"}},
		"mem",
		CC_STACK_R2L
		},
		{
		"pascal",
		CC_STACK_CALLER_SAVED, {},
		{},
		"al",
		{{"eax", "eax", "eax"}},
		"mem",
		CC_STACK_L2R
		},
		//x86_64
		{
		"microsoft64",
		CC_STACK_CALLER_SAVED, {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"},
		{{"rcx", "rcx", "xmm0", "xmm0", "ymm0"}, {"rdx", "rdx", "xmm1", "xmm1", "ymm1"}, {"r8", "r8", "xmm2", "xmm2", "ymm2"}, {"r9", "r9", "xmm3", "xmm3", "ymm3"}},
		nullptr,
		{{"rax", "rax", "xmm0", "xmm0", "ymm0"}},
		"mem",
		CC_STACK_R2L
		},*/
		{
			0, "vectorcall",
		{ "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "cs" },
			{
				{ "rcx", CCParameterTypeFlags::eInt, 1 },{ "rdx", CCParameterTypeFlags::eInt, 2 },{ "r8", CCParameterTypeFlags::eInt, 3 },{ "r9", CCParameterTypeFlags::eInt, 4 },
		{ "zmm0", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 1 },
		{ "zmm1", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 2 },
		{ "zmm2", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 3 },
		{ "zmm3", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 4 }
			},
		{ { "rax", CCParameterTypeFlags::eInt, 1 },{ "zmm0", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 1 } },
			nullptr,
			"stack",
			CCStackAdjust::eCallee,
			CCStackPolicy::eR2L
		},
		{
			0, "amd64",
		{ "rbp", "rbx", "r12", "r13", "r14", "r15", "cs" },
			{
				{ "rdi", CCParameterTypeFlags::eInt, 1 },{ "rsi", CCParameterTypeFlags::eInt, 2 },{ "rdx", CCParameterTypeFlags::eInt, 3 },{ "rcx", CCParameterTypeFlags::eInt, 4 },
		{ "r8", CCParameterTypeFlags::eInt, 5 },{ "r9", CCParameterTypeFlags::eInt, 6 },
		{ "zmm0", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 1 },
		{ "zmm1", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 2 },
		{ "zmm2", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 3 },
		{ "zmm3", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 4 },
		{ "zmm4", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 5 },
		{ "zmm5", Flags<CCParameterTypeFlags>() | CCParameterTypeFlags::eFloat | CCParameterTypeFlags::eVec128 | CCParameterTypeFlags::eVec256, 6 },
		{ "cs", CCParameterTypeFlags::eNone, 0 }
			},
		{ { "rax", CCParameterTypeFlags::eAll, 1 },{ "rdx", CCParameterTypeFlags::eAll, 2 } },
			"rax",
			"stack",
			CCStackAdjust::eCallee,
			CCStackPolicy::eR2L
		}
	},
	{},//instructionIds
	{
		{X86_INS_INVALID, "invalid", {}, InstructionType::eMov},
		{X86_INS_MOV, "mov", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVABS, "movabs", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVDQA, "movdqa", {{2, "=(#arg[1],#arg[2])"}}},
		{X86_INS_MOVDQU, "movdqu", {{2, "=(#arg[1],#arg[2])"}}},
		{X86_INS_MOVQ, "movq", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVD, "movd", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{
			X86_INS_MOVBE,
			"movbe", {
				{2, "==(#bsize(#arg[1]),16)", "=(#arg[1],#app(#arg[2][8,8],#arg[2][0,8]))"},
				{2, "==(#bsize(#arg[1]),32)", "=(#arg[1],#app(#arg[2][24,8],#arg[2][16,8],#arg[2][8,8],#arg[2][0,8]))"},
				{2, "==(#bsize(#arg[1]),64)", "=(#arg[1],#app(#arg[2][56,8],#arg[2][48,8],#arg[2][40,8],#arg[2][32,8],#arg[2][24,8],#arg[2][16,8],#arg[2][8,8],#arg[2][0,8]))"}
			}, InstructionType::eMov
		},
		{
			X86_INS_MOVDDUP,
			"movddup", {
				{2, "==(#bsize(#arg[1]),128)", "=(#arg[1],#app(#arg[2],#arg[2]))"},
				{2, "==(#bsize(#arg[1]),64)", "=(#arg[1],#app(#arg[2][0,64],#arg[2][0,64]))"},
			}, InstructionType::eMov
		},
		{
			X86_INS_MOVHPS,
			"movhps", {
				{2, "==(#bsize(#arg[1]),64)", "=(#arg[1],#arg[2][64,64])"},
				{2, "==(#bsize(#arg[1]),128)", "=(#arg[1],#app(#arg[2],#arg[1][64,64]))"},
			}, InstructionType::eMov
		},
		{X86_INS_MOVLHPS, "movlhps", {{2, "=(#arg[1],#app(#arg[1][0,64],#arg[2][0,64]))"}}, InstructionType::eMov},
		{
			X86_INS_MOVLPD,
			"movlpd", {
				{2, "==(#bsize(#arg[1]),64)", "=(#arg[1],#arg[2][0,64])"},
				{2, "==(#bsize(#arg[1]),128)", "=(#arg[1],#app(#arg[2],#arg[1][64,64]))"},
			}, InstructionType::eMov
		},
		{X86_INS_MOVMSKPD, "movskpd", {{2, "=(#arg[1],#app(#arg[2][63],#arg[2][127]))"}}, InstructionType::eMov},
		{X86_INS_MOVMSKPS, "movskps", {{2, "=(#arg[1],#app(#arg[2][31],#arg[2][63],#arg[2][95],#arg[2][127]))"}}, InstructionType::eMov},
		{X86_INS_MOVNTDQA, "movntdqa", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVNTDQ, "movntdq", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVNTI, "movnti", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVNTPD, "movntpd", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVNTPS, "movntps", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVNTSD, "movntsd", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVNTSS, "movntss", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVSHDUP, "movshdup", {{2, "=(#arg[1],#app(#arg[2][32,32],#arg[2][32,32],#arg[2][96,32],#arg[2][96,32]))"}}, InstructionType::eMov},
		{X86_INS_MOVSLDUP, "movsldup", {{2, "=(#arg[1],#app(#arg[2][0,32],#arg[2][0,32],#arg[2][64,32],#arg[2][64,32]))"}}, InstructionType::eMov},
		{X86_INS_MOVSXD, "movsxd", {{2, "=(#arg[1],#ext[s](#arg[2],#bsize(#arg[1])))"}}, InstructionType::eMov},
		{X86_INS_MOVUPD, "movupd", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},
		{X86_INS_MOVUPS, "movups", {{2, "=(#arg[1],#arg[2])"}}, InstructionType::eMov},

		{X86_INS_LEA, "lea", {{2, "=(#arg[1],#val(#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVE, "cmovz", {{2, "?($zf,=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVNE, "cmovne", {{2, "?(#not($zf),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVA, "cmova", {{2, "?(#and($cf,$zf),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVBE, "cmovbe", {{2, "?(#or($cf,$zf),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVG,	"cmovg", {{2, "?(#and(#not($zf),==($sf,$of)),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVGE, "cmovge", {{2, "?(==($sf,$of),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVL,	"cmovge", {{2, "?(<>($sf,$of),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},
		{X86_INS_CMOVLE,	"cmovle", {{2,  "?(#or($zf,<>($sf,$of)),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		//{X86_INS_CMOVC,{"cmovc", {0, 0, "?($cf) #arg[1] = #arg[2]"}}, INSTR_TYPE_MOV, INSTR_TYPE_UNKNOWN, INSTR_COND_C}},
		//{X86_INS_CMOVNC,{"cmovnc", {0, 0, "?(#not($cf)) #arg[1] = #arg[2]"}}, INSTR_TYPE_MOV, INSTR_TYPE_UNKNOWN, INSTR_COND_NC}},

		{X86_INS_CMOVB,	"cmovb", {{2,  "?($cf,=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVAE,	"cmovae", {{2, "?(#not($cf),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVO,	"cmovo", {{2, "?($of,=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVNO,	"cmovno", {{2, "?(#not($of),=(#arg[1],#arg[2])) "}}, InstructionType::eMov},

		{X86_INS_CMOVS,	"cmovs", {{2, "?($sf,=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVNS,	"cmovns", {{2, "?(#not($sf),=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVP, "cmovp", {{2, "?($pf,=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_CMOVNP, "cmovp", {{2, "?($pf,=(#arg[1],#arg[2]))"}}, InstructionType::eMov},

		{X86_INS_JMP, "jmp", {{1, "#jmp(#arg[1])"}}, InstructionType::eJmp, InstructionType::eUnknown},

		{X86_INS_JE, "je", {{1, "#jmp(#arg[1],#arg[2],$zf)"}}, InstructionType::eCJmp},
		{X86_INS_JNE, "jne", {{1, "#jmp(#arg[1],#arg[2],#not($zf))"}}, InstructionType::eCJmp},
		{X86_INS_JA, "ja", {{1, "#jmp(#arg[1],#arg[2],#not(#or($cf,$zf)))"}}, InstructionType::eCJmp},
		{X86_INS_JAE, "jae", {{1, "#jmp(#arg[1],#arg[2],#not($cf))"}}, InstructionType::eCJmp},
		{X86_INS_JB, "jb", {{1, "#jmp(#arg[1],#arg[2],#not($cf))"}}, InstructionType::eCJmp},
		{X86_INS_JBE, "jbe", {{1, "#jmp(#arg[1],#arg[2],#or($cf,$zf))"}}, InstructionType::eCJmp},
		{X86_INS_JG, "jg", {{1, "#jmp(#arg[1],#arg[2],#and(#not($zf),==($sf,$of)))"}}, InstructionType::eCJmp},
		{X86_INS_JGE, "jge", {{1, "#jmp(#arg[1],#arg[2],==($sf,$of))"}}, InstructionType::eCJmp},
		{X86_INS_JL, "jl", {{1, "#jmp(#arg[1],#arg[2],<>($sf,$of))"}}, InstructionType::eCJmp},
		{X86_INS_JLE, "jle", {{1, "#jmp(#arg[1],#arg[2],#or($zf,<>($sf,$of)))"}}, InstructionType::eCJmp},
		{X86_INS_JO, "jo", {{1, "#jmp(#arg[1],#arg[2],$of)"}}, InstructionType::eCJmp},
		{X86_INS_JNO, "jno", {{1, "#jmp(#arg[1],#arg[2],#not($of))"}}, InstructionType::eCJmp},
		{X86_INS_JS, "js", {{1, "#jmp(#arg[1],#arg[2],$sf)"}}, InstructionType::eCJmp},
		{X86_INS_JNS, "jns", {{1, "#jmp(#arg[1],#arg[2],#not($sf))"}}, InstructionType::eCJmp},

		{X86_INS_JP, "jp", {{1, "#jmp(#arg[1],#arg[2],$pf)"}}, InstructionType::eCJmp},
		{X86_INS_JNP, "jnp", {{1, "#jmp(#arg[1],#arg[2],#not($pf))"}}, InstructionType::eCJmp},

		{X86_INS_JCXZ, "jcxz", {{1, "#jmp(#arg[1],#arg[2],#not($cx))"}}, InstructionType::eCJmp},
		{X86_INS_JECXZ, "jecxz", {{1, "#jmp(#arg[1],#arg[2],#not($ecx))"}}, InstructionType::eCJmp},
		{X86_INS_JRCXZ, "jrcxz", {{1, "#jmp(#arg[1],#arg[2],#not($rcx))"}}, InstructionType::eCJmp},


		{X86_INS_XCHG, "xchg", {{2, "#seq(=(#t[1],#arg[1]),=(#arg[1],#arg[2]),=(#arg[2],#t[1]))"}}, InstructionType::eXchg},

		{X86_INS_BSWAP, "bswap", {{1, "=(#arg[1],#app(#arg[1][24,8],#arg[1][16,8],#arg[1][8,8],#arg[1][0,8]))"}}, InstructionType::eSwap},

		{X86_INS_XADD, "xadd", {{2, "#seq(#rec[xchg](#arg[1],#arg[2]),#rec[add](#arg[1],#arg[2]))"}}, InstructionType::eXchg, InstructionType::eAdd},


		//X86_INS_CMPXCHG16B,
		{
			X86_INS_CMPXCHG,
			"cmpxchg", {
				{2, "==(#bsize(#arg[1]),8)", "#seq(#rec[cmp]($al,#arg[1]),?($zf,=(#arg[1],#arg[2]),=($al,#arg[1])))"},
				{2, "==(#bsize(#arg[1]),16)", "#seq(#rec[cmp]($al,#arg[1]),?($zf,=(#arg[1],#arg[2]),=($ax,#arg[1])))"},
				{2, "==(#bsize(#arg[1]),32)", "#seq(#rec[cmp]($eax,#arg[1]),?($zf,=(#arg[1],#arg[2]),=($eax,#arg[1])))"},
			}, InstructionType::eXchg, InstructionType::eUnknown
		},
		{
			X86_INS_CMPXCHG8B,
			"cmpxchg8g", {
				{2, "#seq(=($zf,==(#app($eax,$edx),#arg[1])),?($zf,=(#arg[1],#app($ebx,$ecx)),#seq(=($eax,#arg[1][0,32]),=($edx,#arg[1][32,32]))))"}
			}, InstructionType::eXchg, InstructionType::eUnknown

		},
		{
			X86_INS_CMPXCHG16B,
			"cmpxchg16g", {
				{2, "#seq(=($zf,==(#app($rax,$rdx),#arg[1])),?($zf,=(#arg[1],#app($rbx,$rcx)),#seq(=($rax,#arg[1][0,64]),=($rdx,#arg[1][64,64]))))"}
			}, InstructionType::eXchg, InstructionType::eUnknown
		},
		{X86_INS_PUSH, "push", {{1, "#seq(=($rsp,-($rsp,#size(#arg[1]))),#st($mem,+($rsp,1),#arg[1]))"}}, InstructionType::ePush},
		{X86_INS_POP, "pop", {{1, "#seq(=(#arg[1],#ld($mem,+($rsp,1),#size(#arg[1]))),=($rsp,+($rsp,#size(#arg[1]))))"}}, InstructionType::ePop},

		{X86_INS_PUSHAW, "pushad", {{1, "#seq(=(#t[1],$esp),#rec[push]($eax),#rec[push]($ecx),#rec[push]($edx),#rec[push]($edx),#rec[push]($ebx),#rec[push](#t[1]),#rec[push]($ebp),#rec[push]($esi),#rec[push]($edi))"}}, InstructionType::ePush},
		{X86_INS_PUSHAL, "pusha", {{1, "#seq(=(#t[1],$sp),#rec[push]($ax),#rec[push]($cx),#rec[push]($dx),#rec[push]($dx),#rec[push]($bx),#rec[push](#t[1]),#rec[push]($bp),#rec[push]($si),#rec[push]($di))"}}, InstructionType::ePush},

		{X86_INS_POPAW, "popad", {{1, "#seq(#rec[pop]($edi),#rec[pop]($esi),#rec[pop]($ebp),=($esp,+($esp,4)),#rec[pop]($ebx),#rec[pop]($edx),#rec[pop]($ecx),#rec[pop]($eax))"}}, InstructionType::ePush},
		{X86_INS_POPAL, "popa", {{1, "#seq(#rec[pop]($di),#rec[pop]($si),#rec[pop]($bp),=($esp,+($esp,2)),#rec[pop]($bx),#rec[pop]($dx),#rec[pop]($cx),#rec[pop]($ax))"}}, InstructionType::ePush},

		{X86_INS_RET, "ret", {{0, "#ret(#pop($stack,8))"}, {1, "#seq(#pop($stack,#arg[1]),#ret(#pop($stack,8)))"}}, InstructionType::eRet},
		{X86_INS_IRET, "iret", {{0, "#ret(#pop($stack,8))"}, {1, "#seq(#pop($stack,#arg[1]),#ret(#pop($stack,8)))"}}, InstructionType::eRet},
		{X86_INS_IRETD, "iretd", {{0, "#ret(#pop($stack,8))"}, {1, "#seq(#pop($stack,#arg[1]),#ret(#pop($stack,8)))"}}, InstructionType::eRet},
		{X86_INS_IRETQ, "iretq", {{0, "#ret(#pop($stack,8))"}, {1, "#seq(#pop($stack,#arg[1]),#ret(#pop($stack,8)))"}}, InstructionType::eRet},
		{X86_INS_RETF, "retf", {{0, "#ret(#pop($stack,8))"}, {1, "#seq(#pop($stack,#arg[1]),#ret(#pop($stack,8)))"}}, InstructionType::eRet},
		{X86_INS_RETFQ, "retfq", {{0, "#ret(#pop($stack,8))"}, {1, "#seq(#pop($stack,#arg[1]),#ret(#pop($stack,8)))"}}, InstructionType::eRet},

		{X86_INS_HLT, "hlt", {{0, "#trap"}}},

		{X86_INS_CBW, "cbw", {{0, "=($ax,#ext[s]($al,#bsize($ax)))"}}, InstructionType::eExtend},
		{X86_INS_CWDE, "cwde", {{0, "=($eax,#ext($ax,#bsize($eax)))"}}, InstructionType::eExtend},
		{X86_INS_CDQE, "cdqe", {{0, "=($rax,#ext[s]($eax,#bsize($rax)))"}}, InstructionType::eExtend},

		{X86_INS_CWD, "cwd", {{0, "=($dx,#ext[s]($ax,#bsize($dx)))"}}, InstructionType::eExtend},
		{X86_INS_CDQ, "cdq", {{0, "=($edx,#ext[s]($eax,#bsize($edx)))"}}, InstructionType::eExtend},
		{X86_INS_CQO, "cqo", {{0, "=($rdx,#ext[s]($rax,#bsize($rdx)))"}}, InstructionType::eExtend},

		{X86_INS_MOVSX, "movsx", {{2, "=(#arg[1],#ext[s](#arg[2],#bsize(#arg[1])))"}}, InstructionType::eMov, InstructionType::eExtend},
		{X86_INS_MOVZX, "movzx", {{2, "=(#arg[1],#ext(#arg[2],#bsize(#arg[1])))"}}, InstructionType::eMov, InstructionType::eExtend},

		{X86_INS_ADD, "add", {{2, "#seq(=(#arg[1],+(#arg[1],#arg[2])),=($of,#o),=($cf,#c),=($af,#c(4)),=($pf,$parity[u](#arg[1])),=($sf,<[s](#arg[1],0)),=($zf,==(#arg[1],0)))"}}, InstructionType::eAdd},
		{X86_INS_ADC, "adc", {{2, "#seq(=(#arg[1],+(#arg[1],#arg[2],$cf)),=($of,#o),=($cf,#c),=($af,#c(4)),=($pf,$parity[u](#arg[1])),=($sf,<[s](#arg[1],0)),=($zf,==(#arg[1],0)))"}}, InstructionType::eAdd},

		{X86_INS_SUB, "sub", {{2, "#seq(-(#arg[1][0,4],#arg[2][0,4]),=($af,#c),=(#arg[1],-(#arg[1],#arg[2])),=($of,#o),=($cf,#c),=($pf,$parity[u](#arg[1])),=($sf,<[s](#arg[1],0)),=($zf,==(#arg[1],0)))"}}, InstructionType::eSub},
		{X86_INS_SBB, "sbb", {{2, "#seq(-(#arg[1][0,4],#arg[2][0,4],$cf),=($af,#c),=(#arg[1],-(#arg[1],#arg[2],$cf)),=($of,#o),=($cf,#c),=($pf,$parity[u](#arg[1])),=($sf,<[s](#arg[1],0)),=($zf,==(#arg[1],0)))"}}, InstructionType::eSub},

		{X86_INS_ADCX, "adcx", {{2, "#seq(+(#arg[1][0,4],#arg[2][0,4],$cf),=($af,#c),=(#arg[1],+(#arg[1],#arg[2],$cf)),=($of,#o),=($cf,#c),=($pf,$parity[u](#arg[1])),=($sf,<[s](#arg[1],0)),=($zf,==(#arg[1],0)))"}}, InstructionType::eAdd},
		{X86_INS_ADOX, "adox", {{2, "#seq(+(#arg[1][0,4],#arg[2][0,4],$of),=($af,#c),=(#arg[1],+(#arg[1],#arg[2],$of)),=($of,#o),=($cf,#c),=($pf,$parity[u](#arg[1])),=($sf,<[s](#arg[1],0)),=($zf,==(#arg[1],0)))"}}, InstructionType::eAdd},

		{
			X86_INS_MUL,
			"mul", {
				{1, "==(#bsize(#arg[1]),8)", "#seq(=($ax,*($al,#arg[1])),=($cf,#c),=($of,#o),#undef($sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),16)", "#seq(=(#t[1],*($ax,#arg[1])),=($cf,#c),=($of,#o),=($dx,#t[1][0,16]),=($ax,#t[1][16,16]),#undef($sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),32)", "#seq(=(#t[1],*($eax,#arg[1])),=($cf,#c),=($of,#o),=($edx,#t[1][0,32]),=($eax,#t[1][32,32]),#undef($sf,$zf,$af,$pf))"},
			}, InstructionType::eMul
		},
		{
			X86_INS_IMUL,
			"imul", {
				{1, "==(#bsize(#arg[1]),8)", "#seq(=($ax,*($al,#arg[1])),=($cf,#c),=($of,#o),#undef($zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),16)", "#seq(=(#t[1],*($ax,#arg[1])),=($cf,#c),=($of,#o),=($dx,#t[1][0,16]),=($ax,#t[1][16,16]),#undef($zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),32)", "#seq(=(#t[1],*($eax,#arg[1])),=($cf,#c),=($of,#o),=($edx,#t[1][0,32]),=($eax,#t[1][32,32]),#undef($zf,$af,$pf))"},
				{2, "#seq(=(#arg[1],*[s](#arg[1],#ext[s](#arg[2],#bsize(#arg[1])))),=($cf,#c),=($of,#o),#undef($zf,$af,$pf))"},
				{3, "#seq(=(#arg[1],*[s](#arg[1],#ext[s](#arg[3],#bsize(#arg[2])))),=($cf,#c),=($of,#o),#undef($zf,$af,$pf))"},
			}, InstructionType::eMul
		},
		{
			X86_INS_DIV,
			"div", {
				{1, "==(#bsize(#arg[1]),8)", "#seq(=(#t[1],$ax),=($eax,#div(#t[1],#arg[1])),=($edx,#mod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),16)", "#seq(=(#t[1],#app($dx,$ax)),=($eax,#div(#t[1],#arg[1])),=($edx,#mod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),32)", "#seq(=(#t[1],#app($edx,$eax)),=($eax,#div(#t[1],#arg[1])),=($edx,#mod(#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
			}, InstructionType::eDiv
		},
		{
			X86_INS_IDIV,
			"idiv", {
				{1, "==(#bsize(#arg[1]),8)", "#seq(=(#t[1],$ax),=($al,#div[s](#t[1],#arg[1])),=($ah,#mod[s](#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),16)", "#seq(=(#t[1],#app($dx,$ax)),=($ax,#div[s](#t[1],#arg[1])),=($dx,#mod[s](#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
				{1, "==(#bsize(#arg[1]),32)", "#seq(=(#t[1],#app($edx,$eax)),=($eax,#div[s](#t[1],#arg[1])),=($edx,#mod[s](#t[1],#arg[1])),#undef($cf,$of,$sf,$zf,$af,$pf))"},
			}, InstructionType::eDiv
		},
		{X86_INS_NOP, "nop", {{0, "#nop"}, {1, "#nop"}}},

		{X86_INS_INC, "inc", {{1, "#seq(+(#arg[1][0,4],1),=($af,#c),=(#arg[1],+(#arg[1],1)),=($pf,$parity[u](#arg[1])),=($sf,<[s](#arg[1],0)),=($of,#o),=($zf,==(#arg[1],0)))"}}, InstructionType::eAdd},
		{X86_INS_DEC, "dec", {{1, "#seq(-(#arg[1][0,4],1),=($af,#c),=(#arg[1],-(#arg[1],1)),=($pf,$parity[u](#arg[1])),=($sf,<[s](#arg[1],0)),=($of,#o),=($zf,==(#arg[1],0)))"}}, InstructionType::eSub},

		{X86_INS_NEG, "neg", {{1, "#seq(=(#t[1],0),=(#t[2],#not(==(#arg[1],0))),#rec[sub](#t[1],#arg[1]),=(#arg[1],#t[1]),=($cf,#t[2]))"}}, InstructionType::eNeg},

		{X86_INS_CMP, "cmp", {{2, "#seq(=(#t[1],#arg[1]),#rec[sub](#t[1],#ext[s](#arg[2],#bsize(#arg[1]))))"}}, InstructionType::eCmp},

		{X86_INS_AND, "and", {{2, "#seq(=(#arg[1],#band(#arg[1],#arg[2])),=($of,0),=($cf,0),=($sf,<[s](#arg[1],0)),=($pf,$parity[u](#arg[1])),=($zf,==(#arg[1],0)),#undef($af))"}}, InstructionType::eAnd},
		{X86_INS_ANDPD, "andpd", {{2, "=(#arg[1],#band(#arg[1],#arg[2]))"}}},
		{X86_INS_ANDPS, "andps", {{2, "=(#arg[1],#band(#arg[1],#arg[2]))"}}},
		{X86_INS_PAND, "pand", {{2, "=(#arg[1],#band(#arg[1],#arg[2]))"}}},
//TODO flags undef checkpoint
		{X86_INS_ANDN, "andn", {{2, "=(#arg[1],#band(#bnot(#arg[1]),#arg[2]))"}}},
		{X86_INS_ANDNPD, "andnpd", {{2, "=(#arg[1],#band(#bnot(#arg[1]),#arg[2]))"}}},
		{X86_INS_ANDNPS, "andnps", {{2, "=(#arg[1],#band(#bnot(#arg[1]),#arg[2]))"}}},
		{X86_INS_PANDN, "pandn", {{2, "#seq(=(#arg[1],#band(#bnot(#arg[1]),#arg[2])),=($of,0),=($cf,0),=($sf,<[s](#arg[1],0)),=($zf,==(#arg[1],0)))"}}},

		{X86_INS_OR, "or", {{2, "#seq(=(#arg[1],#bor(#arg[1],#arg[2])),=($of,0),=($cf,0),=($sf,<[s](#arg[1],0)),=($pf,$parity[u](#arg[1])),=($zf,==(#arg[1],0)))"}}, InstructionType::eOr},
		{X86_INS_ORPD, "orpd", {{2, "=(#arg[1],#bor(#arg[1],#arg[2]))"}}},
		{X86_INS_ORPS, "orps", {{2, "=(#arg[1],#bor(#arg[1],#arg[2]))"}}},
		{X86_INS_POR, "por", {{2, "=(#arg[1],#bor(#arg[1],#arg[2]))"}}},

		{X86_INS_XOR, "xor", {{2, "#seq(=(#arg[1],#bxor(#arg[1],#arg[2])),=($of,0),=($cf,0),=($sf,<[s](#arg[1],0)),=($pf,$parity(#arg[1])),=($zf,==(#arg[1],0)))"}}, InstructionType::eXor},
		{X86_INS_XORPD, "xorpd", {{2, "=(#arg[1],#bxor(#arg[1],#arg[2]))"}}},
		{X86_INS_XORPS, "xorps", {{2, "=(#arg[1],#bxor(#arg[1],#arg[2]))"}}},
		{X86_INS_PXOR, "pxor", {{2, "=(#arg[1],#bxor(#arg[1],#arg[2]))"}}},

		{X86_INS_NOT, "not", {{1, "=(#arg[1],#bnot(#arg[1]))"}}, InstructionType::eNot},

		{
			X86_INS_SAR,
			"sar", {
				{1, "#seq(=(#t[1],#shr(#arg[1],1)),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($of,#o),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]),=($zf,==(#t[1],0)),#undef($af))"},
		{2, "#seq(=(#t[1],#shr[s](#arg[1],#arg[2])),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($of,#o),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]),=($zf,==(#t[1],0)),#undef($af))"},
			}, InstructionType::eShr
		},

		{
			X86_INS_SHR,
			"shr", {
				{1, "#seq(=(#t[1],#shr(#arg[1],1)),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($of,#o),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]),=($zf,==(#t[1],0)),#undef($af))"},
				{2, "#seq(=(#t[1],#shr(#arg[1],#arg[2])),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($of,#o),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]),=($zf,==(#t[1],0)),#undef($af))"}
			}, InstructionType::eShr
		},

		{
			X86_INS_SAL,
			"sal", {
				{1, "#seq(=(#t[1],#shl[s](#arg[1],1)),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($of,#o),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]),=($zf,==(#t[1],0)),#undef($af))"},
				{2, "#seq(=(#t[1],#shl[s](#arg[1],#arg[2])),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($of,#o),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]),=($zf,==(#t[1],0)),#undef($af))"}
			}, InstructionType::eShl
		},

		{
			X86_INS_SHL,
			"shl", {
				{1, "#seq(=(#t[1],#shl(#arg[1],1)),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($of,#o),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]),=($zf,==(#t[1],0)),#undef($af))"},
				{2, "#seq(=(#t[1],#shl(#arg[1],#arg[2])),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($of,#o),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]),=($zf,==(#t[1],0)),#undef($af))"}
			}, InstructionType::eShl
		},

//TODO flags
		{X86_INS_SHRD, "shrd", { {2, "=(#arg[1],#shr(#app(#arg[1],#arg[2]),$cl))"}, {3, "=(#arg[1],#app(#shr(#arg[1],#arg[2]),#arg[3]))"}},InstructionType:: eShr},
		{X86_INS_SHLD, "shld", { {2, "=(#arg[1],#shl(#app(#arg[1],#arg[2]),$cl))"}, {3, "=(#arg[1],#app(#shl(#arg[1],#arg[2]),#arg[3]))"}}, InstructionType::eShl},

//TODO flags for rotates
		{X86_INS_ROR, "ror", {{2, "=(#arg[1],#ror(#arg[1],1))"}, {3, "=(#arg[1],#ror(#arg[1],#arg[2]))"}}, InstructionType::eRor},
		{X86_INS_ROL, "rol", {{2, "=(#arg[1],#rol(#arg[1],1))"}, {3, "=(#arg[1],#rol(#arg[1],#arg[2]))"}}, InstructionType::eRol}, {
			X86_INS_RCR,
			"rcr", {
				{1, "#seq(=(#t[1],#ror(#app(#arg[1],$cf),1)),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
				{2, "#seq(=(#t[1],#ror(#app(#arg[1],$cf),#arg[2])),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"}
			}, InstructionType::eRor
		}, {
			X86_INS_RCL,
			"rcl", {
				{1, "#seq(=(#t[1],#rol(#app(#arg[1],$cf),1)),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"},
				{2, "#seq(=(#t[1],#rol(#app(#arg[1],$cf),#arg[2])),=(#arg[1],#t[1]),=($cf,#t[1][#bsize(#arg[1]),1]))"}
			}, InstructionType::eRol
		},

		{X86_INS_BT, "bt", {{2, "=($cf,#arg[1][#arg[2]])"}}, InstructionType::eBitTest},
		{X86_INS_BTS, "bts", {{2, "#seq(=($cf,#arg[1][#arg[2]]),=(#arg[1][#arg[2]],1))"}}, InstructionType::eBitTest, InstructionType::eBitSet},
		{X86_INS_BTR, "btr", {{2, "#seq(=($cf,#arg[1][#arg[2]]),=(#arg[1][#arg[2]],0))"}}, InstructionType::eBitTest, InstructionType::eBitReset},
		{X86_INS_BTC, "btc", {{2, "#seq(=($cf,#arg[1][#arg[2]]),=(#arg[1][#arg[2]],#not(#arg[1][#arg[2]])))"}}, InstructionType::eBitTest, InstructionType::eCpl},

		{X86_INS_LOOP, "loop", {{1, "#seq(=($ecx,-($ecx,1)),#jmp(#arg[1],#arg[2],#not($ecx)))"}}, InstructionType::eCJmp},


		{X86_INS_LOOPE, "loope", {{1, "#seq(=($ecx,-($ecx,1)),#jmp(#arg[1],#arg[2],#not(#and($ecx,$zf))))"}}, InstructionType::eCJmp},

		{X86_INS_LOOPNE, "loopne", {{1, "#seq(=($ecx,-($ecx,1)),#jmp(#arg[1],#arg[2],#not(#and($ecx,#not($zf)))))"}}, InstructionType::eCJmp},

		{X86_INS_CALL, "call", {{1, "#seq(#push($stack,#ip),#call(#arg[1]))"}},InstructionType::eCall},

		{X86_INS_INT, "int", {{1, "#syscall(#arg[1])"}}, InstructionType::eSyscall, InstructionType::eUnknown},
		{X86_INS_INTO, "into", {{"#syscall"}}, InstructionType::eSyscall, InstructionType::eUnknown},

		{X86_INS_BOUND, "bound", {{2, "#seq(=(#t[1],#ld($mem,#arg[2],#size(#arg[2]))),=(#t[2],#ld($mem,+(#arg[2],#size(#arg[1])),#size(#arg[1]))),?(#or(<(#arg[1],#t[1]),>(#arg[1],#t[2])),#trap))"}}},

		{X86_INS_ENTER, "enter", {{1, "#seq(#rec[push]($ebp),#rec[mov]($ebp,$esp),#rec[sub]($esp,#arg[1]))"}}},
		{X86_INS_LEAVE, "leave", {{0, "#seq(#rec[mov]($esp,$ebp),#rec[pop]($ebp))"}}},

		{X86_INS_SETE, "sete", {{1, "=(#arg[1],$zf)"}}, InstructionType::eMov},
		{X86_INS_SETNE, "setne", {{1, "=(#arg[1],#not($zf))"}}, InstructionType::eMov},
		{X86_INS_SETA, "seta", {{1, "=(#arg[1],#not(#or($cf,$zf)))"}}, InstructionType::eMov},
		{X86_INS_SETAE, "setae", {{1, "=(#arg[1],#not($cf))"}}, InstructionType::eMov},
		{X86_INS_SETB, "setae", {{1, "=(#arg[1],$cf)"}}, InstructionType::eMov},
		{X86_INS_SETBE, "setbe", {{1, "=(#arg[1],#or($cf,$zf))"}}, InstructionType::eMov},
		{X86_INS_SETG, "setg", {{1, "=(#arg[1],#and(#not($zf),==($sf,$of)))"}}, InstructionType::eMov},
		{X86_INS_SETGE, "setge", {{1, "=(#arg[1],==($sf,$of))"}}, InstructionType::eMov},
		{X86_INS_SETL, "setl", {{1, "=(#arg[1],<>($sf,$of))"}}, InstructionType::eMov},
		{X86_INS_SETLE, "setle", {{1, "=(#arg[1],#or($zf,<>($sf,$of)))"}}, InstructionType::eMov},

		{X86_INS_SETS, "sets", {{1, "=(#arg[1],$sf)"}}, InstructionType::eMov},
		{X86_INS_SETNS, "setns", {{1, "=(#arg[1],#not($sf))"}}, InstructionType::eMov},
		{X86_INS_SETO, "seto", {{1, "=(#arg[1],$of)"}}, InstructionType::eMov},
		{X86_INS_SETNO, "setno", {{1, "=(#arg[1],#not($of))"}}, InstructionType::eMov},

		{X86_INS_SETP, "setp", {{1, "=(#arg[1],$pf)"}}, InstructionType::eMov},
		{X86_INS_SETNP, "setnp", {{1, "=(#arg[1],#not($pf))"}}, InstructionType::eMov},

		{X86_INS_TEST, "test", {{2, "#seq(=(#t[1],#band(#arg[1],#arg[2])),=($cf,0),=($of,0),=($pf,$parity[u](#t[1])),=($sf,<[s](#t[1],0)),=($zf,==(#t[1],0)))"}}, InstructionType::eAnd},

		//TODO
		{X86_INS_BSF, "bsf", {}},
		{X86_INS_BSR, "bsr", {}},
		{X86_INS_CRC32, "crc32", {}},
		{X86_INS_POPCNT, "popcnt", {}},

		{X86_INS_STC, "stc", {{0, "=($cf,1)"}}, InstructionType::eBitSet},
		{X86_INS_CLC, "clc", {{0, "=($cf,0)"}}, InstructionType::eBitReset},
		{X86_INS_CMC, "cmc", {{0, "=($cf,#not($cf))"}}, InstructionType::eCpl},

		{X86_INS_STD, "std", {{0, "=($df,1[1])"}}, InstructionType::eBitSet},
		{X86_INS_CLD, "cld", {{0, "=($df,0[1])"}}, InstructionType::eBitReset},

		{X86_INS_LAHF, "lahf", {{0, "=($ah,#app($cf,1[1],$pf,0[1],$af,0[1],$zf,$sf))"}}, InstructionType::eMov},
		{X86_INS_SAHF, "sahf", {{0, "#seq(=($cf,$ah[0]),=($pf,$ah[2]),=($af,$ah[4]),=($zf,$ah[6]),=($sf,$ah[7]))"}}, InstructionType::eMov},

		{X86_INS_PUSHF, "pushf", {{0, "#rec[push](#app($cf,1[1],$pf,0[1],$af,0[1],$zf,$sf,$tf,$if,$df,$of,$iopl,$nt,0[1]))"}}, InstructionType::ePush},
		{X86_INS_PUSHFD, "pushfd", {{0, "#rec[push](#app($cf,1[1],$pf,0[1],$af,0[1],$zf,$sf,$tf,$if,$df,$of,$iopl,$nt,0[1],$rf,$vm,$ac,$vif,$vip,$id,0[10]))"}}, InstructionType::ePush},
			{X86_INS_PUSHFQ, "pushfq", {{0, "#rec[push](#app($cf,1[1],$pf,0[1],$af,0[1],$zf,$sf,$tf,$if,$df,$of,$iopl,$nt,0[1],$rf,$vm,$ac,$vif,$vip,$id,0[42]))"}}, InstructionType::ePush},

		{X86_INS_POPF, "popf", {{0, "#seq(#rec[pop](#t[1][16]),=($cf,#t[1][0]),=($pf,#t[1][2]),=($af,#t[1][4]),=($zf,#t[1][6]),=($sf,#t[1][7]),=($tf,#t[1][8]),=($if,#t[1][9]),=($df,#t[1][10]),=($of,#t[1][11]),=($iopl,#t[1][12,2]),=($nt,#t[1][14]))"}}, InstructionType::ePop},
		{X86_INS_POPFD, "popfd", {{0, "#seq(#rec[pop](#t[1][32]),=($cf,#t[1][0]),=($pf,#t[1][2]),=($af,#t[1][4]),=($zf,#t[1][6]),=($sf,#t[1][7]),=($tf,#t[1][8]),=($if,#t[1][9]),=($df,#t[1][10]),=($of,#t[1][11]),=($iopl,#t[1][12,2]),=($nt,#t[1][14]),=($rf,#t[1][16]),=($vm,#t[1][17]),=($ac,#t[1][18]),=($vif,#t[1][19]),=($vip,#t[1][20]),=($id,#t[1][21]))"}}, InstructionType::ePop},
		{X86_INS_POPFQ, "popfq", {{0, "#seq(#rec[pop](#t[1][64]),=($cf,#t[1][0]),=($pf,#t[1][2]),=($af,#t[1][4]),=($zf,#t[1][6]),=($sf,#t[1][7]),=($tf,#t[1][8]),=($if,#t[1][9]),=($df,#t[1][10]),=($of,#t[1][11]),=($iopl,#t[1][12,2]),=($nt,#t[1][14]),=($rf,#t[1][16]),=($vm,#t[1][17]),=($ac,#t[1][18]),=($vif,#t[1][19]),=($vip,#t[1][20]),=($id,#t[1][21]))"}}, InstructionType::ePop},

		{X86_INS_STI, "sti", {{0, "=($if,1)"}}, InstructionType::eBitSet},
		{X86_INS_CLI, "cli", {{0, "=($if,0)"}}, InstructionType::eBitReset},

//TODO
		{X86_INS_AAA, "aaa", {}},
		{X86_INS_AAD, "aad", {}},
		{X86_INS_AAM, "aam", {}},
		{X86_INS_AAS, "aas", {}},
		{X86_INS_DAA, "daa", {}},
		{X86_INS_DAS, "das", {}},

		{X86_INS_FABS, "fabs", {{0, "=($st[0],*[f]($st[0],-1))"}}},
		{X86_INS_ADDPD, "addpd", {{2, "=(#arg[1],#app(+[f](#arg[1][0,64],#arg[2][0,64]),+[f](#arg[1][64,64],#arg[2][64,64])))"}}},
		{
			X86_INS_ADDPS,
			"addps", {
				{
					2, 
					"=("
						"#arg[1],#app("
							"+[f](#arg[1][0,32],#arg[2][0,32]),"
							"+[f](#arg[1][32,32],#arg[2][32,32]),"
							"+[f](#arg[1][64,32],#arg[2][64,32]),"
							"+[f](#arg[1][96,32],#arg[2][96,32])"
						")"
					")"
				}
			}
		},
		{X86_INS_ADDSD, "addsd", {{2, "=(#arg[1],#app(+[f](#arg[1][0,64],#arg[2][0,64]),#arg[1][64]))"}}},
		{X86_INS_ADDSS, "addss", {{2, "=(#arg[1],#app(+[f](#arg[1][0,32],#arg[2][0,32]),#arg[1][32]))"}}},
		{X86_INS_ADDSUBPD, "addsubpd", {{2, "=(#arg[1],#app(-[f](#arg[1][0,64],#arg[2][0,64]),+[f](#arg[1][64,64],#arg[2][64,64])))"}}},
		{
			X86_INS_ADDSUBPS,
			"addsubps", {
				{
					2, "=(#arg[1],#app(-[f](#arg[1][0,32],#arg[2][0,32]),+[f](#arg[1][32,32],#arg[2][32,32]),"
					"-[f](#arg[1][64,32],#arg[2][64,32]),+[f](#arg[1][96,32],#arg[2][96,32])))"
				}
			}
		},

		{X86_INS_CVTDQ2PD, "cvtdq2pd", {{2, "=(#arg[1],#app(#ext[f](#cast[f](#arg[2][0,32]),64),#ext[f](#cast[f](#arg[2][32,32]),64)))"}}},
		{X86_INS_CVTDQ2PS, "cvtdq2ps", {{2, "=(#arg[1],#app(#cast[f](#arg[2][0,32]),#cast[f](#arg[2][32,32]),#cast[f](#arg[2][64,32]),#cast[f](#arg[2][96,32])))"}}},
		{X86_INS_CVTPD2DQ, "cvtpd2dq", {{2, "=(#arg[1],#app(#cast(#arg[2][f,0,32]),#cast(#arg[2][f,32,32]),#ext(0,64)))"}}},
		{X86_INS_CVTPD2PS, "cvtpd2ps", {{2, "=(#arg[1],#app(#ext[f](#arg[2][0,64],32),#ext[f](#arg[2][64,64],32)))"}}},
		{X86_INS_CVTPS2DQ, "cvtps2dq", {{2, "=(#arg[1],#app(#cast(#arg[2][f,0,32]),#cast(#arg[2][f,32,32]),#cast(#arg[2][f,64,32]),#cast(#arg[2][f,96,32])))"}}},
		{X86_INS_CVTPS2PD, "cvtps2pd", {{2, "=(#arg[1],#app(#ext[f](#arg[2][0,32],64),#ext[f](#arg[2][32,32],64)))"}}},
		{X86_INS_CVTSD2SI, "cvtsd2si", {{2, "=(#arg[1],#app(#cast(#arg[2][f,0,64],32),#arg[1][32]))"}}},
		{X86_INS_CVTSD2SS, "cvtsd2ss", {{2, "=(#arg[1],#app(#ext[f](#arg[2][0,64],32),#arg[1][32]))"}}},
		{X86_INS_CVTSI2SD, "cvtsi2sd", {{2, "=(#arg[1],#app(#cast[f](#arg[2][0,32],64),#arg[1][64]))"}}},
		{X86_INS_CVTSI2SS, "cvtsi2ss", {{2, "=(#arg[1],#app(#cast[f](#arg[2][0,32]),#arg[1][32]))"}}},
		{X86_INS_CVTSS2SD, "cvtss2sd", {{2, "=(#arg[1],#app(#ext[f](#arg[2][0,32],64),#arg[1][64]))"}}},
		{X86_INS_CVTSS2SI, "cvtss2si", {{2, "=(#arg[1],#app(#cast(#arg[2][f,0,32]),#arg[1][32]))"}}},
		{X86_INS_CVTTPD2DQ, "cvttpd2dq", {{2, "=(#arg[1],#app(#ext(#cast(#arg[2][f,0,64]),32),#ext(#cast(#arg[2][f,64,64]),32),#ext(0,64)))"}}},
		{X86_INS_CVTTPS2DQ, "cvttps2dq", {{2, "=(#arg[1],#app(#cast(#arg[2][f,0,32]),#cast(#arg[2][f,32,32]),#cast(#arg[2][f,64,32]),#cast(#arg[2][f,96,32])))"}}},
		{X86_INS_CVTTSD2SI, "cvttsd2si", {{2, "=(#arg[1],#app(#cast(#arg[2][f,0,64],32),#arg[1][32]))"}}},
		{X86_INS_CVTTSS2SI, "cvttss2si", {{2, "=(#arg[1],#app(#cast(#arg[2][f,0,64],32),#arg[1][32]))"}}},

		{X86_INS_AESDECLAST, "aesdeclast", {}, InstructionType::eCrypto},
		{X86_INS_AESDEC, "aesdec", {}, InstructionType::eCrypto},
		{X86_INS_AESENCLAST, "aesenclast", {}, InstructionType::eCrypto},
		{X86_INS_AESENC, "aesenc", {}, InstructionType::eCrypto},
		{X86_INS_AESIMC, "aesimc", {}, InstructionType::eCrypto},
		{X86_INS_AESKEYGENASSIST, "aeskeygenassist", {}, InstructionType::eCrypto},

/*
		{X86_INS_INSB, "insb", {}},
		{X86_INS_INSD, "insd", {}},
		{X86_INS_INSW, "insw", {}},

		{X86_INS_INSB | CUSOM_X86_INSTR_EXTR_REP, "rep insb", {}},
		{X86_INS_INSD | CUSOM_X86_INSTR_EXTR_REP, "rep insd", {}},
		{X86_INS_INSD | CUSOM_X86_INSTR_EXTR_REP, "rep insw", {}},

		{X86_INS_MOVSB, "movsb", {}, INSTR_TYPE_MOV},
		{X86_INS_MOVSW, "movsw", {}, INSTR_TYPE_MOV},
		{X86_INS_MOVSD, "movsd", {}, INSTR_TYPE_MOV},
		{X86_INS_MOVSQ, "movsq", {}, INSTR_TYPE_MOV},

		{X86_INS_MOVSB | CUSOM_X86_INSTR_EXTR_REP, "rep movsb", {}, INSTR_TYPE_MOV},
		{X86_INS_MOVSW | CUSOM_X86_INSTR_EXTR_REP, "rep movsw", {}, INSTR_TYPE_MOV},
		{X86_INS_MOVSD | CUSOM_X86_INSTR_EXTR_REP, "rep movsd", {}, INSTR_TYPE_MOV},
		{X86_INS_MOVSQ | CUSOM_X86_INSTR_EXTR_REP, "rep movsq", {}, INSTR_TYPE_MOV},

		{X86_INS_OUTSB, "outsb", {}},
		{X86_INS_OUTSD, "outsd", {}},
		{X86_INS_OUTSW, "outsw", {}},

		{X86_INS_OUTSB | CUSOM_X86_INSTR_EXTR_REP, "rep outsb", {}},
		{X86_INS_OUTSD | CUSOM_X86_INSTR_EXTR_REP, "rep outsd", {}},
		{X86_INS_OUTSW | CUSOM_X86_INSTR_EXTR_REP, "rep outsw", {}},
		 */

		{X86_INS_LODSB, "lodsb", {{2, "#seq(=(#arg[1],#ld($mem,#arg[2],#size(#arg[2]))),?($df,=($rdi,-($rdi,1)),=($rdi,+($rdi,1))))"}}, InstructionType::eLoad},
		{X86_INS_LODSW, "lodsw", {{2, "#seq(=(#arg[1],#ld($mem,#arg[2],#size(#arg[2]))),?($df,=($rdi,-($rdi,2)),=($rdi,+($rdi,2))))"}}, InstructionType::eLoad},
		{X86_INS_LODSD, "lodsd", {{2, "#seq(=(#arg[1],#ld($mem,#arg[2],#size(#arg[2]))),?($df,=($rdi,-($rdi,4)),=($rdi,+($rdi,4))))"}}, InstructionType::eLoad},
		{X86_INS_LODSQ, "lodsq", {{2, "#seq(=(#arg[1],#ld($mem,#arg[2],#size(#arg[2]))),?($df,=($rdi,-($rdi,8)),=($rdi,+($rdi,8))))"}}, InstructionType::eLoad},
		
		{X86_INS_LODSB | CUSOM_X86_INSTR_EXTR_REP, "rep lodsb", {{2, "#rep($rcx,#seq(#rec[lodsb](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, InstructionType::eLoad},
		{X86_INS_LODSW | CUSOM_X86_INSTR_EXTR_REP, "rep lodsw", {{2, "#rep($rcx,#seq(#rec[lodsw](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, InstructionType::eLoad},
		{X86_INS_LODSD | CUSOM_X86_INSTR_EXTR_REP, "rep lodsd", {{2, "#rep($rcx,#seq(#rec[lodsd](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, InstructionType::eLoad},
		{X86_INS_LODSQ | CUSOM_X86_INSTR_EXTR_REP, "rep lodsq", {{2, "#rep($rcx,#seq(#rec[lodsq](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, InstructionType::eLoad},

		{X86_INS_STOSB, "stosb", {{2, "#seq(#st($mem,#arg[2],#arg[1]),?($df,=($rdi,-($rdi,1)),=($rdi,+($rdi,1))))"}}, InstructionType::eStore},
		{X86_INS_STOSW, "stosw", {{2, "#seq(#st($mem,#arg[2],#arg[1]),?($df,=($rdi,-($rdi,2)),=($rdi,+($rdi,2))))"}}, InstructionType::eStore},
		{X86_INS_STOSD, "stosd", {{2, "#seq(#st($mem,#arg[2],#arg[1]),?($df,=($rdi,-($rdi,4)),=($rdi,+($rdi,4))))"}}, InstructionType::eStore},
		{X86_INS_STOSQ, "stosq", {{2, "#seq(#st($mem,#arg[2],#arg[1]),?($df,=($rdi,-($rdi,8)),=($rdi,+($rdi,8))))"}}, InstructionType::eStore},

		{X86_INS_STOSB | CUSOM_X86_INSTR_EXTR_REP, "rep stosb", {{2, "#rep($rcx,#seq(#rec[stosb](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, InstructionType::eStore},
		{X86_INS_STOSW | CUSOM_X86_INSTR_EXTR_REP, "rep stosw", {{2, "#rep($rcx,#seq(#rec[stosw](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, InstructionType::eStore},
		{X86_INS_STOSD | CUSOM_X86_INSTR_EXTR_REP, "rep stosd", {{2, "#rep($rcx,#seq(#rec[stosd](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, InstructionType::eStore},
		{X86_INS_STOSQ | CUSOM_X86_INSTR_EXTR_REP, "rep stosq", {{2, "#rep($rcx,#seq(#rec[stosq](#arg[1],#arg[2]),=($rcx,-($rcx,1))))"}}, InstructionType::eStore},
		
		{X86_INS_CMPSB, "cmpsb", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,1),-($rdi,1))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSW, "cmpsw", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,2),-($rdi,2))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSD, "cmpsd", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,4),-($rdi,4))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSQ, "cmpsq", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,8),-($rdi,8))))"}}, InstructionType::eCmp},
		
		{X86_INS_CMPSB | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsb", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[cmpsb](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSW | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsw", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[cmpsw](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSD | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsd", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[cmpsd](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSQ | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsq", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[cmpsq](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},

		{X86_INS_CMPSB | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsb", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[cmpsb](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSW | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsw", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[cmpsw](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSD | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsd", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[cmpsd](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_CMPSQ | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsq", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[cmpsq](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},

		{X86_INS_SCASB, "scasb", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),?($df,=($rdi,-($rdi,1)),=($rdi,+($rdi,1))))"}}, InstructionType::eCmp},
		{X86_INS_SCASW, "scasw", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),?($df,=($rdi,-($rdi,2)),=($rdi,+($rdi,2))))"}}, InstructionType::eCmp},
		{X86_INS_SCASD, "scasd", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),?($df,=($rdi,-($rdi,4)),=($rdi,+($rdi,4))))"}}, InstructionType::eCmp},
		{X86_INS_SCASQ, "scasq", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),?($df,=($rdi,-($rdi,8)),=($rdi,+($rdi,8))))"}}, InstructionType::eCmp},

		{X86_INS_SCASB | CUSOM_X86_INSTR_EXTR_REPE, "repe scasb", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[scasb](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_SCASW | CUSOM_X86_INSTR_EXTR_REPE, "repe scasw", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[scasw](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_SCASD | CUSOM_X86_INSTR_EXTR_REPE, "repe scasd", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[scasd](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_SCASQ | CUSOM_X86_INSTR_EXTR_REPE, "repe scasq", {{2, "#seq(=($zf,1),#rep(#and($rcx,$zf),#seq(#rec[scasq](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},

		{X86_INS_SCASB | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasb", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[scasb](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_SCASW | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasw", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[scasw](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_SCASD | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasd", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[scasd](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},
		{X86_INS_SCASQ | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasq", {{2, "#seq(=($zf,0),#rep(#and($rcx,#not($zf)),#seq(#rec[scasq](#arg[1],#arg[2]),=($rcx,-($rcx,1)))))"}}, InstructionType::eCmp},

//x87
		{X86_INS_FADD, "add[f]", {{1, "=($st[0],+[f]($st[0],#ext[f](#arg[1],#bsize($st[0]))))"}, {2, "=(#arg[1],+[f](#arg[1],#arg[2]))"}}},
		{X86_INS_FIADD, "fiadd", {{1, "=($st[0],+[f]($st[0],#ext[f](#arg[1],#bsize($st[0]))))"}}},
		{X86_INS_FADDP, "add[f]p", {{0, "#push($st,+[f](#pop($st),#pop($st)))"}, {2, "#seq(=(#arg[1],+[f](#arg[1],#arg[2])),#pop($st))"}}}

//TODO add missing instructions

	}
};
