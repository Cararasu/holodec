
#include "Hx86FunctionAnalyzer.h"
#include "HInstrDefinition.h"

using namespace holodec;


holox86::HArchitecture holox86::x86architecture {"x86", "x86", 64, 8, {
		[] (HBinary * binary) {
			static HFunctionAnalyzer* analyzer = nullptr;
			if (analyzer == nullptr) {
				printf ("Create New Object\n");
				analyzer = new holox86::Hx86FunctionAnalyzer (&holox86::x86architecture);
			}
			if (analyzer->canAnalyze (binary)) {
				HFunctionAnalyzer* temp = analyzer;
				analyzer = nullptr;
				return temp;
			}
			return (HFunctionAnalyzer*) nullptr;
		}
	},
	{
		{"rax", 64, 0, true, { {"eax", 32, 0, true, { {"ax", 16, 0, {{"al", 8, 0}, {"ah", 8, 8}}}}}}},
		{"rbx", 64, 0, true, { {"ebx", 32, 0, true, { {"bx", 16, 0, {{"bl", 8, 0}, {"bh", 8, 8}}}}}}},
		{"rcx", 64, 0, true, { {"ecx", 32, 0, true, { {"cx", 16, 0, {{"cl", 8, 0}, {"ch", 8, 8}}}}}}},
		{"rdx", 64, 0, true, { {"edx", 32, 0, true, { {"dx", 16, 0, {{"dl", 8, 0}, {"dh", 8, 8}}}}}}},
		{"r8", 64, 0, true, { {"r8d", 32, 0, true, { {"r8w", 16, 0, {{"r8b", 8, 0}}}}}}},
		{"r9", 64, 0, true, { {"r9d", 32, 0, true, { {"r9w", 16, 0, {{"r9b", 8, 0}}}}}}},
		{"r10", 64, 0, true, { {"r10d", 32, 0, true, { {"r10w", 16, 0, {{"r10b", 8, 0}}}}}}},
		{"r11", 64, 0, true, { {"r11d", 32, 0, true, { {"r11w", 16, 0, {{"r11b", 8, 0}}}}}}},
		{"r12", 64, 0, true, { {"r12d", 32, 0, true, { {"r12w", 16, 0, {{"r12b", 8, 0}}}}}}},
		{"r13", 64, 0, true, { {"r13d", 32, 0, true, { {"r13w", 16, 0, {{"r13b", 8, 0}}}}}}},
		{"r14", 64, 0, true, { {"r14d", 32, 0, true, { {"r14w", 16, 0, {{"r14b", 8, 0}}}}}}},
		{"r15", 64, 0, true, { {"r15d", 32, 0, true, { {"r15w", 16, 0, {{"r15b", 8, 0}}}}}}},

		{"rbp", H_REG_STACKPTR, 64, 0, true, { {"ebp", 32, 0, true, { {"bp", 16, 0}}}}},
		{"rsi", 64, 0, true, { {"esi", 32, 0, true, { {"si", 16, 0}}}}},
		{"rdi", 64, 0, true, { {"edi", 32, 0, true, { {"di", 16, 0}}}}},
		{"rsp", H_REG_STACKPTR, 64, 0, true, { {"esp", 32, 0, true, { {"sp", 16, 0}}}}},
		{"rip", H_REG_INSTRPTR, H_REG_TRACK_VOLATILE, 64, 0, true, { {"eip", 32, 0, true, { {"ip", 16, 0}}}}},

		{
			"rflags", H_REG_FLAGS, 64, 0,
			{ {
					"eflags", 32, 0,
					{ {
							"flags", 16, 0,
							{	{"cf", 1, 0}, {"pf", 1, 2}, {"af", 1, 4}, {"zf", 1, 6}, {"sf", 1, 7}, {"tf", 1, 8}, {"if", 1, 9},
								{"df", 1, 10}, {"of", 1, 11}, {"iopl", 2, 12}, {"nt", 1, 14}
							}
						}, {"rf", 1, 16}, {"vm", 1, 17}, {"ac", 1, 18}, {"vif", 1, 19}, {"vip", 1, 20}, {"id", 1, 21}
					}
				},
			}
		},

		{"cs", H_REG_SEGMENT, H_REG_TRACK_VOLATILE, 16, 0},
		{"ds", H_REG_SEGMENT, H_REG_TRACK_VOLATILE, 16, 0},
		{"ss", H_REG_SEGMENT, H_REG_TRACK_VOLATILE, 16, 0},
		{"es", H_REG_SEGMENT, H_REG_TRACK_VOLATILE, 16, 0},
		{"fs", H_REG_SEGMENT, H_REG_TRACK_VOLATILE, 16, 0},
		{"gs", H_REG_SEGMENT, H_REG_TRACK_VOLATILE, 16, 0},

		{"dr0", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr1", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr2", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr3", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0},
		{"dr4", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr5", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr6", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr7", H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0},
		{"dr8",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr9",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr10",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr11",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0},
		{"dr12",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr13",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr14",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0}, {"dr15",  H_REG_DEBUG, H_REG_TRACK_VOLATILE, 64, 0},


		{"cr0",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr1",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr2",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr3",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0},
		{"cr4",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr5",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr6",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0}, {"cr7",  H_REG_CONTROL, H_REG_TRACK_VOLATILE, 32, 0},
//sw,cw,tw,fp_ip,...

		{"zmm0", H_REG_VEC, 512, 0, true, {{"ymm0", 256, 0, true, {{"xmm0", 128, 0, true}}}}},
		{"zmm1", H_REG_VEC, 512, 0, true, {{"ymm1", 256, 0, true, {{"xmm1", 128, 0, true}}}}},
		{"zmm2", H_REG_VEC, 512, 0, true, {{"ymm2", 256, 0, true, {{"xmm2", 128, 0, true}}}}},
		{"zmm3", H_REG_VEC, 512, 0, true, {{"ymm3", 256, 0, true, {{"xmm3", 128, 0, true}}}}},
		{"zmm4", H_REG_VEC, 512, 0, true, {{"ymm4", 256, 0, true, {{"xmm4", 128, 0, true}}}}},
		{"zmm5", H_REG_VEC, 512, 0, true, {{"ymm5", 256, 0, true, {{"xmm5", 128, 0, true}}}}},
		{"zmm6", H_REG_VEC, 512, 0, true, {{"ymm6", 256, 0, true, {{"xmm6", 128, 0, true}}}}},
		{"zmm7", H_REG_VEC, 512, 0, true, {{"ymm7", 256, 0, true, {{"xmm7", 128, 0, true}}}}},
		{"zmm8", H_REG_VEC, 512, 0, true, {{"ymm8", 256, 0, true, {{"xmm8", 128, 0, true}}}}},
		{"zmm9", H_REG_VEC, 512, 0, true, {{"ymm9", 256, 0, true, {{"xmm9", 128, 0, true}}}}},
		{"zmm10", H_REG_VEC, 512, 0, true, {{"ymm10", 256, 0, true, {{"xmm10", 128, 0, true}}}}},
		{"zmm11", H_REG_VEC, 512, 0, true, {{"ymm11", 256, 0, true, {{"xmm11", 128, 0, true}}}}},
		{"zmm12", H_REG_VEC, 512, 0, true, {{"ymm12", 256, 0, true, {{"xmm12", 128, 0, true}}}}},
		{"zmm13", H_REG_VEC, 512, 0, true, {{"ymm13", 256, 0, true, {{"xmm13", 128, 0, true}}}}},
		{"zmm14", H_REG_VEC, 512, 0, true, {{"ymm14", 256, 0, true, {{"xmm14", 128, 0, true}}}}},
		{"zmm15", H_REG_VEC, 512, 0, true, {{"ymm15", 256, 0, true, {{"xmm15", 128, 0, true}}}}},
		{"zmm16", H_REG_VEC, 512, 0, true},
		{"zmm17", H_REG_VEC, 512, 0, true},
		{"zmm18", H_REG_VEC, 512, 0, true},
		{"zmm19", H_REG_VEC, 512, 0, true},
		{"zmm20", H_REG_VEC, 512, 0, true},
		{"zmm21", H_REG_VEC, 512, 0, true},
		{"zmm22", H_REG_VEC, 512, 0, true},
		{"zmm23", H_REG_VEC, 512, 0, true},
		{"zmm24", H_REG_VEC, 512, 0, true},
		{"zmm25", H_REG_VEC, 512, 0, true},
		{"zmm26", H_REG_VEC, 512, 0, true},
		{"zmm27", H_REG_VEC, 512, 0, true},
		{"zmm28", H_REG_VEC, 512, 0, true},
		{"zmm29", H_REG_VEC, 512, 0, true},
		{"zmm30", H_REG_VEC, 512, 0, true},
		{"zmm31", H_REG_VEC, 512, 0, true},
		
		//the mmx registers share the lower 64 bits of the st[n], but we ignore this dependency, because they shouldn't normally be used together
		{"mm0", H_REG_FLOAT, 64, 0},
		{"mm1", H_REG_FLOAT, 64, 0},
		{"mm2", H_REG_FLOAT, 64, 0},
		{"mm3", H_REG_FLOAT, 64, 0},
		{"mm4", H_REG_FLOAT, 64, 0},
		{"mm5", H_REG_FLOAT, 64, 0},
		{"mm6", H_REG_FLOAT, 64, 0},
		{"mm7", H_REG_FLOAT, 64, 0}
		/* The proper way to set up the st[n] registers but they conflict with the st-stack
		{"st0", H_REG_FLOAT, 80, 0, { {"mm0", 64, 0}}},
		{"st1", H_REG_FLOAT, 80, 0, { {"mm1", 64, 0}}},
		{"st2", H_REG_FLOAT, 80, 0, { {"mm2", 64, 0}}},
		{"st3", H_REG_FLOAT, 80, 0, { {"mm3", 64, 0}}},
		{"st4", H_REG_FLOAT, 80, 0, { {"mm4", 64, 0}}},
		{"st5", H_REG_FLOAT, 80, 0, { {"mm5", 64, 0}}},
		{"st6", H_REG_FLOAT, 80, 0, { {"mm6", 64, 0}}},
		{"st7", H_REG_FLOAT, 80, 0, { {"mm7", 64, 0}}},
		 */
	},
	{
		{
			0,
			"mem",//name
			H_STACK_MEMORY,//what backs the memory
			H_STACKPOLICY_BOTTOM,//where to add new elements
			0,8,//maxcount(0 = infinite), wordbitsize
			"rsp"//stackptr
		},
		{
			0,
			"st",
			H_STACK_BUILTIN,
			H_STACKPOLICY_BOTTOM,
			8,80,
			nullptr
		},
	},
	{
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
		},
		{
			"vectorcall",
			H_CC_STACK_CALLER_SAVED, {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"},
			{{"rcx", "rcx", "xmm0", "xmm0", "ymm0"}, {"rdx", "rdx", "xmm1", "xmm1", "ymm1"}, {"r8", "r8", "xmm2", "xmm2", "ymm2"}, {"r9", "r9", "xmm3", "xmm3", "ymm3"}},
			nullptr,
			{{"rax", "rax", "xmm0", "xmm0", "ymm0"}},
			"mem",
			H_CC_STACK_R2L
		},
		{
			"amd64",
			H_CC_STACK_CALLEE_SAVED, {"rbp", "rbx", "r12", "r13", "r14", "r15"},
			{{"rdi", "rdi", "xmm0"}, {"rsi", "rsi", "xmm1"}, {"rdx", "rdx", "xmm2"}, {"rcx", "rcx", "xmm3"}, {"r8", "r8", "xmm4"}, {"r9", "r9", "xmm5"}},
			"rax",
			{{"rax", "rax", "rax"}},
			"mem",
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

		{X86_INS_JCXZ, "jcxz", {{1, "#cjmp(#not($cx),#arg[1]))"}}, H_INSTR_TYPE_CJMP, H_INSTR_TYPE_CMP},
		{X86_INS_JECXZ, "jecxz", {{1, "#cjmp(#not($ecx),#arg[1]))"}}, H_INSTR_TYPE_CJMP, H_INSTR_TYPE_CMP},
		{X86_INS_JRCXZ, "jrcxz", {{1, "#cjmp(#not($rcx),#arg[1]))"}}, H_INSTR_TYPE_CJMP, H_INSTR_TYPE_CMP},


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
		{X86_INS_PUSH, "push", {{1, "#push($mem,#arg[1])"}}, H_INSTR_TYPE_PUSH},
		{X86_INS_POP, "pop", {{1, "=(#arg[1],#pop($mem,#size(#arg[1])))"}}, H_INSTR_TYPE_POP},

		{X86_INS_PUSHAW, "pushad", {{1, "#seq(=(#t[1],$esp),#rec[push]($eax),#rec[push]($ecx),#rec[push]($edx),#rec[push]($edx),#rec[push]($ebx),#rec[push](#t[1]),#rec[push]($ebp),#rec[push]($esi),#rec[push]($edi))"}}, H_INSTR_TYPE_PUSH},
		{X86_INS_PUSHAL, "pusha", {{1, "#seq(=(#t[1],$sp),#rec[push]($ax),#rec[push]($cx),#rec[push]($dx),#rec[push]($dx),#rec[push]($bx),#rec[push](#t[1]),#rec[push]($bp),#rec[push]($si),#rec[push]($di))"}}, H_INSTR_TYPE_PUSH},

		{X86_INS_POPAW, "popad", {{1, "#seq(#rec[pop]($edi),#rec[pop]($esi),#rec[pop]($ebp),=($esp,+($esp,4)),#rec[pop]($ebx),#rec[pop]($edx),#rec[pop]($ecx),#rec[pop]($eax))"}}, H_INSTR_TYPE_PUSH},
		{X86_INS_POPAL, "popa", {{1, "#seq(#rec[pop]($di),#rec[pop]($si),#rec[pop]($bp),=($esp,+($esp,2)),#rec[pop]($bx),#rec[pop]($dx),#rec[pop]($cx),#rec[pop]($ax))"}}, H_INSTR_TYPE_PUSH},

		{X86_INS_RET, "ret", {{0, "#ret"}, {1, "#seq(#pop($mem,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_IRET, "iret", {{0, "#ret"}, {1, "#seq(#pop($mem,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_IRETD, "iretd", {{0, "#ret"}, {1, "#seq(#pop($mem,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_IRETQ, "iretq", {{0, "#ret"}, {1, "#seq(#pop($mem,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_RETF, "retf", {{0, "#ret"}, {1, "#seq(#pop($mem,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},
		{X86_INS_RETFQ, "retfq", {{0, "#ret"}, {1, "#seq(#pop($mem,#arg[1]),#ret)"}}, H_INSTR_TYPE_RET, H_INSTR_TYPE_UNKNOWN},

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
		{X86_INS_NOP, "nop", {{0, "#nop"}}},

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

		{X86_INS_BOUND, "bound", {{2, "#seq(=(#t[1],#ld(#arg[2],#size(#arg[2]))),=(#t[2],#ld(+(#arg[2],#size(#arg[1])),#size(#arg[1]))),?(#or(<(#arg[1],#t[1]),>(#arg[1],#t[2])),#trap))"}}},

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

		{X86_INS_LODSB, "lodsb", {{2, "#seq(=(#arg[1],#ld(#arg[2],#size(#arg[2]))),=($rdi,?($df,-($rdi,1),+($rdi,1))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSW, "lodsw", {{2, "#seq(=(#arg[1],#ld(#arg[2],#size(#arg[2]))),=($rdi,?($df,-($rdi,2),+($rdi,2))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSD, "lodsd", {{2, "#seq(=(#arg[1],#ld(#arg[2],#size(#arg[2]))),=($rdi,?($df,-($rdi,4),+($rdi,4))))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSQ, "lodsq", {{2, "#seq(=(#arg[1],#ld(#arg[2],#size(#arg[2]))),=($rdi,?($df,-($rdi,8),+($rdi,8))))"}}, H_INSTR_TYPE_LOAD},

		{X86_INS_LODSB | CUSOM_X86_INSTR_EXTR_REP, "rep lodsb", {{2, "#rep($rcx,#rec[lodsb](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSW | CUSOM_X86_INSTR_EXTR_REP, "rep lodsw", {{2, "#rep($rcx,#rec[lodsw](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSD | CUSOM_X86_INSTR_EXTR_REP, "rep lodsd", {{2, "#rep($rcx,#rec[lodsd](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_LOAD},
		{X86_INS_LODSQ | CUSOM_X86_INSTR_EXTR_REP, "rep lodsq", {{2, "#rep($rcx,#rec[lodsq](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_LOAD},

		{X86_INS_STOSB, "stosb", {{2, "#seq(#st(#arg[2],#arg[1]),=($rdi,?($df,-($rdi,1),+($rdi,1))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSW, "stosw", {{2, "#seq(#st(#arg[2],#arg[1]),=($rdi,?($df,-($rdi,2),+($rdi,2))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSD, "stosd", {{2, "#seq(#st(#arg[2],#arg[1]),=($rdi,?($df,-($rdi,4),+($rdi,4))))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSQ, "stosq", {{2, "#seq(#st(#arg[2],#arg[1]),=($rdi,?($df,-($rdi,8),+($rdi,8))))"}}, H_INSTR_TYPE_STORE},

		{X86_INS_STOSB | CUSOM_X86_INSTR_EXTR_REP, "rep stosb", {{2, "#rep($rcx,#rec[stosb](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSW | CUSOM_X86_INSTR_EXTR_REP, "rep stosw", {{2, "#rep($rcx,#rec[stosw](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSD | CUSOM_X86_INSTR_EXTR_REP, "rep stosd", {{2, "#rep($rcx,#rec[stosd](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_STORE},
		{X86_INS_STOSQ | CUSOM_X86_INSTR_EXTR_REP, "rep stosq", {{2, "#rep($rcx,#rec[stosq](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_STORE},

		{X86_INS_CMPSB, "cmpsb", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,1),-($rdi,1))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSW, "cmpsw", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,2),-($rdi,2))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSD, "cmpsd", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,4),-($rdi,4))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSQ, "cmpsq", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,+($rdi,8),-($rdi,8))))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_CMPSB | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsb", {{2, "#rep(#and($rcx,$zf),#rec[scasb](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSW | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsw", {{2, "#rep(#and($rcx,$zf),#rec[scasw](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSD | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsd", {{2, "#rep(#and($rcx,$zf),#rec[scasd](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSQ | CUSOM_X86_INSTR_EXTR_REPE, "repe cmpsq", {{2, "#rep(#and($rcx,$zf),#rec[scasq](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_CMPSB | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsb", {{2, "#rep(#and($rcx,#not($zf)),#rec[scasb](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSW | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsw", {{2, "#rep(#and($rcx,#not($zf)),#rec[scasw](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSD | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsd", {{2, "#rep(#and($rcx,#not($zf)),#rec[scasd](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_CMPSQ | CUSOM_X86_INSTR_EXTR_REPNE, "repne cmpsq", {{2, "#rep(#and($rcx,#not($zf)),#rec[scasq](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_SCASB, "scasb", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,-($rdi,1),+($rdi,1))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASW, "scasw", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,-($rdi,2),+($rdi,2))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASD, "scasd", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,-($rdi,4),+($rdi,4))))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASQ, "scasq", {{2, "#seq(#rec[cmp](#arg[1],#arg[2]),=($rdi,?($df,-($rdi,8),+($rdi,8))))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_SCASB | CUSOM_X86_INSTR_EXTR_REPE, "repe scasb", {{2, "#rep(#and($rcx,$zf),#rec[scasb](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASW | CUSOM_X86_INSTR_EXTR_REPE, "repe scasw", {{2, "#rep(#and($rcx,$zf),#rec[scasw](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASD | CUSOM_X86_INSTR_EXTR_REPE, "repe scasd", {{2, "#rep(#and($rcx,$zf),#rec[scasd](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASQ | CUSOM_X86_INSTR_EXTR_REPE, "repe scasq", {{2, "#rep(#and($rcx,$zf),#rec[scasq](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},

		{X86_INS_SCASB | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasb", {{2, "#rep(#and($rcx,#not($zf)),#rec[scasb](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASW | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasw", {{2, "#rep(#and($rcx,#not($zf)),#rec[scasw](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASD | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasd", {{2, "#rep(#and($rcx,#not($zf)),#rec[scasd](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},
		{X86_INS_SCASQ | CUSOM_X86_INSTR_EXTR_REPNE, "repne scasq", {{2, "#rep(#and($rcx,#not($zf)),#rec[scasq](#arg[1],#arg[2]))"}}, H_INSTR_TYPE_CMP},

//x87
		{X86_INS_FADD, "fadd", {{1, "=($st[0],#fadd($st[0],#fext(#arg[1],#bsize($st[0]))))"}, {2, "=(#arg[1],#fadd(#arg[1],#arg[2]))"}}},
		{X86_INS_FIADD, "fiadd", {{1, "=($st[0],#fadd($st[0],#fext(#arg[1],#bsize($st[0]))))"}}},
		{X86_INS_FADDP, "faddp", {{0, "#push($st,#fadd(#pop($st),#pop($st)))"}, {2, "#seq(=(#arg[1],#fadd(#arg[1],#arg[2])),#pop($st))"}}},

//TODO add missing instructions

	},
};
