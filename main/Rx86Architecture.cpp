
#include "Rx86FunctionAnalyzer.h"
#include "RInstrDefinition.h"

using namespace holodec;


holox86::RArchitecture holox86::x86architecture = {"x86", "x86", 32, {
		[] (RBinary * binary) {
			static RFunctionAnalyzer* analyzer = nullptr;
			if (analyzer == nullptr) {
				printf ("Create New Object\n");
				analyzer = new holox86::Rx86FunctionAnalyzer (&holox86::x86architecture);
			}
			if (analyzer->canAnalyze (binary)) {
				RFunctionAnalyzer* temp = analyzer;
				analyzer = nullptr;
				return temp;
			}
			return (RFunctionAnalyzer*) nullptr;
		}
	},
	{
		{"rax", 64, 0, {	{"eax", 32, 0, {	{"ax", 16, 0, {{"al", 8, 0}, {"ah", 8, 8}}}}}}},
		{"rbx", 64, 0, {	{"ebx", 32, 0, {	{"bx", 16, 0, {{"bl", 8, 0}, {"bh", 8, 8}}}}}}},
		{"rcx", 64, 0, {	{"ecx", 32, 0, {	{"cx", 16, 0, {{"cl", 8, 0}, {"ch", 8, 8}}}}}}},
		{"rdx", 64, 0, {	{"edx", 32, 0, {	{"dx", 16, 0, {{"dl", 8, 0}, {"dh", 8, 8}}}}}}},
		{"r8", 64, 0, {	{"r8d", 32, 0, {	{"r8w", 16, 0, {{"r8b", 8, 0}}}}}}},
		{"r9", 64, 0, {	{"r9d", 32, 0, {	{"r9w", 16, 0, {{"r9b", 8, 0}}}}}}},
		{"r10", 64, 0, {	{"r10d", 32, 0, {	{"r10w", 16, 0, {{"r10b", 8, 0}}}}}}},
		{"r11", 64, 0, {	{"r11d", 32, 0, {	{"r11w", 16, 0, {{"r11b", 8, 0}}}}}}},
		{"r12", 64, 0, {	{"r12d", 32, 0, {	{"r12w", 16, 0, {{"r12b", 8, 0}}}}}}},
		{"r13", 64, 0, {	{"r13d", 32, 0, {	{"r13w", 16, 0, {{"r13b", 8, 0}}}}}}},
		{"r14", 64, 0, {	{"r14d", 32, 0, {	{"r14w", 16, 0, {{"r14b", 8, 0}}}}}}},
		{"r15", 64, 0, {	{"r15d", 32, 0, {	{"r15w", 16, 0, {{"r15b", 8, 0}}}}}}},

		{"rbp", 64, 0, {	{"ebp", 32, 0, {	{"bp", 16, 0}}}}},
		{"rsi", 64, 0, {	{"esi", 32, 0, {	{"si", 16, 0}}}}},
		{"rdi", 64, 0, {	{"edi", 32, 0, {	{"di", 16, 0}}}}},
		{"rsp", 64, 0, {	{"esp", 32, 0, {	{"sp", 16, 0}}}}},
		{"rip", 64, 0, {	{"eip", 32, 0, {	{"ip", 16, 0}}}}},

		{
			"rflags", 64, 0,
			{	{
					"eflags", 32, 0,
					{	{
							"flags", 16, 0,
							{	{"cf", 1, 0}, {"pf", 1, 2}, {"af", 1, 4}, {"zf", 1, 6}, {"sf", 1, 7}, {"tf", 1, 8}, {"if", 1, 9},
								{"df", 1, 10}, {"of", 1, 11}, {"iopl", 2, 12}, {"nt", 1, 14}
							}
						}, {"rf", 1, 16}, {"vm", 1, 17}, {"ac", 1, 18}, {"vif", 1, 19}, {"vip", 1, 20}, {"id", 1, 21}
					}
				},
			}
		},

		{"st0", 80, 0, {	{"mm0", 64, 0}}},
		{"st1", 80, 0, {	{"mm1", 64, 0}}},
		{"st2", 80, 0, {	{"mm2", 64, 0}}},
		{"st3", 80, 0, {	{"mm3", 64, 0}}},
		{"st4", 80, 0, {	{"mm4", 64, 0}}},
		{"st5", 80, 0, {	{"mm5", 64, 0}}},
		{"st6", 80, 0, {	{"mm6", 64, 0}}},
		{"st7", 80, 0, {	{"mm7", 64, 0}}},

		{"cs", 16, 0},
		{"ds", 16, 0},
		{"ss", 16, 0},
		{"es", 16, 0},
		{"fs", 16, 0},
		{"gs", 16, 0},

		{"dr0", 64, 0}, {"dr1", 64, 0}, {"dr2", 64, 0}, {"dr3", 64, 0},
		{"dr4", 64, 0}, {"dr5", 64, 0}, {"dr6", 64, 0}, {"dr7", 64, 0},
		//{"dr8", X86_REG_DR8, 64, 0}, {"dr9", X86_REG_DR9, 64, 0}, {"dr10", X86_REG_DR10, 64, 0}, {"dr11", X86_REG_DR11, 64, 0},
		//{"dr12", X86_REG_DR12, 64, 0}, {"dr13", X86_REG_DR13, 64, 0}, {"dr14", X86_REG_DR14, 64, 0}, {"dr15", X86_REG_DR15, 64, 0},

		//cr0 - cr15 control register
		//sw,cw,tw,fp_ip,...

		//{"cr0", X86_REG_CR0, 512, 0},

		{"zmm0", 512, 0, {{"ymm0", 256, 0, {{"xmm0", 128, 0 }}}}},
		{"zmm1", 512, 0, {{"ymm1", 256, 0, {{"xmm1", 128, 0 }}}}},
		{"zmm2", 512, 0, {{"ymm2", 256, 0, {{"xmm2", 128, 0 }}}}},
		{"zmm3", 512, 0, {{"ymm3", 256, 0, {{"xmm3", 128, 0 }}}}},
		{"zmm4", 512, 0, {{"ymm4", 256, 0, {{"xmm4", 128, 0 }}}}},
		{"zmm5", 512, 0, {{"ymm5", 256, 0, {{"xmm5", 128, 0 }}}}},
		{"zmm6", 512, 0, {{"ymm6", 256, 0, {{"xmm6", 128, 0 }}}}},
		{"zmm7", 512, 0, {{"ymm7", 256, 0, {{"xmm7", 128, 0 }}}}},
		{"zmm8", 512, 0, {{"ymm8", 256, 0, {{"xmm8", 128, 0 }}}}},
		{"zmm9", 512, 0, {{"ymm9", 256, 0, {{"xmm9", 128, 0 }}}}},
		{"zmm10", 512, 0, {{"ymm10", 256, 0, {{"xmm10", 128, 0 }}}}},
		{"zmm11", 512, 0, {{"ymm11", 256, 0, {{"xmm11", 128, 0 }}}}},
		{"zmm12", 512, 0, {{"ymm12", 256, 0, {{"xmm12", 128, 0 }}}}},
		{"zmm13", 512, 0, {{"ymm13", 256, 0, {{"xmm13", 128, 0 }}}}},
		{"zmm14", 512, 0, {{"ymm14", 256, 0, {{"xmm14", 128, 0 }}}}},
		{"zmm15", 512, 0, {{"ymm15", 256, 0, {{"xmm15", 128, 0 }}}}},
		{"zmm16", 512, 0},
		{"zmm17", 512, 0},
		{"zmm18", 512, 0},
		{"zmm19", 512, 0},
		{"zmm20", 512, 0},
		{"zmm21", 512, 0},
		{"zmm22", 512, 0},
		{"zmm23", 512, 0},
		{"zmm24", 512, 0},
		{"zmm25", 512, 0},
		{"zmm26", 512, 0},
		{"zmm27", 512, 0},
		{"zmm28", 512, 0},
		{"zmm29", 512, 0},
		{"zmm30", 512, 0},
		{"zmm31", 512, 0}
	},
	{
		{"mov",		{"mov", {0, 0, "=(#arg1,#arg2)", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"movq",	{"movq", {0, 0, "=(#arg1,#arg2)", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"movd",	{"movd", {0, 0, "=(#arg1,#arg2)", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"lea",	{"lea", {0, 0, "=(#arg1,#arg2)", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"cmovz",	{"cmovz", {0, 0, "?($z,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_E}},
		{"cmove",	{"cmove", {0, 0, "?($z,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_E}},

		{"cmovnz",	{"cmovnz", {0, 0, "?($z,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NE}},
		{"cmovne",	{"cmovne", {0, 0, "?($z,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NE}},

		{"cmova",	{"cmova", {0, 0, "?(#and($c,$z),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_A}},
		{"cmovnbe",	{"cmovnbe", {0, 0, "?(#and($c,$z),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_A}},

		{"cmovbe",	{"cmovbe", {0, 0, "?(#or($c,$z),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_BE}},
		{"cmovna",	{"cmovna", {0, 0, "?(#or($c,$z),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_BE}},

		{"cmovg",	{"cmovg", {0, 0, "?(#and(#not($z),==($s,$o)),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_G}},
		{"cmovnle",	{"cmovnle", {0, 0, "?(#and(#not($z),==($s,$o)),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_G}},

		{"cmovge",	{"cmovge", {0, 0, "?(==($s,$o),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_GE}},
		{"cmovnl",	{"cmovnl", {0, 0, "?(==($s,$o),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_GE}},

		{"cmovl",	{"cmovge", {0, 0, "?(<>($s,$o),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_L}},
		{"cmovnge",	{"cmovnl", {0, 0, "?(<>($s,$o),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_L}},

		{"cmovle",	{"cmovle", {0, 0, "?(#or($z,<>($s,$o)),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_LE}},
		{"cmovng",	{"cmovng", {0, 0, "?(#or($z,<>($s,$o)),=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_LE}},

		{"cmovc",	{"cmovc", {0, 0, "?($c,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_C}},

		{"cmovnc",	{"cmovnc", {0, 0, "?($c,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NC}},

		{"cmovb",	{"cmovb", {0, 0, "?($c,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_B}},
		{"cmovnae",	{"cmovnae", {0, 0, "?($c,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_B}},

		{"cmovae",	{"cmovae", {0, 0, "?($c,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_AE}},
		{"cmovnb",	{"cmovnb", {0, 0, "?($c,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_AE}},

		{"cmovo",	{"cmovo", {0, 0, "?($o,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_O}},

		{"cmovno",	{"cmovno", {0, 0, "?($o,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NO}},

		{"cmovs",	{"cmovs", {0, 0, "?($s,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NEG}},

		{"cmovns",	{"cmovns", {0, 0, "?($s,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_POS}},

		{"cmovp",	{"cmovp", {0, 0, "?($p,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_UNK}},
		{"cmovpe",	{"cmovpe", {0, 0, "?($p,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_UNK}},

		{"cmovnp",	{"cmovp", {0, 0, "?($p,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_UNK}},
		{"cmovpo",	{"cmovpo", {0, 0, "?($p,,=(#arg1,#arg2))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_UNK}},

		{"jmp",		{"jmp", {0, "#jmp(#arg1)", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN}},

		{"je",		{"je", {0, "?($z,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_E}},
		{"jz",		{"jz", {0, "?($z,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_E}},

		{"jne",		{"jne", {0, "?($z,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NE}},
		{"jnz",		{"jnz", {0, "?($z,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NE}},

		{"ja",		{"ja", {0, "?(#and($c,$z),,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_A}},
		{"jnbe",	{"jnbe", {0, "?(#and($c,$z),,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_A}},

		{"jae",		{"jae", {0, "?($c,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_AE}},
		{"jnb",		{"jnb", {0, "?($c,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_AE}},

		{"jb",		{"jb", {0, "?($c,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_B}},
		{"jnae",		{"jnae", {0, "?($c,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_B}},

		{"jbe",		{"jbe", {0, "?(#or($c,$z),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_BE}},
		{"jna",		{"jna", {0, "?(#or($c,$z),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_BE}},

		{"jg",		{"jg", {0, "?(#and(#not($z),==($s,$o)),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_G}},
		{"jnle",	{"jnle", {0, "?(#and(#not($z),==($s,$o)),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_G}},

		{"jge",		{"jge", {0, "?(==($s,$o)),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_GE}},
		{"jnl",		{"jge", {0, "?(==($s,$o)),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_GE}},

		{"jl",		{"jl", {0, "?(<>($s,$o)),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_L}},
		{"jnge",	{"jnge", {0, "?(<>($s,$o)),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_L}},

		{"jle",		{"jle", {0, "?(#or($z,<>($s,$o)),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_LE}},
		{"jng",		{"jng", {0, "?(#or($z,<>($s,$o)),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_LE}},

		{"jc",		{"jc", {0, "?($c,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_C}},

		{"jnc",		{"jnc", {0, "?($c,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_C}},

		{"jo",		{"jo", {0, "?($o,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_O}},

		{"jno",		{"jno", {0, "?($o,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NO}},

		{"js",		{"js", {0, "?($s,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NEG}},

		{"jns",		{"jns", {0, "?($s,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_POS}},

		{"jp",		{"jp", {0, "?($p,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_UNK}},
		{"jpe",		{"jpe", {0, "?($p,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_UNK}},

		{"jpo",		{"jpo", {0, "?($p,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_UNK}},
		{"jnp",		{"jnp", {0, "?($p,,#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_UNK}},

		{"jcxz",	{"jcxz", {0, "?(==($cx,0),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_CMP, R_INSTR_COND_E}},
		{"jecxz",	{"jecxz", {0, "?(==($ecx,0),#jmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_CMP, R_INSTR_COND_E}},

		{"xchg",	{"xchg", {0, 0, "=(#t0,#arg1)&=(#arg1,#arg2)&=(#arg2,#t0)", 0}, R_INSTR_TYPE_XCHG, R_INSTR_TYPE_UNKNOWN}},

		{"bswap",	{"bswap", {0, "=(#arg1,#append(#slice(#arg1,24,31),#slice(#arg1,23,16),#slice(#arg1,15,8),#slice(#arg1,7,0)))", 0, 0}, R_INSTR_TYPE_SWAP, R_INSTR_TYPE_UNKNOWN}},

		{"xadd",	{"xadd", {0, 0, "#rec[xchg](#arg1,#arg2)&#rec[add](#arg1,#arg2)", 0}, R_INSTR_TYPE_XCHG, R_INSTR_TYPE_ADD}},

		{"cmpxchg",	{"cmpxchg", {0, 0, "#rec[cmp](#slice($eax,0,#size(#arg1)),#arg1)&?($z,#rec[xchg](#arg1,#arg2))", 0}, R_INSTR_TYPE_XCHG, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_E}},

		{"cmpxchg8b", {"cmpxchg", {0, 0, "?(==(#append($eax,$edx),#arg1),=($z,1)&=(#arg1,#append($ebx,$ecx)),=($z,1)&=(#append($eax,$edx),#arg1))", 0}, R_INSTR_TYPE_XCHG, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_E}},

		{"push",	{"push", {0, "=($esp,-($esp,4))&#st($esp,#arg1)", 0, 0}, R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},
		{"pop",		{"pop", {0, "#ld(#arg1,$esp)&=($esp,+($esp,4))", 0, 0}, R_INSTR_TYPE_POP, R_INSTR_TYPE_UNKNOWN}},

		{"pushad",	{"pushad", {0, "=(#t0,$esp)&#push($eax)&#push($ecx)&#push($edx)&#push($edx)&#push($ebx)&#push(#t0)&#push($ebp)&#push($esi)&#push($edi)", 0, 0}, R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},
		{"pusha",	{"pusha", {0, "=(#t0,$sp)&#push($ax)&#push($cx)&#push($dx)&#push($dx)&#push($bx)&#push(#t0)&#push($bp)&#push($si)&#push($di)", 0, 0}, R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},

		{"pushad",	{"pushad", {0, "#pop($edi)&#pop($esi)&#pop($ebp)&=($esp,+($esp,4))&#pop($ebx)&#pop($edx)&#pop($ecx)&#pop($eax)", 0, 0}, R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},
		{"pusha",	{"pusha", {0, "#pop($di)&#pop($si)&#pop($bp)&=($esp,+($esp,2))&#pop($bx)&#pop($dx)&#pop($cx)&#pop($ax)", 0, 0}, R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},

		{"ret",		{"ret", {"#rec[pop](#t0)&#jmp(#t0)", 0, 0, 0}, R_INSTR_TYPE_RET, R_INSTR_TYPE_UNKNOWN, {}, R_INSTR_COND_TRUE}},

		{"cwd",		{"cwd", {"=($dx,#sextend($ax,#size($dx)))", 0, 0, 0}, R_INSTR_TYPE_EXTEND, R_INSTR_TYPE_UNKNOWN}},
		{"cdq",		{"cdq", {"=($edx,#sextend($eax,#size($edx)))", 0, 0, 0}, R_INSTR_TYPE_EXTEND, R_INSTR_TYPE_UNKNOWN}},

		{"cbw",		{"cbw", {"=($ax,#sextend($al,#size($ax)))", 0, 0, 0}, R_INSTR_TYPE_EXTEND, R_INSTR_TYPE_UNKNOWN}},
		{"cwde",	{"cwde", {"=($eax,#sextend($al,#size($eax)))", 0, 0, 0}, R_INSTR_TYPE_EXTEND, R_INSTR_TYPE_UNKNOWN}},

		{"movsx",	{"movsx", {0, 0, "=(#arg1,#sextend(#arg2,#size(#arg1)))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_EXTEND}},
		{"movzx",	{"movzx", {0, 0, "=(#arg1,#extend(#arg2,#size(#arg1)))", 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_EXTEND}},

		{"add",		{"add", {0, 0, "=(#arg1,+(#arg1,#arg2)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($c,#c)&=($a,#a))", 0}, R_INSTR_TYPE_ADD, R_INSTR_TYPE_UNKNOWN}},
		{"adc",		{"adc", {0, 0, "=(#arg1,+(#arg1,#arg2,$c)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($c,#c)& =($a,#a))", 0}, R_INSTR_TYPE_ADD, R_INSTR_TYPE_UNKNOWN}},

		{"sub",		{"sub", {0, 0, "=(#arg1,-(#arg1,#arg2)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($c,#c)&=($a,#a))", 0}, R_INSTR_TYPE_SUB, R_INSTR_TYPE_UNKNOWN}},
		{"sbb",		{"sbb", {0, 0, "=(#arg1,-(#arg1,#arg2,$c)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($c,#c)&=($a,#a))", 0}, R_INSTR_TYPE_SUB, R_INSTR_TYPE_UNKNOWN}},

		{"adcx",	{"adcx", {0, 0, "#=(#arg1,#uadd(#arg1,#arg2,c)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($c,#c)&=($a,#a))", 0}, R_INSTR_TYPE_ADD, R_INSTR_TYPE_UNKNOWN}},
		{"adox",	{"adox", {0, 0, "#=(#arg1,#uadd(#arg1,#arg2,o)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($c,#c)&=($a,#a))", 0}, R_INSTR_TYPE_ADD, R_INSTR_TYPE_UNKNOWN}},

		{
			"imul",	{
				"imul", {
					"?(==(#size(#arg1),8),=($ax,*($al,#arg1)))&"
					"?(==(#size(#arg1),16),=(#append($dx,$ax),*($ax,#arg1)))"
					"?(==(#size(#arg1),32),=(#append($edx,$eax),*($eax,#arg1)))"
					"&=($c,#c)&=($o,#o)",
					"=(#arg1,*(#arg1,#arg2))&=($c,#c)&=($o,#o)",
					"=(#arg1,*(#arg2,#arg3))&=($c,#c)&=($o,#o)", 0
				}, R_INSTR_TYPE_MUL, R_INSTR_TYPE_UNKNOWN
			}
		},
		{
			"imul_signed", {
				"imul", {
					0,
					"=(#arg1,*(#arg1,#sextend(#arg2,#size(#arg1)))&=($c,#c)&=($o,#o)",
					"=(#arg1,*(#arg2,#sextend(#arg3,#size(#arg2))))&=($c,#c)&=($o,#o)", 0
				}, R_INSTR_TYPE_MUL, R_INSTR_TYPE_UNKNOWN
			}
		},
		{
			"idiv",	{
				"idiv", {
					0,
					"?(==(#size(#arg1),8),=($al,#div($ax,#arg1))&=($ah,#mod($ax,#arg1)))&"
					"?(==(#size(#arg1),16),=($ax,#div(#append($dx,$ax),#arg1))&=($dx,#mod(#append($dx,$ax),#arg1)))"
					"?(==(#size(#arg1),32),=($eax,#div(#append($edx,$eax),#arg1))&=($edx,#mod(#append($edx,$eax),#arg1)))",
					0, 0
				}, R_INSTR_TYPE_DIV, R_INSTR_TYPE_UNKNOWN
			}
		},
		{
			"div",	{
				"div", {
					0,
					"?(==(#size(#arg1),8),=($al,#udiv($ax,#arg1))&=($ah,#umod($ax,#arg1)))&"
					"?(==(#size(#arg1),16),=($ax,#udiv(#append($dx,$ax),#arg1))&=($dx,#umod(#append($dx,$ax),#arg1)))"
					"?(==(#size(#arg1),32),=($eax,#udiv(#append($edx,$eax),#arg1))&=($edx,#umod(#append($edx,$eax),#arg1)))",
					0, 0
				}, R_INSTR_TYPE_DIV, R_INSTR_TYPE_UNKNOWN
			}
		},
		{"nop",		{"nop", {"", "", 0, 0}, R_INSTR_TYPE_UNKNOWN, R_INSTR_TYPE_UNKNOWN}},

		{"inc",		{"inc", {0, 0, "=(#arg1,+(#arg1,1)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))", 0}, R_INSTR_TYPE_ADD, R_INSTR_TYPE_UNKNOWN}},
		{"dec",		{"dec", {0, 0, "=(#arg1,-(#arg1,1)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))", 0}, R_INSTR_TYPE_SUB, R_INSTR_TYPE_UNKNOWN}},

		{"neg",		{"neg", {0, 0, "=(#arg1,#neg(#arg1,1)&=($c,#eq(#arg1,0))", 0}, R_INSTR_TYPE_NEG, R_INSTR_TYPE_UNKNOWN}},

		{"cmp",		{"cmp", {0, 0, "=(#t0,#arg1)&#rec[sub](#t0,#arg2)", 0}, R_INSTR_TYPE_CMP, R_INSTR_TYPE_UNKNOWN}},

		{"and",		{"and", {0, 0, "=(#arg1,#band(#arg1,#arg2))&=($o,0)&=($c,0)&=($s,#s)&=($z,#z)&=($p,#p)", 0}, R_INSTR_TYPE_AND, R_INSTR_TYPE_UNKNOWN}},
		{"or",		{"or", {0, 0, "=(#arg1,#bor(#arg1,#arg2))&=($o,0)&=($c,0)&=($s,#s)&=($z,#z)&=($p,#p)", 0}, R_INSTR_TYPE_OR, R_INSTR_TYPE_UNKNOWN}},
		{"xor",		{"xor", {0, 0, "=(#arg1,#bxor(#arg1,#arg2))&=($o,0)&=($c,0)&=($s,#s)&=($z,#z)&=($p,#p)", 0}, R_INSTR_TYPE_XOR, R_INSTR_TYPE_UNKNOWN}},
		{"not",		{"not", {0, 0, "=(#arg1,#bnot(#arg1,#arg2))", 0}, R_INSTR_TYPE_NOT, R_INSTR_TYPE_UNKNOWN}},

		//TODO carry flags for shifts
		//The CF flag contains the value of the last bit shifted out of the destination operand;
		//it is undefined for SHL and SHR instructions where the count is greater than or equal to the size (in bits) of the destination operand.
		{
			"sar",		{
				"sar", {
					"=(#arg1,#sar(#arg1,1)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))",
					"=(#arg1,#sar(#arg1,#arg2)&=($z,#z)&=($p,#p)&=($s,#s)&=($a,#a))", 0, 0
				}, R_INSTR_TYPE_SHR, R_INSTR_TYPE_UNKNOWN
			}
		},
		{"sar_cl",	{"sar", { "=(#arg1,#sar(#arg1,$cl)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))", 0, 0, 0}, R_INSTR_TYPE_SHR, R_INSTR_TYPE_UNKNOWN}},

		{
			"shr",		{
				"shr", {
					"=(#arg1,#shr(#arg1,1)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))",
					"=(#arg1,#shr(#arg1,#arg2)&=($z,#z)&=($p,#p)&=($s,#s)&=($a,#a))", 0, 0
				}, R_INSTR_TYPE_SHR, R_INSTR_TYPE_UNKNOWN
			}
		},
		{"shr_cl",	{"shr", { "=(#arg1,#shr(#arg1,$cl)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))", 0, 0, 0}, R_INSTR_TYPE_SHR, R_INSTR_TYPE_UNKNOWN}},

		{
			"sal",		{
				"sal", {
					"=(#arg1,#sal(#arg1,1)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))",
					"=(#arg1,#sal(#arg1,#arg2)&=($z,#z)&=($p,#p)&=($s,#s)&=($a,#a))", 0, 0
				}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN
			}
		},
		{"sal_cl",	{"sal", { "=(#arg1,#sal(#arg1,$cl)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))", 0, 0, 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},

		{
			"shl",		{
				"shl", {
					"=(#arg1,#shl(#arg1,1)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))",
					"=(#arg1,#shl(#arg1,#arg2)&=($z,#z)&=($p,#p)&=($s,#s)&=($a,#a))", 0, 0
				}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN
			}
		},
		{"shl_cl",	{"shl", { "=(#arg1,#shl(#arg1,$cl)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a))", 0, 0, 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},

		//TODO flags
		{"shrd",	{"shrd", { 0, "=(#arg1,#shr(#append(#arg1,#arg2),$cl))", "=(#arg1,#shr(#append(#arg1,#arg2),$arg3))", 0}, R_INSTR_TYPE_SHR, R_INSTR_TYPE_UNKNOWN}},
		{"shld",	{"shld", { 0, "=(#arg1,#shl(#append(#arg1,#arg2),$cl))", "=(#arg1,#shl(#append(#arg1,#arg2),$arg3))", 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},

		//TODO flags for rotates
		{"ror",		{"ror", {0, "=(#arg1,#ror(#arg1,1))", "=(#arg1,#ror(#arg1,$arg2))", 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},
		{"ror_cl",	{"ror", {0, "=(#arg1,#ror(#arg1,$cl))", 0, 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},
		{"rol",		{"rol", {0, "=(#arg1,#rol(#arg1,1))", "=(#arg1,#rol(#arg1,$arg2))", 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},
		{"rol_cl",	{"rol", {0, "=(#arg1,#rol(#arg1,$cl))", 0, 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},
		{
			"rcr", {
				"rcr", {
					0,
					"=(#t0,#ror(#append(#arg1,$c),1))&=(#arg1,#t0)&=($c,#split(#t0,#size(#arg1),1))",
					"=(#t0,#ror(#append(#arg1,$c),$arg2))&=(#arg1,#t0)&=($c,#split(#t0,#size(#arg1),1))", 0
				}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN
			}
		},
		{"rcr_cl",	{"rcr", {0, "=(#t0,#ror(#append(#arg1,$c),#cl))&=(#arg1,#t0)&=($c,#split(#t0,#size(#arg1),1))", 0, 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},
		{
			"rcl", {
				"rcl", {
					0,
					"=(#t0,#rol(#append(#arg1,$c),1))&=(#arg1,#t0)&=($c,#split(#t0,#size(#arg1),1))",
					"=(#t0,#rol(#append(#arg1,$c),$arg2))&=(#arg1,#t0)&=($c,#split(#t0,#size(#arg1),1))", 0
				}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN
			}
		},
		{"rcl_cl",	{"rcl", {0, "=(#t0,#rol(#append(#arg1,$c),#cl))&=(#arg1,#t0)&=($c,#split(#t0,#size(#arg1),1))", 0, 0}, R_INSTR_TYPE_SHL, R_INSTR_TYPE_UNKNOWN}},

		{"bt",		{"bt", {0, 0, "=($c,#split($arg1,$arg2))", 0}, R_INSTR_TYPE_BITTEST, R_INSTR_TYPE_UNKNOWN}},
		{"bts",		{"bts", {0, 0, "=($c,#split($arg1,$arg2))&=(#split($arg1,$arg2),1)", 0}, R_INSTR_TYPE_BITTEST, R_INSTR_TYPE_BITSET}},
		{"btr",		{"btr", {0, 0, "=($c,#split($arg1,$arg2))&=(#split($arg1,$arg2),0)", 0}, R_INSTR_TYPE_BITTEST, R_INSTR_TYPE_BITRESET}},
		{"btc",		{"btc", {0, 0, "=($c,#split($arg1,$arg2))&=(#split($arg1,$arg2),#not(#split($arg1,$arg2)))", 0}, R_INSTR_TYPE_BITTEST, R_INSTR_TYPE_CPL}},

		{"loop",	{"loop", {0, "=($ecx,-($ecx,1))&?(<>($ecx,0),#rjmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN}},


		{"loope",	{"loope", {0, "=($ecx,-($ecx,1))&?(#and(<>($ecx,0),$z),#rjmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_E}},
		{"loopz",	{"loopz", {0, "=($ecx,-($ecx,1))&?(#and(<>($ecx,0),$z),#rjmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_E}},

		{"loopne",	{"loopne", {0, "=($ecx,-($ecx,1))&?(#and(<>($ecx,0),#not($z)),#rjmp(#arg1))", 0,  0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NE}},
		{"loopnz",	{"loopnz", {0, "=($ecx,-($ecx,1))&?(#and(<>($ecx,0),#not($z)),#rjmp(#arg1))", 0, 0}, R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_NE}},

		{"call",	{"call", {0, "#call(#arg1)", 0, 0}, R_INSTR_TYPE_CALL, R_INSTR_TYPE_UNKNOWN}},

		{"ret",		{"ret", {"#ret()", 0, 0, 0}, R_INSTR_TYPE_RET, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_TRUE}},
		{"reti",	{"reti", {"#ret()", 0, 0, 0}, R_INSTR_TYPE_RET, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_TRUE}},

		{"int",		{"int", {0, "#syscall(#arg1)", 0, 0}, R_INSTR_TYPE_SYSCALL, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_TRUE}},
		{"into",	{"into", {"#syscall()", 0, 0, 0}, R_INSTR_TYPE_SYSCALL, R_INSTR_TYPE_UNKNOWN, R_INSTR_COND_TRUE}},

		//TODO il
		{"bound",	{"bound", {0, 0, 0, 0}, R_INSTR_TYPE_UNKNOWN, R_INSTR_TYPE_UNKNOWN}},

		{"enter",	{"enter", {0, "#rec[push]($ebp)&#rec[mov]($ebp,$esp)&#rec[sub]($esp,#arg1)", 0, 0}, R_INSTR_TYPE_UNKNOWN, R_INSTR_TYPE_UNKNOWN}},
		{"leave",	{"leave", {"#rec[mov]($esp,$ebp)&#rec[pop]($ebp)", 0, 0, 0}, R_INSTR_TYPE_UNKNOWN, R_INSTR_TYPE_UNKNOWN}},

		{"setz",	{"setz", {0, "=(#arg1,$z)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"sete",	{"sete", {0, "=(#arg1,$z)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setnz",	{"setnz", {0, "=(#arg1,#not($z))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setne",	{"setne", {0, "=(#arg1,#not($z))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"seta",	{"seta", {0, "=(#arg1,#not(#or($c,$z)))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setnbe",	{"setnbe", {0, "=(#arg1,#not(#or($c,$z)))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setae",	{"setae", {0, "=(#arg1,#not($c))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setnb",	{"setnb", {0, "=(#arg1,#not($c))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setnc",	{"setnc", {0, "=(#arg1,#not($c))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setb",	{"setae", {0, "=(#arg1,$c)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setnae",	{"setnb", {0, "=(#arg1,$c)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setc",	{"setnc", {0, "=(#arg1,$c)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setbe",	{"setbe", {0, "=(#arg1,#or($c,$z))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setna",	{"setna", {0, "=(#arg1,#or($c,$z))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setg",	{"setg", {0, "=(#arg1,#and(#not($z),==($s,$o)))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setnle",	{"setnle", {0, "=(#arg1,#and(#not($z),==($s,$o)))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setge",	{"setge", {0, "=(#arg1,==($s,$o))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setnl",	{"setnl", {0, "=(#arg1,==($s,$o))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setl",	{"setl", {0, "=(#arg1,<>($s,$o))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setnge",	{"setnge", {0, "=(#arg1,<>($s,$o))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setle",	{"setle", {0, "=(#arg1,#or($z,<>($s,$o)))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setng",	{"setng", {0, "=(#arg1,#or($z,<>($s,$o)))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"sets",	{"sets", {0, "=(#arg1,$s)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setns",	{"setns", {0, "=(#arg1,#not($s))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"seto",	{"seto", {0, "=(#arg1,$o)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setno",	{"setno", {0, "=(#arg1,#not($o))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setp",	{"setp", {0, "=(#arg1,$p)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setpe",	{"setpe", {0, "=(#arg1,$p)", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"setpo",	{"setpo", {0, "=(#arg1,#not($p))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"setnp",	{"setnp", {0, "=(#arg1,#not($p))", 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"test",	{"test", {0, 0, "#band(#arg1,#arg2)&==($c,0)&==($o,0)&==($p,#p)&==($z,#z)&==($s,#s)", 0}, R_INSTR_TYPE_AND, R_INSTR_TYPE_UNKNOWN}},

		{"bsf",		{"bsf", {0, 0, 0, 0}, R_INSTR_TYPE_UNKNOWN, R_INSTR_TYPE_UNKNOWN}},
		{"bsr",		{"bsr", {0, 0, 0, 0}, R_INSTR_TYPE_UNKNOWN, R_INSTR_TYPE_UNKNOWN}},
		{"crc32",	{"crc32", {0, 0, 0, 0}, R_INSTR_TYPE_UNKNOWN, R_INSTR_TYPE_UNKNOWN}},
		{"popcnt",	{"popcnt", {0, 0, 0, 0}, R_INSTR_TYPE_UNKNOWN, R_INSTR_TYPE_UNKNOWN}},

		{"stc",		{"stc", {"=($c,1)", 0, 0, 0}, R_INSTR_TYPE_BITSET, R_INSTR_TYPE_UNKNOWN}},
		{"clc",		{"clc", {"=($c,0)", 0, 0, 0}, R_INSTR_TYPE_BITRESET, R_INSTR_TYPE_UNKNOWN}},
		{"cmc",		{"cmc", {"=($c,#not($c))", 0, 0, 0}, R_INSTR_TYPE_CPL, R_INSTR_TYPE_UNKNOWN}},

		{"std",		{"std", {"=($d,1)", 0, 0, 0}, R_INSTR_TYPE_BITSET, R_INSTR_TYPE_UNKNOWN}},
		{"cld",		{"cld", {"=($d,0)", 0, 0, 0}, R_INSTR_TYPE_BITRESET, R_INSTR_TYPE_UNKNOWN}},

		{"lahf",	{"lahf", {"=($ah,$eflags)", 0, 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},
		{"sahf",	{"sahf", {"=($eflags,$ah)", 0, 0, 0}, R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN}},

		{"pushf",	{"pushf", {"#rec[push]($flags)", 0, 0, 0}, R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},
		{"pushfd",	{"pushfd", {"#rec[push]($eflags)", 0, 0, 0}, R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},

		{"popf",	{"popf", {"#rec[pop]($flags)", 0, 0, 0}, R_INSTR_TYPE_POP, R_INSTR_TYPE_UNKNOWN}},
		{"popfd",	{"popfd", {"#rec[pop]($eflags)", 0, 0, 0}, R_INSTR_TYPE_POP, R_INSTR_TYPE_UNKNOWN}},

		{"sti",		{"sti", {"=($i,1)", 0, 0, 0}, R_INSTR_TYPE_BITSET, R_INSTR_TYPE_UNKNOWN}},
		{"cli",		{"cli", {"=($i,0)", 0, 0, 0}, R_INSTR_TYPE_BITRESET, R_INSTR_TYPE_UNKNOWN}},
	},
};

/*
//Decimal Arithmetic Instructions


//String Instructions
case str2int ("movs") :
case str2int ("movsb") :
case str2int ("movsw") :
case str2int ("movsd") :
	instruction.type = R_INSTR_TYPE_MOV;
	break;
case str2int ("cmps") :
case str2int ("cmpsb") :
case str2int ("cmpsw") :
case str2int ("cmpsd") :
	instruction.type = R_INSTR_TYPE_CMP;
	break;
case str2int ("scas") :
case str2int ("scasb") :
case str2int ("scasw") :
case str2int ("scasd") :
	instruction.type = R_INSTR_TYPE_CMP;
	break;
case str2int ("lods") :
case str2int ("lodsb") :
case str2int ("lodsw") :
case str2int ("lodsd") :
	instruction.type = R_INSTR_TYPE_LOAD;
	break;
case str2int ("stos") :
case str2int ("stosb") :
case str2int ("stosw") :
case str2int ("stosd") :
	instruction.type = R_INSTR_TYPE_STORE;
	break;
case str2int ("rep") :
	break;
case str2int ("repe") :
case str2int ("repz") :
	break;
case str2int ("repne") :
case str2int ("repnz") :
	break;

//I/O Instructions
case str2int ("in") :
	instruction.type = R_INSTR_TYPE_IO;
	break;
case str2int ("out") :
	instruction.type = R_INSTR_TYPE_IO;
	break;
case str2int ("ins") :
case str2int ("insb") :
case str2int ("insw") :
case str2int ("insd") :
	instruction.type = R_INSTR_TYPE_IO;
	break;
case str2int ("outs") :
case str2int ("outsb") :
case str2int ("outsw") :
case str2int ("outsd") :
	instruction.type = R_INSTR_TYPE_IO;
	break;

//Enter and Leave Instructions
//Already defined in Control Flow Instructions

//Segment Register Instructions
case str2int ("lds") :
	instruction.type = R_INSTR_TYPE_LOAD;
	break;
case str2int ("les") :
	instruction.type = R_INSTR_TYPE_LOAD;
	break;
case str2int ("lfs") :
	instruction.type = R_INSTR_TYPE_LOAD;
	break;
case str2int ("lgs") :
	instruction.type = R_INSTR_TYPE_LOAD;
	break;
case str2int ("lss") :
	instruction.type = R_INSTR_TYPE_LOAD;
	break;

//Miscellaneous Instructions
case str2int ("ud") :
	instruction.type = R_INSTR_TYPE_UNDEFINED;
	break;
case str2int ("xlat") :
case str2int ("xlatb") :
	break;
case str2int ("cpuid") :
	break;
case str2int ("movbe") :
	instruction.type = R_INSTR_TYPE_MOV;
	break;
case str2int ("prefetchbe") :
	break;
case str2int ("prefetchwt1") :
	break;
case str2int ("clflush") :
	break;
case str2int ("clflushopt") :
	break;
//User Mode Extended Sate Save/Restore Instructions
//Random Number Generator Instructions
//BMI1, BMI2
//Detection of VEX-encoded GPR Instructions, LZCNT and TZCNT, PREFETCHW
//x87 FPU Data Transfer Instructions
//x87 FPU Basic Arithmetic Instructions
//x87 FPU Comparison Instructions
//x87 FPU Transcendental Instructions
//x87 FPU Load Constants Instructions
//x87 FPU Control Instructions
//X87 FPU AND SIMD STATE MANAGEMENT INSTRUCTIONS
//MMX Data Transfer Instructions
case str2int ("movd") :
	instruction.type = R_INSTR_TYPE_MOV;
	break;
case str2int ("movq") :
	instruction.type = R_INSTR_TYPE_MOV;
	break;
//MMX Conversion Instructions
case str2int ("packsswb") :
	break;
case str2int ("packssdw") :
	break;
case str2int ("packuswb") :
	break;
case str2int ("punpckhbw") :
	break;
case str2int ("punpckhwd") :
	break;
case str2int ("punpckhdq") :
	break;
case str2int ("punpcklbw") :
	break;
case str2int ("punpcklwd") :
	break;
case str2int ("punpckldq") :
	break;

//MMX Packed Arithmetic Instructions
//MMX Comparison Instructions
//MMX Logical Instructions
//MMX Shift and Rotate Instructions
//MMX State Management Instructions
//SSE SIMD Single-Precision Floating-Point Instructions
//SSE Data Transfer Instructions
//SSE Packed Arithmetic Instructions
//SSE Comparison Instructions
//SSE Logical Instructions
//SSE Shuffle and Unpack Instructions
//SSE Conversion Instructions
//SSE MXCSR State Management Instructions
//SSE 64-Bit SIMD Integer Instructions
//SSE Cacheability Control, Prefetch, and Instruction Ordering Instructions
//SSE2 Data Movement Instructions
//SSE2 Packed Arithmetic Instructions
//SSE2 Logical Instructions
//SSE2 Compare Instructions
//SSE2 Shuffle and Unpack Instructions
//SSE2 Conversion Instructions
//SSE2 Packed Single-Precision Floating-Point Instructions
//SSE2 128-Bit SIMD Integer Instructions
//SSE2 Cacheability Control and Ordering Instructions
//SSE3 x87-FP Integer Conversion Instruction
//SSE3 Specialized 128-bit Unaligned Data Load Instruction
//SSE3 SIMD Floating-Point Packed ADD/SUB Instructions
//SSE3 SIMD Floating-Point Horizontal ADD/SUB Instructions
//SSE3 SIMD Floating-Point LOAD/MOVE/DUPLICATE Instructions
//SSE3 Agent Synchronization Instructions
//Horizontal Addition/Subtraction
//Packed Absolute Values
//Multiply and Add Packed Signed and Unsigned Bytes
//Packed Multiply High with Round and Scale
//Packed Shuffle Bytes
//Packed Sign
//Packed Align Right
//SSE4
//Dword Multiply Instructions
//Floating-Point Dot Product Instructions
//Streaming Load Hint Instruction
//Packed Blending Instructions
//Packed Integer MIN/MAX Instructions
//Floating-Point Round Instructions with Selectable Rounding Mode
//Insertion and Extractions from XMM Registers
//Packed Integer Format Conversions
//Improved Sums of Absolute Differences (SAD) for 4-Byte Blocks
//Horizontal Search
//Packed Test
//Packed Qword Equality Comparisons
//Dword Packing With Unsigned Saturation
//String and Text Processing Instructions
//Packed Comparison SIMD integer Instruction
//AESNI AND PCLMULQDQ
//16-BIT FLOATING-POINT CONVERSION
//INTEL® TRANSACTIONAL SYNCHRONIZATION EXTENSIONS (INTEL® TSX)
//INTEL® SHA EXTENSIONS
//INTEL® ADVANCED VECTOR EXTENSIONS 512 (INTEL® AVX-512)
//SYSTEM INSTRUCTIONS
case str2int ("clac") :
	instruction.type = R_INSTR_TYPE_BITRESET;
	break;
case str2int ("stac") :
	instruction.type = R_INSTR_TYPE_BITSET;
	break;
case str2int ("hlt") :
	instruction.type = R_INSTR_TYPE_HALT;
	break;
//64-BIT MODE INSTRUCTIONS
case str2int ("syscall") :
	instruction.type = R_INSTR_TYPE_SYSCALL;
	break;
//VIRTUAL-MACHINE EXTENSIONS
//SAFER MODE EXTENSIONS
//INTEL® MEMORY PROTECTION EXTENSIONS
//INTEL® SECURITY GUARD EXTENSIONS
default:
	printf ("Missed %s", insn->mnemonic);
}*/
