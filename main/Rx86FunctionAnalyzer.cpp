#include "Rx86FunctionAnalyzer.h"

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "RArchitecture.h"
#include "RString.h"


#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

using namespace holodec;

RRegister* gr_x86_reg[X86_REG_ENDING] = {0,};
RRegister* gr_x86_reg_al;


RArchitecture x86architecture = {"x86", "x86", {
		[] (RBinary * binary) {
			static RFunctionAnalyzer* analyzer = nullptr;
			if (analyzer == nullptr) {
				printf ("Create New Object\n");
				analyzer = new holox86::Rx86FunctionAnalyzer();
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
		{"rax", X86_REG_RAX, 64, 0, {	{"eax", X86_REG_EAX, 32, 0, {	{"ax", X86_REG_AX, 16, 0, {{"al", X86_REG_AL, 8, 0}, {"ah", X86_REG_AH, 8, 8}}}}}}},
		{"rbx", X86_REG_RBX, 64, 0, {	{"ebx", X86_REG_EBX, 32, 0, {	{"bx", X86_REG_BX, 16, 0, {{"bl", X86_REG_BL, 8, 0}, {"bh", X86_REG_BH, 8, 8}}}}}}},
		{"rcx", X86_REG_RCX, 64, 0, {	{"ecx", X86_REG_ECX, 32, 0, {	{"cx", X86_REG_CX, 16, 0, {{"cl", X86_REG_CL, 8, 0}, {"ch", X86_REG_CH, 8, 8}}}}}}},
		{"rdx", X86_REG_RDX, 64, 0, {	{"edx", X86_REG_EDX, 32, 0, {	{"dx", X86_REG_DX, 16, 0, {{"dl", X86_REG_DL, 8, 0}, {"dh", X86_REG_DH, 8, 8}}}}}}},
		{"r8", X86_REG_R8, 64, 0, {	{"r8d", X86_REG_R8D, 32, 0, {	{"r8w", X86_REG_R8W, 16, 0, {{"r8b", X86_REG_R8B, 8, 0}}}}}}},
		{"r9", X86_REG_R9, 64, 0, {	{"r9d", X86_REG_R9D, 32, 0, {	{"r9w", X86_REG_R9W, 16, 0, {{"r9b", X86_REG_R9B, 8, 0}}}}}}},
		{"r10", X86_REG_R10, 64, 0, {	{"r10d", X86_REG_R10D, 32, 0, {	{"r10w", X86_REG_R10W, 16, 0, {{"r10b", X86_REG_R10, 8, 0}}}}}}},
		{"r11", X86_REG_R11, 64, 0, {	{"r11d", X86_REG_R11D, 32, 0, {	{"r11w", X86_REG_R11W, 16, 0, {{"r11b", X86_REG_R11, 8, 0}}}}}}},
		{"r12", X86_REG_R12, 64, 0, {	{"r12d", X86_REG_R12D, 32, 0, {	{"r12w", X86_REG_R12W, 16, 0, {{"r12b", X86_REG_R12, 8, 0}}}}}}},
		{"r13", X86_REG_R13, 64, 0, {	{"r13d", X86_REG_R13D, 32, 0, {	{"r13w", X86_REG_R13W, 16, 0, {{"r13b", X86_REG_R13, 8, 0}}}}}}},
		{"r14", X86_REG_R14, 64, 0, {	{"r14d", X86_REG_R14D, 32, 0, {	{"r14w", X86_REG_R14W, 16, 0, {{"r14b", X86_REG_R14, 8, 0}}}}}}},
		{"r15", X86_REG_R15, 64, 0, {	{"r15d", X86_REG_R15D, 32, 0, {	{"r15w", X86_REG_R15W, 16, 0, {{"r15b", X86_REG_R15, 8, 0}}}}}}},

		{"rbp", X86_REG_RBP, 64, 0, {	{"ebp", X86_REG_EBP, 32, 0, {	{"bp", X86_REG_BP, 16, 0}}}}},
		{"rsi", X86_REG_RSI, 64, 0, {	{"esi", X86_REG_ESI, 32, 0, {	{"si", X86_REG_SI, 16, 0}}}}},
		{"rdi", X86_REG_RSI, 64, 0, {	{"edi", X86_REG_EDI, 32, 0, {	{"di", X86_REG_DI, 16, 0}}}}},
		{"rsp", X86_REG_RSP, 64, 0, {	{"esp", X86_REG_ESP, 32, 0, {	{"sp", X86_REG_SP, 16, 0}}}}},
		{"rip", X86_REG_RIP, 64, 0, {	{"eip", X86_REG_EIP, 32, 0, {	{"ip", X86_REG_IP, 16, 0}}}}},

		{
			"rflags", 0, 64, 0,
			{	{
					"eflags", X86_REG_EFLAGS, 32, 0,
					{	{
							"flags", 0, 16, 0,
							{	{"cf", 0, 1, 0}, {"pf", 0, 1, 2}, {"af", 0, 1, 4}, {"zf", 0, 1, 6}, {"sf", 0, 1, 7}, {"tf", 0, 1, 8}, {"if", 0, 1, 9},
								{"df", 0, 1, 10}, {"of", 0, 1, 11}, {"iopl", 0, 2, 12}, {"nt", 0, 1, 14}
							}
						}, {"rf", 0, 1, 16}, {"vm", 0, 1, 17}, {"ac", 0, 1, 18}, {"vif", 0, 1, 19}, {"vip", 0, 1, 20}, {"id", 0, 1, 21}
					}
				},
			}
		},

		{"st0", X86_REG_ST0, 80, 0, {	{"mm0", X86_REG_MM0, 64, 0}}},
		{"st1", X86_REG_ST1, 80, 0, {	{"mm1", X86_REG_MM1, 64, 0}}},
		{"st2", X86_REG_ST2, 80, 0, {	{"mm2", X86_REG_MM2, 64, 0}}},
		{"st3", X86_REG_ST3, 80, 0, {	{"mm3", X86_REG_MM3, 64, 0}}},
		{"st4", X86_REG_ST4, 80, 0, {	{"mm4", X86_REG_MM4, 64, 0}}},
		{"st5", X86_REG_ST5, 80, 0, {	{"mm5", X86_REG_MM5, 64, 0}}},
		{"st6", X86_REG_ST6, 80, 0, {	{"mm6", X86_REG_MM6, 64, 0}}},
		{"st7", X86_REG_ST7, 80, 0, {	{"mm7", X86_REG_MM7, 64, 0}}},

		{"cs", X86_REG_CS, 16, 0},
		{"ds", X86_REG_DS, 16, 0},
		{"ss", X86_REG_SS, 16, 0},
		{"es", X86_REG_ES, 16, 0},
		{"fs", X86_REG_FS, 16, 0},
		{"gs", X86_REG_GS, 16, 0},

		{"dr0", X86_REG_DR0, 64, 0}, {"dr1", X86_REG_DR1, 64, 0}, {"dr2", X86_REG_DR2, 64, 0}, {"dr3", X86_REG_DR3, 64, 0},
		{"dr4", X86_REG_DR4, 64, 0}, {"dr5", X86_REG_DR5, 64, 0}, {"dr6", X86_REG_DR6, 64, 0}, {"dr7", X86_REG_DR7, 64, 0},
		//{"dr8", X86_REG_DR8, 64, 0}, {"dr9", X86_REG_DR9, 64, 0}, {"dr10", X86_REG_DR10, 64, 0}, {"dr11", X86_REG_DR11, 64, 0},
		//{"dr12", X86_REG_DR12, 64, 0}, {"dr13", X86_REG_DR13, 64, 0}, {"dr14", X86_REG_DR14, 64, 0}, {"dr15", X86_REG_DR15, 64, 0},

		//cr0 - cr15 control register
		//sw,cw,tw,fp_ip,...

		//{"cr0", X86_REG_CR0, 512, 0},

		{"zmm0", X86_REG_ZMM0, 512, 0, {{"ymm0", X86_REG_YMM0, 256, 0, {{"xmm0", X86_REG_XMM0, 128, 0 }}}}},
		{"zmm1", X86_REG_ZMM1, 512, 0, {{"ymm1", X86_REG_YMM1, 256, 0, {{"xmm1", X86_REG_XMM1, 128, 0 }}}}},
		{"zmm2", X86_REG_ZMM2, 512, 0, {{"ymm2", X86_REG_YMM2, 256, 0, {{"xmm2", X86_REG_XMM2, 128, 0 }}}}},
		{"zmm3", X86_REG_ZMM3, 512, 0, {{"ymm3", X86_REG_YMM3, 256, 0, {{"xmm3", X86_REG_XMM3, 128, 0 }}}}},
		{"zmm4", X86_REG_ZMM4, 512, 0, {{"ymm4", X86_REG_YMM4, 256, 0, {{"xmm4", X86_REG_XMM4, 128, 0 }}}}},
		{"zmm5", X86_REG_ZMM5, 512, 0, {{"ymm5", X86_REG_YMM5, 256, 0, {{"xmm5", X86_REG_XMM5, 128, 0 }}}}},
		{"zmm6", X86_REG_ZMM6, 512, 0, {{"ymm6", X86_REG_YMM6, 256, 0, {{"xmm6", X86_REG_XMM6, 128, 0 }}}}},
		{"zmm7", X86_REG_ZMM7, 512, 0, {{"ymm7", X86_REG_YMM7, 256, 0, {{"xmm7", X86_REG_XMM7, 128, 0 }}}}},
		{"zmm8", X86_REG_ZMM8, 512, 0, {{"ymm8", X86_REG_YMM8, 256, 0, {{"xmm8", X86_REG_XMM8, 128, 0 }}}}},
		{"zmm9", X86_REG_ZMM9, 512, 0, {{"ymm9", X86_REG_YMM9, 256, 0, {{"xmm9", X86_REG_XMM9, 128, 0 }}}}},
		{"zmm10", X86_REG_ZMM10, 512, 0, {{"ymm10", X86_REG_YMM10, 256, 0, {{"xmm10", X86_REG_XMM10, 128, 0 }}}}},
		{"zmm11", X86_REG_ZMM11, 512, 0, {{"ymm11", X86_REG_YMM11, 256, 0, {{"xmm11", X86_REG_XMM11, 128, 0 }}}}},
		{"zmm12", X86_REG_ZMM12, 512, 0, {{"ymm12", X86_REG_YMM12, 256, 0, {{"xmm12", X86_REG_XMM12, 128, 0 }}}}},
		{"zmm13", X86_REG_ZMM13, 512, 0, {{"ymm13", X86_REG_YMM13, 256, 0, {{"xmm13", X86_REG_XMM13, 128, 0 }}}}},
		{"zmm14", X86_REG_ZMM14, 512, 0, {{"ymm14", X86_REG_YMM14, 256, 0, {{"xmm14", X86_REG_XMM14, 128, 0 }}}}},
		{"zmm15", X86_REG_ZMM15, 512, 0, {{"ymm15", X86_REG_YMM15, 256, 0, {{"xmm15", X86_REG_XMM15, 128, 0 }}}}},
		{"zmm16", X86_REG_ZMM16, 512, 0},
		{"zmm17", X86_REG_ZMM17, 512, 0},
		{"zmm18", X86_REG_ZMM18, 512, 0},
		{"zmm19", X86_REG_ZMM19, 512, 0},
		{"zmm20", X86_REG_ZMM20, 512, 0},
		{"zmm21", X86_REG_ZMM21, 512, 0},
		{"zmm22", X86_REG_ZMM22, 512, 0},
		{"zmm23", X86_REG_ZMM23, 512, 0},
		{"zmm24", X86_REG_ZMM24, 512, 0},
		{"zmm25", X86_REG_ZMM25, 512, 0},
		{"zmm26", X86_REG_ZMM26, 512, 0},
		{"zmm27", X86_REG_ZMM27, 512, 0},
		{"zmm28", X86_REG_ZMM28, 512, 0},
		{"zmm29", X86_REG_ZMM29, 512, 0},
		{"zmm30", X86_REG_ZMM30, 512, 0},
		{"zmm31", X86_REG_ZMM31, 512, 0}
	},
	{
		{hashRString ("add"),		{"add", "%s %s, %s", "=(%1$s,+(%1$s,%2$s)&=(z,#z)&=(p,#p)&=(s,#s)&=(o,#o)&=(c,#c)&=(a,#a))", R_INSTR_TYPE_ADD, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}}},
		{hashRString ("adc"),		{"adc", "%s %s, %s", "=(%1$s,+(%1$s,%2$s,c)&=(z,#z)&=(p,#p)&=(s,#s)&=(o,#o)&=(c,#c)& =(a,#a))", R_INSTR_TYPE_ADD, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}}},

		{hashRString ("sub"),		{"sub", "%s %s, %s", "=(%1$s,-(%1$s,%2$s)&=(z,#z)&=(p,#p)&=(s,#s)&=(o,#o)&=(c,#c)&=(a,#a))", R_INSTR_TYPE_SUB, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}}},
		{hashRString ("sbb"),		{"sbb", "%s %s, %s", "=(%1$s,-(%1$s,%2$s,c)&=(z,#z)&=(p,#p)&=(s,#s)&=(o,#o)&=(c,#c)&=(a,#a))", R_INSTR_TYPE_SUB, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}}},

		{hashRString ("mov"),		{"mov", "%s %s, %s", "=(%1$s,%2$s)", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}}},
		{hashRString ("movq"),		{"mov", "%s %s, %s", "=(%1$s,%2$s)", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}}},
		{hashRString ("movd"),		{"mov", "%s %s, %s", "=(%1$s,%2$s)", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}}},

		{hashRString ("cmovz"), 	{"cmovz", "%s %s, %s", "?(z,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_E}},
		{hashRString ("cmove"),		{"cmove", "%s %s, %s", "?(z,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_E}},

		{hashRString ("cmovnz"), 	{"cmovnz", "%s %s, %s", "?(z,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_NE}},
		{hashRString ("cmovne"), 	{"cmovne", "%s %s, %s", "?(z,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_NE}},

		{hashRString ("cmova"), 	{"cmova", "%s %s, %s", "?(#and(c,z),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_A}},
		{hashRString ("cmovnbe"), 	{"cmovnbe", "%s %s, %s", "?(#and(c,z),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_A}},

		{hashRString ("cmovbe"),	{"cmovbe", "%s %s, %s", "?(#or(c,z),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_BE}},
		{hashRString ("cmovna"),	{"cmovna", "%s %s, %s", "?(#or(c,z),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_BE}},

		{hashRString ("cmovg"),		{"cmovg", "%s %s, %s", "?(#and(#not(z),==(s,o)),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_G}},
		{hashRString ("cmovnle"),	{"cmovnle", "%s %s, %s", "?(#and(#not(z),==(s,o)),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_G}},

		{hashRString ("cmovge"),	{"cmovge", "%s %s, %s", "?(==(s,o),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_GE}},
		{hashRString ("cmovnl"),	{"cmovnl", "%s %s, %s", "?(==(s,o),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_GE}},

		{hashRString ("cmovl"),	{"cmovge", "%s %s, %s", "?(<>(s,o),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_L}},
		{hashRString ("cmovnge"),	{"cmovnl", "%s %s, %s", "?(<>(s,o),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_L}},

		{hashRString ("cmovle"),	{"cmovle", "%s %s, %s", "?(#or(z,<>(s,o)),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_LE}},
		{hashRString ("cmovng"),	{"cmovng", "%s %s, %s", "?(#or(z,<>(s,o)),=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_LE}},

		{hashRString ("cmovc"),		{"cmovc", "%s %s, %s", "?(c,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_C}},

		{hashRString ("cmovnc"),	{"cmovnc", "%s %s, %s", "?(c,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_NC}},

		{hashRString ("cmovb"),		{"cmovb", "%s %s, %s", "?(c,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_B}},
		{hashRString ("cmovnae"),	{"cmovnae", "%s %s, %s", "?(c,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_B}},

		{hashRString ("cmovae"),	{"cmovae", "%s %s, %s", "?(c,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_AE}},
		{hashRString ("cmovnb"),	{"cmovnb", "%s %s, %s", "?(c,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_AE}},

		{hashRString ("cmovo"),		{"cmovo", "%s %s, %s", "?(o,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_O}},

		{hashRString ("cmovno"),	{"cmovno", "%s %s, %s", "?(o,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_NO}},

		{hashRString ("cmovs"),		{"cmovs", "%s %s, %s", "?(s,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_NEG}},

		{hashRString ("cmovns"),	{"cmovns", "%s %s, %s", "?(s,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_POS}},

		{hashRString ("cmovp"),		{"cmovp", "%s %s, %s", "?(p,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_UNK}},
		{hashRString ("cmovpe"),	{"cmovpe", "%s %s, %s", "?(p,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_UNK}},

		{hashRString ("cmovnp"),	{"cmovp", "%s %s, %s", "?(p,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_UNK}},
		{hashRString ("cmovpo"),	{"cmovpo", "%s %s, %s", "?(p,,=(%1$s,%2$s))", R_INSTR_TYPE_MOV, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT, R_ARG_IN}, R_INSTR_COND_UNK}},

		{hashRString ("jmp"),	{"jmp", "%s %s", "#jmp(%1$s)", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}}},

		{hashRString ("je"),	{"je", "%s %s", "?(z,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_E}},
		{hashRString ("jz"),	{"jz", "%s %s", "?(z,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_E}},

		{hashRString ("jne"),	{"jne", "%s %s", "?(z,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_NE}},
		{hashRString ("jnz"),	{"jnz", "%s %s", "?(z,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_NE}},

		{hashRString ("ja"),	{"ja", "%s %s", "?(#and(c,z),,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_A}},
		{hashRString ("jnbe"),	{"jnbe", "%s %s", "?(#and(c,z),,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_A}},

		{hashRString ("jae"),	{"jae", "%s %s", "?(c,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_AE}},
		{hashRString ("jnb"),	{"jnb", "%s %s", "?(c,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_AE}},

		{hashRString ("jb"),	{"jb", "%s %s", "?(c,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_B}},
		{hashRString ("jnae"),	{"jnae", "%s %s", "?(c,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_B}},

		{hashRString ("jbe"),	{"jbe", "%s %s", "?(#or(c,z),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_BE}},
		{hashRString ("jna"),	{"jna", "%s %s", "?(#or(c,z),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_BE}},

		{hashRString ("jg"),	{"jg", "%s %s", "?(#and(#not(z),==(s,o)),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_G}},
		{hashRString ("jnle"),	{"jnle", "%s %s", "?(#and(#not(z),==(s,o)),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_G}},

		{hashRString ("jge"),	{"jge", "%s %s", "?(==(s,o)),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_GE}},
		{hashRString ("jnl"),	{"jge", "%s %s", "?(==(s,o)),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_GE}},

		{hashRString ("jl"),	{"jl", "%s %s", "?(<>(s,o)),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_L}},
		{hashRString ("jnge"),	{"jnge", "%s %s", "?(<>(s,o)),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_L}},

		{hashRString ("jle"),	{"jle", "%s %s", "?(#or(z,<>(s,o)),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_LE}},
		{hashRString ("jng"),	{"jng", "%s %s", "?(#or(z,<>(s,o)),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_LE}},

		{hashRString ("jc"),	{"jc", "%s %s", "?(c,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_C}},

		{hashRString ("jnc"),	{"jnc", "%s %s", "?(c,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_C}},

		{hashRString ("jo"),	{"jo", "%s %s", "?(o,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_O}},

		{hashRString ("jno"),	{"jno", "%s %s", "?(o,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_NO}},

		{hashRString ("js"),	{"js", "%s %s", "?(s,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_NEG}},

		{hashRString ("jns"),	{"jns", "%s %s", "?(s,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_POS}},

		{hashRString ("jp"),	{"jp", "%s %s", "?(p,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_UNK}},
		{hashRString ("jpe"),	{"jpe", "%s %s", "?(p,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_UNK}},

		{hashRString ("jpo"),	{"jpo", "%s %s", "?(p,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_UNK}},
		{hashRString ("jnp"),	{"jnp", "%s %s", "?(p,,#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN}, R_INSTR_COND_UNK}},

		{hashRString ("jcxz"),	{"jcxz", "%s %s", "?(==($cx,0),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_CMP, {R_ARG_IN}, R_INSTR_COND_E}},
		{hashRString ("jecxz"),	{"jecxz", "%s %s", "?(==($ecx,0),#jmp(%1$s))", R_INSTR_TYPE_JMP, R_INSTR_TYPE_CMP, {R_ARG_IN}, R_INSTR_COND_E}},

		{hashRString ("xchg"),	{"xchg", "%s %s, %s", "=(#t0,%1$s)&=(%1$s,%2$s)&=(%2$s,#t0)", R_INSTR_TYPE_XCHG, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN | R_ARG_OUT, R_ARG_IN | R_ARG_OUT}}},

		{hashRString ("bswap"),	{"bswap", "%s %s", "=(%1$s,#append([](%1$s,24,31),[](%1$s,23,16),[](%1$s,15,8),[](%1$s,7,0)))", R_INSTR_TYPE_SWAP, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN | R_ARG_OUT}}},

		{hashRString ("xadd"),	{"xadd", "%s %s, %s", "#rec[xchg](%1$s,%2$s)&#rec[add](%1$s,%2$s)", R_INSTR_TYPE_XCHG, R_INSTR_TYPE_ADD, {R_ARG_IN | R_ARG_OUT, R_ARG_IN | R_ARG_OUT}}},

		{hashRString ("cmpxchg"), {"cmpxchg", "%s %s, %s", "#rec[cmp]([]($eax,0,#size),%1$s)&?(z,#rec[xchg](%1$s,%2$s))", R_INSTR_TYPE_XCHG, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN | R_ARG_OUT,R_ARG_IN | R_ARG_OUT},R_INSTR_COND_E}},

		{hashRString ("cmpxchg8b"), {"cmpxchg", "%s %s", "?(==(#append($eax,$edx),%1$s),=(z,1)&=(%1$s,#append($ebx,$ecx)),=(z,1)&=(#append($eax,$edx),%1$s))", R_INSTR_TYPE_XCHG, R_INSTR_TYPE_UNKNOWN, {R_ARG_IN | R_ARG_OUT},R_INSTR_COND_E}},

		{hashRString ("push"),	{"push", "%s %s", "#push(%1$s)", R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT}}},
		
		{hashRString ("pop"),	{"pop", "%s %s", "#pop(%1$s)", R_INSTR_TYPE_POP, R_INSTR_TYPE_UNKNOWN, {R_ARG_OUT}}},

		{hashRString ("pushad"),{"pushad", "%s", "=(#t0,$esp)&#push($eax)&#push($ecx)&#push($edx)&#push($edx)&#push($ebx)&#push(#t0)&#push($ebp)&#push($esi)&#push($edi)", R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},
		{hashRString ("pusha"),	{"pusha", "%s", "=(#t0,$sp)&#push($ax)&#push($cx)&#push($dx)&#push($dx)&#push($bx)&#push(#t0)&#push($bp)&#push($si)&#push($di)", R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},

		{hashRString ("pushad"),{"pushad", "%s", "#pop($edi)&#pop($esi)&#pop($ebp)&=($esp,+($esp,4))&#pop($ebx)&#pop($edx)&#pop($ecx)&#pop($eax)", R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},
		{hashRString ("pusha"),	{"pusha", "%s", "#pop($di)&#pop($si)&#pop($bp)&=($esp,+($esp,2))&#pop($bx)&#pop($dx)&#pop($cx)&#pop($ax)", R_INSTR_TYPE_PUSH, R_INSTR_TYPE_UNKNOWN}},

		{hashRString ("ret"),	{"ret", "%s", "#ret", R_INSTR_TYPE_RET, R_INSTR_TYPE_UNKNOWN, {},R_INSTR_COND_TRUE}},
		/*
		case str2int ("cwd") :
		case str2int ("cdq") :
			instruction.type = R_INSTR_TYPE_EXTEND;
			break;
		case str2int ("cbw") :
		case str2int ("cwde") :
			instruction.type = R_INSTR_TYPE_SEXTEND;
			break;
		case str2int ("movsx") :
			instruction.type = R_INSTR_TYPE_MOV;
			instruction.type2 = R_INSTR_TYPE_SEXTEND;
			break;
		case str2int ("movzx") :
			instruction.type = R_INSTR_TYPE_MOV;
			instruction.type2 = R_INSTR_TYPE_EXTEND;
			break;

		//Binary Arithmetic Instructions
		case str2int ("adcx") :
			instruction.type = R_INSTR_TYPE_ADD;
			break;
		case str2int ("adox") :
			instruction.type = R_INSTR_TYPE_ADD;
			break;
		case str2int ("imul") :
			instruction.type = R_INSTR_TYPE_MUL;
			break;
		case str2int ("mul") :
			instruction.type = R_INSTR_TYPE_MUL;
			break;
		case str2int ("idiv") :
			instruction.type = R_INSTR_TYPE_DIV;
			break;
		case str2int ("div") :
			instruction.type = R_INSTR_TYPE_DIV;
			break;
		case str2int ("inc") :
			instruction.type = R_INSTR_TYPE_ADD;
			break;
		case str2int ("dec") :
			instruction.type = R_INSTR_TYPE_SUB;
			break;
		case str2int ("neg") :
			instruction.type = R_INSTR_TYPE_NEG;
			break;
		case str2int ("cmp") :
			instruction.type = R_INSTR_TYPE_CMP;
			break;

		//Decimal Arithmetic Instructions

		//Logical Instructions
		case str2int ("and") :
			instruction.type = R_INSTR_TYPE_AND;
			break;
		case str2int ("or") :
			instruction.type = R_INSTR_TYPE_OR;
			break;
		case str2int ("xor") :
			instruction.type = R_INSTR_TYPE_XOR;
			break;
		case str2int ("not") :
			instruction.type = R_INSTR_TYPE_NOT;
			break;

		//Shift and Rotate Instructions
		case str2int ("sar") :
			instruction.type = R_INSTR_TYPE_SHR;
			break;
		case str2int ("shr") :
			instruction.type = R_INSTR_TYPE_SHR;
			break;
		case str2int ("sal") :
			instruction.type = R_INSTR_TYPE_SHL;
			break;
		case str2int ("shl") :
			instruction.type = R_INSTR_TYPE_SHL;
			break;
		case str2int ("shrd") :
			instruction.type = R_INSTR_TYPE_SHR;
			break;
		case str2int ("shld") :
			instruction.type = R_INSTR_TYPE_SHL;
			break;
		case str2int ("ror") :
			instruction.type = R_INSTR_TYPE_ROR;
			break;
		case str2int ("rol") :
			instruction.type = R_INSTR_TYPE_ROL;
			break;
		case str2int ("rcr") :
			instruction.type = R_INSTR_TYPE_ROR;
			break;
		case str2int ("rcl") :
			instruction.type = R_INSTR_TYPE_ROL;
			break;

		//Bit and Byte Instructions
		case str2int ("bt") :
			instruction.type = R_INSTR_TYPE_BITTEST;
			break;
		case str2int ("bts") :
			instruction.type = R_INSTR_TYPE_BITTEST;
			instruction.type2 = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("btr") :
			instruction.type = R_INSTR_TYPE_BITTEST;
			instruction.type2 = R_INSTR_TYPE_BITRESET;
			break;
		case str2int ("btc") :
			instruction.type = R_INSTR_TYPE_BITTEST;
			instruction.type2 = R_INSTR_TYPE_CPL;
			break;
		case str2int ("bsf") :
			break;
		case str2int ("bsr") :
			break;
		case str2int ("sete") :
		case str2int ("setz") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setne") :
		case str2int ("setnz") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("seta") :
		case str2int ("setnbe") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setae") :
		case str2int ("setnb") :
		case str2int ("setnc") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setb") :
		case str2int ("setnae") :
		case str2int ("setc") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setbe") :
		case str2int ("setna") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setg") :
		case str2int ("setnle") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setge") :
		case str2int ("setnl") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setl") :
		case str2int ("setnge") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setle") :
		case str2int ("setng") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("sets") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setns") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("seto") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setno") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setpe") :
		case str2int ("setp") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("setpo") :
		case str2int ("setnp") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("test") :
			instruction.type = R_INSTR_TYPE_AND;
			break;
		case str2int ("crc32") :
			break;
		case str2int ("popcnt") :
			break;

		//Control Transfer Instructions
		case str2int ("jmp") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_TRUE;
			setJumpDest (&instruction);
			break;
		case str2int ("je") :
		case str2int ("jz") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_E;
			setJumpDest (&instruction);
			break;
		case str2int ("jne") :
		case str2int ("jnz") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_NE;
			setJumpDest (&instruction);
			break;
		case str2int ("ja") :
		case str2int ("jnbe") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_A;
			setJumpDest (&instruction);
			break;
		case str2int ("jae") :
		case str2int ("jnb") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_AE;
			setJumpDest (&instruction);
			break;
		case str2int ("jb") :
		case str2int ("jnae") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_B;
			setJumpDest (&instruction);
			break;
		case str2int ("jbe") :
		case str2int ("jna") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_BE;
			setJumpDest (&instruction);
			break;
		case str2int ("jg") :
		case str2int ("jnle") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_G;
			setJumpDest (&instruction);
			break;
		case str2int ("jge") :
		case str2int ("jnl") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_GE;
			setJumpDest (&instruction);
			break;
		case str2int ("jl") :
		case str2int ("jnge") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_L;
			setJumpDest (&instruction);
			break;
		case str2int ("jle") :
		case str2int ("jng") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_LE;
			setJumpDest (&instruction);
			break;
		case str2int ("jc") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_C;
			setJumpDest (&instruction);
			break;
		case str2int ("jnc") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_NC;
			setJumpDest (&instruction);
			break;
		case str2int ("jo") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_O;
			setJumpDest (&instruction);
			break;
		case str2int ("jno") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_NO;
			setJumpDest (&instruction);
			break;
		case str2int ("js") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_POS;
			setJumpDest (&instruction);
			break;
		case str2int ("jns") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_NEG;
			setJumpDest (&instruction);
			break;
		case str2int ("jpo") :
		case str2int ("jnp") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_NP;
			break;
		case str2int ("jpe") :
		case str2int ("jp") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_P;
			break;
		case str2int ("jcxz") :
		case str2int ("jecxz") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.type2 = R_INSTR_TYPE_CMP;
			instruction.condition = R_INSTR_COND_E;
			break;
		case str2int ("loop") :
			instruction.type = R_INSTR_TYPE_JMP;
			break;
		case str2int ("loopz") :
		case str2int ("loope") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_E;
			break;
		case str2int ("loopnz") :
		case str2int ("loopne") :
			instruction.type = R_INSTR_TYPE_JMP;
			instruction.condition = R_INSTR_COND_NE;
			break;
		case str2int ("call") :
			instruction.type = R_INSTR_TYPE_CALL;
			instruction.condition = R_INSTR_COND_TRUE;
			setJumpDest (&instruction);
			break;
		case str2int ("ret") :
			instruction.type = R_INSTR_TYPE_RET;
			instruction.condition = R_INSTR_COND_TRUE;
			setJumpDest (&instruction);
			break;
		case str2int ("reti") :
			instruction.type = R_INSTR_TYPE_RET;
			instruction.condition = R_INSTR_COND_TRUE;
			setJumpDest (&instruction);
			break;
		case str2int ("int") :
			instruction.type = R_INSTR_TYPE_SYSCALL;
			break;
		case str2int ("into") :
			break;
		case str2int ("bound") :
			break;
		case str2int ("enter") :
			break;
		case str2int ("leave") :
			break;

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

		//Flag Control (EFLAG) Instructions
		case str2int ("stc") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("clc") :
			instruction.type = R_INSTR_TYPE_BITRESET;
			break;
		case str2int ("cmc") :
			instruction.type = R_INSTR_TYPE_CPL;
			break;
		case str2int ("cld") :
			instruction.type = R_INSTR_TYPE_BITRESET;
			break;
		case str2int ("std") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("lahf") :
			instruction.type = R_INSTR_TYPE_MOV;
			break;
		case str2int ("sahf") :
			instruction.type = R_INSTR_TYPE_MOV;
			break;
		case str2int ("pushf") :
		case str2int ("pushfd") :
			instruction.type = R_INSTR_TYPE_PUSH;
			break;
		case str2int ("popf") :
		case str2int ("popfd") :
			instruction.type = R_INSTR_TYPE_POP;
			break;
		case str2int ("sti") :
			instruction.type = R_INSTR_TYPE_BITSET;
			break;
		case str2int ("cli") :
			instruction.type = R_INSTR_TYPE_BITRESET;
			break;

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
		case str2int ("lea") :
			instruction.type = R_INSTR_TYPE_LEA;
			break;
		case str2int ("nop") :
			instruction.type = R_INSTR_TYPE_NOP;
			break;
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
	},
};

void setJumpDest (RInstruction * instruction);
void setOperands (RInstruction * instruction, cs_x86 * x86info);


RRegister * getRegister (x86_reg reg) {
	if (reg >= X86_REG_ENDING)
		return 0;
	return gr_x86_reg[reg];
}

holox86::Rx86FunctionAnalyzer::Rx86FunctionAnalyzer() {
}

holox86::Rx86FunctionAnalyzer::~Rx86FunctionAnalyzer() {
}


bool holox86::Rx86FunctionAnalyzer::canAnalyze (RBinary* binary) {
	return holodec::caseCmpRString ("x86", binary->arch);
}
bool holox86::Rx86FunctionAnalyzer::init (RBinary* binary) {
	this->binary = binary;
	if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false;
	if (cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		return false;
	return true;
}

bool holox86::Rx86FunctionAnalyzer::terminate() {
	this->binary = 0;
	cs_close (&handle);
}
constexpr unsigned int str2int (const char* str, int h = 0) {
	return !str[h] ? 5381 : (str2int (str, h + 1) * 33) ^ str[h];
}

void analyzeInstruction (RInstruction* instr, size_t addr, cs_insn *insn);

void holox86::Rx86FunctionAnalyzer::analyzeInsts (size_t addr, size_t max_count) {
	cs_insn *insn;
	size_t count;

	size_t size = binary->getVDataSize (addr);
	size = size > 100 ? 100 : size;

	RInstruction instruction;
	do {
		count = cs_disasm (handle, binary->getVDataPtr (addr), size, addr, 1, &insn);
		if (count > 0) {

			printf ("0x%x:\t%s\t\t%s\n", insn->address, insn->mnemonic,
			        insn->op_str);
			memset (&instruction, 0, sizeof (RInstruction));

			analyzeInstruction (&instruction, addr, insn);
			addr += insn->size;

			cs_free (insn, count);
		} else
			printf ("ERROR: Failed to disassemble given code!\n");
	} while (this->postInstruction (&instruction));
}



void analyzeInstruction (RInstruction* instr, size_t addr, cs_insn *insn) {
	RInstruction& instruction = *instr;
	instruction.addr = addr;

	setOperands (instr, &insn->detail->x86);

	instruction.size = insn->size;

	instruction.instrdef = & (*x86architecture.instrdefs.find (str2int (insn->mnemonic))).second;

	setJumpDest (&instruction);

}

void setOperands (RInstruction* instruction, cs_x86* x86info) {

	cs_x86& x86 = *x86info;
	for (uint8_t i = 0; i < x86.op_count; i++) {
		switch (x86.operands[i].type) {
		case X86_OP_INVALID:
			printf ("Invalid\n");
			break;
		case X86_OP_REG:
			instruction->operands[i].type = {R_LOCAL_TYPE_REGISTER, x86.operands[i].size, 0};
			instruction->operands[i].reg = x86architecture.getRegister (x86.operands[i].reg);
			if (instruction->operands[i].reg)
				printf ("Reg: %s", instruction->operands[i].reg->name);
			break;
		case X86_OP_IMM:
			instruction->operands[i].type = {R_LOCAL_TYPE_IMM_UNSIGNED, x86.operands[i].size, 0};
			instruction->operands[i].ival = x86.operands[i].imm;
			printf ("Imm: %d", instruction->operands[i].ival);
			break;
		case X86_OP_MEM:
			instruction->operands[i].type = {R_LOCAL_TYPE_MEM, x86.operands[i].size, 0};
			instruction->operands[i].mem.base = x86architecture.getRegister (x86.operands[i].mem.base);
			instruction->operands[i].mem.disp = x86.operands[i].mem.disp;
			instruction->operands[i].mem.index = x86architecture.getRegister (x86.operands[i].mem.index);
			instruction->operands[i].mem.scale = x86.operands[i].mem.scale;


			printf ("[%s + %s*%d + %d]", instruction->operands[i].mem.base ? instruction->operands[i].mem.base->name : "-",
			        instruction->operands[i].mem.index ? instruction->operands[i].mem.index->name : "-",
			        instruction->operands[i].mem.scale, instruction->operands[i].mem.disp);
			break;
		case X86_OP_FP:
			instruction->operands[i].type = {R_LOCAL_TYPE_IMM_FLOAT, x86.operands[i].size, 0};
			instruction->operands[i].fval = x86.operands[i].fp;
			printf ("F: %f", instruction->operands[i].fval);
			break;
		default:
			printf ("--------");
		}
		printf (" -- ");
	}
	printf ("\n");
}

void setJumpDest (RInstruction* instruction) {

	if (instruction->instrdef && (instruction->instrdef->type == R_INSTR_TYPE_JMP || instruction->instrdef->type2 == R_INSTR_TYPE_JMP)) {
		if (instruction->operands[0].type.type == R_LOCAL_TYPE_IMM_UNSIGNED)
			instruction->jumpdest = instruction->operands[0].ival;
		else if (instruction->operands[0].type.type == R_LOCAL_TYPE_IMM_SIGNED)
			instruction->jumpdest = instruction->addr + (int64_t) instruction->operands[0].ival;
	}
	instruction->nojumpdest = instruction->addr + instruction->size;
}
