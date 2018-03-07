
#include "AvrFunctionAnalyzer.h"
#include "../InstrDefinition.h"

using namespace holodec;

namespace holoavr {

	Architecture avrarchitecture{
		"avr", "", 8, 3, 8,
	{
		[](Binary * binary) {
		static FunctionAnalyzer* analyzer = nullptr;
		if (analyzer == nullptr) {
			printf("Create New Object\n");
			analyzer = new AVRFunctionAnalyzer(&avrarchitecture);
		}
		if (analyzer->canAnalyze(binary)) {
			FunctionAnalyzer* temp = analyzer;
			analyzer = nullptr;
			return temp;
		}
		return (FunctionAnalyzer*) nullptr;
	}
	},
		{
			{ 0, "r0", RegType::eGPR, nullptr, "r0", 8, 0, false },//0x00
			{ 0, "r1", RegType::eGPR, nullptr, "r1", 8, 0, false },
			{ 0, "r2", RegType::eGPR, nullptr, "r2", 8, 0, false },
			{ 0, "r3", RegType::eGPR, nullptr, "r3", 8, 0, false },
			{ 0, "r4", RegType::eGPR, nullptr, "r4", 8, 0, false },
			{ 0, "r5", RegType::eGPR, nullptr, "r5", 8, 0, false },
			{ 0, "r6", RegType::eGPR, nullptr, "r6", 8, 0, false },
			{ 0, "r7", RegType::eGPR, nullptr, "r7", 8, 0, false },
			{ 0, "r8", RegType::eGPR, nullptr, "r8", 8, 0, false },
			{ 0, "r9", RegType::eGPR, nullptr, "r9", 8, 0, false },
			{ 0, "r10", RegType::eGPR, nullptr, "r10", 8, 0, false },
			{ 0, "r11", RegType::eGPR, nullptr, "r11", 8, 0, false },
			{ 0, "r12", RegType::eGPR, nullptr, "r12", 8, 0, false },
			{ 0, "r13", RegType::eGPR, nullptr, "r13", 8, 0, false },
			{ 0, "r14", RegType::eGPR, nullptr, "r14", 8, 0, false },
			{ 0, "r15", RegType::eGPR, nullptr, "r15", 8, 0, false },
			{ 0, "r16", RegType::eGPR, nullptr, "r16", 8, 0, false },
			{ 0, "r17", RegType::eGPR, nullptr, "r17", 8, 0, false },
			{ 0, "r18", RegType::eGPR, nullptr, "r18", 8, 0, false },
			{ 0, "r19", RegType::eGPR, nullptr, "r19", 8, 0, false },
			{ 0, "r20", RegType::eGPR, nullptr, "r20", 8, 0, false },
			{ 0, "r21", RegType::eGPR, nullptr, "r21", 8, 0, false },
			{ 0, "r22", RegType::eGPR, nullptr, "r22", 8, 0, false },
			{ 0, "r23", RegType::eGPR, nullptr, "r23", 8, 0, false },
			{ 0, "r24", RegType::eGPR, nullptr, "r24", 8, 0, false },
			{ 0, "r25", RegType::eGPR, nullptr, "r25", 8, 0, false },

			{ 0, "x", RegType::eGPR, nullptr, "x", 16, 0, false },
			{ 0, "r26", RegType::eGPR, "x", "x", 8, 0, false },
			{ 0, "r27", RegType::eGPR, "x", "x", 8, 8, false },

			{ 0, "y", RegType::eGPR, nullptr, "y", 16, 0, false },
			{ 0, "r28", RegType::eGPR, "y", "y", 8, 0, false },
			{ 0, "r29", RegType::eGPR, "y", "y", 8, 8, false },

			{ 0, "z", RegType::eGPR, nullptr, "z", 16, 0, false },
			{ 0, "r30", RegType::eGPR, "z", "z", 8, 0, false },
			{ 0, "r31", RegType::eGPR, "z", "z", 8, 8, false },//0x1f

			{ 0, "ccp", RegType::eSegment, nullptr, "ccp", 8, 0, false },//0x34
			{ 0, "rampd", RegType::eSegment, nullptr, "rampd", 8, 0, false },//0x38
			{ 0, "rampx", RegType::eSegment, nullptr, "rampx", 8, 0, false },//0x39
			{ 0, "rampy", RegType::eSegment, nullptr, "rampy", 8, 0, false },//0x3A
			{ 0, "rampz", RegType::eSegment, nullptr, "rampz", 8, 0, false },//0x3B
			{ 0, "eind", RegType::eSegment, nullptr, "eind", 8, 0, false },//0x3C
			{ 0, "sp", RegType::eStackPtr, nullptr, "sp", 16, 0, false },//0x3e-0x3d
			{ 0, "sph", RegType::eStackPtr, "sp", "sp", 8, 0, false },//0x3e
			{ 0, "spl", RegType::eStackPtr, "sp", "sp", 8, 8, false },//0x3d

			//{ 0, nullptr, RegType::eFlag, nullptr, nullptr, 8, 0, false },//0x3f
			{ 0, "cf", RegType::eFlag, nullptr, "cf", 1, 0, false },
			{ 0, "zf", RegType::eFlag, nullptr, "zf", 1, 0, false },
			{ 0, "nf", RegType::eFlag, nullptr, "nf", 1, 0, false },
			{ 0, "vf", RegType::eFlag, nullptr, "vf", 1, 0, false },
			{ 0, "sf", RegType::eFlag, nullptr, "sf", 1, 0, false },
			{ 0, "hf", RegType::eFlag, nullptr, "hf", 1, 0, false },
			{ 0, "tf", RegType::eFlag, nullptr, "tf", 1, 0, false },
			{ 0, "if", RegType::eFlag, nullptr, "if", 1, 0, false }
		},
		{
			{
				0,
				"stack",//name
				StackType::eMemory,//what backs the memory
				StackPolicy::eBottom,//where to add new elements
				0, 8, //maxcount(0 = infinite), wordbitsize
				"dmem",
				"sp",//stackptr
				{}
			},
		},
		{
			{ 0, "pmem", 2 },
			{ 0, "dmem", 1 }
		},
		{
			{ 0, "in" },
			{ 0, "out" },
			{ 0, "watchdogreset" },
		},
		{
			{}
		},
	{},
	{
		{ AVR_INSTR_ADC, "adc",{ 
			{ 2, "#and(==(#bsize(#arg[1]),#bsize(#arg[2])))", "#seq(=(#arg[1],+(#arg[1],#arg[2],$cf)),=($vf,#o),=($cf,#c),=($hf,#c(4)),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eAdd },
		{ AVR_INSTR_ADD, "add",{
			{ 2, "==(#bsize(#arg[1]),#bsize(#arg[2]))", "#seq(=(#arg[1],+(#arg[1],#arg[2])),=($vf,#o),=($cf,#c),=($hf,#c(4)),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($sf,<>($nf,$vf)))" },
			{ 3, "#and(==(#bsize(#arg[1]),#bsize(#arg[2])),==(+(#bsize(#arg[1]),#bsize(#arg[2])),#bsize(#arg[3])))", "#seq(=(#t[1],+(#app(#arg[1],#arg[2]),#arg[3])),=(#arg[1],#t[1][0,8]),=(#arg[2],#t[1][8,8]),=($vf,#o),=($cf,#c),=($hf,#c(4)),=($zf,==(#t[1],0)),=($nf,<[s](#t[1],0)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eAdd },
		{ AVR_INSTR_AND, "and",{
			{ 2, "#and(==(#bsize(#arg[1]),#bsize(#arg[2])))", "#seq(=(#arg[1],#and(#arg[1],#arg[2])),=($vf,0),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eAnd },
		{ AVR_INSTR_ASR, "asr",{
			{ 1, "#seq(=($cf,#arg[1][0]),#div[s](#arg[1],2),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($vf,<>($nf,$cf)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eShr },
		{ AVR_INSTR_BCLR, "bclr",{
			{ 1, "==(0,#arg[1])", "=($cf,0)" },
			{ 1, "==(1,#arg[1])", "=($zf,0)" },
			{ 1, "==(2,#arg[1])", "=($nf,0)" },
			{ 1, "==(3,#arg[1])", "=($vf,0)" },
			{ 1, "==(4,#arg[1])", "=($sf,0)" },
			{ 1, "==(5,#arg[1])", "=($hf,0)" },
			{ 1, "==(6,#arg[1])", "=($tf,0)" },
			{ 1, "==(7,#arg[1])", "=($if,0)" },
		}, InstructionType::eBitSet },
		{ AVR_INSTR_BLD, "bld",{
			{ 2, "=(#arg[1],#bor(#band(#arg[1],#bnot(#shl(1[8],#arg[2]))),#shl($tf[8],#arg[2])))" }
		}, InstructionType::eShr },
		{ AVR_INSTR_BST, "bst",{
			{ 2, "=($tf,<>(#band(#arg[1],#shl(1[8],#arg[2])),0[8]))" }
		}, InstructionType::eShr },
		{ AVR_INSTR_BRBC, "brbc",{
			{ 2, "==(0,#arg[1])", "#cjmp(#arg[2],#not($cf))" },
			{ 2, "==(1,#arg[1])", "#cjmp(#arg[2],#not($zf))" },
			{ 2, "==(2,#arg[1])", "#cjmp(#arg[2],#not($nf))" },
			{ 2, "==(3,#arg[1])", "#cjmp(#arg[2],#not($vf))" },
			{ 2, "==(4,#arg[1])", "#cjmp(#arg[2],#not($sf))" },
			{ 2, "==(5,#arg[1])", "#cjmp(#arg[2],#not($hf))" },
			{ 2, "==(6,#arg[1])", "#cjmp(#arg[2],#not($tf))" },
			{ 2, "==(7,#arg[1])", "#cjmp(#arg[2],#not($if))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRBS, "brbs",{
			{ 2, "==(0,#arg[1])", "#cjmp(#arg[2],$cf)" },
			{ 2, "==(1,#arg[1])", "#cjmp(#arg[2],$zf)" },
			{ 2, "==(2,#arg[1])", "#cjmp(#arg[2],$nf)" },
			{ 2, "==(3,#arg[1])", "#cjmp(#arg[2],$vf)" },
			{ 2, "==(4,#arg[1])", "#cjmp(#arg[2],$sf)" },
			{ 2, "==(5,#arg[1])", "#cjmp(#arg[2],$hf)" },
			{ 2, "==(6,#arg[1])", "#cjmp(#arg[2],$tf)" },
			{ 2, "==(7,#arg[1])", "#cjmp(#arg[2],$if)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRCC, "brcc",{
			{ 1, "#cjmp(#arg[1],#not($cf))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRCS, "brcs",{
			{ 1, "#cjmp(#arg[1],$cf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BREAK, "break",{
			{ 1, "#trap" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BREQ, "breq",{
			{ 1, "#cjmp(#arg[1],$zf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRGE, "brge",{
			{ 1, "#cjmp(#arg[1],#not($sf))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRHC, "brhc",{
			{ 1, "#cjmp(#arg[1],#not($hf))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRHS, "brhs",{
			{ 1, "#cjmp(#arg[1],$hf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRID, "brid",{
			{ 1, "#cjmp(#arg[1],#not($hf))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRIE, "brie",{
			{ 1, "#cjmp(#arg[1],$hf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRLO, "brlo",{
			{ 1, "#cjmp(#arg[1],$cf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRLT, "brlt",{
			{ 1, "#cjmp(#arg[1],$sf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRMI, "brmi",{
			{ 1, "#cjmp(#arg[1],$nf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRNE, "brne",{
			{ 1, "#cjmp(#arg[1],#not($zf))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRPL, "brpl",{
			{ 1, "#cjmp(#arg[1],$nf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRSH, "brsh",{
			{ 1, "#cjmp(#arg[1],#not($cf))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRTC, "brtc",{
			{ 1, "#cjmp(#arg[1],#not($tf))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRTS, "brts",{
			{ 1, "#cjmp(#arg[1],$tf)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRVC, "bvc",{
			{ 1, "#cjmp(#arg[1],#not($vf))" },
		}, InstructionType::eShr },
		{ AVR_INSTR_BRVS, "brvs",{
			{ 1, "#cjmp(#arg[1],$vf)" },
		}, InstructionType::eShr },

		{ AVR_INSTR_BSET, "bset",{
			{ 1, "==(0,#arg[1])", "=($cf,1)" },
			{ 1, "==(1,#arg[1])", "=($zf,1)" },
			{ 1, "==(2,#arg[1])", "=($nf,1)" },
			{ 1, "==(3,#arg[1])", "=($vf,1)" },
			{ 1, "==(4,#arg[1])", "=($sf,1)" },
			{ 1, "==(5,#arg[1])", "=($hf,1)" },
			{ 1, "==(6,#arg[1])", "=($tf,1)" },
			{ 1, "==(7,#arg[1])", "=($if,1)" },
		}, InstructionType::eShr },
		{ AVR_INSTR_CALL, "call",{
			{ 1, "#seq(#push($stack,#ip),#call(#arg[1]))" }
		}, InstructionType::eShr },
		{ AVR_INSTR_CBI, "cbi",{
			{ 2, "#seq(#rec[in](#t[1],#arg[1]),#rec[out](#arg[1],#and(#t[1],#bnot(#shl(1,#arg[2])))))" }
		}, InstructionType::eShr },
		{ AVR_INSTR_CBR, "cbr",{
			{ 2, "#seq(=(#arg[1],#and(#arg[1],#bnot(#shl(1,#arg[2])))),=($vf,0),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eShr },
		{ AVR_INSTR_CLC, "clc",{
			{ 0, "=($cf,0)" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CLH, "clh",{
			{ 0, "=($hf,0)" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CLI, "cli",{
			{ 0, "=($if,0)" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CLN, "cln",{
			{ 0, "=($nf,0)" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CLR, "clr",{
			{ 1, "#seq(=(#arg[1],0),=($sf,0),=($vf,0),=($nf,0),=($zf,1))" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CLS, "cls",{
			{ 0, "=($sf,0)" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CLT, "clt",{
			{ 0, "=($tf,0)" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CLV, "clv",{
			{ 0, "=($vf,0)" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CLZ, "clz",{
			{ 0, "=($zf,0)" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_COM, "com",{
			{ 1, "#seq(=(#t[1],255[8]),#rec[sub](#t[1],#arg[1]),=(#arg[1],#t[1]))" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CP, "cp",{
			{ 2, "#seq(=(#t[1],#arg[1]),#rec[sub](#t[1],#arg[2]))" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CPC, "cpc",{
			{ 2, "#seq(=(#t[1],#arg[1]),#rec[sbc](#t[1],#arg[2]))" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_CPSE, "cpse",{
			{ 2, "#rec[cp](#arg[1],#arg[2])" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_DEC, "dec",{
			{ 1, "#seq(=(#t[1],$cf),#rec[sub](#arg[1],1),=($cf,#t[1]))" }
		}, InstructionType::eBitReset },
		{ AVR_INSTR_EICALL, "eicall",{
			{ 0, "#seq(#push($stack,#ip),#call(#app($z,$eind)))" }
		}, InstructionType::eCall },
		{ AVR_INSTR_EIJMP, "eijmp",{
			{ 0, "#jmp(#app($z,$eind))" }
		}, InstructionType::eCall },
		{ AVR_INSTR_ELPM, "elpm",{
			{ 1, "=(#arg[1],#ld($pmem,#app($z,$rampz),#size(#arg[1])))" }
		}, InstructionType::eCall },
		{ AVR_INSTR_ELPM | AVR_INSTR_INC_PTR, "elpm+",{
			{ 1, "#seq(=(#arg[1],#ld($pmem,#app($z,$rampz),#size(#arg[1]))),=(#t[1],+(#app($z,$rampz),1)),=($z,#t[1][0,16]),=($rampz,#t[1][16,8]))" }
		}, InstructionType::eCall },
		{ AVR_INSTR_EOR, "eor",{
			{ 2, "#seq(=(#arg[1],#bxor(#arg[1],#arg[2])),=($vf,0),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eXor },
		{ AVR_INSTR_FMUL, "fmul",{
			{ 2, "#seq(=(#t[1],#shl(#mul(#arg[1],#arg[2]),1)),=($r0,#t[1][0,8]),=($r1,#t[1][8,8]),=($zf,==(#t[1],0)),=($cf,#c))" }
		}, InstructionType::eMul },
		{ AVR_INSTR_FMULS, "fmuls",{
			{ 2, "#seq(=(#t[1],#shl(#mul[s](#arg[1],#arg[2]),1)),=($r0,#t[1][0,8]),=($r1,#t[1][8,8]),=($zf,==(#t[1],0)),=($cf,#c))" }
		}, InstructionType::eMul },
		{ AVR_INSTR_FMULSU, "fmulsu",{//TODO check if that is correct as I think something needs to be done here, but for now it should work
			{ 2, "#seq(=(#t[1],#shl(#mul[s](#arg[1],#arg[2]),1)),=($r0,#t[1][0,8]),=($r1,#t[1][8,8]),=($zf,==(#t[1],0)),=($cf,#c))" }
		}, InstructionType::eMul },
		{ AVR_INSTR_ICALL, "icall",{
			{ 2, "#seq(#push($stack,#ip),#call($z))" }
		}, InstructionType::eCall },
		{ AVR_INSTR_IJMP, "ijmp",{
			{ 2, "#call($z)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_IN, "in",{
			{ 2, "==(#arg[2],52)", "=(#arg[1],$ccp)" },
			{ 2, "==(#arg[2],56)", "=(#arg[1],$rampd)" },
			{ 2, "==(#arg[2],57)", "=(#arg[1],$rampx)" },
			{ 2, "==(#arg[2],58)", "=(#arg[1],$rampy)" },
			{ 2, "==(#arg[2],59)", "=(#arg[1],$rampz)" },
			{ 2, "==(#arg[2],60)", "=(#arg[1],$eind)" },
			{ 2, "==(#arg[2],61)", "=(#arg[1],$spl)" },
			{ 2, "==(#arg[2],62)", "=(#arg[1],$sph)" },
			{ 2, "==(#arg[2],63)", "=(#arg[1],#app($cf,$zf,$nf,$vf,$sf,$hf,$tf,$if))" },
			{ 2, "=(#arg[1],$in(#arg[2]))" }
		}, InstructionType::eCall },
		{ AVR_INSTR_INC, "inc",{
			{ 2, "#seq(=(#t[1],$cf),#rec[add](#arg[1],1),=($cf,#t[1]))" }
		}, InstructionType::eAdd },
		{ AVR_INSTR_JMP, "jmp",{
			{ 1, "#jmp(#arg[1])" }
		}, InstructionType::eJmp },
		{ AVR_INSTR_LD, "ld",{
			{ 2, "=(#arg[1],#ld($dmem,#arg[2],#size(#arg[1])))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LDD, "ldd",{
			{ 3, "=(#arg[1],#ld($dmem,+(#arg[2],#arg[3]),#size(#arg[1])))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LD | AVR_INSTR_INC_PTR, "ld+",{
			{ 2, "#seq(=(#arg[1],#ld($dmem,#arg[2],#size(#arg[1]))),=(#arg[2],+(#arg[2],1)))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LD | AVR_INSTR_DEC_PTR, "ld-",{
			{ 2, "#seq(=(#arg[2],-(#arg[2],1)),=(#arg[1],#ld($dmem,#arg[2],#size(#arg[1]))))" }
		}, InstructionType::eLoad },

		//TODO maybe use rampz for these??
		{ AVR_INSTR_LAT, "lat",{
			{ 1, "#seq(=(#t[1],#ld($dmem,$z,1)),#st($dmem,$z,<>(#arg[1],#t[1])),=(#arg[1],#t[1]))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LAS, "las",{
			{ 1, "#seq(=(#t[1],#ld($dmem,$z,1)),#st($dmem,$z,#or(#arg[1],#t[1])),=(#arg[1],#t[1]))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LAC, "lac",{
			{ 1, "#seq(=(#t[1],#ld($dmem,$z,1)),#st($dmem,$z,#and(-(255,#arg[1]),#t[1])),=(#arg[1],#t[1]))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LDI, "ldi",{
			{ 2, "=(#arg[1],#arg[2])" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LDS, "lds",{
			{ 2, "=(#arg[1],#ld($dmem,#arg[2],1))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LPM, "lpm",{
			{ 1, "=(#arg[1],#ld($pmem,$z,1))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_LPM | AVR_INSTR_INC_PTR, "lpm+",{
			{ 1, "#seq(=(#arg[1],#ld($pmem,$z,#size(#arg[1]))),=($z,+($z,1)))" }
		}, InstructionType::eLoad },

		{ AVR_INSTR_LSL, "lsl",{
			{ 1, "#seq(=($hf,#arg[1][3]),=(#arg[1],#shl(#arg[1],1)),=($cf,#c),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($vf,<>($nf,$cf)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eShl },
		{ AVR_INSTR_LSR, "lsr",{
			{ 1, "#seq(=(#arg[1],#shl(#arg[1],1)),=($cf,#c),=($hf,0),=($zf,==(#arg[1],0)),=($nf,0),=($vf,$cf),=($sf,$vf))" }
		}, InstructionType::eShr },
		{ AVR_INSTR_MOV, "mov",{
			{ 2, "=(#arg[1],#arg[2])" }
		}, InstructionType::eMov },
		{ AVR_INSTR_MOVW, "movw",{
			{ 2, "=(#arg[1],#arg[2])" },
			{ 3, "==(#bsize(#arg[1]),16)", "=(#arg[1],#app(#arg[2],#arg[3]))" },
			{ 3, "==(#bsize(#arg[3]),16)", "#seq(=(#arg[1],#arg[3][0,8]),=(#arg[2],#arg[3][8,8]))" },
			{ 4, "#seq(=(#arg[1],#arg[3]),=(#arg[2],#arg[4]))" }
		}, InstructionType::eMov },

		{ AVR_INSTR_MUL, "mul",{
			{ 2, "#seq(=(#t[1],#mul(#arg[1],#arg[2])),=($r0,#t[1][0,8]),=($r1,#t[1][8,8]),=($zf,==(#t[1],0)),=($cf,<[s](#t[1],0)))" }
		}, InstructionType::eMul },
		{ AVR_INSTR_MULS, "muls",{
			{ 2, "#seq(=(#t[1],#mul[s](#arg[1],#arg[2])),=($r0,#t[1][0,8]),=($r1,#t[1][8,8]),=($zf,==(#t[1],0)),=($cf,<[s](#t[1],0)))" }
		}, InstructionType::eMul },
		{ AVR_INSTR_MULSU, "mulsu",{//TODO check if that is correct as I think something needs to be done here, but for now it should work
			{ 2, "#seq(=(#t[1],#mul[s](#arg[1],#arg[2])),=($r0,#t[1][0,8]),=($r1,#t[1][8,8]),=($zf,==(#t[1],0)),=($cf,<[s](#t[1],0)))" }
		}, InstructionType::eMul },

		{ AVR_INSTR_NEG, "neg",{
			{ 1, "#seq(=(#t[1],0[8]),#rec[sub](#t[1],#arg[1]),=(#arg[1],#t[1]))" }
		}, InstructionType::eMul },

		{ AVR_INSTR_NOP, "nop",{ { "#nop" } }, InstructionType::eNop },

		{ AVR_INSTR_OR, "or",{
			{ 2, "#seq(=(#arg[1],#or(#arg[1],#arg[2])),=($cf,#c),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($vf,0),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eOr },

		{ AVR_INSTR_OUT, "out",{
			{ 2, "==(#arg[1],52)", "=($ccp,#arg[2])" },
			{ 2, "==(#arg[1],56)", "=($rampd,#arg[2])" },
			{ 2, "==(#arg[1],57)", "=($rampx,#arg[2])" },
			{ 2, "==(#arg[1],58)", "=($rampy,#arg[2])" },
			{ 2, "==(#arg[1],59)", "=($rampz,#arg[2])" },
			{ 2, "==(#arg[1],60)", "=($eind,#arg[2])" },
			{ 2, "==(#arg[1],61)", "=($spl,#arg[2])" },
			{ 2, "==(#arg[1],62)", "=($sph,#arg[2])" },
			{ 2, "==(#arg[1],63)", "#seq(=($cf,#arg[2][0]),=($zf,#arg[2][1]),=($nf,#arg[2][2]),=($vf,#arg[2][3]),=($sf,#arg[2][4]),=($hf,#arg[2][5]),=($tf,#arg[2][6]),=($if,#arg[2][7]))" },
			{ 2, "$out(#arg[1],#arg[2])" }
		}, InstructionType::eIO },

		{ AVR_INSTR_POP, "pop",{
			{ 1, "=(#arg[1],#pop($stack,#size(#arg[1])))" }
		}, InstructionType::ePop },
		{ AVR_INSTR_PUSH, "push",{
			{ 1, "#push($stack,#arg[1])" }
		}, InstructionType::ePush },

		{ AVR_INSTR_RCALL, "rcall",{
			{ 1, "#seq(#push($stack,#ip),#call(#arg[1]))" }
		}, InstructionType::eCall },
		{ AVR_INSTR_RET, "ret",{
			{ 0, "#seq(#ret(#pop($stack,#size(#ip))))" }
		}, InstructionType::eRet },
		{ AVR_INSTR_RETI, "reti",{
			{ 0, "#seq(#pop($stack,#ip),=($if,1),#ret(#pop($stack,#size(#ip))))" }
		}, InstructionType::eRet },
		{ AVR_INSTR_RJMP, "rjmp",{
			{ 1, "#jmp(#arg[1])" }
		}, InstructionType::eJmp },

		{ AVR_INSTR_ROL, "rol",{
			{ 1, "#seq(=($hf,#arg[1][3]),=(#t[1],#rol(#app($cf,#arg[1]))),=($cf,#t[1][8]),=(#arg[1],#t[1][0,8]),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($vf,<>($nf,$cf)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eShr },
		{ AVR_INSTR_ROR, "ror",{
			{ 1, "#seq(=(#t[1],#ror(#app($cf,#arg[1]))),=($cf,#t[1][8]),=(#arg[1],#t[1][0,8]),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($vf,<>($nf,$cf)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eShr },

		{ AVR_INSTR_SBC, "sbc",{
			{ 2, "#seq(=(#arg[1],-(#arg[1],#arg[2],$cf)),=($cf,#c),=($hf,#c(4)),=($vf,#o),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eSub },

		{ AVR_INSTR_SBI, "sbi",{
			{ 2, "#seq(#rec[in](#t[1],#arg[1]),$out(#arg[1],#or(#t[1]),#shl(1,#arg[2])))" }
		}, InstructionType::eSub },
		{ AVR_INSTR_SBIC, "sbic",{
			{ 3, "#seq(#rec[in](#t[1],#arg[1]),#cjmp(#arg[3],==(#or(#t[1],#shl(1,#arg[2])),0)))" }
		}, InstructionType::eSub },
		{ AVR_INSTR_SBIS, "sbis",{
			{ 3, "#seq(#rec[in](#t[1],#arg[1]),#cjmp(#arg[3],<>(#or(#t[1],#shl(1,#arg[2])),0)))" }
		}, InstructionType::eSub },

		{ AVR_INSTR_SBR, "sbr",{
			{ 3, "#rec[or](#arg[1],#shl(1,#arg[2]))" }
		}, InstructionType::eOr },
		{ AVR_INSTR_SBRC, "sbrc",{
			{ 3, "#cjmp(#arg[3],==(#or(#arg[1],#shl(1,#arg[2])),0))" }
		}, InstructionType::eJmp },
		{ AVR_INSTR_SBRS, "sbrs",{
			{ 3, "#cjmp(#arg[3],<>(#or(#arg[1],#shl(1,#arg[2])),0))" }
		}, InstructionType::eJmp },

		{ AVR_INSTR_SEC, "sec",{
			{ 0, "=($sf,1)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SEH, "seh",{
			{ 0, "=($hf,1)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SEI, "sei",{
			{ 0, "=($if,1)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SER, "ser",{
			{ 0, "=(#arg[1],255)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SES, "ses",{
			{ 0, "=($sf,1)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SET, "set",{
			{ 0, "=($tf,1)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SEV, "sev",{
			{ 0, "=($vf,1)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SEZ, "sez",{
			{ 0, "=($zf,1)" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SLEEP, "sleep",{
			{ 0, "#trap" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SPM, "spm",{
			{ 1, "#st($pmem,#app($z,$rampz),#arg[1])" }
		}, InstructionType::eCall },
		{ AVR_INSTR_SPM, "spm",{
			{ 1, "#st($pmem,#app($z,$rampz),#arg[1])" }
		}, InstructionType::eCall },

		{ AVR_INSTR_ST, "st",{
			{ 2, "#st($dmem,#arg[1],#arg[2])" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_STD, "std",{
			{ 3, "#st($dmem,+(#arg[1],#arg[2]),#arg[3])" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_ST | AVR_INSTR_INC_PTR, "st+",{
			{ 2, "#seq(#st($dmem,#arg[1],#arg[2]),=(#arg[1],+(#arg[1],1)))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_ST | AVR_INSTR_DEC_PTR, "st-",{
			{ 2, "#seq(=(#arg[2],-(#arg[2],1)),#st($dmem,#arg[1],#arg[2]))" }
		}, InstructionType::eLoad },

		{ AVR_INSTR_SUB, "sub",{
			{ 2, "#seq(=(#arg[1],-(#arg[1],#arg[2])),=($cf,#c),=($hf,#c(4)),=($vf,#o),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($sf,<>($nf,$vf)))" },
			{ 3, "#seq(=(#t[1],-(#app(#arg[1],#arg[2]),#arg[3])),=(#arg[1],#t[1][0,8]),=(#arg[1],#t[1][8,8]),=($cf,#c),=($hf,#c(4)),=($vf,#o),=($zf,==(#arg[1],0)),=($nf,<[s](#arg[1],0)),=($sf,<>($nf,$vf)))" }
		}, InstructionType::eCall },


		{ AVR_INSTR_SWAP, "swap",{
			{ 1, "#seq(=(#t[1],#arg[1]),=(#arg[1],#app(#t[1][4,4],#t[1][0,4])))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_TST, "tst",{
			{ 1, "#seq(=(#t[1],#arg[1]),#rec[and](#t[1],#arg[2]))" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_WDR, "wdr",{
			{ 1, "$watchdogreset" }
		}, InstructionType::eLoad },
		{ AVR_INSTR_XCH, "xch",{
			{ 1, "#seq(=(#t[1],#ld($dmem,$z,1)),#st($dmem,$z,#arg[1]),=(#arg[1],#t[1]))" }
		}, InstructionType::eLoad },

		}

	};
}