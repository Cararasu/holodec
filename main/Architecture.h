#ifndef ARCHITECTURE_H
#define ARCHITECTURE_H

#include <stdint.h>
#include <functional>
#include "FunctionAnalyzer.h"
#include "InstrDefinition.h"
#include "Register.h"
#include "Stack.h"
#include "CallingConvention.h"
#include "IRGen.h"
#include "IR.h"
#include "Memory.h"

namespace holodec {

	struct IRExpression;

	struct Builtin {
		HId id;
		HString name;
	};

	struct Architecture {
		HString name;
		HString desc;
		//How many bits are in one byte
		uint32_t bitbase;
		//how many bytes are in one default unit on the system
		uint32_t bytebase;
		//ho many bytes are the instructionpointer
		uint32_t instrptrsize;

		HList<std::function<FunctionAnalyzer* (Binary*) >> functionanalyzerfactories;
		HIdList<Register> registers;

		HIdList<Stack> stacks;

		HIdList<Memory> memories;

		HIdList<Builtin> builtins;

		HIdList<CallingConvention> callingconventions;

		HUniqueList<HId> instrIds;
		HIdMap<HId, InstrDefinition> instrdefs;

		HSparseIdList<IRExpression> irExpressions;

		Architecture() = default;
		Architecture (Architecture&) = default;
		Architecture (Architecture&&) = default;
		~Architecture() = default;

		void init();

		inline uint32_t bitToByte(uint32_t bit) {
			return (bit + bitbase - 1) / bitbase;
		}

		FunctionAnalyzer* createFunctionAnalyzer (Binary* binary) {
			for (std::function<FunctionAnalyzer* (Binary*) >& fac : functionanalyzerfactories) {
				FunctionAnalyzer* analyzer = fac (binary);
				if (analyzer)
					return analyzer;

			}
			return nullptr;
		}

		Register* getRegister (const StringRef stringRef) {
			if (stringRef.refId) {
				for (Register& reg : registers) {
					if (stringRef.refId == reg.id)
						return &reg;
				}
			}else if (stringRef.name){
				for (Register& reg : registers) {
					if (stringRef.name == reg.name)
						return &reg;
				}
			}
			return &invalidReg;
		}
		Stack* getStack (const StringRef stringRef) {
			if (stringRef.refId) {
				for (Stack& stack : stacks) {
					if (stringRef.refId == stack.id)
						return &stack;
				}
			}else if (stringRef.name){
				for (Stack& stack : stacks) {
					if (stringRef.name == stack.name)
						return &stack;
				}
			}
			return &invalidStack;
		}
		Memory* getMemory(const StringRef stringRef) {
			if (stringRef.refId) {
				for (Memory& memory : memories) {
					if (stringRef.refId == memory.id)
						return &memory;
				}
			}
			else if (stringRef.name) {
				for (Memory& memory : memories) {
					if (stringRef.name == memory.name)
						return &memory;
				}
			}
			return &invalidMem;
		}
		Memory* getDefaultMemory() {
			return memories.get(1);
		}
		Builtin* getBuiltin(const StringRef stringRef) {
			if (stringRef.refId) {
				for (Builtin& builtin : builtins) {
					if (stringRef.refId == builtin.id)
						return &builtin;
				}
			}
			else if (stringRef.name) {
				for (Builtin& builtin : builtins) {
					if (stringRef.name == builtin.name)
						return &builtin;
				}
			}
			return nullptr;
		}

		CallingConvention* getCallingConvention(const HString string){
			if(string){
				for(CallingConvention& cc : callingconventions){
					if(string == cc.name)
						return &cc;
				}
			}
			return nullptr;
		}
		CallingConvention* getCallingConvention(const HId id){
			if(id){
				for(CallingConvention& cc : callingconventions){
					if(id == cc.id)
						return &cc;
				}
			}
			return nullptr;
		}
		InstrDefinition* getInstrDef (HId id, HString mnemonic) {
			auto it = instrdefs.find (id);
			if (it != instrdefs.end())
				return & (*it).second;
			printf ("%s not found\n", mnemonic.cstr());
			return nullptr;
		}
		InstrDefinition* getInstrDef (HId id) {
			auto it = instrdefs.find (id);
			if (it != instrdefs.end())
				return & (*it).second;
			printf ("%d Instruction not found\n", id);
			return nullptr;
		}
		InstrDefinition* getInstrDef (HString mnemonic) {
			for (auto& entry : instrdefs) {
				if (entry.second.mnemonics == mnemonic)
					return &entry.second;
			}
			return nullptr;
		}
		IRExpression* getIrExpr (HId id) {
			return irExpressions.get (id);
		}
		HId addIrExpr (IRExpression expr) {
			for (IRExpression& expression : irExpressions) {   //Do CSE
				if (expression == expr){
					return expression.id;
				}
			}
			irExpressions.push_back (expr);
			return expr.id;
		}

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Architecture %s\n", name.cstr());
			printIndent (indent);
			printf ("Registers\n");
			for (Register & rr : registers) {
				rr.print (indent + 1);
			}
			printIndent (indent);
			printf("Memories\n");
			for (Memory& memory : memories) {
				printIndent(indent + 1);
				printf("%s\n", memory.name.cstr());
			}
			/*
			printIndent (indent);
			printf ("IR-Expressions\n");
			for (IRExpression& expr : irExpressions.list) {
				expr.print (this, indent + 1);
			}
			printIndent (indent);
			printf ("Instructions\n");
			for (auto & id : instrdefs) {
				id.second.print (indent + 1);
			}*/
		}
	};

}

#endif // ARCHITECTURE_H
