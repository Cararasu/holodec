#ifndef H_AHCHITECTUHE_H
#define H_AHCHITECTUHE_H

#include <stdint.h>
#include <functional>
#include "HFunctionAnalyzer.h"
#include "HInstrDefinition.h"
#include "HRegister.h"
#include "HStack.h"
#include "HCallingConvention.h"
#include "HIRGen.h"
#include "HIR.h"
#include "HMemory.h"

namespace holodec {

	struct HIRExpression;

	struct HArchitecture {
		HString name;
		HString desc;
		uint64_t bitbase;
		uint64_t wordbase;

		HList<std::function<HFunctionAnalyzer* (HBinary*) >> functionanalyzerfactories;
		HSparseIdList<HRegister> registers;

		HSparseIdList<HStack> stacks;
		
		HSparseIdList<HMemory> memories;

		HSparseIdList<HCallingConvention> callingconventions;

		HIdMap<HId, HInstrDefinition> instrdefs;

		HSparseIdList<HIRExpression> irExpressions;

		HArchitecture() = default;
		HArchitecture (HArchitecture&) = default;
		HArchitecture (HArchitecture&&) = default;
		~HArchitecture() = default;

		void init();

		HFunctionAnalyzer* createFunctionAnalyzer (HBinary* binary) {
			for (std::function<HFunctionAnalyzer* (HBinary*) >& fac : functionanalyzerfactories) {
				HFunctionAnalyzer* analyzer = fac (binary);
				if (analyzer)
					return analyzer;

			}
			return nullptr;
		}

		HRegister* getRegister (const HStringRef stringRef) {
			if (stringRef.refId) {
				for (HRegister& reg : registers) {
					if (stringRef.refId == reg.id)
						return &reg;
				}
			}else if (stringRef.name){
				for (HRegister& reg : registers) {
					if (stringRef.name == reg.name)
						return &reg;
				}
			}
			return &invalidReg;
		}
		HStack* getStack (const HStringRef stringRef) {
			if (stringRef.refId) {
				for (HStack& stack : stacks) {
					if (stringRef.refId == stack.id)
						return &stack;
				}
			}else if (stringRef.name){
				for (HStack& stack : stacks) {
					if (stringRef.name == stack.name)
						return &stack;
				}
			}
			return &invalidStack;
		}
		HMemory* getMemory (const HStringRef stringRef) {
			if (stringRef.refId) {
				for (HMemory& memory : memories) {
					if (stringRef.refId == memory.id)
						return &memory;
				}
			}else if (stringRef.name){
				for (HMemory& memory : memories) {
					if (stringRef.name == memory.name)
						return &memory;
				}
			}
			return &invalidMem;
		}
		HMemory* getDefaultMemory () {
			return memories.get(1);
		}
		HCallingConvention* getCallingConvention(const HString string){
			if(string){
				for(HCallingConvention& cc : callingconventions){
					if(string == cc.name)
						return &cc;
				}
			}
			return nullptr;
		}
		HCallingConvention* getCallingConvention(const HId id){
			if(id){
				for(HCallingConvention& cc : callingconventions){
					if(id == cc.id)
						return &cc;
				}
			}
			return nullptr;
		}
		HInstrDefinition* getInstrDef (HId id, HString mnemonic) {
			auto it = instrdefs.find (id);
			if (it != instrdefs.end())
				return & (*it).second;
			printf ("%s not found\n", mnemonic.cstr());
			return nullptr;
		}
		HInstrDefinition* getInstrDef (HId id) {
			auto it = instrdefs.find (id);
			if (it != instrdefs.end())
				return & (*it).second;
			printf ("%d Instruction not found\n", id);
			return nullptr;
		}
		HInstrDefinition* getInstrDef (HString mnemonic) {
			for (auto& entry : instrdefs) {
				if (entry.second.mnemonics == mnemonic)
					return &entry.second;
			}
			return nullptr;
		}
		HIRExpression* getIrExpr (HId id) {
			return irExpressions.get (id);
		}
		HId addIrExpr (HIRExpression expr) {
			for (HIRExpression& expression : irExpressions) {   //Do CSE
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
			for (HRegister & rr : registers) {
				rr.print (indent + 1);
			}
			printIndent (indent);
			/*printf ("IR-Expressions\n");
			for (HIRExpression& expr : irExpressions.list) {
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

#endif // H_AHCHITECTUHE_H
