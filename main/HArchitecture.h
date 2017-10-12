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
		HList<HRegister> registers;

		HIdList<HStack> stacks;
		
		HIdList<HMemory> memories;

		HIdList<HCallingConvention> callingconventions;

		HIdMap<HId, HInstrDefinition> instrdefs;

		HIdList<HIRExpression> irExpressions;

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

		HRegister* getRegister (const HString string) {
			if (string) {
				for (HRegister& reg : registers) {
					if (string == reg.name)
						return &reg;
					HRegister* r = reg.getRegister (string);
					if (r) return r;
				}
			}
			return nullptr;
		}
		HRegister* getRegister (const HId id) {
			if (id) {
				for (HRegister& reg : registers) {
					if (id == reg.id)
						return &reg;
					HRegister* r = reg.getRegister (id);
					if (r) return r;
				}
			}
			return nullptr;
		}
		HRegister* getParentRegister (const HId id) {
			if (id) {
				for (HRegister& reg : registers) {
					if (id == reg.id)
						return &reg;
					HRegister* r = reg.getRegister (id);
					if (r) return &reg;
				}
			}
			return nullptr;
		}
		HStack* getStack (const HString string) {
			if (string) {
				for (HStack& stack : stacks) {
					if (string == stack.name)
						return &stack;
				}
			}
			return nullptr;
		}
		HStack* getStack (const HId id) {
			if (id) {
				for (HStack& stack : stacks) {
					if (id == stack.id)
						return &stack;
				}
			}
			return nullptr;
		}
		HMemory* getMemory (const HString string) {
			if (string) {
				for (HMemory& memory : memories) {
					if (string == memory.name)
						return &memory;
				}
			}
			return nullptr;
		}
		HMemory* getMemory (const HId id) {
			if (id) {
				for (HMemory& memory : memories) {
					if (id == memory.id)
						return &memory;
				}
			}
			return nullptr;
		}
		HMemory* getDefaultMemory () {
			return &(memories.list[0]);
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
			for (HIRExpression& expression : irExpressions.list) {   //Do CSE
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
