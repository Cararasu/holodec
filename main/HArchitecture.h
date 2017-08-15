#ifndef H_AHCHITECTUHE_H
#define H_AHCHITECTUHE_H

#include <stdint.h>
#include <functional>
#include "HFunctionAnalyzer.h"
#include "HInstrDefinition.h"
#include "HRegister.h"
#include "HStack.h"
#include "HCallingConvention.h"
#include "HSSA.h"

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

		HList<HCallingConvention> callingconventions;

		HMap<HId, HInstrDefinition> instrdefs;

		HIdList<HIRExpression> irExpressions;
		HIdList<HSSAExpression> ssaExpressions;

		HArchitecture() = default;
		HArchitecture (HArchitecture&) = default;
		HArchitecture (HArchitecture&&) = default;
		~HArchitecture() = default;

		void init() {
			HIdGenerator gen;
			for (HRegister& reg : registers) {
				reg.relabel (&gen);
				reg.setParentId (reg.id);
			}
			for (HStack& stack : stacks) {
				for (HRegister& reg : stack.regs) {
					reg.relabel (&gen);
					reg.setParentId (reg.id);
				}
			}
			
			for (auto& entry : instrdefs) {
				HIRParser parser (this);
				for (int i = 0; i < 4; i++) {
					if (entry.second.irs[i]) {
						parser.parse (&entry.second.irs[i]);
					}
				}
			}
		}

		HFunctionAnalyzer* createFunctionAnalyzer (HBinary* binary) {
			for (std::function<HFunctionAnalyzer* (HBinary*) >& fac : functionanalyzerfactories) {
				HFunctionAnalyzer* analyzer = fac (binary);
				if (analyzer)
					return analyzer;

			}
			return nullptr;
		}

		HRegister* getRegister (const HString string) {
			if (!string)
				return &invalidReg;
			for (HRegister& reg : registers) {
				if (string == reg.name)
					return &reg;
				HRegister* r = reg.getRegister (string);
				if (r) return r;
			}
			for (HStack& stack : stacks) {
				for (HRegister& reg : stack.regs) {
					if (string == reg.name)
						return &reg;
					HRegister* r = reg.getRegister (string);
					if (r) return r;
				}
			}
			return &invalidReg;
		}
		HRegister* getRegister (const HId id) {
			for (HRegister& reg : registers) {
				if (id == reg.id)
					return &reg;
				HRegister* r = reg.getRegister (id);
				if (r) return r;
			}
			for (HStack& stack : stacks) {
				for (HRegister& reg : stack.regs) {
					if (id == reg.id)
						return &reg;
					HRegister* r = reg.getRegister (id);
					if (r) return r;
				}
			}
			return &invalidReg;
		}
		HRegister* getParentRegister (const HId id) {
			for (HRegister& reg : registers) {
				if (id == reg.id)
					return &reg;
				HRegister* r = reg.getRegister (id);
				if (r) return &reg;
			}
			for (HStack& stack : stacks) {
				for (HRegister& reg : stack.regs) {
					if (id == reg.id)
						return &reg;
					HRegister* r = reg.getRegister (id);
					if (r) return &reg;
				}
			}
			return &invalidReg;
		}
		HStack* getStack (const HString string) {
			if (!string)
				return nullptr;
			for (HStack& stack : stacks) {
				if (string == stack.name)
					return &stack;
			}
			return nullptr;
		}
		HStack* getStack (const HId id) {
			if (!id)
				return nullptr;
			for (HStack& stack : stacks) {
				if (id == stack.id)
					return &stack;
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
				if (expression == expr)
					return expression.id;
			}
			irExpressions.add (expr);
			return expr.id;
		}
		HSSAExpression* getSSAExpr (HId id) {
			return ssaExpressions.get (id);
		}
		HId addSSAExpr (HSSAExpression expr) {
			for (HSSAExpression& expression : ssaExpressions.list) {   //Do CSE
				if (expression == expr)
					return expression.id;
			}
			ssaExpressions.add (expr);
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
