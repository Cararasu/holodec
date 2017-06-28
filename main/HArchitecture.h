#ifndef H_AHCHITECTUHE_H
#define H_AHCHITECTUHE_H

#include <stdint.h>
#include <functional>
#include "HFunctionAnalyzer.h"
#include "HInstrDefinition.h"

namespace holodec {

	struct HArchitecture {
		HString name;
		HString desc;
		uint64_t bitcount;

		HList<std::function<HFunctionAnalyzer* (HBinary*) >> functionanalyzerfactories;
		HList<HRegister> registers;

		HStringMap<HInstrDefinition> instrdefs;

		//HInstructionSet

		HArchitecture() = default;
		HArchitecture (HArchitecture&) = default;
		HArchitecture (HArchitecture&&) = default;
		~HArchitecture() = default;

		HFunctionAnalyzer* createFunctionAnalyzer (HBinary* binary) {
			for (std::function<HFunctionAnalyzer* (HBinary*) >& fac : functionanalyzerfactories) {
				HFunctionAnalyzer* analyzer = fac (binary);
				if (analyzer)
					return analyzer;

			}
			return 0;
		}

		HRegister* getRegister (HString string) {
			for (HRegister& reg : registers) {
				if (string == reg.name)
					return &reg;
				HRegister* r = reg.getRegister (string);
				if (r) return r;
			}
			return 0;
		}

		HInstrDefinition* getInstrDef (HString mnemonics) {
			auto it = instrdefs.find (mnemonics);
			if (it != instrdefs.end())
				return & (*it).second;
			printf ("%s not found\n", mnemonics.cstr());
			return 0;
		}

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Architecture %s\n", name.cstr());
			for (HRegister & rr : registers) {
				rr.print (indent + 1);
			}
			for (auto & id : instrdefs) {
				id.second.print (indent + 1);
			}
		}
	};

}

#endif // H_AHCHITECTUHE_H
