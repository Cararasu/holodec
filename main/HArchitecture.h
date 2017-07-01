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
		uint64_t bitbase;

		HList<std::function<HFunctionAnalyzer* (HBinary*) >> functionanalyzerfactories;
		HList<HRegister> registers;

		HMap<HId, HInstrDefinition> instrdefs;

		//HInstructionSet

		HArchitecture() = default;
		HArchitecture (HArchitecture&) = default;
		HArchitecture (HArchitecture&&) = default;
		~HArchitecture() = default;

		void init() {
			for (auto entry : instrdefs) {
				for(int i = 0; i < 4; i++)
					if(entry.second.il_string[i])
						entry.second.il_string[i].parse();
			}
		}

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

		HInstrDefinition* getInstrDef (HId id, HString mnemonic) {
			auto it = instrdefs.find (id);
			if (it != instrdefs.end())
				return & (*it).second;
			printf ("%s not found\n", mnemonic.cstr());
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
