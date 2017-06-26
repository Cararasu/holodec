#ifndef R_ARCHITECTURE_H
#define R_ARCHITECTURE_H

#include <stdint.h>
#include <functional>
#include "RFunctionAnalyzer.h"
#include "RInstrDefinition.h"

namespace holodec {

	struct RArchitecture {
		RString name;
		RString desc;
		uint64_t bitcount;

		RList<std::function<RFunctionAnalyzer* (RBinary*) >> functionanalyzerfactories;
		RList<RRegister> registers;

		RStringMap<RInstrDefinition> instrdefs;

		//RInstructionSet

		RArchitecture() = default;
		RArchitecture (RArchitecture&) = default;
		RArchitecture (RArchitecture&&) = default;
		~RArchitecture() = default;

		RFunctionAnalyzer* createFunctionAnalyzer (RBinary* binary) {
			for (std::function<RFunctionAnalyzer* (RBinary*) >& fac : functionanalyzerfactories) {
				RFunctionAnalyzer* analyzer = fac (binary);
				if (analyzer)
					return analyzer;

			}
			return 0;
		}

		RRegister* getRegister (RString string) {
			for (RRegister& reg : registers) {
				if (string == reg.name)
					return &reg;
				RRegister* r = reg.getRegister (string);
				if (r) return r;
			}
			return 0;
		}

		RInstrDefinition* getInstrDef (RString mnemonics) {
			auto it = instrdefs.find (mnemonics);
			if (it != instrdefs.end())
				return & (*it).second;
			printf ("%s not found\n", mnemonics.cstr());
			return 0;
		}

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Architecture %s\n", name.cstr());
			for (RRegister & rr : registers) {
				rr.print (indent + 1);
			}
			for (auto & id : instrdefs) {
				id.second.print (indent + 1);
			}
		}
	};

}

#endif // R_ARCHITECTURE_H
