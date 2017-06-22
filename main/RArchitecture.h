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
		
		RList<std::function<RFunctionAnalyzer*(RBinary*)>> functionanalyzerfactories;
		RList<RRegister> registers;
		
		RMap<uint64_t,RInstrDefinition> instrdefs;
		
		//RInstructionSet
		
		RArchitecture() = default;
		RArchitecture(RArchitecture&) = default;
		RArchitecture(RArchitecture&&) = default;
		~RArchitecture() = default;

		RFunctionAnalyzer* createFunctionAnalyzer(RBinary* binary){
			for (std::function<RFunctionAnalyzer*(RBinary*)>& fac : functionanalyzerfactories){
				RFunctionAnalyzer* analyzer = fac(binary);
				if(analyzer)
					return analyzer;
					
			}
			return 0;
		}

		RRegister* getRegister(RRegisterIndex index){
			for(RRegister& reg : registers){
				if(reg.index == index)
					return &reg;
				RRegister* r = reg.getRegister(index);
				if(r) return r;
			}
			return 0;
		}
		RRegister* getRegister(RString string){
			for(RRegister& reg : registers){
				if(strcmp(string,reg.name) == 0)
					return &reg;
				RRegister* r = reg.getRegister(string);
				if(r) return r;
			}
			return 0;
		}
		
		void print (int indent = 0) {
			printIndent(indent);
			printf("Architecture %s\n",name);
			for (RRegister & rr : registers) {
				rr.print(indent+1);
			}
		}
	};

}

#endif // R_ARCHITECTURE_H
