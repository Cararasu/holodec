#include "Architecture.h"


namespace holodec {

	void Architecture::init() {
		for (Register& reg : registers) {
			reg.parentRef.refId = getRegister(reg.parentRef)->id;
			reg.directParentRef.refId = getRegister(reg.directParentRef)->id;
		}
		for (Stack& stack : stacks) {
			stack.trackingReg.refId = getRegister(stack.trackingReg)->id;
			stack.backingMem.refId = getMemory(stack.backingMem)->id;
			for(StringRef& ref : stack.backingRegs){
				ref.refId = getRegister(ref)->id;
			}
		}
		for (CallingConvention& cc : callingconventions) {
			cc.parameterCount.refId = getRegister(cc.parameterCount)->id;
			
			for(StringRef& ref : cc.nonVolatileReg){
				ref.refId = getRegister(ref)->id;
			}
			for(CCParameter& para : cc.parameters){
				para.regref.refId = getRegister(para.regref)->id;
			}
			for(CCParameter& para : cc.returns){
				para.regref.refId = getRegister(para.regref)->id;
			}
		}

		for (auto& entry : instrdefs) {
			IRParser parser (this);
			for (int i = 0; i < entry.second.irs.size(); i++) {
				if (entry.second.irs[i]) {
					parser.parse (&entry.second.irs[i]);
				}
			}
		}
	}
	

}
