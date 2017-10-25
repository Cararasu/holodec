#include "HArchitecture.h"


namespace holodec {

	void HArchitecture::init() {
		for (HRegister& reg : registers) {
			reg.parentRef.refId = getRegister(reg.parentRef)->id;
			reg.directParentRef.refId = getRegister(reg.directParentRef)->id;
		}
		for (HStack& stack : stacks) {
			stack.trackingReg.refId = getRegister(stack.trackingReg)->id;
			stack.backingMem.refId = getMemory(stack.backingMem)->id;
			for(HStringRef& ref : stack.backingRegs){
				ref.refId = getRegister(ref)->id;
			}
		}
		for (HCallingConvention& cc : callingconventions) {
			cc.parameterCount.refId = getRegister(cc.parameterCount)->id;
			
			for(HStringRef& ref : cc.nonVolatileReg){
				ref.refId = getRegister(ref)->id;
			}
			for(HCCParameter& para : cc.parameters){
				para.regref.refId = getRegister(para.regref)->id;
			}
			for(HCCParameter& para : cc.returns){
				para.regref.refId = getRegister(para.regref)->id;
			}
		}

		for (auto& entry : instrdefs) {
			HIRParser parser (this);
			for (int i = 0; i < entry.second.irs.size(); i++) {
				if (entry.second.irs[i]) {
					parser.parse (&entry.second.irs[i]);
				}
			}
		}
	}
	

}
