#include "HArchitecture.h"


namespace holodec {

	void HArchitecture::init() {
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
			printf("Parsing Instruction %s!\n",entry.second.mnemonics.cstr());
			HIRParser parser (this);
			for (int i = 0; i < entry.second.irs.size(); i++) {
				if (entry.second.irs[i]) {
					parser.parse (&entry.second.irs[i]);
				}
			}
		}
	}

}
