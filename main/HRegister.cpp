#include "HRegister.h"

namespace holodec{


	HRegister invalidReg = {"", 0, 0};

	HRegister* HRegister::addRegister (HRegister* reg) {
		subregisters.push_back (*reg);
		return &subregisters.back();
	};
	HRegister* HRegister::getRegister (const HString string) {
		for (HRegister& reg : subregisters) {
			if (string == reg.name)
				return &reg;
			HRegister* r = reg.getRegister (string);
			if (r) return r;
		}
		return 0;
	}
	HRegister* HRegister::getRegister (const HId id) {
		for (HRegister& reg : subregisters) {
			if (id == reg.id)
				return &reg;
			HRegister* r = reg.getRegister (id);
			if (r) return r;
		}
		return 0;
	}
	void HRegister::setParentId (HId parentId) {
		this->parentId = parentId;
		for (HRegister& reg : subregisters) {
			reg.setParentId (parentId);
		}
	}
	void HRegister::relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer) {
		HId newid = gen->next();
		if (replacer)
			replacer (id, newid);
		id = newid;
		for (HRegister& reg : subregisters) {
			reg.relabel (gen, replacer);
		}
	}
	void HRegister::print (int indent) {
		printIndent (indent);
		std::printf ("Register %d %s s: %d o: %d %s\n", id, name.cstr(), size, offset, track == H_REG_TRACK_TRACKED ? "t" : "v");
		for (HRegister & reg : subregisters) {
			reg.print (indent + 1);
		}
	}

}
