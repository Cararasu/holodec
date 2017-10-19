#include "HRegister.h"

namespace holodec{


	HRegister invalidReg = {0, "invalid reg", H_REG_OTHER, nullptr, nullptr, 0, 0, false};

	void HRegister::print (int indent) {
		printIndent (indent);
		std::printf ("Register %d %s s: %d o: %d\n", id, name.cstr(), size, offset);
	}

}
