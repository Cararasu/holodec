#include "Register.h"

namespace holodec{


	Register invalidReg = {0, "invalid reg", H_REG_OTHER, nullptr, nullptr, 0, 0, false};

	void Register::print (int indent) {
		printIndent (indent);
		std::printf ("Register %d %s s: %d o: %d\n", id, name.cstr(), size, offset);
	}

}
