
#include "General.h"

#include <stdio.h>

namespace holodec {

	const HString emptyString("");

	void printIndent (int indent) {
		printf("%*c", indent*6, ' ');
	}
}
