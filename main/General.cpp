
#include "General.h"

#include <stdio.h>

namespace holodec {

	void printIndent (int indent) {
		printf("%*c", indent*6, ' ');
	}
}
