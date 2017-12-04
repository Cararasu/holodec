
#include "General.h"

#include <stdio.h>

namespace holodec {

	void printIndent (int indent) {
		for (int i = 0; i < indent ; i++)
			printf ("\t");
	}
}
