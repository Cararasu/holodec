
#include "HGeneral.h"

#include <stdio.h>

namespace holodec {

	HVisibilityType gr_visibilityPublic = {.name = "public"};
	HVisibilityType gr_visibilityProtected = {.name = "protected"};
	HVisibilityType gr_visibilityPrivate = {.name = "private"};

	void printIndent (int indent) {
		for (int i = 0; i < indent ; i++)
			printf ("\t");
	}
}
