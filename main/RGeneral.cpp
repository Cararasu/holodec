
#include "RGeneral.h"

#include <stdio.h>

namespace holodec {

	RVisibilityType gr_visibilityPublic = {.name = "public"};
	RVisibilityType gr_visibilityProtected = {.name = "protected"};
	RVisibilityType gr_visibilityPrivate = {.name = "private"};

	void printIndent (int indent) {
		for (int i = 0; i < indent ; i++)
			printf ("\t");
	}
}
