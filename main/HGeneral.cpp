
#include "HGeneral.h"

#include <stdio.h>

namespace holodec {

	HVisibilityType gh_visibilityPublic = {.name = "public"};
	HVisibilityType gh_visibilityProtected = {.name = "protected"};
	HVisibilityType gh_visibilityPrivate = {.name = "private"};

	void printIndent (int indent) {
		for (int i = 0; i < indent ; i++)
			printf ("\t");
	}
}
