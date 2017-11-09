
#include "General.h"

#include <stdio.h>

namespace holodec {

	VisibilityType g_visibilityPublic = {.name = "public"};
	VisibilityType g_visibilityProtected = {.name = "protected"};
	VisibilityType g_visibilityPrivate = {.name = "private"};

	void printIndent (int indent) {
		for (int i = 0; i < indent ; i++)
			printf ("\t");
	}
}
