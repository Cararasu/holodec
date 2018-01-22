#ifndef DYNAMICLIBRARY_H
#define DYNAMICLIBRARY_H

#include "General.h"
namespace holodec {

	struct DynamicProfile {
		HId id;
		HString name;
	};

	struct DynamicLibrary {
		HId id;
		HString name;

		DynamicLibrary (HString name) : id (0), name (name) {}
	};
}


#endif // DYNAMICLIBRARY_H
