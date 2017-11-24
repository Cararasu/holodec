#ifndef HSCHIPTINGINTEHFACE_H
#define HSCHIPTINGINTEHFACE_H

#include "Architecture.h"
namespace holodec {

	class ScriptingInterface {

	public:
		void registerBinary();
		void registerArchitecture();
		void testModule(Architecture* arch);
	};

}

#endif // HSCHIPTINGINTEHFACE_H
