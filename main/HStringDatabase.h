#ifndef HSTHINGDATABASE_H
#define HSTHINGDATABASE_H


#include "HGeneral.h"
namespace holodec {
	
	typedef HStringMap<HString> HStringDatabase;

	namespace holokey{
		extern const char* system;
		extern const char* architecture;
		extern const char* bit;
		extern const char* endianess;
	}
}

#endif // HSTHINGDATABASE_H
