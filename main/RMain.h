#ifndef RMAIN_H
#define RMAIN_H

#include "RGeneral.h"
#include "RString.h"
#include "RFileFormat.h"
#include "RArchitecture.h"

namespace radpp {


	struct RMain {
		RList<RFileFormat*> fileformats;
		RList<RArchitecture*> architectures;

		//RConsole* console;
		//RLogger* logger;

		bool registerArchitecture (RArchitecture* arch);
		RArchitecture* getArchitecture (RString arch);

		bool registerFileFormat (RFileFormat* fileformat);
		RFileFormat* getFileFormat (RString fileformat);


		static RData* loadRDataFromFile (RString);
		static RData* loadRData (uint8_t* data, size_t size);

		static RMain* gr_main;
		static void initRMain();
	};

}

#endif // RMAIN_H
