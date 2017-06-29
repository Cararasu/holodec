#ifndef HMAIN_H
#define HMAIN_H

#include "HGeneral.h"
#include "HString.h"
#include "HFileFormat.h"
#include "HArchitecture.h"

namespace holodec {


	struct HMain {
		HList<HFileFormat*> fileformats;
		HList<HArchitecture*> architectures;

		//HConsole* console;
		//HLogger* logger;

		bool registerArchitecture (HArchitecture* arch);
		HArchitecture* getArchitecture (HString arch);

		bool registerFileFormat (HFileFormat* fileformat);
		HFileFormat* getFileFormat (HString fileformat);


		static HData* loadHDataFromFile (HString);
		static HData* loadHData (uint8_t* data, size_t size);

		static HMain* gh_main;
		static void initHMain();
	};

}

#endif // HMAIN_H
