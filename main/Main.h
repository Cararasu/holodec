#ifndef HMAIN_H
#define HMAIN_H

#include "General.h"
#include "HString.h"
#include "FileFormat.h"
#include "Architecture.h"

namespace holodec {


	struct Main {
		HList<FileFormat*> fileformats;
		HList<Architecture*> architectures;

		//Console* console;
		//Logger* logger;

		bool registerArchitecture (Architecture* arch);
		Architecture* getArchitecture (HString arch);

		bool registerFileFormat (FileFormat* fileformat);
		FileFormat* getFileFormat (HString fileformat);


		static File* loadDataFromFile (HString);

		static Main* g_main;
		static void initMain();
	};

}

#endif // HMAIN_H
