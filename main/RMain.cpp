#include "RMain.h"
#include <fstream>

using namespace holodec;

RMain* RMain::gr_main;
		
bool RMain::registerArchitecture (RArchitecture* arch) {
	for (RArchitecture * a : architectures)
		if (caseCmpRString (a->name, arch->name))
			return false;
	architectures.push_back (arch);
	return true;
}

RArchitecture* RMain::getArchitecture (RString arch) {
	for (RArchitecture * a : architectures)
		if (caseCmpRString (a->name, arch))
			return a;
	return nullptr;
}

bool RMain::registerFileFormat (RFileFormat* fileformat) {
	for (RFileFormat * ff : fileformats)
		if (caseCmpRString (ff->name, fileformat->name))
			return false;
	fileformats.push_back (fileformat);
	return true;
}

RFileFormat* RMain::getFileFormat (RString fileformat) {
	for (RFileFormat * ff : fileformats)
		if (caseCmpRString (ff->name, fileformat))
			return ff;
	return nullptr;
}


RData* RMain::loadRDataFromFile (RString file) {
	std::ifstream t (file);
	size_t size;
	uint8_t* data;
	if (t) {
		t.seekg (0, t.end);
		size = (size_t) t.tellg();
		data = (uint8_t*) malloc (size);

		t.seekg (0, t.beg);

		t.read ( (char*) data, size);
		return new RData (data, size, file);
	}
	return 0;
}

RData* RMain::loadRData (uint8_t* data, size_t size) {
	return new RData (data, size, 0);
}

void holodec::RMain::initRMain() {
	gr_main = new RMain();
}
