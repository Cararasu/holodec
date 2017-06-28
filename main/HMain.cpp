#include "HMain.h"
#include <fstream>

using namespace holodec;

HMain* HMain::gr_main;
		
bool HMain::registerArchitecture (HArchitecture* arch) {
	for (HArchitecture * a : architectures)
		if (caseCmpHString (a->name, arch->name))
			return false;
	architectures.push_back (arch);
	return true;
}

HArchitecture* HMain::getArchitecture (HString arch) {
	for (HArchitecture * a : architectures)
		if (caseCmpHString (a->name, arch))
			return a;
	return nullptr;
}

bool HMain::registerFileFormat (HFileFormat* fileformat) {
	for (HFileFormat * ff : fileformats)
		if (caseCmpHString (ff->name, fileformat->name))
			return false;
	fileformats.push_back (fileformat);
	return true;
}

HFileFormat* HMain::getFileFormat (HString fileformat) {
	for (HFileFormat * ff : fileformats)
		if (caseCmpHString (ff->name, fileformat))
			return ff;
	return nullptr;
}


HData* HMain::loadHDataFromFile (HString file) {
	std::ifstream t (file.cstr());
	size_t size;
	uint8_t* data;
	if (t) {
		t.seekg (0, t.end);
		size = (size_t) t.tellg();
		data = (uint8_t*) malloc (size);

		t.seekg (0, t.beg);

		t.read ( (char*) data, size);
		return new HData (data, size, file);
	}
	return 0;
}

HData* HMain::loadHData (uint8_t* data, size_t size) {
	return new HData (data, size, 0);
}

void holodec::HMain::initHMain() {
	gr_main = new HMain();
}
