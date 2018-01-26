#include "Main.h"
#include <fstream>

using namespace holodec;

Main* Main::g_main;
		
bool Main::registerArchitecture (Architecture* arch) {
	for (Architecture * a : architectures)
		if (caseCmpHString (a->name, arch->name))
			return false;
	architectures.push_back (arch);
	return true;
}

Architecture* Main::getArchitecture (HString arch) {
	for (Architecture * a : architectures)
		if (caseCmpHString (a->name, arch))
			return a;
	return nullptr;
}

bool Main::registerFileFormat (FileFormat* fileformat) {
	for (FileFormat * ff : fileformats)
		if (caseCmpHString (ff->name, fileformat->name))
			return false;
	fileformats.push_back (fileformat);
	return true;
}

FileFormat* Main::getFileFormat (HString fileformat) {
	for (FileFormat * ff : fileformats)
		if (caseCmpHString (ff->name, fileformat))
			return ff;
	return nullptr;
}


Data* Main::loadDataFromFile (HString file) {
	std::ifstream t (file.cstr(), std::ios_base::binary);
	size_t size;
	uint8_t* data;
	if (t) {
		t.seekg (0, t.end);
		size = (size_t) t.tellg();
		data = new uint8_t[size];

		t.seekg (0, t.beg);

		uint64_t offset = 0;
		while (offset < size) {
			t.read((char*)data, size);
			uint64_t read = t.gcount();
			if (read == 0)
				break;
			offset += read;
			printf("Read %d chars\n", t.gcount());
		}
		return new Data (data, size, file);
	}
	return nullptr;
}

Data* Main::loadData (uint8_t* data, size_t size) {
	return new Data (data, size, 0);
}

void holodec::Main::initMain() {
	g_main = new Main();
}
