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


File* Main::loadDataFromFile (HString file) {
	std::ifstream t (file.cstr(), std::ios_base::binary);
	size_t size;
	std::vector<uint8_t> data;
	if (t) {
		t.seekg (0, t.end);
		size = (size_t) t.tellg();
		data.resize(size);

		t.seekg (0, t.beg);

		uint64_t offset = 0;
		while (offset < size) {
			t.read((char*)data.data() + offset, size);
			uint64_t read = t.gcount();
			if (read == 0)
				break;
			offset += read;
			printf("Read %zu chars\n", t.gcount());
		}
		return new File(file, data);
	}
	return nullptr;
}

void holodec::Main::initMain() {
	g_main = new Main();
}
