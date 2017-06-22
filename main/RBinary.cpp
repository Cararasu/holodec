#include "RBinary.h"
#include "RMain.h"

holodec::RBinary::RBinary (RString filename) : data (RMain::loadRDataFromFile(filename)) {
}

holodec::RBinary::RBinary (RData* data) : data (data) {

}


holodec::RBinary::~RBinary() {
}

holodec::RSection* holodec::RBinary::addSection (RSection* section) {
	for (RSection & sectionit : sections) {
		RSection* sec = sectionit.addSection (section);
		                if (sec) return sec;
	}
	sections.push_back (*section);
}
holodec::RSymbol* holodec::RBinary::addSymbol (RSymbol* symbol) {
	for (RSection & sectionit : sections) {
		RSymbol* sym = sectionit.addSymbol (symbol);
		               if (sym) return sym;
	}
	return nullptr;
}
holodec::RFunction* holodec::RBinary::addFunction (RFunction* function) {
	functions.push_back (*function);
	return &functions.back();
}
bool holodec::RBinary::addEntrypoint (RSymbol* entrypoint) {
	entrypoints.push_back (entrypoint);
	return true;
}
