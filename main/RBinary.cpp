#include "RBinary.h"
#include "RMain.h"

radpp::RBinary::RBinary (RString filename) : data (RMain::loadRDataFromFile(filename)) {
}

radpp::RBinary::RBinary (RData* data) : data (data) {

}


radpp::RBinary::~RBinary() {
}

radpp::RSection* radpp::RBinary::addSection (RSection* section) {
	for (RSection & sectionit : sections) {
		RSection* sec = sectionit.addSection (section);
		                if (sec) return sec;
	}
	sections.push_back (*section);
}
radpp::RSymbol* radpp::RBinary::addSymbol (RSymbol* symbol) {
	for (RSection & sectionit : sections) {
		RSymbol* sym = sectionit.addSymbol (symbol);
		               if (sym) return sym;
	}
	return nullptr;
}
radpp::RFunction* radpp::RBinary::addFunction (RFunction* function) {
	functions.push_back (*function);
	return &functions.back();
}
bool radpp::RBinary::addEntrypoint (RSymbol* entrypoint) {
	entrypoints.push_back (entrypoint);
	return true;
}
