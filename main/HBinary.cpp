#include "HBinary.h"
#include "HMain.h"

holodec::HBinary::HBinary (HString filename) : data (HMain::loadHDataFromFile (filename)) {
}

holodec::HBinary::HBinary (HData* data) : data (data) {

}


holodec::HBinary::~HBinary() {
}

holodec::HId holodec::HBinary::addSection (HSection section) {
	section.id = gen_sections.next();
	for (HSection & sectionit : sections) {
		HId ret = sectionit.addSection (section);
		if (ret) return ret;
	}
	sections.push_back (section);
	return section.id;
}
holodec::HSection* holodec::HBinary::getSection (HString name) {
	for (HSection & section : sections) {
		HSection* sec = section.getSection (name);
		if (sec) return sec;
	}
	return nullptr;
}
holodec::HSection* holodec::HBinary::getSection (HId id) {
	for (HSection & section : sections) {
		HSection* sec = section.getSection (id);
		if (sec) return sec;
	}
	return nullptr;
}
holodec::HId holodec::HBinary::addSymbol (HSymbol symbol) {
	symbol.id = gen_symbols.next();
	printf("Add Symbol %d\n",symbol.id);
	symbols.push_back (symbol);
	return symbol.id;
}
holodec::HSymbol* holodec::HBinary::getSymbol (HString name) {
	for (HSymbol & symbol : symbols) {
		if(symbol.name == name)
			return &symbol;
	}
	return nullptr;
}
holodec::HSymbol* holodec::HBinary::getSymbol (HId id) {
	for (HSymbol & symbol : symbols) {
		if(symbol.id == id)
			return &symbol;
	}
	return nullptr;
}
holodec::HSymbol* holodec::HBinary::findSymbol (size_t addr,const HSymbolType* type) {
	for (HSymbol & symbol : symbols) {
		if(symbol.vaddr == addr && (symbol.symboltype == type || symbol.symboltype->name == type->name))
			return &symbol;
	}
	return nullptr;
}
holodec::HId holodec::HBinary::addFunction (HFunction function) {
	function.id = gen_functions.next();
	functions.push_back (function);
	function.print();
	return function.id;
}
bool holodec::HBinary::addEntrypoint (HId id) {
	entrypoints.push_back (id);
	return true;
}
