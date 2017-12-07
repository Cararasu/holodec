#include "Binary.h"
#include "Main.h"

holodec::Binary::Binary (HString filename) : data (Main::loadDataFromFile (filename)) {
}

holodec::Binary::Binary (Data* data) : data (data) {

}


holodec::Binary::~Binary() {
}

holodec::HId holodec::Binary::addSection (Section* section) {
	for (Section* sectionit : sections) {
		HId ret = sectionit->addSection (section);
		if (ret) return ret;
	}
	return sections.push_back (section);
}
holodec::Section* holodec::Binary::getSection (HString name) {
	for (Section* section : sections) {
		Section* sec = section->getSection (name);
		if (sec) return sec;
	}
	return nullptr;
}
holodec::Section* holodec::Binary::getSection (HId id) {
	for (Section* section : sections) {
		Section* sec = section->getSection (id);
		if (sec) return sec;
	}
	return nullptr;
}
holodec::HId holodec::Binary::addSymbol (Symbol* symbol) {
	return symbols.push_back (symbol);
}
holodec::Symbol* holodec::Binary::getSymbol (HString name) {
	for (Symbol* symbol : symbols) {
		if(symbol->name == name)
			return symbol;
	}
	return nullptr;
}
holodec::Symbol* holodec::Binary::getSymbol (HId id) {
	for (Symbol* symbol : symbols) {
		if(symbol->id == id)
			return symbol;
	}
	return nullptr;
}
holodec::Symbol* holodec::Binary::findSymbol (size_t addr,const SymbolType* type) {
	for (Symbol* symbol : symbols) {
		if(symbol->vaddr == addr && (symbol->symboltype == type || symbol->symboltype->name == type->name))
			return symbol;
	}
	return nullptr;
}
holodec::HId holodec::Binary::addFunction (Function* function) {
	return functions.push_back (function);
}
holodec::Function* holodec::Binary::getFunction (HString name){
	for (Function* function : functions) {
		Symbol* sym = getSymbol(function->symbolref);
		if(sym && sym->name == name)
			return function;
	}
	return nullptr;
}
holodec::Function* holodec::Binary::getFunction (HId id){
	return functions[id];
}
bool holodec::Binary::addEntrypoint (HId id) {
	entrypoints.push_back (id);
	return true;
}
