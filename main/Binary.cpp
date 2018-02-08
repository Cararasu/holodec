#include "Binary.h"
#include "Main.h"

namespace holodec {

	Binary::Binary (HString name) : name (name) {
	}

	Binary::~Binary() {
	}

	HId Binary::addSection (Section* section) {
		for (Section* sectionit : sections) {
			HId ret = sectionit->addSection (section);
			if (ret) return ret;
		}
		return sections.push_back (section);
	}
	Section* Binary::getSection (HString name) {
		for (Section* section : sections) {
			Section* sec = section->getSection (name);
			if (sec) return sec;
		}
		return nullptr;
	}
	Section* Binary::getSection (HId id) {
		for (Section* section : sections) {
			Section* sec = section->getSection (id);
			if (sec) return sec;
		}
		return nullptr;
	}
	HId Binary::addSymbol (Symbol* symbol) {
		return symbols.push_back (symbol);
	}
	Symbol* Binary::getSymbol (HString name) {
		for (Symbol* symbol : symbols) {
			if (symbol->name == name)
				return symbol;
		}
		return nullptr;
	}
	Symbol* Binary::getSymbol (HId id) {
		for (Symbol* symbol : symbols) {
			if (symbol->id == id)
				return symbol;
		}
		return nullptr;
	}
	Symbol* Binary::findSymbol (size_t addr, const SymbolType* type = nullptr) {
		for (Symbol* symbol : symbols) {
			if (symbol->vaddr == addr && (type == nullptr || (symbol->symboltype == type || symbol->symboltype->name == type->name)))
				return symbol;
		}
		return nullptr;
	}
	HId Binary::addFunction (Function* function) {
		return functions.push_back (function);
	}
	Function* Binary::getFunction (HString name) {
		for (Function* function : functions) {
			Symbol* sym = getSymbol (function->symbolref);
			if (sym && sym->name == name)
				return function;
		}
		return nullptr;
	}
	Function* Binary::getFunction (HId id) {
		return functions[id];
	}
	HId Binary::addDynamicLibrary (DynamicLibrary* dynamicLibrary){
		return dynamic_libraries.push_back (dynamicLibrary);
	}
	DynamicLibrary* Binary::getDynamicLibrary (HString string){
		for(DynamicLibrary* dynlib : dynamic_libraries){
			if(dynlib->name == string){
				return dynlib;
			}
		}
		return nullptr;
	}
	DynamicLibrary* Binary::getDynamicLibrary (HId id){
		return dynamic_libraries[id];
	}

	bool Binary::addEntrypoint (HId id) {
		entrypoints.push_back (id);
		return true;
	}

}
