#include "RSection.h"


holodec::RSymbolType holodec::RSymbolType::symbool = {"bool"};
holodec::RSymbolType holodec::RSymbolType::symint = {"int"};
holodec::RSymbolType holodec::RSymbolType::symuint = {"uint"};
holodec::RSymbolType holodec::RSymbolType::symfloat = {"float"};
holodec::RSymbolType holodec::RSymbolType::symstring = {"string"};
holodec::RSymbolType holodec::RSymbolType::symfunc = {"func"};

holodec::RSection* holodec::RSection::addSection (RSection* section) {
	if (vaddr > section->vaddr || vaddr + size <= section->vaddr)
		return nullptr;
	for (RSection& sectionit : subsections) {
		RSection* sec = sectionit.addSection (section);
		if (sec) return sec;
	}
	subsections.push_back (*section);
	return &subsections.back();
}
holodec::RSymbol* holodec::RSection::addSymbol (RSymbol* symbol) {
	if (vaddr > symbol->vaddr || vaddr + size <= symbol->vaddr)
		return nullptr;
	for (RSection& sectionit : subsections) {
		RSymbol* sym = sectionit.addSymbol (symbol);
		if (sym) return sym;
	}
	symbols.push_back(*symbol);
	return &symbols.back();
}

void holodec::RSymbol::print(int indent) {
	printIndent (indent);
	printf ("Symbol %s \t%x-%x\n", name, vaddr, vaddr + size);
	printIndent (indent);
	printf ("Type: %s\n",symboltype.name);
}
