#include "RSection.h"


radpp::RSymbolType radpp::RSymbolType::symbool = {"bool"};
radpp::RSymbolType radpp::RSymbolType::symint = {"int"};
radpp::RSymbolType radpp::RSymbolType::symuint = {"uint"};
radpp::RSymbolType radpp::RSymbolType::symfloat = {"float"};
radpp::RSymbolType radpp::RSymbolType::symstring = {"string"};
radpp::RSymbolType radpp::RSymbolType::symfunc = {"func"};

radpp::RSection* radpp::RSection::addSection (RSection* section) {
	if (vaddr > section->vaddr || vaddr + size <= section->vaddr)
		return nullptr;
	for (RSection& sectionit : subsections) {
		RSection* sec = sectionit.addSection (section);
		if (sec) return sec;
	}
	subsections.push_back (*section);
	return &subsections.back();
}
radpp::RSymbol* radpp::RSection::addSymbol (RSymbol* symbol) {
	if (vaddr > symbol->vaddr || vaddr + size <= symbol->vaddr)
		return nullptr;
	for (RSection& sectionit : subsections) {
		RSymbol* sym = sectionit.addSymbol (symbol);
		if (sym) return sym;
	}
	symbols.push_back(*symbol);
	return &symbols.back();
}

void radpp::RSymbol::print(int indent) {
	printIndent (indent);
	printf ("Symbol %s \t%x-%x\n", name, vaddr, vaddr + size);
	printIndent (indent);
	printf ("Type: %s\n",symboltype.name);
}
