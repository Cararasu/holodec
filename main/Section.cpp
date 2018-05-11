#include "Section.h"


const holodec::SymbolType holodec::SymbolType::symbool = {"bool"};
const holodec::SymbolType holodec::SymbolType::symint = {"int"};
const holodec::SymbolType holodec::SymbolType::symuint = {"uint"};
const holodec::SymbolType holodec::SymbolType::symfloat = {"float"};
const holodec::SymbolType holodec::SymbolType::symstring = {"string"};
const holodec::SymbolType holodec::SymbolType::symfunc = {"func"};
const holodec::SymbolType holodec::SymbolType::symdynfunc = {"dynfunc"};

holodec::HId holodec::Section::addSection (Section* section) {
	if (vaddr > section->vaddr || vaddr + size <= section->vaddr)
		return 0;
	for (Section* sectionit : subsections) {
		HId ret = sectionit->addSection (section);
		if (ret) return ret;
	}
	subsections.push_back (section);
	return section->id;
}
holodec::Section* holodec::Section::getSection (HId id){
	if(this->id == id)
		return this;
	for (Section* section : subsections) {
		Section* sec = section->getSection (id);
		if (sec) return sec;
	}
	return nullptr;
}
holodec::Section* holodec::Section::getSection (HString name){
	if(this->name == name)
		return this;
	for (Section* section : subsections) {
		Section* sec = section->getSection (name);
		if (sec) return sec;
	}
	return nullptr;
}

void holodec::Symbol::print(int indent) {
	printIndent (indent);
	printf ("Symbol %s \t%" PRIx64 "-%" PRIx64 "\n", name.cstr(), vaddr, vaddr + size);
	printIndent (indent);
	printf ("Type: %s\n",symboltype->name.cstr());
}
