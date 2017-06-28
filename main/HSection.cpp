#include "HSection.h"


holodec::HSymbolType holodec::HSymbolType::symbool = {"bool"};
holodec::HSymbolType holodec::HSymbolType::symint = {"int"};
holodec::HSymbolType holodec::HSymbolType::symuint = {"uint"};
holodec::HSymbolType holodec::HSymbolType::symfloat = {"float"};
holodec::HSymbolType holodec::HSymbolType::symstring = {"string"};
holodec::HSymbolType holodec::HSymbolType::symfunc = {"func"};

holodec::HId holodec::HSection::addSection (HSection section) {
	if (vaddr > section.vaddr || vaddr + size <= section.vaddr)
		return 0;
	for (HSection& sectionit : subsections) {
		HId ret = sectionit.addSection (section);
		if (ret) return ret;
	}
	subsections.push_back (section);
	return section.id;
}
holodec::HSection* holodec::HSection::getSection (HId id){
	if(this->id == id)
		return this;
	for (HSection& section : subsections) {
		HSection* sec = section.getSection (id);
		if (sec) return sec;
	}
	return nullptr;
}
holodec::HSection* holodec::HSection::getSection (HString name){
	if(this->name == name)
		return this;
	for (HSection& section : subsections) {
		HSection* sec = section.getSection (name);
		if (sec) return sec;
	}
	return nullptr;
}

void holodec::HSymbol::print(int indent) {
	printIndent (indent);
	printf ("Symbol %s \t%x-%x\n", name.cstr(), vaddr, vaddr + size);
	printIndent (indent);
	printf ("Type: %s\n",symboltype.name.cstr());
}
