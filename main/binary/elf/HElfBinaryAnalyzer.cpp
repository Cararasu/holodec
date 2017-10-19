#include "HElfBinaryAnalyzer.h"

#include <stdio.h>

using namespace holodec;


bool holoelf::HElfBinaryAnalyzer::canAnalyze (holodec::HData* pdata) {
	holodec::HData data = *pdata;
	//Magic number
	if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
		printf ("Wrong Header %s\n", data.data);
		return false;
	}
	return true;
}
bool holoelf::HElfBinaryAnalyzer::init (holodec::HData* file) {
	if (!file)
		return false;
	this->binary = new holodec::HBinary (file);


	if (!parseFileHeader())
		return false;

	if (!parseProgramHeaderTable())
		return false;

	if (!parseSectionHeaderTable())
		return false;


	//handle entry and exit points
	{
		uint32_t entrypoint = binary->data->get<uint32_t> (0x18);
		binary->addEntrypoint (binary->addSymbol ({0,HString::create ("entry0"), &HSymbolType::symfunc, 0, entrypoint, 0}));
		int entrycount = 1;
		int exitcount = 0;
		char buffer[20];
		if (HSection* init = binary->getSection (".init")) {
			snprintf (buffer, 20, "entry%d", entrycount++);
			binary->addEntrypoint (binary->addSymbol ({0,HString::create (buffer), &HSymbolType::symfunc, 0, init->vaddr, 0}));
		}
		if (HSection* finit = binary->getSection (".finit")) {
			snprintf (buffer, 20, "exit%d", entrycount);
			binary->addEntrypoint (binary->addSymbol ({0,HString::create (buffer), &HSymbolType::symfunc, 0, finit->vaddr, 0}));
		}
		if (HSection* init_array = binary->getSection (".init_array")) {
			if (binary->bitbase == 32) {
				for (size_t i = 0; i < init_array->size; i += 4) {
					size_t fncptr = init_array->getValue<uint32_t> (binary->data, i);
					snprintf (buffer, 20, "entry%d", entrycount++);
					binary->addEntrypoint (binary->addSymbol ({0,HString::create (buffer), &HSymbolType::symfunc, 0, fncptr, 0}));
				}
			} else if (binary->bitbase == 64) {
				for (size_t i = 0; i < init_array->size; i += 8) {
					size_t fncptr = init_array->getValue<uint32_t> (binary->data, i);
					snprintf (buffer, 20, "entry%d", entrycount++);
					binary->addEntrypoint (binary->addSymbol ({0,HString::create (buffer), &HSymbolType::symfunc, 0, fncptr, 0}));
				}
			}
		}
		if (HSection* finit_array = binary->getSection (".finit_array")) {
			if (binary->bitbase == 32) {
				for (size_t i = 0; i < finit_array->size; i += 4) {
					size_t fncptr = finit_array->getValue<uint32_t> (binary->data, i);
					snprintf (buffer, 20, "exit%d", exitcount++);
					binary->addEntrypoint (binary->addSymbol ({0,HString::create (buffer), &HSymbolType::symfunc, 0, fncptr, 0}));
				}
			} else if (binary->bitbase == 64) {
				printf ("%p", finit_array->vaddr);
				for (size_t i = 0; i < finit_array->size; i += 8) {
					size_t fncptr = finit_array->getValue<uint32_t> (binary->data, i);
					snprintf (buffer, 20, "exit%d", exitcount++);
					binary->addEntrypoint (binary->addSymbol ({0,HString::create (buffer), &HSymbolType::symfunc, 0, fncptr, 0}));
				}
			}
		}
	}
	{
		HSection* dynsym,* dynstr;
		if ((dynsym = binary->getSection (".dynsym") )&& (dynstr = binary->getSection (".dynstr")) ){
			size_t structlength;
			size_t valueoffset;
			size_t sizeoffset;
			if(binary->bitbase == 32)
				structlength = 16;
			else
				structlength = 24;
				
			for(size_t entryoffset = 0; entryoffset < dynsym->size; entryoffset += structlength){
				char* name = dynstr->getPtr<char>(binary->data,dynsym->getValue<uint32_t>(binary->data,entryoffset));
				uint64_t value;
				uint64_t size;
				if(binary->bitbase == 32){
					value = dynsym->getValue<uint32_t>(binary->data,entryoffset + 0x4);
					size = dynsym->getValue<uint32_t>(binary->data,entryoffset + 0x8);
				}else{
					value = dynsym->getValue<uint64_t>(binary->data,entryoffset + 0x8);
					size = dynsym->getValue<uint64_t>(binary->data,entryoffset + 0x10);
				}
				if(value){
					HSymbol* sym = binary->findSymbol(value,&HSymbolType::symfunc);
					if(sym){
						sym->name.del();
						HString s = holodec::HString::create(name);
						sym->name = s;
						sym->size = size;
					}else{
						binary->addSymbol({0,holodec::HString::create(name),&holodec::HSymbolType::symfunc,0,value,size});
					}
				}
			}
		}
	}

	return true;
}
bool holoelf::HElfBinaryAnalyzer::terminate() {
	return true;
}

void holoelf::HElfBinaryAnalyzer::analyzeAllSymbols() {
}

void holoelf::HElfBinaryAnalyzer::analyzeEntryPoint() {
}

void holoelf::HElfBinaryAnalyzer::analyzeFunctions() {
}

void holoelf::HElfBinaryAnalyzer::analyzeStrings() {
}

void holoelf::HElfBinaryAnalyzer::analyzeValues() {
}

void holoelf::HElfBinaryAnalyzer::doSectionAnalysis() {
}


bool holoelf::HElfBinaryAnalyzer::parseFileHeader() {

	HData& data = *binary->data;

	//Magic number
	if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
		printf ("Wrong Header %s\n", data.data);
		return false;
	}
	//Architecture flag
	switch (data[4]) {
	case 0x01:
		binary->stringDB.insert (std::pair<HString, HString> (holokey::bit, HString::create ("32-bit")));
		binary->bitbase = 32;
		break;
	case 0x02:
		binary->stringDB.insert (std::pair<HString, HString> (holokey::bit, HString::create ("64-bit")));
		binary->bitbase = 64;
		break;
	default:
		printf ("Not supported Architecture\n");
		return false;
	}
	//Endianess flag
	switch (data[5]) {
	case 0x01:
		binary->stringDB.insert (std::pair<HString, HString> (holokey::endianess, HString::create ("little")));
		break;
	case 0x02:
		binary->stringDB.insert (std::pair<HString, HString> (holokey::endianess, HString::create ("big")));
		break;
	default:
		printf ("Not supported Endianess\n");
		return false;
	}
	//ELF Version
	switch (data[6]) {
	case 0x01:
		break;
	default:
		printf ("Not supported Elf version\n");
		return false;
	}
	//OS-ABI
	if (data[7] <= 0x11 && systems[data[7]]) {
		binary->stringDB.insert (std::pair<HString, HString> (holokey::system, HString::create (systems[data[7]])));
	} else if (data[7] == 0x53) {
		binary->stringDB.insert (std::pair<HString, HString> (holokey::system, HString::create ("Sortix")));
	} else {
		return false;
	}
	//ABI Version + Padding ignored

	//Type
	switch (data.get<uint16_t> (0x10)) {
	case 1:
		//printf ("Helocatable\n");
		break;
	case 2:
		//printf ("Executable\n");
		break;
	case 3:
		//printf ("Shared\n");
		break;
	case 4:
		//printf ("Core\n");
		break;
	default:
		//0xfe00	Operating system-specific
		//0xfeff	Operating system-specific
		//0xff00	Processor-specific
		//0xffff	Processor-specific
		printf ("Not supported Type 0x%02x\n", data.get<uint16_t> (0x10));
		return false;
	}
	//Instruction Set
	elf_is = (Elf_Instructionset) data.get<uint16_t> (0x12);
	if (instructionsets[elf_is]) {
		binary->stringDB.insert (std::pair<HString, HString> (holokey::architecture, HString::create (instructionsets[elf_is])));
		printf ("InstructionSet: %s\n", instructionsets[elf_is]);
	}
	switch (elf_is) {
	case ELF_IS_X86:
		binary->arch = "x86";
		break;

	}
	//ELF Version
	if (data.get<uint32_t> (0x14) == 1)
		printf ("Original Version\n");
	else
		printf ("Not supported Version\n");

	size_t offset64bit;
	if (binary->bitbase == 32) {
		//Ptr to EntryPoint handled later
		//Ptr to Program Header Table
		programHeaderTable.offset = data.get<uint32_t> (0x1C);
		//Ptr to Section Header Table
		sectionHeaderTable.offset =  data.get<uint32_t> (0x20);
		offset64bit = 0;
	} else {
		//Ptr to EntryPoint
		//Ptr to Program Header Table
		programHeaderTable.offset = data.get<uint64_t> (0x20);
		//Ptr to Section Header Table
		sectionHeaderTable.offset = data.get<uint64_t> (0x28);
		offset64bit = 0xC;
	}
	printf ("Processor specific Flags: %d\n", data.get<uint32_t> (0x24 + offset64bit));
	printf ("Header Size: 0x%X\n", data.get<uint16_t> (0x28  + offset64bit));
	programHeaderTable.size = data.get<uint16_t> (0x2A + offset64bit);
	programHeaderTable.entries = data.get<uint16_t> (0x2C + offset64bit);

	sectionHeaderTable.size = data.get<uint16_t> (0x2E + offset64bit);
	sectionHeaderTable.entries = data.get<uint16_t> (0x30 + offset64bit);
	sectionHeaderTable.namesectionindex = data.get<uint16_t> (0x32 + offset64bit);
	return true;
}
//https://github.com/tbursztyka/python-elf/tree/master/elf

bool holoelf::HElfBinaryAnalyzer::parseProgramHeaderTable () {

	size_t entrysize = 0;

	if (binary->bitbase == 32)
		entrysize = 0x20;
	else if (binary->bitbase == 64)
		entrysize = 0x38;

	for (unsigned int i = 0; i < programHeaderTable.entries; i++) {
		size_t entryoffset = programHeaderTable.offset + i * entrysize;
		HData& data = *binary->data;
		size_t size = binary->data->size - entryoffset;

		if (data.get<uint32_t> (entryoffset) == 0x1) {
			HSection section = HSection();

			uint32_t flags;
			if (binary->bitbase == 32)
				flags = data.get<uint32_t> (entryoffset + 0x18);
			else if (binary->bitbase == 64)
				flags = data.get<uint32_t> (entryoffset + 0x04);
			section.srwx = (flags & 0x4 ? 0x1 : 0x0) | (flags & 0x2 ? 0x2 : 0x0) | (flags & 0x1 ? 0x4 : 0x0);

			if (binary->bitbase == 32) {
				section.offset = data.get<uint32_t> (entryoffset + 0x04);
				section.vaddr = data.get<uint32_t> (entryoffset + 0x08);
				//section.paddr = data.get<uint32_t> (entryoffset + 0x0C);
				//section.size = data.get<uint32_t> (entryoffset +0x10);//Size in File Image
				section.size = data.get<uint32_t> (entryoffset + 0x14);//Size in Memory
				//printf ("Alignment: %X\n", data.get<uint32_t> (entryoffset + 0x1C));
			} else if (binary->bitbase == 64) {
				section.offset = data.get<uint32_t> (entryoffset + 0x08);
				section.vaddr = data.get<uint32_t> (entryoffset + 0x10);
				//section.paddr = data.get<uint32_t> (entryoffset + 0x18);
				//section.size = data.get<uint32_t> (entryoffset + 0x20);//Size in File Image
				section.size = data.get<uint32_t> (entryoffset + 0x28);//Size in Memory
				//printf ("Alignment: %X\n", data.get<uint32_t> (entryoffset + 0x30));
			}

			binary->addSection (section);
		}

	}
	return true;
}

bool holoelf::HElfBinaryAnalyzer::parseSectionHeaderTable () {

	size_t entrysize = 0;

	if (binary->bitbase == 32)
		entrysize = 0x28;
	else if (binary->bitbase == 64)
		entrysize = 0x40;

	HSection sections[sectionHeaderTable.entries];
	for (HSection & section : sections)
		section = HSection();

	uint32_t nameoffset[sectionHeaderTable.entries];
	for (unsigned int i = 0; i < sectionHeaderTable.entries; i++) {
		size_t entryoffset = sectionHeaderTable.offset + i * entrysize;
		//TODO check size
		size_t size = binary->data->size - entryoffset;
		nameoffset[i] = binary->getValue<uint32_t> (entryoffset + 0x00);

		uint64_t flags = binary->bitbase == 32 ? binary->getValue<uint32_t> (entryoffset + 0x08) : binary->getValue<uint32_t> (entryoffset + 0x08);
		sections[i].srwx = 0;
		if (flags & 0x1)
			sections[i].srwx |= 0x2;
		//printf ("SHF_WRITE\n");
		if (flags & 0x2)
			sections[i].srwx |= 0x1;
		//printf ("SHF_ALLOC\n");
		if (flags & 0x4)
			sections[i].srwx |= 0x4;
		//printf ("SHF_EXECINSTR\n");

		if (binary->bitbase == 32) {
			sections[i].vaddr = binary->getValue<uint32_t> (entryoffset + 0x0C);
			sections[i].offset = binary->getValue<uint32_t> (entryoffset + 0x10);
			sections[i].size = binary->getValue<uint32_t> (entryoffset + 0x14);
			//printf ("Link: %X\n", binary->getValue<uint32_t> (entryoffset + 0x18));
			//printf ("Info: %X\n", binary->getValue<uint32_t> (entryoffset + 0x1C));
			//printf ("Alignment: %X\n", binary->getValue<uint32_t> (entryoffset + 0x20));
			//printf ("Entrysize: %X\n", binary->getValue<uint32_t> (entryoffset + 0x24));
		} else if (binary->bitbase == 64) {
			sections[i].vaddr = binary->getValue<uint32_t> (entryoffset + 0x10);
			sections[i].offset = binary->getValue<uint32_t> (entryoffset + 0x18);
			sections[i].size = binary->getValue<uint32_t> (entryoffset + 0x20);
			//printf ("Link: %X\n", binary->getValue<uint32_t> (entryoffset + 0x28));
			//printf ("Info: %X\n", binary->getValue<uint32_t> (entryoffset + 0x2C));
			//printf ("Alignment: %X\n", getValue<uint64_t> (data, 0x30));
			//printf ("Entrysize: %X\n", getValue<uint64_t> (data, 0x38));
		}
	}
	void* nameentryptr = binary->data->data + sections[sectionHeaderTable.namesectionindex].offset;
	for (unsigned int i = 0; i < sectionHeaderTable.entries; i++) {
		HSection & section = sections[i];
		HString s = HString::create ( (char*) (nameentryptr) + nameoffset[i]);
		sections[i].name = s;
		printf ("Name: %s\n", section.name.cstr());
		printf ("Addr: 0x%X\n", section.offset);
		printf ("Size: 0x%X\n", section.size);
		if (!section.vaddr)
			continue;
		binary->addSection (section);
	}
	return true;
}
