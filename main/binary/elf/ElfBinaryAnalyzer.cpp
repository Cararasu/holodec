#include "ElfBinaryAnalyzer.h"
#include "../../Architecture.h"
#include "../../Main.h"

#include <stdio.h>
#include <assert.h>

using namespace holodec;


bool holoelf::ElfBinaryAnalyzer::canAnalyze(holodec::File* data) {
	//Magic number
	if (data->data[0] != 0x7F || data->data[1] != 'E' || data->data[2] != 'L' || data->data[3] != 'F') {
		return false;
	}
	return true;
}

template<typename T>
T* getPtrInFile(File* file, uint64_t addr) {
	return reinterpret_cast<T*>(file->data.data() + addr);
}
//TODO byte order!!!
template<typename T>
const T getValue(File* file, uint64_t addr, Endianess endianess) {
	uint8_t buffer[sizeof(T)];
	switch (endianess) {
	case Endianess::eBig: {
		for (size_t i = 0; i < sizeof(T); i++) {
			buffer[i] = file->data[addr + i];
		}
	}break;
	case Endianess::eLittle: {
		for (size_t i = 1; i <= sizeof(T); i++) {
			buffer[i] = file->data[addr + sizeof(T) - i];
		}
	}break;
	}
	return *(T*)buffer;
}

void createSymbol(Binary* binary, File* file, uint64_t addr, const SymbolType* type, Section* dynsym, Section* dynstr, uint64_t index) {

	/*
	typedef struct elf32_sym{
	Elf32_Word	st_name;
	Elf32_Addr	st_value;
	Elf32_Word	st_size;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf32_Half	st_shndx;
	} Elf32_Sym;
	typedef struct elf64_sym {
	Elf64_Word st_name;//32
	unsigned char	st_info;//8
	unsigned char	st_other;//8
	Elf64_Half st_shndx;//16
	Elf64_Addr st_value;//64
	Elf64_Xword st_size;//64
	} Elf64_Sym;
	*/
	size_t dynsim_structlength = binary->bytebase == 4 ? 0x10 : 0x18;
	size_t dynsim_offset = dynsim_structlength * index;
	const char* name = getPtrInFile<char>(file, dynstr->offset + getValue<uint32_t>(file, dynsym->offset + dynsim_offset, binary->endianess));
	uint64_t value = 0;
	uint64_t size = 0;
	uint8_t info = 0;
	if (binary->bytebase == 4) {
		value = getValue<uint32_t>(file, dynsym->offset + dynsim_offset + 0x4, binary->endianess);
		size = getValue<uint32_t>(file, dynsym->offset + dynsim_offset + 0x8, binary->endianess);
		info = getValue<uint8_t>(file, dynsym->offset + dynsim_offset + 0xC, binary->endianess);
	}
	else {
		info = getValue<uint8_t>(file, dynsym->offset + dynsim_offset + 0x4, binary->endianess);
		value = getValue<uint64_t>(file, dynsym->offset + dynsim_offset + 0x10, binary->endianess);
		size = getValue<uint64_t>(file, dynsym->offset + dynsim_offset + 0x18, binary->endianess);
	}
	Symbol* sym = binary->findSymbol(addr, type);
	if (sym) {
		sym->name = HString(name);
		sym->size = binary->bytebase;
	}
	else {
		Symbol* sym = new Symbol();
		*sym = { 0, name, type, 0, addr, binary->bytebase };
		binary->addSymbol(sym);
	}
}

bool holoelf::ElfBinaryAnalyzer::init(holodec::File* file) {
	if (!file)
		return false;
	this->binary = new holodec::Binary(file->name);
	this->file = file;


	if (!parseFileHeader())
		return false;

	if (!parseProgramHeaderTable())
		return false;

	if (!parseSectionHeaderTable())
		return false;


	//handle entry and exit points
	{
		uint32_t entrypoint = getValue<uint32_t>(file, 0x18, binary->endianess);
		binary->addEntrypoint(binary->addSymbol(new Symbol({ 0, "entry0", &SymbolType::symfunc, 0, entrypoint, 0 })));

		char buffer[20];
		if (Section* init = binary->getSection(".init")) {
			binary->addEntrypoint(binary->addSymbol(new Symbol({ 0, ".init", &SymbolType::symfunc, 0, init->vaddr, 0 })));
		}
		if (Section* finit = binary->getSection(".finit")) {
			binary->addSymbol(new Symbol({ 0, ".finit", &SymbolType::symfunc, 0, finit->vaddr, 0 }));
		}
		if (Section* init_array = binary->getSection(".init_array")) {
			if (binary->bytebase == 4) {
				for (size_t i = 0; i < init_array->size; i += 4) {
					size_t fncptr = getValue<uint32_t>(file, init_array->offset + i, binary->endianess);
					snprintf(buffer, 20, ".init_array%zu", i);
					binary->addEntrypoint(binary->addSymbol(new Symbol({ 0, buffer, &SymbolType::symfunc, 0, fncptr, 0 })));
				}
			}
			else if (binary->bytebase == 8) {
				for (size_t i = 0; i < init_array->size; i += 8) {
					size_t fncptr = getValue<uint32_t>(file, init_array->offset + i, binary->endianess);
					snprintf(buffer, 20, ".init_array%zu", i);
					binary->addEntrypoint(binary->addSymbol(new Symbol({ 0, buffer, &SymbolType::symfunc, 0, fncptr, 0 })));
				}
			}
		}
		if (Section* finit_array = binary->getSection(".finit_array")) {
			if (binary->bytebase == 4) {
				for (size_t i = 0; i < finit_array->size; i += 4) {
					size_t fncptr = getValue<uint32_t>(file, finit_array->offset + i, binary->endianess);
					snprintf(buffer, 20, ".finit_array%zu", i);
					binary->addSymbol(new Symbol({ 0, buffer, &SymbolType::symfunc, 0, fncptr, 0 }));
				}
			}
			else if (binary->bytebase == 8) {
				for (size_t i = 0; i < finit_array->size; i += 8) {
					size_t fncptr = getValue<uint32_t>(file, finit_array->offset + i, binary->endianess);
					snprintf(buffer, 20, ".finit_array%zu", i);
					binary->addSymbol(new Symbol({ 0, buffer, &SymbolType::symfunc, 0, fncptr, 0 }));
				}
			}
		}
	}
	{

		Section* dynsym, *dynstr;
		if ((dynsym = binary->getSection(".dynsym")) &&
			(dynstr = binary->getSection(".dynstr"))) {

			size_t rela_structlength = binary->bytebase == 4 ? 0x0c : 0x18;
			for (Section* section : binary->sections) {
				if (section->name.str().compare(0, 6, ".rela.") == 0) {
					for (size_t entryoffset = 0; entryoffset < section->size; entryoffset += rela_structlength) {

						uint64_t offset = getValue<uint64_t>(file, section->offset + entryoffset, binary->endianess);
						uint64_t info = getValue<uint64_t>(file, section->offset + entryoffset + 0x8, binary->endianess);
						uint64_t addend = getValue<uint64_t>(file, section->offset + entryoffset + 0x10, binary->endianess);

						uint64_t type = binary->bytebase == 4 ? info >> 8 : info >> 32;

						if (binary->arch && binary->arch->name == "x86") {
							switch (binary->bytebase == 4 ? info & 0xF : info & 0xFFFFFFFF) {
							case 0x07: {
								createSymbol(binary, file, offset, &SymbolType::symdynfunc, dynsym, dynstr, type);
							}break;
							default:
								printf("Unimplemented relocation\n");
								break;
							}
						}
					}
				}
				else if (section->name.str().compare(0, 5, ".rel.") == 0) {
					printf("------------------------\n");
					printf("Section %s\n", section->name.cstr());
					for (size_t entryoffset = 0; entryoffset < section->size; entryoffset += rela_structlength) {
						uint64_t offset = getValue<uint64_t>(file, section->offset + entryoffset, binary->endianess);
						uint64_t info = getValue<uint64_t>(file, section->offset + entryoffset + 0x8, binary->endianess);

						uint64_t type = binary->bytebase == 4 ? info >> 8 : info >> 32;

						if (binary->arch && binary->arch->name == "x86") {
							switch (info & 0xF) {
							case 0x07:
								createSymbol(binary, file, offset, &SymbolType::symdynfunc, dynsym, dynstr, type);
								break;
							default:
								printf("Unimplemented relocation\n");
								break;
							}
						}
					}
				}
			}
		}

	}
	{
		Section* dynstr, *dynamic;
		if ((dynstr = binary->getSection(".dynstr")) &&
			(dynamic = binary->getSection(".dynamic"))) {
			size_t structlength;

			if (binary->bytebase == 4)
				structlength = 0x08;
			else
				structlength = 0x10;

			size_t entryoffset = 0;
			bool going = true;
			while (going && entryoffset < dynamic->size) {
				/*
				typedef struct dynamic{
				Elf32_Sword d_tag;
				union{
				Elf32_Sword	d_val;
				Elf32_Addr	d_ptr;
				} d_un;
				} Elf32_Dyn;
				typedef struct {
				Elf64_Sxword d_tag;
				union {
				Elf64_Xword d_val;
				Elf64_Addr d_ptr;
				} d_un;
				} Elf64_Dyn;
				*/

				uint64_t tag;
				uint64_t value;
				if (binary->bytebase == 4) {
					tag = getValue<uint32_t>(file, dynamic->offset + entryoffset, binary->endianess);
					value = getValue<uint32_t>(file, dynamic->offset + entryoffset + 0x4, binary->endianess);
				}
				else {
					tag = getValue<uint64_t>(file, dynamic->offset + entryoffset, binary->endianess);
					value = getValue<uint64_t>(file, dynamic->offset + entryoffset + 0x8, binary->endianess);
				}

				switch (tag) {
				case 0: {
					going = false;
				}break;
				case 1: {
					const char* name = getPtrInFile<char>(file, dynstr->offset + value);
					printf("Dynamic Library %s\n", name);
					binary->addDynamicLibrary(new DynamicLibrary(name));
				}break;
				default:
					break;
				}
				entryoffset += structlength;
			}

		}
	}

	return true;
}
bool holoelf::ElfBinaryAnalyzer::terminate() {
	return true;
}


bool holoelf::ElfBinaryAnalyzer::parseFileHeader() {

	//Magic number
	if (file->data[0] != 0x7F || file->data[1] != 'E' || file->data[2] != 'L' || file->data[3] != 'F') {
		printf("Wrong Header\n");
		return false;
	}
	//Architecture flag
	switch (file->data[4]) {
	case 0x01:
		binary->bitbase = 4;
		binary->bytebase = 8;
		break;
	case 0x02:
		binary->bitbase = 8;
		binary->bytebase = 8;
		break;
	default:
		printf("Not supported Architecture\n");
		return false;
	}
	//Endianess flag
	switch (file->data[5]) {
	case 0x01:
		// little endian 
		binary->endianess = Endianess::eBig;
		break;
	case 0x02:
		// big endian 
		binary->endianess = Endianess::eLittle;
		break;
	default:
		printf("Not supported Endianess\n");
		return false;
	}
	//ELF Version
	switch (file->data[6]) {
	case 0x01:
		break;
	default:
		printf("Not supported Elf version\n");
		return false;
	}
	//OS-ABI
	if (file->data[7] <= 0x11 && systems[file->data[7]]) {
		//binary->stringDB.insert(std::pair<HString, HString>(holokey::system, systems[data[7]]));
	}
	else if (file->data[7] == 0x53) {
		//binary->stringDB.insert(std::pair<HString, HString>(holokey::system, "Sortix"));
	}
	else {
		return false;
	}
	//ABI Version + Padding ignored

	//Type
	switch (getValue<uint16_t>(file, 0x10, binary->endianess)) {
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
		printf("Not supported Type 0x%02x\n", getValue<uint16_t>(file, 0x10, binary->endianess));
		return false;
	}
	//Instruction Set
	elf_is = (Elf_Instructionset)getValue<uint16_t>(file, 0x12, binary->endianess);
	if (instructionsets[elf_is]) {
		printf("InstructionSet: %s\n", instructionsets[elf_is]);
	}
	switch (elf_is) {
	case ELF_IS_X86:
		binary->arch = holodec::Main::g_main->getArchitecture("x86");
		break;
	default:
		break;
	}
	//ELF Version
	if (getValue<uint32_t>(file, 0x14, binary->endianess) == 1)
		printf("Original Version\n");
	else
		printf("Not supported Version\n");

	size_t offset64bit;
	if (binary->bytebase == 4) {
		//Ptr to EntryPoint handled later
		//Ptr to Program Header Table
		programHeaderTable.offset = getValue<uint32_t>(file, 0x1C, binary->endianess);
		//Ptr to Section Header Table
		sectionHeaderTable.offset = getValue<uint32_t>(file, 0x20, binary->endianess);
		offset64bit = 0;
	}
	else {
		//Ptr to EntryPoint
		//Ptr to Program Header Table
		programHeaderTable.offset = getValue<uint64_t>(file, 0x20, binary->endianess);
		//Ptr to Section Header Table
		sectionHeaderTable.offset = getValue<uint64_t>(file, 0x28, binary->endianess);
		offset64bit = 0xC;
	}
	printf("Processor specific Flags: %d\n", getValue<uint32_t>(file, 0x24 + offset64bit, binary->endianess));
	printf("Header Size: 0x%X\n", getValue<uint16_t>(file, 0x28 + offset64bit, binary->endianess));
	programHeaderTable.size = getValue<uint16_t>(file, 0x2A + offset64bit, binary->endianess);
	programHeaderTable.entries = getValue<uint16_t>(file, 0x2C + offset64bit, binary->endianess);

	sectionHeaderTable.size = getValue<uint16_t>(file, 0x2E + offset64bit, binary->endianess);
	sectionHeaderTable.entries = getValue<uint16_t>(file, 0x30 + offset64bit, binary->endianess);
	sectionHeaderTable.namesectionindex = getValue<uint16_t>(file, 0x32 + offset64bit, binary->endianess);
	return true;
}
//https://github.com/tbursztyka/python-elf/tree/master/elf

bool holoelf::ElfBinaryAnalyzer::parseProgramHeaderTable() {

	size_t entrysize = 0;

	if (binary->bytebase == 4)
		entrysize = 0x20;
	else if (binary->bytebase == 8)
		entrysize = 0x38;

	for (unsigned int i = 0; i < programHeaderTable.entries; i++) {
		size_t entryoffset = programHeaderTable.offset + i * entrysize;

		if (getValue<uint32_t>(file, entryoffset, binary->endianess) == 0x1) {
			Section* section = new Section();

			uint32_t flags = 0;
			if (binary->bytebase == 4)
				flags = getValue<uint32_t>(file, entryoffset + 0x18, binary->endianess);
			else if (binary->bytebase == 8)
				flags = getValue<uint32_t>(file, entryoffset + 0x04, binary->endianess);
			section->srwx = (flags & 0x4 ? 0x1 : 0x0) | (flags & 0x2 ? 0x2 : 0x0) | (flags & 0x1 ? 0x4 : 0x0);

			if (binary->bytebase == 4) {
				section->offset = getValue<uint32_t>(file, entryoffset + 0x04, binary->endianess);
				section->vaddr = getValue<uint32_t>(file, entryoffset + 0x08, binary->endianess);
				//section.paddr = data.get<uint32_t> (entryoffset + 0x0C);
				//section.size = data.get<uint32_t> (entryoffset +0x10);//Size in File Image
				section->size = getValue<uint32_t>(file, entryoffset + 0x14, binary->endianess);//Size in Memory
																			   //printf ("Alignment: %X\n", data.get<uint32_t> (entryoffset + 0x1C));
			}
			else if (binary->bytebase == 8) {
				section->offset = getValue<uint32_t>(file, entryoffset + 0x08, binary->endianess);
				section->vaddr = getValue<uint32_t>(file, entryoffset + 0x10, binary->endianess);
				//section.paddr = data.get<uint32_t> (entryoffset + 0x18);
				//section.size = data.get<uint32_t> (entryoffset + 0x20);//Size in File Image
				section->size = getValue<uint32_t>(file, entryoffset + 0x28, binary->endianess);//Size in Memory
																			   //printf ("Alignment: %X\n", data.get<uint32_t> (entryoffset + 0x30));
			}

			binary->addSection(section);
		}

	}
	return true;
}

bool holoelf::ElfBinaryAnalyzer::parseSectionHeaderTable() {

	size_t entrysize = 0;

	if (binary->bytebase == 4)
		entrysize = 0x28;
	else if (binary->bytebase == 8)
		entrysize = 0x40;
		
#ifdef _MSC_VER
	Section** sections = new Section*[sectionHeaderTable.entries];
#else
	Section* sections[sectionHeaderTable.entries];
#endif
	for (unsigned int i = 0; i < sectionHeaderTable.entries; i++)
		sections[i] = new Section();
#ifdef _MSC_VER
	uint32_t* nameoffset = new uint32_t[sectionHeaderTable.entries];
#else
	uint32_t nameoffset[sectionHeaderTable.entries];
#endif

	for (unsigned int i = 0; i < sectionHeaderTable.entries; i++) {
		size_t entryoffset = sectionHeaderTable.offset + i * entrysize;
		//TODO check size
		//size_t size = binary->data->size - entryoffset;

		nameoffset[i] = getValue<uint32_t>(file, entryoffset + 0x00, binary->endianess);

		uint64_t flags = binary->bytebase == 4 ? getValue<uint32_t>(file, entryoffset + 0x08, binary->endianess) : getValue<uint32_t>(file, entryoffset + 0x08, binary->endianess);
		sections[i]->srwx = 0;
		if (flags & 0x1)
			sections[i]->srwx |= 0x2;
		//printf ("SHF_WRITE\n");
		if (flags & 0x2)
			sections[i]->srwx |= 0x1;
		//printf ("SHF_ALLOC\n");
		if (flags & 0x4)
			sections[i]->srwx |= 0x4;
		//printf ("SHF_EXECINSTR\n");

		if (binary->bytebase == 4) {
			sections[i]->vaddr = getValue<uint32_t>(file, entryoffset + 0x0C, binary->endianess);
			sections[i]->offset = getValue<uint32_t>(file, entryoffset + 0x10, binary->endianess);
			sections[i]->size = getValue<uint32_t>(file, entryoffset + 0x14, binary->endianess);
			//printf ("Link: %X\n", binary->getValue<uint32_t> (entryoffset + 0x18));
			//printf ("Info: %X\n", binary->getValue<uint32_t> (entryoffset + 0x1C));
			//printf ("Alignment: %X\n", binary->getValue<uint32_t> (entryoffset + 0x20));
			//printf ("Entrysize: %X\n", binary->getValue<uint32_t> (entryoffset + 0x24));
		}
		else if (binary->bytebase == 8) {
			sections[i]->vaddr = getValue<uint32_t>(file, entryoffset + 0x10, binary->endianess);
			sections[i]->offset = getValue<uint32_t>(file, entryoffset + 0x18, binary->endianess);
			sections[i]->size = getValue<uint32_t>(file, entryoffset + 0x20, binary->endianess);
			//printf ("Link: %X\n", binary->getValue<uint32_t> (entryoffset + 0x28));
			//printf ("Info: %X\n", binary->getValue<uint32_t> (entryoffset + 0x2C));
			//printf ("Alignment: %X\n", getValue<uint64_t> (data, 0x30));
			//printf ("Entrysize: %X\n", getValue<uint64_t> (data, 0x38));
		}
	}
	const void* nameentryptr = getPtrInFile<void>(file, sections[sectionHeaderTable.namesectionindex]->offset);
	for (unsigned int i = 0; i < sectionHeaderTable.entries; i++) {
		Section* section = sections[i];
		section->name = static_cast<const char*> (nameentryptr) + nameoffset[i];
		printf("Name: %s\n", section->name.cstr());
		printf("Addr: 0x%" PRIx64 "\n", section->offset);
		printf("Size: 0x%" PRIx64 "\n", section->size);
		if (!section->vaddr)
			continue;
		binary->addSection(section);
	}
#ifdef _MSC_VER
	delete[]sections;
	delete[]nameoffset;
#endif
	return true;
}
