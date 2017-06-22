#include "RElfBinaryAnalyzer.h"

#include <stdio.h>

using namespace holodec;


const char* instructionsets[] = {
	0,
	"AT&T WE 32100",
	"SPARC",
	"Intel 80386",
	"Motorola 68000",
	"Motorola 88000",
	0,
	"Intel 80860",
	"MIPS I Architecture",
	"IBM System/370 Processor",
	"MIPS RS3000 Little-endian",//10
	0, 0, 0, 0,
	"Hewlett-Packard PA-RISC",
	0,
	"Fujitsu VPP500",
	"Enhanced instruction set SPARC",
	"Intel 80960",
	"PowerPC",//20
	"64-bit PowerPC",
	"IBM System/390 Processor",
	0, 0, 0, 0, 0, 0, 0, 0, //30
	0, 0, 0, 0, 0,
	"NEC V800",
	"Fujitsu FR20",
	"TRW RH-32",
	"Motorola RCE",
	"Advanced RISC Machines ARM",//40
	"Digital Alpha",
	"Hitachi SH",
	"SPARC Version 9",
	"Siemens TriCore embedded processor",
	"Argonaut RISC Core, Argonaut Technologies Inc.",
	"Hitachi H8/300",
	"Hitachi H8/300H",
	"Hitachi H8S",
	"Hitachi H8/500",
	"Intel IA-64 processor architecture",//50
	"Stanford MIPS-X",
	"Motorola ColdFire",
	"Motorola M68HC12",
	"Fujitsu MMA Multimedia Accelerator",
	"Siemens PCP",
	"Sony nCPU embedded RISC processor",
	"Denso NDR1 microprocessor",
	"Motorola Star*Core processor",
	"Toyota ME16 processor",
	"STMicroelectronics ST100 processor",//60
	"Advanced Logic Corp. TinyJ embedded processor family",
	"AMD x86-64 architecture",
	"Sony DSP Processor",
	"Digital Equipment Corp. PDP-10",
	"Digital Equipment Corp. PDP-11",
	"Siemens FX66 microcontroller",
	"STMicroelectronics ST9+ 8/16 bit microcontroller",
	"STMicroelectronics ST7 8-bit microcontroller",
	"Motorola MC68HC16 Microcontroller",
	"Motorola MC68HC11 Microcontroller",//70
	"Motorola MC68HC08 Microcontroller",
	"Motorola MC68HC05 Microcontroller",
	"Silicon Graphics SVx",
	"STMicroelectronics ST19 8-bit microcontroller",
	"Digital VAX",
	"Axis Communications 32-bit embedded processor",
	"Infineon Technologies 32-bit embedded processor",
	"Element 14 64-bit DSP Processor",
	"LSI Logic 16-bit DSP Processor",
	"Donald Knuth's educational 64-bit processor",//80
	"Harvard University machine-independent object files",
	"SiTera Prism",
	"Atmel AVR 8-bit microcontroller",
	"Fujitsu FR30",
	"Mitsubishi D10V",
	"Mitsubishi D30V",
	"NEC v850",
	"Mitsubishi M32R",
	"Matsushita MN10300",
	"Matsushita MN10200",//90
	"picoJava",
	"OpenRISC 32-bit embedded processor",
	"ARC Cores Tangent-A5",
	"Tensilica Xtensa Architecture",
	"Alphamosaic VideoCore processor",
	"Thompson Multimedia General Purpose Processor",
	"National Semiconductor 32000 series",
	"Tenor Network TPC processor",
	"Trebia SNP 1000 processor",
	"STMicroelectronics (www.st.com) ST200 microcontroller",//100
	"Ubicom IP2xxx microcontroller family",
	"MAX Processor",
	"National Semiconductor CompactRISC microprocessor",
	"Fujitsu F2MC16",
	"Texas Instruments embedded microcontroller msp430",
	"Analog Devices Blackfin (DSP) processor",
	"S1C33 Family of Seiko Epson processors",
	"Sharp embedded microprocessor",
	"Arca RISC Microprocessor",
	"Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University"//110
};

bool holoelf::RElfBinaryAnalyzer::canAnalyze(holodec::RData* pdata){
	holodec::RData data = *pdata;
	//Magic number
	if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
		printf ("Wrong Header %s\n", data.data);
		return false;
	}
	return true;
}
bool holoelf::RElfBinaryAnalyzer::init (holodec::RData* file) {
	if (!file)
		return false;
	this->binary = new holodec::RBinary (file);
	

	if (!parseFileHeader())
		return false;

	if (!parseProgramHeaderTable())
		return false;

	if (!parseSectionHeaderTable())
		return false;

	RSymbol symbol = {
		"entry0", RSymbolType::symfunc, 0, entrypoint, entrypoint, 0
	};
	RSymbol* entry = binary->addSymbol (&symbol);
	binary->addEntrypoint (entry);

	return true;
}
bool holoelf::RElfBinaryAnalyzer::terminate() {
	return true;
}

void holoelf::RElfBinaryAnalyzer::analyzeAllSymbols() {
}

void holoelf::RElfBinaryAnalyzer::analyzeEntryPoint() {
}

void holoelf::RElfBinaryAnalyzer::analyzeFunctions() {
}

void holoelf::RElfBinaryAnalyzer::analyzeStrings() {
}

void holoelf::RElfBinaryAnalyzer::analyzeValues() {
}

void holoelf::RElfBinaryAnalyzer::doSectionAnalysis() {
}

template<typename T>
inline T getValue (uint8_t* data, size_t offset) {
	return ( (T*) (data + offset)) [0];
}

bool holoelf::RElfBinaryAnalyzer::parseFileHeader() {

	RData& data = *binary->data;

	//Magic number
	if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
		printf ("Wrong Header %s\n", data.data);
		return false;
	}
	//Architecture flag
	switch (data[4]) {
	case 0x01:
		printf ("32-bit\n");
		bitcount = 32;
		break;
	case 0x02:
		printf ("64-bit\n");
		bitcount = 64;
		break;
	default:
		printf ("Not supported Architecture\n");
		return false;
	}
	//Endianess flag
	switch (data[5]) {
	case 0x01:
		printf ("little endian\n");
		break;
	case 0x02:
		printf ("big endian\n");
		break;
	default:
		printf ("Not supported Endianess\n");
		return false;
	}
	//ELF Version
	switch (data[6]) {
	case 0x01:
		printf ("Orignal Elf\n");
		break;
	default:
		printf ("Not supported Elf version\n");
		return false;
	}
	//OS-ABI
	switch (data[7]) {
	case 0x00:
		printf ("System V or default\n");
		break;
	case 0x01:
		printf ("HP-UX\n");
		break;
	case 0x02:
		printf ("NetBSD\n");
		break;
	case 0x03:
		printf ("Linux\n");
		break;
	case 0x04:
		printf ("GNU Hurd\n");
		break;
	case 0x06:
		printf ("Solaris\n");
		break;
	case 0x07:
		printf ("AIX\n");
		break;
	case 0x08:
		printf ("IRIX\n");
		break;
	case 0x09:
		printf ("FreeBSD\n");
		break;
	case 0x0a:
		printf ("Tru64\n");
		break;
	case 0x0b:
		printf ("Novell Modesto\n");
		break;
	case 0x0c:
		printf ("OpenBSD\n");
		break;
	case 0x0d:
		printf ("OpenVMS\n");
		break;
	case 0x0e:
		printf ("NonStop Kernel\n");
		break;
	case 0x0f:
		printf ("AROS\n");
		break;
	case 0x10:
		printf ("Fenix OS\n");
		break;
	case 0x11:
		printf ("CloudABI\n");
		break;
	case 0x53:
		printf ("Sortix\n");
		break;
	}
	//ABI Version + Padding ignored

	//Type
	switch (data.get<uint16_t> (0x10)) {
	case 1:
		printf ("Relocatable\n");
		break;
	case 2:
		printf ("Executable\n");
		break;
	case 3:
		printf ("Shared\n");
		break;
	case 4:
		printf ("Core\n");
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
	if (instructionsets[elf_is])
		printf ("InstructionSet: %s\n", instructionsets[elf_is]);
	switch(elf_is){
	case 62:
		binary->arch = holodec::copyRString("x86");
		break;
		
	}
	//ELF Version
	if (data.get<uint32_t> (0x14) == 1)
		printf ("Original Version\n");
	else
		printf ("Not supported Version\n");

	size_t offset64bit;
	if (bitcount == 32) {
		//Ptr to EntryPoint
		entrypoint = data.get<uint32_t> (0x18);
		//Ptr to Program Header Table
		programHeaderTable.offset = data.get<uint32_t> (0x1C);
		//Ptr to Section Header Table
		sectionHeaderTable.offset =  data.get<uint32_t> (0x20);
		offset64bit = 0;
	} else {
		//Ptr to EntryPoint
		entrypoint = data.get<size_t> (0x18);
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

bool holoelf::RElfBinaryAnalyzer::parseProgramHeaderTable () {

	size_t entrysize = 0;

	if (bitcount == 32)
		entrysize = 0x20;
	else if (bitcount == 64)
		entrysize = 0x38;

	for (unsigned int i = 0; i < programHeaderTable.entries; i++) {
		size_t entryoffset = programHeaderTable.offset + i * entrysize;
		RData& data = *binary->data;
		size_t size = binary->data->size - entryoffset;

		if (data.get<uint32_t> (entryoffset) == 0x1) {
			RSection section = RSection();

			uint32_t flags;
			if (bitcount == 32)
				flags = data.get<uint32_t> (entryoffset + 0x18);
			else if (bitcount == 64)
				flags = data.get<uint32_t> (entryoffset + 0x04);
			section.srwx = (flags & 0x4 ? 0x1 : 0x0) | (flags & 0x2 ? 0x2 : 0x0) | (flags & 0x1 ? 0x4 : 0x0);

			if (bitcount == 32) {
				section.offset = data.get<uint32_t> (entryoffset + 0x04);
				section.vaddr = data.get<uint32_t> (entryoffset + 0x08);
				section.paddr = data.get<uint32_t> (entryoffset + 0x0C);
				//section.size = data.get<uint32_t> (entryoffset +0x10);//Size in File Image
				section.size = data.get<uint32_t> (entryoffset + 0x14);//Size in Memory
				//printf ("Alignment: %X\n", data.get<uint32_t> (entryoffset + 0x1C));
			} else if (bitcount == 64) {
				section.offset = data.get<uint32_t> (entryoffset + 0x08);
				section.vaddr = data.get<uint32_t> (entryoffset + 0x10);
				section.paddr = data.get<uint32_t> (entryoffset + 0x18);
				//section.size = data.get<uint32_t> (entryoffset + 0x20);//Size in File Image
				section.size = data.get<uint32_t> (entryoffset + 0x28);//Size in Memory
				//printf ("Alignment: %X\n", data.get<uint32_t> (entryoffset + 0x30));
			}

			binary->addSection (&section);
		}

	}
	return true;
}

bool holoelf::RElfBinaryAnalyzer::parseSectionHeaderTable () {

	size_t entrysize = 0;

	if (bitcount == 32)
		entrysize = 0x28;
	else if (bitcount == 64)
		entrysize = 0x40;

	RSection sections[sectionHeaderTable.entries];
	for (RSection & section : sections)
		section = RSection();

	for (unsigned int i = 0; i < sectionHeaderTable.entries; i++) {
		size_t entryoffset = sectionHeaderTable.offset + i * entrysize;
		uint8_t* data = binary->data->data + entryoffset;
		size_t size = binary->data->size - entryoffset;
		sections[i].name = (char*) getValue<uint32_t> (data, 0x00);

		uint64_t flags = bitcount == 32 ? getValue<uint32_t> (data, 0x08) : getValue<uint64_t> (data, 0x08);
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

		if (bitcount == 32) {
			sections[i].vaddr = sections[i].paddr = getValue<uint32_t> (data, 0x0C);
			sections[i].offset = getValue<uint32_t> (data, 0x10);
			sections[i].size = getValue<uint32_t> (data, 0x14);
			//printf ("Link: %X\n", getValue<uint32_t> (data, 0x18));
			//printf ("Info: %X\n", getValue<uint32_t> (data, 0x1C));
			//printf ("Alignment: %X\n", getValue<uint32_t> (data, 0x20));
			//printf ("Entrysize: %X\n", getValue<uint32_t> (data, 0x24));
		} else if (bitcount == 64) {
			sections[i].vaddr = sections[i].paddr = getValue<uint32_t> (data, 0x10);
			sections[i].offset = getValue<uint32_t> (data, 0x18);
			sections[i].size = getValue<uint32_t> (data, 0x20);
			//printf ("Link: %X\n", getValue<uint32_t> (data, 0x28));
			//printf ("Info: %X\n", getValue<uint32_t> (data, 0x2C));
			//printf ("Alignment: %X\n", getValue<uint64_t> (data, 0x30));
			//printf ("Entrysize: %X\n", getValue<uint64_t> (data, 0x38));
		}
	}
	for (RSection & section : sections) {
		section.name += (size_t) binary->data->data + sections[sectionHeaderTable.namesectionindex].offset;
		if (!section.vaddr)
			continue;
		binary->addSection (&section);
	}
	return true;
}
