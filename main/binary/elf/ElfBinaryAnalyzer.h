#ifndef H_ELFBINAHYANALYZEH_H
#define H_ELFBINAHYANALYZEH_H

#include "../../Binary.h"
#include "../../HString.h"
#include "../../BinaryAnalyzer.h"

namespace holoelf {

	enum Elf_Instructionset {
		ELF_IS_MIPS_I = 8,
		ELF_IS_MIPS_HS3000 = 10,
		ELF_IS_AHM = 40,
		ELF_IS_MIPS_X = 51,
		ELF_IS_X86 = 62,
	};
	class ElfBinaryAnalyzer : public holodec::BinaryAnalyzer {

		holodec::Binary* binary;

		struct {
			size_t offset;
			size_t size;
			size_t entries;
		} programHeaderTable;

		struct {
			size_t offset;
			size_t size;
			size_t entries;
			size_t namesectionindex;
		} sectionHeaderTable;

		Elf_Instructionset elf_is;

	public:
		ElfBinaryAnalyzer () : holodec::BinaryAnalyzer ("elf", "elf") {}

		virtual bool canAnalyze(holodec::Data* data);
		
		virtual bool init (holodec::Data* data);
		virtual bool terminate();

		virtual holodec::Binary* getBinary () {
			return binary;
		}

		bool parseFileHeader();
		bool parseProgramHeaderTable();
		bool parseSectionHeaderTable();

	};

}
extern const char* instructionsets[];
extern const char* systems[];

#endif // H_ELFBINAHYANALYZEH_H
