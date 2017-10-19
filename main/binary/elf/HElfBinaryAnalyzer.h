#ifndef H_ELFBINAHYANALYZEH_H
#define H_ELFBINAHYANALYZEH_H

#include "HBinary.h"
#include "HString.h"
#include "HBinaryAnalyzer.h"

namespace holoelf {

	enum Elf_Instructionset {
	    ELF_IS_MIPS_I = 8,
	    ELF_IS_MIPS_HS3000 = 10,
	    ELF_IS_AHM = 40,
	    ELF_IS_MIPS_X = 51,
	    ELF_IS_X86 = 62,
	};
	class HElfBinaryAnalyzer : public holodec::HBinaryAnalyzer {

		holodec::HBinary* binary;

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
		HElfBinaryAnalyzer () : holodec::HBinaryAnalyzer ("elf", "elf") {}

		virtual bool canAnalyze(holodec::HData* data);
		
		virtual bool init (holodec::HData* data);
		virtual bool terminate();

		virtual holodec::HBinary* getBinary () {
			return binary;
		}
		virtual void analyzeAllSymbols();
		virtual void analyzeEntryPoint();
		virtual void analyzeFunctions();
		virtual void analyzeStrings();
		virtual void analyzeValues();
		virtual void doSectionAnalysis();

		bool parseFileHeader();
		bool parseProgramHeaderTable();
		bool parseSectionHeaderTable();

	};

}
extern const char* instructionsets[];
extern const char* systems[];

#endif // H_ELFBINAHYANALYZEH_H
