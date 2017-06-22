#ifndef R_ELFBINARYANALYZER_H
#define R_ELFBINARYANALYZER_H

#include "RBinary.h"
#include "RString.h"
#include "RBinaryAnalyzer.h"

namespace holoelf {

	enum Elf_Instructionset {
	    ELF_IS_MIPS_I = 8,
	    ELF_IS_MIPS_RS3000 = 10,
	    ELF_IS_ARM = 40,
	    ELF_IS_MIPS_X = 51,
	    ELF_IS_X86 = 62,
	};
	class RElfBinaryAnalyzer : public holodec::RBinaryAnalyzer {

		holodec::RBinary* binary;

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

		size_t entrypoint;

		size_t bitcount;

	public:
		RElfBinaryAnalyzer () : holodec::RBinaryAnalyzer ("elf", "elf") {}

		virtual bool canAnalyze(holodec::RData* data);
		
		virtual bool init (holodec::RData* data);
		virtual bool terminate();

		virtual holodec::RBinary* getBinary () {
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

#endif // R_ELFBINARYANALYZER_H
