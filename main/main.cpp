#include <stdio.h>
#include <HBinary.h>
#include <HElfBinaryAnalyzer.h>
#include "Hx86FunctionAnalyzer.h"

#include "HMain.h"
#include "HFileFormat.h"
#include "HArchitecture.h"

using namespace holodec;

HString filename = "E:/GNUProg/holodec/workingdir/leo";

HFileFormat elffileformat = {"elf", "elf", {
		[] (HData * data, HString name) {
			static holoelf::HElfBinaryAnalyzer* analyzer = nullptr;
			if (analyzer == nullptr) {
				printf ("Create New Object\n");
				analyzer = new holoelf::HElfBinaryAnalyzer();
			}
			if (analyzer->canAnalyze (data)) {
				holoelf::HElfBinaryAnalyzer* temp = analyzer;
				analyzer = nullptr;
				return (HBinaryAnalyzer*) temp;
			}
			return (HBinaryAnalyzer*) nullptr;
		}
	}
};
extern HArchitecture holox86::x86architecture;

int main (int argc, char** argv, char** envp) {
	
	
	HMain::initHMain();
	HData* data = HMain::loadHDataFromFile (filename);

	HMain::gr_main->registerFileFormat (&elffileformat);
	HMain::gr_main->registerArchitecture (&holox86::x86architecture);

	HBinaryAnalyzer* analyzer = nullptr;
	for (HFileFormat * fileformat : HMain::gr_main->fileformats) {
		analyzer = fileformat->createBinaryAnalyzer (data);
		if (analyzer)
			break;
	}
	analyzer->init (data);
	HBinary* binary = analyzer->getBinary();
	
	HFunctionAnalyzer* func_analyzer;
	for (HArchitecture * architecture : HMain::gr_main->architectures) {
		func_analyzer = architecture->createFunctionAnalyzer (binary);
		if (func_analyzer)
			break;
	}
	func_analyzer->init (binary);

	printf ("Binary File: %s\n", binary->data->filename.cstr());
	printf ("Size: %d Bytes\n", binary->data->size);
	

	binary->print();

	holox86::x86architecture.print();

	for (HId& id : binary->entrypoints) {
		func_analyzer->analyzeFunction(binary->getSymbol(id));
	}
	
	printf("%d\n",sizeof(HInstruction));
	printf("%d\n",sizeof(HInstArgument));
	

	return 0;
}
//binary analyzer
//data analyzer
//assembler/disassembler
