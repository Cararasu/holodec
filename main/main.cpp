#include <stdio.h>
#include <RBinary.h>
#include <RElfBinaryAnalyzer.h>
#include "Rx86FunctionAnalyzer.h"

#include "RMain.h"
#include "RFileFormat.h"
#include "RArchitecture.h"
using namespace holodec;

RString filename = "E:/GNUProg/holodec/workingdir/leo";

RFileFormat elffileformat = {"elf", "elf", {
		[] (RData * data, RString name) {
			static holoelf::RElfBinaryAnalyzer* analyzer = nullptr;
			if (analyzer == nullptr) {
				printf ("Create New Object\n");
				analyzer = new holoelf::RElfBinaryAnalyzer();
			}
			if (analyzer->canAnalyze (data)) {
				holoelf::RElfBinaryAnalyzer* temp = analyzer;
				analyzer = nullptr;
				return (RBinaryAnalyzer*) temp;
			}
			return (RBinaryAnalyzer*) nullptr;
		}
	}
};
extern RArchitecture holox86::x86architecture;

int main (int argc, char** argv) {

	RMain::initRMain();
	RData* data = RMain::loadRDataFromFile (filename);

	RMain::gr_main->registerFileFormat (&elffileformat);
	RMain::gr_main->registerArchitecture (&holox86::x86architecture);

	RBinaryAnalyzer* analyzer = nullptr;
	for (RFileFormat * fileformat : RMain::gr_main->fileformats) {
		analyzer = fileformat->createBinaryAnalyzer (data);
		if (analyzer)
			break;
	}
	analyzer->init (data);
	RBinary* binary = analyzer->getBinary();

	RFunctionAnalyzer* func_analyzer;
	for (RArchitecture * architecture : RMain::gr_main->architectures) {
		func_analyzer = architecture->createFunctionAnalyzer (binary);
		if (func_analyzer)
			break;
	}
	func_analyzer->init (binary);

	printf ("Binary File: %s\n", binary->data->filename.cstr());
	printf ("Size: %d Bytes\n", binary->data->size);
	

	binary->print();

	holox86::x86architecture.print();
	
	holodec::RList<holodec::RFunction*> list = func_analyzer->analyzeFunctions (&binary->entrypoints);

	for (RSymbol * symbol : binary->entrypoints) {
		func_analyzer->analyzeFunction(symbol);
	}

	return 0;
}
//binary analyzer
//data analyzer
//assembler/disassembler

//File
//Binary -> File
