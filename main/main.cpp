#include <stdio.h>
#include <HBinary.h>
#include <binary/elf/HElfBinaryAnalyzer.h>
#include <arch/x86/Hx86FunctionAnalyzer.h>

#include "HMain.h"
#include "HFileFormat.h"
#include "HArchitecture.h"
#include "HIRGen.h"
#include "HSSAGen.h"
#include "HSSAPhiNodeGenerator.h"
#include "HSSAAddressToBlockTransformer.h"
#include "HSSACallingConvApplier.h"
#include "HSSAAssignmentSimplifier.h"
#include "HSSADeadCodeEliminationTransformer.h"
#include "HIdList.h"

using namespace holodec;

HString filename = "../../workingdir/leo";

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

int main (int argc, char** argv) {
	
	
	HMain::initHMain();
	HData* data = HMain::loadHDataFromFile (filename);
	if (!data) {
		printf ("Could not Load File %s\n", filename.cstr());
		return -1;
	}

	HMain::gh_main->registerFileFormat (&elffileformat);
	HMain::gh_main->registerArchitecture (&holox86::x86architecture);

	printf ("Init X86\n");
	holox86::x86architecture.init();

	HBinaryAnalyzer* analyzer = nullptr;
	for (HFileFormat * fileformat : HMain::gh_main->fileformats) {
		analyzer = fileformat->createBinaryAnalyzer (data);
		if (analyzer)
			break;
	}
	analyzer->init (data);
	HBinary* binary = analyzer->getBinary();

	HFunctionAnalyzer* func_analyzer;
	for (HArchitecture * architecture : HMain::gh_main->architectures) {
		func_analyzer = architecture->createFunctionAnalyzer (binary);
		if (func_analyzer)
			break;
	}
	func_analyzer->init (binary);

	printf ("Binary File: %s\n", binary->data->filename.cstr());
	printf ("Size: %d Bytes\n", binary->data->size);


	binary->print();

	holox86::x86architecture.print();


	HSSATransformer* transformer1 = new HSSAAddressToBlockTransformer();
	HSSATransformer* transformer2 = new HSSACallingConvApplier();
	HSSATransformer* transformer3 = new HSSAPhiNodeGenerator();
	HSSATransformer* transformer4 = new HSSAAssignmentSimplifier();
	HSSATransformer* transformer5 = new HSSADeadCodeEliminationTransformer();

	transformer1->arch = &holox86::x86architecture;
	transformer2->arch = &holox86::x86architecture;
	transformer3->arch = &holox86::x86architecture;
	transformer4->arch = &holox86::x86architecture;
	transformer5->arch = &holox86::x86architecture;
	
	for (HSymbol& sym : binary->symbols){
		if(sym.symboltype == &HSymbolType::symfunc){
			func_analyzer->analyzeFunction (&sym);
		}
	}
	
	
	for (HFunction& func : binary->functions) {
		
		transformer1->doTransformation (&func);
		func.callingconvention = holox86::x86architecture.getCallingConvention("amd64")->id;
		transformer2->doTransformation (&func);
		transformer3->doTransformation (&func);
		//from here remove actually expressions
		transformer4->doTransformation (&func);
		transformer5->doTransformation (&func);
		func.print (&holox86::x86architecture);
	}
	return 0;
}
