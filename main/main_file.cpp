#include <stdio.h>
#include <Binary.h>
#include <binary/elf/ElfBinaryAnalyzer.h>
#include <arch/x86/X86FunctionAnalyzer.h>

#include "Main.h"
#include "FileFormat.h"
#include "Architecture.h"
#include "IRGen.h"
#include "SSAGen.h"
#include "SSAPhiNodeGenerator.h"
#include "SSAAddressToBlockTransformer.h"
#include "SSACallingConvApplier.h"
#include "SSAAssignmentSimplifier.h"
#include "SSADeadCodeEliminationTransformer.h"
#include "HIdList.h"
#include "SSAPeepholeOptimizer.h"
#include "SSATransformToC.h"
#include "PeepholeOptimizer.h"
#include "ScriptingInterface.h"

using namespace holodec;

HString filename = "../../workingdir/leo";

FileFormat elffileformat = {"elf", "elf", {
		[] (Data * data, HString name) {
			static holoelf::ElfBinaryAnalyzer* analyzer = nullptr;
			if (analyzer == nullptr) {
				printf ("Create New Object\n");
				analyzer = new holoelf::ElfBinaryAnalyzer();
			}
			if (analyzer->canAnalyze (data)) {
				holoelf::ElfBinaryAnalyzer* temp = analyzer;
				analyzer = nullptr;
				return (BinaryAnalyzer*) temp;
			}
			return (BinaryAnalyzer*) nullptr;
		}
	}
};
extern Architecture holox86::x86architecture;

int main (int argc, char** argv) {
	
	
	
	/*
	 * Ok
	 * Let's go
	 * 
	 * Input i = MemAccess(0, unlimited)
	 * 
	 * uint64 xx = Lea(...)
	 * MemoryAccess yy = MemAccess(xx, size, list of possible overlapping MemoryAccesses)
	 * uint(size) zz = Load(yy, value, other MemoryAccess)
	 * MemoryAccess aa = Store(yy, value)
	 * 
	 */
	
	
	Main::initMain();
	Data* data = Main::loadDataFromFile (filename);
	if (!data) {
		printf ("Could not Load File %s\n", filename.cstr());
		return -1;
	}

	Main::g_main->registerFileFormat (&elffileformat);
	Main::g_main->registerArchitecture (&holox86::x86architecture);

	printf ("Init X86\n");
	holox86::x86architecture.init();

	//ScriptingInterface script;
	//script.testModule(&holox86::x86architecture);


	BinaryAnalyzer* analyzer = nullptr;
	for (FileFormat * fileformat : Main::g_main->fileformats) {
		analyzer = fileformat->createBinaryAnalyzer (data);
		if (analyzer)
			break;
	}
	analyzer->init (data);
	Binary* binary = analyzer->getBinary();

	FunctionAnalyzer* func_analyzer;
	for (Architecture * architecture : Main::g_main->architectures) {
		func_analyzer = architecture->createFunctionAnalyzer (binary);
		if (func_analyzer)
			break;
	}
	func_analyzer->init (binary);

	printf ("Binary File: %s\n", binary->data->filename.cstr());
	printf ("Size: %d Bytes\n", binary->data->size);


	binary->print();

	holox86::x86architecture.print();
	
	PeepholeOptimizer* optimizer = parsePhOptimizer("../../workingdir/standard.ph", &holox86::x86architecture);
	//return 0;

	std::vector<SSATransformer*> transformers = {
		new SSAAddressToBlockTransformer(),
		new SSACallingConvApplier(),
		new SSAPhiNodeGenerator(),
		new SSAAssignmentSimplifier(),
		new SSADeadCodeEliminationTransformer(),
		//new SSAPeepholeOptimizer(),
		new SSATransformToC()
	};

	for(SSATransformer* transform : transformers){
		transform->arch = &holox86::x86architecture;
	}

	
	for (Symbol& sym : binary->symbols){
		if(sym.symboltype == &SymbolType::symfunc){
			func_analyzer->analyzeFunction (&sym);
		}
	}
	
	
	for (Function& func : binary->functions) {
		
		func.callingconvention = holox86::x86architecture.getCallingConvention("amd64")->id;
		
		for(SSATransformer* transform : transformers){
			transform->doTransformation(&func);
		}
		func.print (&holox86::x86architecture);
	}
	return 0;
}
