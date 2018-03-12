#include <stdio.h>
#include <assert.h>
#include "Binary.h"
#include "binary/elf/ElfBinaryAnalyzer.h"
#include "binary/ihex/IHexBinaryAnalyzer.h"
#include "arch/x86/X86FunctionAnalyzer.h"
#include "arch/AvrFunctionAnalyzer.h"

#include "Main.h"
#include "FileFormat.h"
#include "Architecture.h"
#include "IRGen.h"
#include "SSAGen.h"
#include "SSAPhiNodeGenerator.h"
#include "SSAAddressToBlockTransformer.h"
#include "SSACallingConvApplier.h"
#include "SSAAssignmentSimplifier.h"
#include "SSADCETransformer.h"
#include "SSACalleeCallerRegs.h"
#include "HIdList.h"
#include "SSAPeepholeOptimizer.h"
#include "SSATransformToC.h"
#include "SSAApplyRegRef.h"
#include "PeepholeOptimizer.h"
#include "ScriptingInterface.h"

#include "CHolodec.h"

#include <thread>

#include "HoloIO.h"


//FileFormat		-> proposes BinaryAnalyzer
//BinaryAnalyzer	-> configuration
//					-> proposes Architecture
//					-> maps data into vmemory
//Architecture		-> proposes FunctionAnalyzer

//Binary -> Symbol, Section, Function, DataSegment, Architecture*
//Binary -> Architecture*
//Symbol -> Symbol, Binary*
//Section -> Symbol, Binary*, CC*
//Function -> Symbol, Binary*, SSARep
//Architecture -> CC, ISA, Regs

using namespace holodec;

FileFormat elffileformat = { "elf", "elf",{
	[](File* file, HString name) {
		static holoelf::ElfBinaryAnalyzer* analyzer = nullptr;
		if (analyzer == nullptr) {
			printf("Create New Object\n");
			analyzer = new holoelf::ElfBinaryAnalyzer();
		}
		if (analyzer->canAnalyze(file)) {
			holoelf::ElfBinaryAnalyzer* temp = analyzer;
			analyzer = nullptr;
			return (BinaryAnalyzer*)temp;
		}
		return (BinaryAnalyzer*) nullptr;
	}
}
};
FileFormat ihexfileformat = { "ihex", "ihex",{
	[](File* file, HString name) {
		static holoihex::IHexBinaryAnalyzer* analyzer = nullptr;
		if (analyzer == nullptr) {
			printf("Create New Object\n");
			analyzer = new holoihex::IHexBinaryAnalyzer();
		}
		if (analyzer->canAnalyze(file)) {
			holoihex::IHexBinaryAnalyzer* temp = analyzer;
			analyzer = nullptr;
			return (BinaryAnalyzer*)temp;
		}
		return (BinaryAnalyzer*) nullptr;
	}
}
};
extern Architecture holox86::x86architecture;


int main (int argc, const char** argv) {

	 
	 
	g_logger.log<LogLevel::eInfo> ("Init X86\n");

	if (argc < 2) {
		g_logger.log<LogLevel::eWarn>("No parameters given\n");
		return -1;
	}

	g_logger.log<LogLevel::eInfo>("Analysing file %s\n", argv[1]);
	HString filename = argv[1];
	Main::initMain();
	File* file = Main::loadDataFromFile (filename);
	if (!file) {
		g_logger.log<LogLevel::eWarn> ("Could not Load File %s\n", filename.cstr());
		return -1;
	}

	Main::g_main->registerFileFormat (&elffileformat);
	Main::g_main->registerArchitecture (&holox86::x86architecture);

	Main::g_main->registerFileFormat(&ihexfileformat);
	Main::g_main->registerArchitecture(&holoavr::avrarchitecture);

	g_logger.log<LogLevel::eInfo> ("Init X86\n");
	holox86::x86architecture.init();
	holoavr::avrarchitecture.init();

	//ScriptingInterface script;
	//script.testModule(&holox86::x86architecture);


	BinaryAnalyzer* analyzer = nullptr;
	for (FileFormat * fileformat : Main::g_main->fileformats) {
		analyzer = fileformat->createBinaryAnalyzer (file, "binary");
		if (analyzer)
			break;
	}
	analyzer->init (file);
	Binary* binary = analyzer->binary;

	for(Section* section : binary->sections){
		section->print();
	}

	FunctionAnalyzer* func_analyzer = nullptr;
	for (Architecture * architecture : Main::g_main->architectures) {
		func_analyzer = architecture->createFunctionAnalyzer (binary);
		if (func_analyzer)
			break;
	}
	assert(func_analyzer);
	func_analyzer->init (binary);

	printf ("DataSegment: %s\n", binary->defaultArea->name.name.cstr());

	binary->print();

	for (Symbol* sym : binary->symbols) {
		if (sym->symboltype == &SymbolType::symfunc) {
			Function* newfunction = new Function();
			newfunction->symbolref = sym->id;
			newfunction->baseaddr = sym->vaddr;
			newfunction->addrToAnalyze.insert (sym->vaddr);
			binary->functions.push_back (newfunction);
		}
	}
	bool funcAnalyzed;
	do {
		funcAnalyzed = false;
		for (Function* func : binary->functions) {
			if (!func->addrToAnalyze.empty()) {
				func_analyzer->analyzeFunction (func);
				funcAnalyzed = true;
				if (!func->funcsCalled.empty()) {
					for (uint64_t addr : func->funcsCalled) {
						if (binary->findSymbol (addr, &SymbolType::symfunc) == nullptr) {
							char buffer[100];
							snprintf (buffer, 100, "func_0x%" PRIx64 "", addr);
							Symbol* symbol = new Symbol ({0, buffer, &SymbolType::symfunc, 0, addr, 0});
							binary->addSymbol (symbol);
							Function* newfunction = new Function();
							newfunction->symbolref = symbol->id;
							newfunction->baseaddr = symbol->vaddr;
							newfunction->addrToAnalyze.insert(symbol->vaddr);
							binary->functions.push_back (newfunction);
						}
					}
				}
				break;
			}
		}
	} while (funcAnalyzed);

	binary->print();

	std::vector<SSATransformer*> transformers = {
		new SSAAddressToBlockTransformer(),//0
		new SSAPhiNodeGenerator(),//1
		new SSAAssignmentSimplifier(),//2
		new SSAPeepholeOptimizer(),//3
		new SSADCETransformer(),//4
		new SSAApplyRegRef(),//5
		new SSATransformToC(),//6
		new SSACalleeCallerRegs(),//7
	};

	for (SSATransformer* transform : transformers) {
		transform->arch = binary->arch;
	}

	PeepholeOptimizer* optimizer = parsePhOptimizer ();

	g_peephole_logger.level = LogLevel::eDebug;
	for (Function* func : binary->functions) {
		printf("Function: %s\n", binary->getSymbol(func->symbolref)->name.cstr());
	}
	g_peephole_logger.level = LogLevel::eInfo;
	
	HList<uint64_t> funcs = {
		0x0,
		0x1f7f,
		0x2525,
		0x2516,
	};
	for (Function* func : binary->functions) {
	//for (uint64_t addr : funcs) {
	//	Function* func = binary->getFunctionByAddr(addr);
		if (func) {
			transformers[0]->doTransformation(binary, func);
			transformers[1]->doTransformation(binary, func);
			assert(func->ssaRep.checkIntegrity());
			func->ssaRep.recalcRefCounts();
		}
	}
	bool funcChanged = false;
	do {
		printf("---------------------\n");
		printf("Run Transformations\n");
		printf("---------------------\n");
		funcChanged = false;

		for (Function* func : binary->functions) {
		//for (uint64_t addr : funcs) {
		//	Function* func = binary->getFunctionByAddr(addr);
			if (func) {
				bool applied = false;
				do {
					applied = false;
					applied |= transformers[2]->doTransformation(binary, func);
					func->ssaRep.recalcRefCounts();
					assert(func->ssaRep.checkIntegrity());
					applied |= transformers[3]->doTransformation(binary, func);
					applied |= transformers[4]->doTransformation(binary, func);
					applied |= transformers[5]->doTransformation(binary, func);
					funcChanged |= transformers[7]->doTransformation(binary, func);
					funcChanged |= applied;
					//func->print(binary->arch);
				} while (applied);
				func->ssaRep.recalcRefCounts();
			}
		}
	} while (funcChanged);
	for (Function* func : binary->functions) {
	//for (uint64_t addr : funcs) {
	//	Function* func = binary->getFunctionByAddr(addr);
		if (func) {
			func->ssaRep.recalcRefCounts();
			holodec::g_logger.log<LogLevel::eInfo>("Symbol %s", binary->getSymbol(func->symbolref)->name.cstr());
			//func->print(binary->arch);
			//transformers[6]->doTransformation(binary, func);
			func->print(binary->arch);
		}
	}
	delete optimizer;

	return 0;
}
