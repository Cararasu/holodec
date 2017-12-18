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
#include "SSADCETransformer.h"
#include "HIdList.h"
#include "SSAPeepholeOptimizer.h"
#include "SSATransformToC.h"
#include "PeepholeOptimizer.h"
#include "ScriptingInterface.h"

#include "CHolodec.h"
#include "JobController.h"

#include <thread>

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


holodec::JobController jc;

void job_thread (int id) {
	printf ("Job-Thread %d Starting\n", id);
	jc.start_job_loop ({id});
	printf ("Job-Thread %d Exiting\n", id);
}
int main (int argc, char** argv) {

	/*
	 * Input i = MemAccess(0, unlimited)
	 *
	 * uint64 xx = Lea(...)
	 * MemoryAccess yy = MemAccess(xx, size, list of possible overlapping MemoryAccesses)
	 * uint(size) zz = Load(yy, value, other MemoryAccess)
	 * MemoryAccess aa = Store(yy, value)
	 *
	 */
	printf ("Init X86\n");

	std::vector<std::thread*> threads;
	for (int i = 0; i < 10; i++) {
		threads.push_back (new std::thread (job_thread, i));
	}



	for (int i = 0; i < 1000; i++) {
		holodec::Job job = {[i, &jc] (holodec::JobContext context) {
			if (i == 999) {
				std::this_thread::sleep_for(std::chrono::seconds(2));
				for (int j = 0; j < 500; j++) {
					holodec::Job job = {[j, &jc] (holodec::JobContext context) {
						printf ("Inner Job: %d from Thread: %d\n", j, context.threadId);
					}};
					jc.queue_job (job);
				}
			}
			printf ("Job: %d from Thread: %d\n", i, context.threadId);
		}
		                   };
		jc.queue_job (job);
	}

	jc.wait_for_finish();
	
	jc.wait_for_exit();
	
	printf("Jobs %d\n", jc.jobs.size());

	for (auto it = threads.begin(); it != threads.end(); ++it) {
		(*it)->join();
		delete *it;
	}
	return 0;

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
		analyzer = fileformat->createBinaryAnalyzer (data, "binary");
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

	//return 0;

	std::vector<SSATransformer*> transformers = {
		new SSAAddressToBlockTransformer(),
		//new SSACallingConvApplier(),
		new SSAPhiNodeGenerator(),
		new SSAAssignmentSimplifier(),
		new SSADCETransformer(),
		//new SSAPeepholeOptimizer(),
		new SSATransformToC()
	};

	for (SSATransformer* transform : transformers) {
		transform->arch = &holox86::x86architecture;
	}


	for (Symbol* sym : binary->symbols) {
		if (sym->symboltype == &SymbolType::symfunc) {
			Function* newfunction = new Function();
			newfunction->symbolref = sym->id;
			newfunction->baseaddr = sym->vaddr;
			newfunction->addrToAnalyze.push_back (sym->vaddr);
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
							snprintf (buffer, 100, "func_0x%x", addr);
							Symbol* symbol = new Symbol ({0, buffer, &SymbolType::symfunc, 0, addr, 0});
							binary->addSymbol (symbol);
							Function* newfunction = new Function();
							newfunction->symbolref = symbol->id;
							newfunction->baseaddr = symbol->vaddr;
							newfunction->addrToAnalyze.push_back (symbol->vaddr);
							binary->functions.push_back (newfunction);
						}
					}
				}
				break;
			}
		}
	} while (funcAnalyzed);


	for (Function* func : binary->functions) {

		func->callingconvention = holox86::x86architecture.getCallingConvention ("amd64")->id;

		for (SSATransformer* transform : transformers) {
			transform->doTransformation (func);
		}
		PeepholeOptimizer* optimizer = parsePhOptimizer (&holox86::x86architecture, func);
		transformers[4]->doTransformation (func);
		printf ("Symbol %s\n", binary->getSymbol (func->symbolref)->name.cstr());
		func->print (&holox86::x86architecture);
	}
	return 0;
}
