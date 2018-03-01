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
#include "HIdList.h"
#include "SSAPeepholeOptimizer.h"
#include "SSATransformToC.h"
#include "SSAApplyRegRef.h"
#include "PeepholeOptimizer.h"
#include "ScriptingInterface.h"

#include "CHolodec.h"
#include "JobController.h"

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


holodec::JobController jc;

void job_thread (uint32_t id) {
	printf ("Job-Thread %d Starting\n", id);
	jc.start_job_loop ({id});
	printf ("Job-Thread %d Exiting\n", id);
}
#include <clang-c/Index.h>  // This is libclang.

void parseCXType(CXType type) {
	printf("Size: %" PRId64 " ", clang_Type_getSizeOf(type));
	switch (type.kind) {

	case CXType_Invalid:
		break;

		/**
		* \brief A type whose specific kind is not exposed via this
		* interface.
		*/
	case CXType_Unexposed:
		break;

		/* Builtin types */
	case CXType_Void://CXType_FirstBuiltin
		printf("Void ");
		break;
	case CXType_Bool:
	case CXType_Char_U:
	case CXType_Char16:
	case CXType_Char32:

	case CXType_UChar:
	case CXType_UShort:
	case CXType_UInt:
	case CXType_ULong:
	case CXType_ULongLong:
	case CXType_UInt128:
		printf("Unsigned Int ");
		break;

	case CXType_Char_S:
	case CXType_SChar:
	case CXType_WChar:

	case CXType_Short:
	case CXType_Int:
	case CXType_Long:
	case CXType_LongLong:
	case CXType_Int128:
		printf("Signed Int ");
		break;

	case CXType_NullPtr:
		printf("nullptr ");
		break;
	case CXType_Overload:
	case CXType_Dependent:
		break;
	case CXType_ObjCId:
	case CXType_ObjCClass:
	case CXType_ObjCSel:
		break;
	case CXType_Float128:
	case CXType_Half:
	case CXType_Float16:
	case CXType_Float:
	case CXType_Double:
	case CXType_LongDouble:
		break;//CXType_LastBuiltin

	case CXType_Complex:
		break;
	case CXType_Pointer:
		printf("Ptr of ");
		parseCXType(clang_getPointeeType(type));
		break;
	case CXType_BlockPointer:
	case CXType_LValueReference:
	case CXType_RValueReference:
	case CXType_Record:
	case CXType_Enum:
	case CXType_Typedef:
	case CXType_ObjCInterface:
	case CXType_ObjCObjectPointer:
	case CXType_FunctionNoProto:
	case CXType_FunctionProto:
		break;
	case CXType_ConstantArray:
		printf("Array(%" PRId64 ") of ", clang_getArraySize(type));
		parseCXType(clang_getArrayElementType(type));
		break;
	case CXType_Vector:
	case CXType_IncompleteArray:
	case CXType_VariableArray:
	case CXType_DependentSizedArray:
	case CXType_MemberPointer:
	case CXType_Auto:

	/**
	* \brief Represents a type that was referred to using an elaborated type keyword.
	*
	* E.g., struct S, or via a qualified name, e.g., N::M::type, or both.
	*/
	case CXType_Elaborated:
		break;
	}
}


CXChildVisitResult functionDeclVisitor(CXCursor cursor, CXCursor parent, CXClientData client_data) {
	CXCursorKind kind = clang_getCursorKind(cursor);
	CXType type = clang_getCursorType(cursor);
	if (kind == CXCursor_ParmDecl) {
		CXString name = clang_getCursorSpelling(cursor);
		
		parseCXType(type);
		int *nbParams = (int *)client_data;
		(*nbParams)++;
	}

	return CXChildVisit_Continue;

}
void printStorage(CX_StorageClass storageClass) {
	switch (storageClass) {
	case CX_SC_Invalid:
		printf("Invalid "); break;
	case CX_SC_None:
		printf("None "); break;
	case CX_SC_Extern:
		printf("Extern "); break;
	case CX_SC_Static:
		printf("Static "); break;
	case CX_SC_PrivateExtern:
		printf("PrivateExtern "); break;
	case CX_SC_OpenCLWorkGroupLocal:
		printf("OCL "); break;
	case CX_SC_Auto:
		printf("Auto "); break;
	case CX_SC_Register:
		printf("Register "); break;

	}
}
CXChildVisitResult cursorVisitor(CXCursor cursor, CXCursor parent, CXClientData client_data) {

	CXCursorKind kind = clang_getCursorKind(cursor);
	//CXType type = clang_getCursorType(cursor);
	CXType type = clang_getCanonicalType(clang_getCursorType(cursor));
	switch (kind) {
	case CXCursor_StructDecl:
		printf("Struct %s\n", clang_getCString(clang_getTypeSpelling(type)));
		break;
	case CXCursor_UnionDecl:
		printf("Union %s\n", clang_getCString(clang_getTypeSpelling(type)));
		break;
	case CXCursor_ClassDecl:
		printf("Class %s\n", clang_getCString(clang_getTypeSpelling(type)));
		break;
	case CXCursor_FieldDecl:
		printf("Field %s Offset %lld\n", clang_getCString(clang_getTypeSpelling(type)), clang_Cursor_getOffsetOfField(cursor));
		parseCXType(type); printf("\n");
		break;
	case CXCursor_EnumConstantDecl:
		printf("EnumConst %s\n", clang_getCString(clang_getTypeSpelling(type)));
		break;
	case CXCursor_VarDecl:
		printStorage(clang_Cursor_getStorageClass(cursor));
		printf("Var %s\n", clang_getCString(clang_getTypeSpelling(type)));
		break;
	case CXCursor_TypedefDecl:
		printf("Typedef %s -> %s\n", clang_getCString(clang_getTypeSpelling(type)), clang_getCString(clang_getTypedefName(type)));
		break;
	//...
	//case CXCursor_FunctionDecl:
		printStorage(clang_Cursor_getStorageClass(cursor));
	case CXCursor_ObjCInstanceMethodDecl: {

		printf("Ret: ");
		parseCXType(clang_getResultType(type));
		printf("\n");
		for (signed i = 0; i < clang_getNumArgTypes(type); i++) {
			printf("Arg %d: (%s) ", i, clang_getCString(clang_getTypeSpelling(clang_getArgType(type, i))));
			parseCXType(clang_getArgType(type, i));
			printf("\n");
		}
		printf("%s %s(", clang_getCString(clang_getTypeSpelling(type)), clang_getCString(clang_getCursorSpelling(cursor)));

		// visit method childs
		int nbParams = 0;
		clang_visitChildren(cursor, *functionDeclVisitor, &nbParams);

		printf(")\n");

		CXSourceLocation location = clang_getCursorLocation(cursor);

		CXString filename;
		unsigned int line, column;

		clang_getPresumedLocation(location, &filename, &line, &column);
		return CXChildVisit_Continue;
	}break;
	}
	//printf("cursor '%s' -> %i\n",clang_getCString(name),kind);
	return CXChildVisit_Recurse;
}

int main (int argc, const char** argv) {

	/*
	CXIndex index = clang_createIndex(0, 1);
	CXTranslationUnit unit = clang_parseTranslationUnit(
		index,
		"../workingdir/stdheader.c", nullptr, 0,
		nullptr, 0,
		CXTranslationUnit_None);
	if (unit == nullptr)
	{
		std::cerr << "Unable to parse translation unit. Quitting." << std::endl;
		exit(-1);
	}
	CXCursor rootCursor = clang_getTranslationUnitCursor(unit);

	unsigned int res = clang_visitChildren(rootCursor, *cursorVisitor, 0);

	//return 0;*/
	/*
	 * Input i = MemAccess(0, unlimited)
	 *
	 * uint64 xx = Lea(...)
	 * MemoryAccess yy = MemAccess(xx, size, list of possible overlapping MemoryAccesses)
	 * uint(size) zz = Load(yy, value, other MemoryAccess)
	 * MemoryAccess aa = Store(yy, value)
	 *
	 */
	 
	//clang::SourceManager sourceManager;
	 
	 
	g_logger.log<LogLevel::eInfo> ("Init X86\n");

	std::vector<std::thread*> threads;
	for (int i = 0; i < 10; i++) {
		threads.push_back (new std::thread (job_thread, i));
	}


	jc.wait_for_finish();

	jc.wait_for_exit();

	g_logger.log<LogLevel::eInfo> ("Jobs %d\n", jc.jobs.size());

	for (auto it = threads.begin(); it != threads.end(); ++it) {
		(*it)->join();
		delete *it;
	}
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
		new SSAAddressToBlockTransformer(),
		new SSAPhiNodeGenerator(),
		new SSAAssignmentSimplifier(),
		new SSADCETransformer(),
		new SSAApplyRegRef(),
		new SSATransformToC(),
	};

	for (SSATransformer* transform : transformers) {
		transform->arch = binary->arch;
	}

	PeepholeOptimizer* optimizer = parsePhOptimizer ();

	g_peephole_logger.level = LogLevel::eDebug;
	for (Function* func : binary->functions) {
		printf("Function: %s\n", binary->getSymbol(func->symbolref)->name.cstr());
		/*transformers[0]->doTransformation(binary, func);
		transformers[1]->doTransformation(binary, func);
		assert(func->ssaRep.checkIntegrity());
		func->ssaRep.recalcRefCounts();
		func->print(binary->arch);

		holodec::g_logger.log<LogLevel::eInfo> ("Symbol %s", binary->getSymbol (func->symbolref)->name.cstr());
		//func->print (&holox86::x86architecture);
		assert(func->ssaRep.checkIntegrity());
		bool applied = false;
		do {
			transformers[2]->doTransformation(binary, func);
			func->ssaRep.recalcRefCounts();
			assert(func->ssaRep.checkIntegrity());
			bool applied = false;
			do {
				applied = false;
				assert(func->ssaRep.checkIntegrity());
				for (size_t i = 0; i < func->ssaRep.expressions.size();) {
					SSAExpression& expr = func->ssaRep.expressions[i + 1];

					if (optimizer->ruleSet.match(&holox86::x86architecture, &func->ssaRep, &expr)) {
						assert(func->ssaRep.checkIntegrity());
						applied = true;
					}
					else {
						i++;
					}
				}
				transformers[3]->doTransformation(binary, func);
				func->ssaRep.recalcRefCounts();
				assert(func->ssaRep.checkIntegrity());
			} while (applied);

			holodec::g_logger.log<LogLevel::eInfo>("Symbol %s", binary->getSymbol(func->symbolref)->name.cstr());
		} while (applied);
		func->ssaRep.recalcRefCounts();
		transformers[4]->doTransformation(binary, func);
		func->print(binary->arch);
		printf("");*/
	}
	g_peephole_logger.level = LogLevel::eDebug;
	
	HList<uint64_t> funcs = {
		0x2516,
		0x2525,
	};
	for (uint64_t addr : funcs) {
		Function* func = binary->getFunctionByAddr(addr);
		if (func) {
			transformers[0]->doTransformation(binary, func);
			transformers[1]->doTransformation(binary, func);
			assert(func->ssaRep.checkIntegrity());
			func->ssaRep.recalcRefCounts();
			func->print(binary->arch);

			transformers[2]->doTransformation(binary, func);
			bool applied = false;
			do {
				applied = false;
				func->ssaRep.recalcRefCounts();
				for (size_t i = 0; i < func->ssaRep.expressions.size();) {
					SSAExpression& expr = func->ssaRep.expressions[i + 1];

					if (!optimizer->ruleSet.match(&holox86::x86architecture, &func->ssaRep, &expr)) {
						i++;
					}
					else {
						applied = true;
					}
				}
				transformers[3]->doTransformation(binary, func);
				transformers[4]->doTransformation(binary, func);
				//func->print(binary->arch);
				printf("%d\n", applied);
			} while (applied);
			func->ssaRep.recalcRefCounts();
			transformers[5]->doTransformation(binary, func);

			holodec::g_logger.log<LogLevel::eInfo>("Symbol %s", binary->getSymbol(func->symbolref)->name.cstr());
			func->print(binary->arch);
		}
	}
	delete optimizer;

	return 0;
}
