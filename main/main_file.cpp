

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
#include "SSADCETransformer.h"
#include "SSACalleeCallerRegs.h"
#include "SSAReverseRegUsageAnalyzer.h"
#include "HIdList.h"
#include "SSAPeepholeOptimizer.h"
#include "SSATransformToC.h"
#include "SSAAppendSimplifier.h"
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

extern "C" {
	#include <r_bin.h>
	#include <r_anal.h>
	#include <r_core.h>
	#include <r_socket.h>
}
#define _WINSOCK2API_
#define _WINSOCKAPI_   /* Prevent inclusion of winsock.h in windows.h */
#include <windows.h> 

template<typename T>
struct RListWrapper {
	const RList* list;
	struct RListIterator {
		RListIter* iter;
		RListIterator(RListIter* iter) : iter(iter) {
		}

		RListIterator& operator++() {
			iter = iter->n;
			return *this;
		}
		RListIterator operator++(int) {
			RListIterator t(iter);
			iter = iter->n;
			return t;
		}
		RListIterator& operator--() {
			iter = iter->p;
			return *this;
		}
		RListIterator operator--(int) {
			RListIterator t(iter);
			iter = iter->p;
			return t;
		}
		bool operator==(RListIterator rhs) {
			return iter == rhs.iter;
		}
		bool operator!=(RListIterator rhs) {
			return iter != rhs.iter;
		}
		T* operator*() {
			return static_cast<T*>(iter->data);
		}
	};

	RListWrapper(const RList* list) : list(list) {}

	//for (it = list->head; it && (pos = it->data, 1); it = it->n)
	RListIterator begin() {
		if(list)
			return RListIterator(list->head);
		return end();
	}
	RListIterator end() {
		return RListIterator(nullptr);
	}
};
/*
Improved
*/
#define R2_SPLITBASE "--------xxxxxxxx--------"
static const char R2_splitbase[] = R2_SPLITBASE;
static const char R2_splitcommand[] = "echo " R2_SPLITBASE "\n";
static const size_t R2_splitbaselength = strlen(R2_splitbase);
static const size_t R2_splitcommandlength = strlen(R2_splitcommand);
#undef R2_SPLITBASE
class PipeToR2 {
	HANDLE g_hChildStd_IN_Wr = NULL;
	HANDLE g_hChildStd_OUT_Rd = NULL;


public:
	bool startR2(const char* command) {
		puts ("StartR2");
		wchar_t wtext[200];
		mbstowcs(wtext, command, strlen(command) + 1);//Plus null
		PROCESS_INFORMATION piProcInfo;
		STARTUPINFO siStartInfo;
		BOOL bSuccess = FALSE;

		HANDLE g_hChildStd_IN_Rd = NULL;
		HANDLE g_hChildStd_OUT_Wr = NULL;

		SECURITY_ATTRIBUTES saAttr;
		printf("\n->Start of parent execution.\n");
		// Set the bInheritHandle flag so pipe handles are inherited. 
		saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
		saAttr.bInheritHandle = TRUE;
		saAttr.lpSecurityDescriptor = NULL;
		// Create a pipe for the child process's STDOUT. 
		if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
			puts("StdoutRd CreatePipe");
		// Ensure the read handle to the pipe for STDOUT is not inherited.
		if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
			puts("Stdout SetHandleInformation");
		// Create a pipe for the child process's STDIN. 
		if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
			puts("Stdin CreatePipe");
		// Ensure the write handle to the pipe for STDIN is not inherited. 
		if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
			puts("Stdin SetHandleInformation");

		// Set up members of the PROCESS_INFORMATION structure. 

		ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

		// Set up members of the STARTUPINFO structure. 
		// This structure specifies the STDIN and STDOUT handles for redirection.

		ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
		siStartInfo.cb = sizeof(STARTUPINFO);
		siStartInfo.hStdError = g_hChildStd_OUT_Wr;
		siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
		siStartInfo.hStdInput = g_hChildStd_IN_Rd;
		siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

		// Create the child process. 

		bSuccess = CreateProcess(NULL,
			wtext,       // command line 
			NULL,          // process security attributes 
			NULL,          // primary thread security attributes 
			TRUE,          // handles are inherited 
			0,             // creation flags 
			NULL,          // use parent's environment 
			NULL,          // use parent's current directory 
			&siStartInfo,  // STARTUPINFO pointer 
			&piProcInfo);  // receives PROCESS_INFORMATION 

						   // If an error occurs, exit the application. 
		if (!bSuccess) {
			puts("CreateProcess");
			return false;
		}
		else{
			CloseHandle(piProcInfo.hProcess);
			CloseHandle(piProcInfo.hThread);
			CloseHandle(g_hChildStd_IN_Rd);
			CloseHandle(g_hChildStd_OUT_Wr);
		}
		puts("Started");
		if (!executeSplitCommand())
			printf("Fail\n");
		delete readUntilSplit();
		return true;
	}
	uint32_t readLine(std::vector<char>* buffer) {
		char byte = 0;
		DWORD dwRead = 0, dwWereRead = 0;
		size_t startoffset = buffer->size();
		do {
			bool bSuccess = ReadFile(g_hChildStd_OUT_Rd, &byte, 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) {
				printf("Error %d %d\n", bSuccess, dwRead);
				fflush(stdout);
				return 0;
			}
			if (byte == '\x00')
				continue;
			if (byte == '\n')
				break;
			buffer->back() = byte;
			buffer->push_back('\x00');
			dwWereRead += dwRead;
		} while (true);
		fflush(stdout);
		return dwWereRead;
	}

	std::vector<char>* readUntilSplit() {
		std::vector<char>* buffer = new std::vector<char>();
		buffer->reserve(1024);
		size_t offset = 0, read, commandleng; 
		bool first = true;
		do {
			if (first) {
				first = false;
			}
			else {
				buffer->back() = '\n';
			}
			buffer->push_back('\x00');
			offset = buffer->size();
			read = readLine(buffer);
		} while (read > 0 && strncmp(buffer->data() + buffer->size() - (R2_splitbaselength + 1), R2_splitbase, R2_splitbaselength));
		buffer->erase(buffer->begin() + buffer->size() - (R2_splitbaselength + 1), buffer->end() - 1);
		return buffer;
	}
	bool executeSplitCommand() {
		DWORD dwWritten;
		bool bSuccess = WriteFile(g_hChildStd_IN_Wr, R2_splitcommand, R2_splitcommandlength, &dwWritten, NULL);
		if (!bSuccess || dwWritten == 0)
			return false;
		FlushFileBuffers(g_hChildStd_IN_Wr);
		return true;
	}
	std::vector<char>* execute(const char* command) {
		DWORD dwWritten;
		bool bSuccess = WriteFile(g_hChildStd_IN_Wr, command, strlen(command), &dwWritten, NULL);
		if (!bSuccess || dwWritten == 0)
			return nullptr;
		if (!executeSplitCommand())
			return nullptr;
		return readUntilSplit();
	}
	void close() {
		CloseHandle(g_hChildStd_IN_Wr);
		CloseHandle(g_hChildStd_OUT_Rd);
	}
};



int main (int argc, const char** argv) {
	/*
	PipeToR2 r2pipe;
	r2pipe.startR2("bash -c \"r2 -q0 /bin/ls\"");
	{
		puts("--------");
		std::vector<char>* data = r2pipe.execute("aaaa\n");
		printf("aaaa:\n%s\n", data->data());
		delete data;
		fflush(stdout);
	}
	{
		puts("--------");
		std::vector<char>* data = r2pipe.execute("ia\n");
		printf("ia:\n%s\n", data->data());
		delete data;
		fflush(stdout);
	}
	{
		puts("--------");
		std::vector<char>* data = r2pipe.execute("afl\n");
		printf("af:\n%s\n", data->data());
		delete data;
		fflush(stdout);
	}
	{
		puts("--------");
		std::vector<char>* data = r2pipe.execute("e scr.color = false\n");
		printf("color:\n%s\n", data->data());
		delete data;
		fflush(stdout);
	}
	{
		puts("--------");
		std::vector<char>* data = r2pipe.execute("pdf @ main\n");
		printf("pdf:\n%s\n", data->data());
		delete data;
		fflush(stdout);
	}
	{
		puts("--------");
		std::vector<char>* data = r2pipe.execute("e asm.esil = true\n");
		printf("esil:\n%s\n", data->data());
		delete data;
		fflush(stdout);
	}
	{
		puts("--------");
		std::vector<char>* data = r2pipe.execute("pdf @ main\n");
		printf("pdf:\n%s\n", data->data());
		delete data;
		fflush(stdout);
	}
	r2pipe.close();
	return 0;
	r_cons_new();  // initialize console
	RCore* rcore = r_core_new();
	r_core_loadlibs(rcore, R_CORE_LOADLIBS_ALL, NULL);

	ut64 baddr = 0, mapaddr = 0;
	int perms = 0, va = 0;
	RCoreFile * f = r_core_file_open(rcore, "../workingdir/leo", perms, mapaddr);
	bool loadbin = true;
	if (!f) {
		printf("r_core_file_open failed\n");
		return false;
	}

	if (!forceBinPlugin.isNull()) {
	r_bin_force_plugin(r_core_get_bin(rcore), forceBinPlugin.toUtf8().constData());
	}

	if (loadbin) {
		if (!r_core_bin_load(rcore, "../workingdir/leo", baddr)) {
			printf("CANNOT GET RBIN INFO\n");
		}
	}
	r_config_set_i(rcore->config, "scr.color", false);
	r_config_set_i(rcore->config, "asm.esil", true);
	r_core_cmd0(rcore, "aaa");
	{
		char *res = r_core_cmd_str(rcore, "aflj");
		puts(res);
		r_mem_free(res);
	}
	{
		char *res = r_core_cmd_str(rcore, "iaj");
		puts(res);
		r_mem_free(res);
	}
	{
		char *res = r_core_cmd_str(rcore, "aflj");
		puts(res);
		r_mem_free(res);
	}
	{
		char *res = r_core_cmd_str(rcore, "pdf @ entry0");
		puts(res);
		r_mem_free(res);
	}


	r_core_free(rcore);
	r_cons_free();

	return 1;
	R2Pipe *r2 = r2p_open("bash -c \"r2 /bin/ls\"");
	printf("-----\n");
	fflush(stdout);
	if (r2) {
		r2cmd(r2, "?e Hello World");
		r2cmd(r2, "x");
		r2cmd(r2, "?e Hello World");
		r2cmd(r2, "pd 20");
		r2p_close(r2);
		return 0;
	}
	return 1;*/
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

	RBin* rbin = r_bin_new(); 
	g_logger.log<LogLevel::eInfo>("Load RBin %d\n", r_bin_load(rbin, filename.cstr(), -1, 0, -1, -1, false));

	RBinFile* binfile = r_bin_cur(rbin);
	int narch = binfile ? binfile->narch : 0;
	for (RBinObject* obj : RListWrapper<RBinObject>(binfile->objs)) {
		if (obj->info) {
			printf("wwww %s\n", obj->info->arch);
			fflush(stdout);
		}
	}

	for (RBinAddr* ent : RListWrapper<RBinAddr>(r_bin_get_entries(rbin))) {
		printf("-> 0x%x\n", ent->vaddr);
		fflush(stdout);
	}
	for (char* lib : RListWrapper<char>(r_bin_get_libs(rbin))) {
		printf("-> %s\n", lib);
		fflush(stdout);
	}
	for (RBinPlugin* plugin : RListWrapper<RBinPlugin>(rbin->plugins)) {
		printf("-> atrch %s\n", plugin->name);
	}
	for (RBinSymbol* sym : RListWrapper<RBinSymbol>(r_bin_get_symbols(rbin))) {
		printf("-> 0x%x\n", sym->vaddr);
		printf("-> %s\n", sym->name);
		if (strcmp(sym->type, "FUNC") == 0) {

		}
		printf("-> %s\n", sym->type);
		fflush(stdout);
	}

	for (RBinSection* sec : RListWrapper<RBinSection>(r_bin_get_sections(rbin))) {
		printf("-> 0x%x - 0x%x\n", sec->vaddr, sec->vsize);
		printf("-> %s\n", sec->name);
		printf("-> %s\n", sec->arch);
		fflush(stdout);
	}
	RAnal * ranal = r_anal_new();
	sdb_dump_begin(rbin->sdb);
	printf("------------------\n");
	while (SdbKv * entry = sdb_dump_next(rbin->sdb)) {
		printf("%s - %s\n", entry->key, entry->value);
	}
	r_anal_list(ranal);
	for (RAnalPlugin* plugin : RListWrapper<RAnalPlugin>(ranal->plugins)) {
		if (!strcmp("x86", plugin->arch) && plugin->analyze_fns) {
			plugin->analyze_fns(ranal, 0, -1, 0, 0);
		}
		printf("-> %s - %s\n", plugin->name, plugin->arch);
		fflush(stdout);
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
	if (!analyzer->init(file)) {
		printf("Could not initialize analyzer\n");
	}
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
			newfunction->exported = false;
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
				for (uint64_t addr : func->funcsCaller) {
					if (binary->findSymbol (addr, &SymbolType::symfunc) == nullptr) {
						char buffer[100];
						snprintf (buffer, 100, "func_0x%" PRIx64 "", addr);
						Symbol* symbol = new Symbol ({0, buffer, &SymbolType::symfunc, 0, addr, 0});
						binary->addSymbol (symbol);
						Function* newfunction = new Function();
						newfunction->symbolref = symbol->id;
						newfunction->baseaddr = symbol->vaddr;
						newfunction->exported = false;
						newfunction->addrToAnalyze.insert(symbol->vaddr);
						binary->functions.push_back (newfunction);
					}
				}
				break;
			}
		}
	} while (funcAnalyzed);

	binary->print();

	std::vector<StringRef> volatileRegisters = { "cf" , "zf" , "nf" , "vf" , "sf" , "hf" , "tf" , "if" };

	std::vector<SSATransformer*> starttransformers = {
		new SSAAddressToBlockTransformer(),//0
		new SSAPhiNodeGenerator(),//1
		new SSAPhiNodeGenerator(),//1
	};
	std::vector<SSATransformer*> pretransformers = {
		new SSAReverseRegUsageAnalyzer(),
		new SSAApplyRegRef(),//4
	};
	std::vector<SSATransformer*> transformers = {
		new SSAPeepholeOptimizer(),//2
		new SSADCETransformer(),//3
		new SSAAppendSimplifier(),//5
		new SSACalleeCallerRegs(volatileRegisters),//6
	};
	std::vector<SSATransformer*> endtransformers = {
		new SSATransformToC(),//7
	};

	for (SSATransformer* transform : starttransformers) {
		if (transform)
			transform->arch = binary->arch;
	}
	for (SSATransformer* transform : pretransformers) {
		if (transform)
			transform->arch = binary->arch;
	}
	for (SSATransformer* transform : transformers) {
		if (transform)
			transform->arch = binary->arch;
	}
	for (SSATransformer* transform : endtransformers) {
		if (transform)
			transform->arch = binary->arch;
	}

	PeepholeOptimizer* optimizer = parsePhOptimizer ();

	g_peephole_logger.level = LogLevel::eDebug;
	for (Function* func : binary->functions) {
		printf("Function: %s\n", binary->getSymbol(func->symbolref)->name.cstr());
	}
	g_peephole_logger.level = LogLevel::eInfo;
	
	HSet<uint64_t> funcs = {
		0x0,
	};
	for (Function* func : binary->functions) {
	//for (uint64_t addr : funcs) {
	//	Function* func = binary->getFunctionByAddr(addr);
		if (func) {
			for (SSATransformer* transform : starttransformers) {
				if (transform)
					transform->doTransformation(binary, func);
				func->print(binary->arch);
			}
			/*if (!func->ssaRep.checkIntegrity()) {
				func->print(binary->arch);
				assert(false);
			}*/
			func->ssaRep.recalcRefCounts();
		}
	}

	binary->recalculateCallingHierarchy();

	bool funcChanged = false;
	do {
		printf("---------------------\n");
		printf("Run Transformations\n");
		printf("---------------------\n");
		funcChanged = false;

		for (Function* func : binary->functions) {
			//reset some states maybe move to some other function or class
			func->usedRegStates.reset();
		}
		for (Function* func : binary->functions) {
			for (SSATransformer* transform : pretransformers) {
				if (transform)
					transform->doTransformation(binary, func);
			}
		}
		for (Function* func : binary->functions) {
			printf("Pretransform\n");
			func->print(binary->arch);
		}

		for (Function* func : binary->functions) {
		//for (uint64_t addr : funcs) {
		//	Function* func = binary->getFunctionByAddr(addr);
			if (func) {
				bool applied = false;
				/*if (!func->ssaRep.checkIntegrity()) {
					func->print(binary->arch);
					assert(false);
				}*/
				do {
					applied = false;
					func->ssaRep.recalcRefCounts();
					if (func->baseaddr == 0x0)
						func->print(binary->arch);

					for (SSATransformer* transform : transformers) {
						func->ssaRep.recalcRefCounts();
						if (transform)
							applied |= transform->doTransformation(binary, func);
					}
					funcChanged |= applied;
				} while (applied);
				func->ssaRep.recalcRefCounts();
			}
		}
	} while (funcChanged);
	for (Function* func : binary->functions) {
		func->print(binary->arch);
	}
	for (Function* func : binary->functions) {
	//for (uint64_t addr : funcs) {
	//	Function* func = binary->getFunctionByAddr(addr);
		if (func) {
			func->ssaRep.recalcRefCounts();
			holodec::g_logger.log<LogLevel::eInfo>("Symbol %s", binary->getSymbol(func->symbolref)->name.cstr());
			for (SSATransformer* transform : endtransformers) {
				if (transform)
					transform->doTransformation(binary, func);
			}
		}
	}

	Function* func = new Function();
	for (int i = 0; i < 8; i++) {
		func->ssaRep.bbs.emplace_back();
	}
	 
#define PATH(function, from, to) function->ssaRep.bbs[from].outBlocks.insert(to);function->ssaRep.bbs[to].inBlocks.insert(from);

	SSAExpression retexpr;
	retexpr.type = SSAExprType::eReturn;
	SSAExpression expr;
	expr.type = SSAExprType::eBranch;
	PATH(func, 1, 2);
	PATH(func, 2, 3);
	PATH(func, 2, 4);
	PATH(func, 3, 4);
	PATH(func, 3, 5);
	PATH(func, 4, 3);
	PATH(func, 4, 6);
	PATH(func, 5, 7);
	PATH(func, 5, 8);
	PATH(func, 6, 7);
	PATH(func, 7, 8);
	expr.subExpressions = { SSAArgument::createBlock(2) };
	func->ssaRep.bbs[1].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(3), SSAArgument::createUVal(0, 8), SSAArgument::createBlock(4) };
	func->ssaRep.bbs[2].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(4), SSAArgument::createUVal(0, 8), SSAArgument::createBlock(5) };
	func->ssaRep.bbs[3].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(3), SSAArgument::createUVal(0, 8), SSAArgument::createBlock(6) };
	func->ssaRep.bbs[4].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(7), SSAArgument::createUVal(0, 8), SSAArgument::createBlock(8) };
	func->ssaRep.bbs[5].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(7) };
	func->ssaRep.bbs[6].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(8) };
	func->ssaRep.bbs[7].exprIds.push_back(func->ssaRep.addExpr(&expr));
	func->ssaRep.bbs[8].exprIds.push_back(func->ssaRep.addExpr(&retexpr));
	
	//transformers[8]->doTransformation(binary, func);
	delete func;

	func = new Function();
	for (int i = 0; i < 7; i++) {
		func->ssaRep.bbs.emplace_back();
	}
	PATH(func, 1, 2);
	PATH(func, 2, 3);
	PATH(func, 2, 4);
	PATH(func, 3, 4);
	PATH(func, 4, 5);
	PATH(func, 4, 6);
	PATH(func, 5, 7);
	PATH(func, 6, 7);
	expr.subExpressions = { SSAArgument::createBlock(2) };
	func->ssaRep.bbs[1].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(3), SSAArgument::createUVal(1, 8), SSAArgument::createBlock(4) };
	func->ssaRep.bbs[2].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(4) };
	func->ssaRep.bbs[3].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(5), SSAArgument::createUVal(1, 8), SSAArgument::createBlock(6) };
	func->ssaRep.bbs[4].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(7) };
	func->ssaRep.bbs[5].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(7) };
	func->ssaRep.bbs[6].exprIds.push_back(func->ssaRep.addExpr(&expr));
	func->ssaRep.bbs[7].exprIds.push_back(func->ssaRep.addExpr(&retexpr));
	//transformers[8]->doTransformation(binary, func);
	delete func;

	func = new Function();
	for (int i = 0; i < 4; i++) {
		func->ssaRep.bbs.emplace_back();
	}
	PATH(func, 1, 2);
	PATH(func, 2, 3);
	PATH(func, 2, 4);
	PATH(func, 3, 3);
	PATH(func, 3, 4);
	expr.subExpressions = { SSAArgument::createBlock(2) };
	func->ssaRep.bbs[1].exprIds.push_back(func->ssaRep.addExpr(&expr));
	expr.subExpressions = { SSAArgument::createBlock(3), SSAArgument::createUVal(1, 8), SSAArgument::createBlock(4) };
	func->ssaRep.bbs[2].exprIds.push_back(func->ssaRep.addExpr(&expr));
	func->ssaRep.bbs[3].exprIds.push_back(func->ssaRep.addExpr(&expr));
	func->ssaRep.bbs[4].exprIds.push_back(func->ssaRep.addExpr(&retexpr));
	//transformers[8]->doTransformation(binary, func);
	delete func;

#undef PATH

	delete optimizer;

	return 0;
}
