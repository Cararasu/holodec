#include <stdio.h>
#include <HBinary.h>
#include <HElfBinaryAnalyzer.h>
#include "Hx86FunctionAnalyzer.h"

#include "HMain.h"
#include "HFileFormat.h"
#include "HArchitecture.h"
#include "HIRGen.h"

using namespace holodec;

HString filename = "../../workingdir/leo";

HFileFormat elffileformat = {"elf", "elf", {
		[] ( HData * data, HString name ) {
			static holoelf::HElfBinaryAnalyzer* analyzer = nullptr;
			if ( analyzer == nullptr ) {
				printf ( "Create New Object\n" );
				analyzer = new holoelf::HElfBinaryAnalyzer();
			}
			if ( analyzer->canAnalyze ( data ) ) {
				holoelf::HElfBinaryAnalyzer* temp = analyzer;
				analyzer = nullptr;
				return ( HBinaryAnalyzer* ) temp;
			}
			return ( HBinaryAnalyzer* ) nullptr;
		}
	}
};
extern HArchitecture holox86::x86architecture;

int main ( int argc, char** argv ) {
	HMain::initHMain();
	HData* data = HMain::loadHDataFromFile ( filename );
	if ( !data ) {
		printf ( "Could not Load File %s\n", filename.cstr() );
		return -1;
	}

	HMain::gh_main->registerFileFormat ( &elffileformat );
	HMain::gh_main->registerArchitecture ( &holox86::x86architecture );

	printf ( "Init X86\n" );
	holox86::x86architecture.init();

	HBinaryAnalyzer* analyzer = nullptr;
	for ( HFileFormat * fileformat : HMain::gh_main->fileformats ) {
		analyzer = fileformat->createBinaryAnalyzer ( data );
		if ( analyzer )
			break;
	}
	analyzer->init ( data );
	HBinary* binary = analyzer->getBinary();

	HFunctionAnalyzer* func_analyzer;
	for ( HArchitecture * architecture : HMain::gh_main->architectures ) {
		func_analyzer = architecture->createFunctionAnalyzer ( binary );
		if ( func_analyzer )
			break;
	}
	func_analyzer->init ( binary );

	printf ( "Binary File: %s\n", binary->data->filename.cstr() );
	printf ( "Size: %d Bytes\n", binary->data->size );


	binary->print();

	holox86::x86architecture.print();

	for ( HId& id : binary->entrypoints ) {
		func_analyzer->analyzeFunction ( binary->getSymbol ( id ) );
	}

	printf ( "%d\n", sizeof ( HInstruction ) );
	printf ( "%d\n", sizeof ( HInstArgument ) );

	HRegister* rax = holox86::x86architecture.getRegister ( "rax" );
	HRegister* rbx = holox86::x86architecture.getRegister ( "rbx" );


	HInstrDefinition* instrdef = holox86::x86architecture.getInstrDef ( "mov" );

	instrdef->irs[2].print(&holox86::x86architecture);

	//HSSAGenerator ssaGenerator;
	//ssaGenerator.arch = &holox86::x86architecture;
	for ( HFunction& function : binary->functions ) {
		//ssaGenerator.parseFunction ( &function );
	}
	return 0;
}
