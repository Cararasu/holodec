#include <stdio.h>
#include <HBinary.h>
#include <HElfBinaryAnalyzer.h>
#include "Hx86FunctionAnalyzer.h"

#include "HMain.h"
#include "HFileFormat.h"
#include "HArchitecture.h"
#include "HIRGen.h"
#include "HSSAGen.h"
#include "HSSAPhiNodeGenerator.h"
#include "HSSAAddressToBlockTransformer.h"

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
		HId functionid = func_analyzer->analyzeFunction ( binary->getSymbol ( id ) );
		
		printf("0x%x\n",binary->getFunction(functionid));
		binary->getFunction(functionid)->print(&holox86::x86architecture);
	}

	HSSAGen ssaGenerator(&holox86::x86architecture);
	HSSATransformer* transformer1 = new HSSAPhiNodeGenerator();
	HSSATransformer* transformer2 = new HSSAAddressToBlockTransformer();
	
	transformer1->arch = &holox86::x86architecture;
	transformer2->arch = &holox86::x86architecture;
	for ( HFunction& function : binary->functions ) {
		transformer2->doTransformation(&function);
		transformer1->doTransformation(&function);
		//function.print(&holox86::x86architecture);
	}
	return 0;
}
