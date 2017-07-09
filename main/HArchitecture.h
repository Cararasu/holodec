#ifndef H_AHCHITECTUHE_H
#define H_AHCHITECTUHE_H

#include <stdint.h>
#include <functional>
#include "HFunctionAnalyzer.h"
#include "HInstrDefinition.h"

namespace holodec {

	struct HArchitecture {
		HString name;
		HString desc;
		uint64_t bitbase;

		HList<std::function<HFunctionAnalyzer* ( HBinary* ) >> functionanalyzerfactories;
		HList<HRegister> registers;

		HMap<HId, HInstrDefinition> instrdefs;

		HIdGenerator gen_reg;
		//HInstructionSet

		HArchitecture() = default;
		HArchitecture ( HArchitecture& ) = default;
		HArchitecture ( HArchitecture&& ) = default;
		~HArchitecture() = default;

		void init() {
			for ( auto& entry : instrdefs ) {
				holoir::HIRParser parser ( this );
				for ( int i = 0; i < 4; i++ ) {
					if ( entry.second.il_string[i] ) {
						parser.parse ( &entry.second.il_string[i] );
					}
				}
			}
			for ( HRegister& reg : registers ) {
				labelRegister ( &reg );
			}
		}

		void labelRegister ( HRegister* reg ) {
			reg->id = gen_reg.next();
			for ( HRegister& subreg : reg->subregisters ) {
				labelRegister ( &subreg );
			}
		}

		HFunctionAnalyzer* createFunctionAnalyzer ( HBinary* binary ) {
			for ( std::function<HFunctionAnalyzer* ( HBinary* ) >& fac : functionanalyzerfactories ) {
				HFunctionAnalyzer* analyzer = fac ( binary );
				if ( analyzer )
					return analyzer;

			}
			return nullptr;
		}

		HRegister* getRegister ( const HString string ) {
			for ( HRegister& reg : registers ) {
				if ( string == reg.name )
					return &reg;
				HRegister* r = reg.getRegister ( string );
				if ( r ) return r;
			}
			return &invalidReg;
		}
		HRegister* getRegister ( const HId id ) {
			for ( HRegister& reg : registers ) {
				if ( id == reg.id )
					return &reg;
				HRegister* r = reg.getRegister ( id );
				if ( r ) return r;
			}
			return &invalidReg;
		}
		HRegister* getParentRegister ( const HId id ) {
			for ( HRegister& reg : registers ) {
				if ( id == reg.id )
					return &reg;
				HRegister* r = reg.getRegister ( id );
				if ( r ) return &reg;
			}
			return &invalidReg;
		}
		HId getParentRegisterId ( const HId id ) {
			for ( HRegister& reg : registers ) {
				if ( id == reg.id )
					return reg.id;
				HRegister* r = reg.getRegister ( id );
				if ( r ) return reg.id;
			}
			return 0;
		}

		HInstrDefinition* getInstrDef ( HId id, HString mnemonic ) {
			auto it = instrdefs.find ( id );
			if ( it != instrdefs.end() )
				return & ( *it ).second;
			printf ( "%s not found\n", mnemonic.cstr() );
			return nullptr;
		}
		HInstrDefinition* getInstrDef ( HString mnemonic ) {
			for ( auto& entry : instrdefs ) {
				if ( entry.second.mnemonics == mnemonic )
					return &entry.second;
			}
			return nullptr;
		}

		void print ( int indent = 0 ) {
			printIndent ( indent );
			printf ( "Architecture %s\n", name.cstr() );
			for ( HRegister & rr : registers ) {
				rr.print ( indent + 1 );
			}
			for ( auto & id : instrdefs ) {
				id.second.print ( indent + 1 );
			}
		}
	};

}

#endif // H_AHCHITECTUHE_H
