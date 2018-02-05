
#include "IHexBinaryAnalyzer.h"
#include "../../Function.h"

namespace holoihex {

	bool IHexBinaryAnalyzer::canAnalyze(holodec::Data* data) {
		if ((*data)[0] == ':') {
			return true;
		}
		return false;
	}

	bool IHexBinaryAnalyzer::init(holodec::Data* data) {
		if (!data)
			return false;
		this->binary = new holodec::Binary(new holodec::IHexData(data));

		this->binary->arch = "avr";

		holodec::Symbol* sym = binary->findSymbol(0, &holodec::SymbolType::symfunc);
		if (!sym) {
			sym = new holodec::Symbol();
			sym->name = "entry";
			sym->size = 0;
			sym->symboltype = &holodec::SymbolType::symfunc;
			sym->vaddr = 0x00;
			binary->addSymbol(sym);
		}
		binary->addEntrypoint(sym->id);
		return true;
	}
	bool IHexBinaryAnalyzer::terminate() {
		return true;
	}

}
