#pragma once

#include "../../Binary.h"
#include "../../HString.h"
#include "../../BinaryAnalyzer.h"

namespace holoihex {

	class IHexBinaryAnalyzer : public holodec::BinaryAnalyzer {
		//TODO we need the offset

	public:
		IHexBinaryAnalyzer() : holodec::BinaryAnalyzer("ihex", "ihex") {}

		virtual bool canAnalyze(holodec::File* file);

		virtual bool init(holodec::File* file);
		virtual bool terminate();

	};

}