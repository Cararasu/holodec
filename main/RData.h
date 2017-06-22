#ifndef R_FILE_H
#define R_FILE_H

#include <stdint.h>
#include "RString.h"

namespace radpp {

	struct RData {
		uint8_t* const data;
		const size_t size;
		const char* const filename;

		RData (uint8_t* data, size_t size, const RString filename = 0);
		RData (RData& file);
		RData (RData && file);
		virtual ~RData ();

		inline uint8_t operator[] (size_t index) {
			return data[index];
		}
		template<typename T>
		inline T get (size_t index) {
			return * (T*) (data + index);
		}
	};
}

#endif // R_FILE_H
