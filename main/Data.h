#ifndef H_FILE_H
#define H_FILE_H

#include <stdint.h>
#include "HString.h"

namespace holodec {

	struct Data {
		uint8_t* const data;
		const size_t size;
		HString filename;

		Data (uint8_t* data, size_t size, const HString filename);
		Data (Data& file);
		Data (Data && file);
		virtual ~Data ();

		inline uint8_t operator[] (size_t index) {
			return data[index];
		}
		template<typename T>
		inline T get (size_t index) {
			return * (T*) (data + index);
		}
	};
}

#endif // H_FILE_H
