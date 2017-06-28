#ifndef H_FILE_H
#define H_FILE_H

#include <stdint.h>
#include "HString.h"

namespace holodec {

	struct HData {
		uint8_t* const data;
		const size_t size;
		HString filename;

		HData (uint8_t* data, size_t size, const HString filename = 0);
		HData (HData& file);
		HData (HData && file);
		virtual ~HData ();

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
