#ifndef RSTRING_H
#define RSTRING_H

#include <string.h>

namespace holodec {

	typedef const char* RString;

	constexpr inline unsigned int hashRString (RString str, int h = 0) {
		return !str[h] ? 5381 : (hashRString (str, h + 1) * 33) ^ str[h];
	}

	constexpr bool cmpRString (RString str1, RString str2, int h = 0);

	bool caseCmpRString (RString str1, RString str2);

	void deleteRString (RString str);
	RString copyRString (RString str);
}

#endif // RSTRING_H
