
#include "RString.h"
#include <cstdlib>

constexpr bool holodec::cmpRString (RString str1, RString str2, int h) {
	return str1[h] ? (str2[h] ? (str1[h] == str2[h] ? cmpRString (str1, str2, h + 1) : false) : false) : true;
}
bool holodec::caseCmpRString (RString str1, RString str2){
	return strcasecmp(str1,str2) == 0;
}

void holodec::deleteRString (RString str) {
	free ((void*)str);
}
holodec::RString holodec::copyRString (RString str) {
	return strdup (str);
}