
#include "RString.h"
#include <cstdlib>

constexpr bool radpp::cmpRString (RString str1, RString str2, int h) {
	return str1[h] ? (str2[h] ? (str1[h] == str2[h] ? cmpRString (str1, str2, h + 1) : false) : false) : true;
}
bool radpp::caseCmpRString (RString str1, RString str2){
	return strcasecmp(str1,str2) == 0;
}

void radpp::deleteRString (RString str) {
	free ((void*)str);
}
radpp::RString radpp::copyRString (RString str) {
	return strdup (str);
}