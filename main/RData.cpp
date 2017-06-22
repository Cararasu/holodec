#include "RData.h"

#include <string.h>
#include <fstream>
#include "RString.h"


radpp::RData::RData (uint8_t* data, size_t size, RString filename) : data (data), size (size), filename (copyRString (filename)) {

}
radpp::RData::RData (RData& file) : data ( (uint8_t*) malloc (file.size)), size (file.size), filename (strdup (file.filename)) {
	memcpy (data, file.data, size);
}


radpp::RData::~RData() {
	free (data);
}