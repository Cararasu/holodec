#include "HClass.h"
#include "HString.h"

namespace holodec {
	HType typeuint8 = {0, HString::create ("uint8_t"), H_TYPE_UINT, &gh_visibilityPublic, 8};
	HType typeuint16 = {0, HString::create ("uint16_t"), H_TYPE_UINT, &gh_visibilityPublic, 16};
	HType typeuint32 = {0, HString::create ("uint32_t"), H_TYPE_UINT, &gh_visibilityPublic, 32};
	HType typeuint64 = {0, HString::create ("uint64_t"), H_TYPE_UINT, &gh_visibilityPublic, 64};

	HType typeint8 = {0, HString::create ("int8_t"), H_TYPE_INT, &gh_visibilityPublic, 8};
	HType typeint16 = {0, HString::create ("int16_t"), H_TYPE_INT, &gh_visibilityPublic, 16};
	HType typeint32 = {0, HString::create ("int32_t"), H_TYPE_INT, &gh_visibilityPublic, 32};
	HType typeint64 = {0, HString::create ("int64_t"), H_TYPE_INT, &gh_visibilityPublic, 64};

	HType typefloat32 = {0, HString::create ("float"), H_TYPE_FLOAT, &gh_visibilityPublic, 32};
	HType typefloat64 = {0, HString::create ("double"), H_TYPE_FLOAT, &gh_visibilityPublic, 64};
}
