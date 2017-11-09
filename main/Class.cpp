#include "Class.h"
#include "HString.h"

namespace holodec {
	Type typeuint8 = {0, HString::create ("uint8_t"), H_TYPE_UINT, &g_visibilityPublic, 8};
	Type typeuint16 = {0, HString::create ("uint16_t"), H_TYPE_UINT, &g_visibilityPublic, 16};
	Type typeuint32 = {0, HString::create ("uint32_t"), H_TYPE_UINT, &g_visibilityPublic, 32};
	Type typeuint64 = {0, HString::create ("uint64_t"), H_TYPE_UINT, &g_visibilityPublic, 64};

	Type typeint8 = {0, HString::create ("int8_t"), H_TYPE_INT, &g_visibilityPublic, 8};
	Type typeint16 = {0, HString::create ("int16_t"), H_TYPE_INT, &g_visibilityPublic, 16};
	Type typeint32 = {0, HString::create ("int32_t"), H_TYPE_INT, &g_visibilityPublic, 32};
	Type typeint64 = {0, HString::create ("int64_t"), H_TYPE_INT, &g_visibilityPublic, 64};

	Type typefloat32 = {0, HString::create ("float"), H_TYPE_FLOAT, &g_visibilityPublic, 32};
	Type typefloat64 = {0, HString::create ("double"), H_TYPE_FLOAT, &g_visibilityPublic, 64};
}
