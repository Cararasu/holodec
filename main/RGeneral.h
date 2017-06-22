#ifndef R_GENERAL_H
#define R_GENERAL_H

#include <stdint.h>
#include <vector>
#include <map>
#include "RString.h"

namespace holodec {
	template <typename T>
	using RList = std::vector<T>;
	
	template <typename Key,typename Value>
	using RMap = std::map<Key,Value>;
	
	struct RVisibilityType{
		RString name;
	};
	
	typedef uint64_t RRegisterIndex;
	
	typedef uint32_t RArchType;
	
	typedef uint32_t RTypeId;
	
	extern RVisibilityType gr_visibilityPublic;
	extern RVisibilityType gr_visibilityProtected;
	extern RVisibilityType gr_visibilityPrivate;
	
	void printIndent(int indent);
}

#endif // R_GENERAL_H