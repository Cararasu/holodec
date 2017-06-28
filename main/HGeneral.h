#ifndef H_GENEHAL_H
#define H_GENEHAL_H

#include <stdint.h>
#include <vector>
#include <map>
#include "HString.h"

namespace holodec {
	template <typename T>
	using HList = std::vector<T>;
	
	template <typename Key,typename Value>
	using HMap = std::map<Key,Value>;
	
	template <typename Value>
	using HStringMap = std::map<HString,Value>;
	
	struct HVisibilityType{
		HString name;
	};
	
	extern HVisibilityType gr_visibilityPublic;
	extern HVisibilityType gr_visibilityProtected;
	extern HVisibilityType gr_visibilityPrivate;
	
	void printIndent(int indent);
}

#endif // H_GENEHAL_H