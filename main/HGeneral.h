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
	
	template <typename Key,typename Value>
	using HMap = std::map<Key,Value>;
	
	struct HVisibilityType{
		HString name;
	};
	
	extern HVisibilityType gh_visibilityPublic;
	extern HVisibilityType gh_visibilityProtected;
	extern HVisibilityType gh_visibilityPrivate;
	
	void printIndent(int indent);
}

#endif // H_GENEHAL_H