#ifndef H_GENEHAL_H
#define H_GENEHAL_H

#include <stdint.h>
#include <vector>
#include <map>
#include "HString.h"

namespace holodec {
	template <typename T>
	using HList = std::vector<T>;

	template <typename Key, typename Value>
	using HMap = std::map<Key, Value>;

	template <typename Value>
	using HStringMap = std::map<HString, Value>;

	template <typename Key, typename Value>
	using HMap = std::map<Key, Value>;

	struct HVisibilityType {
		HString name;
	};
	template<typename T, size_t BASE>
	struct HLocalBackedLists {
		uint64_t subexprcount = 0;
		T subexpressions[BASE];
		HList<T> moreExpressions = HList<T> (0);

		HLocalBackedLists() = default;
		HLocalBackedLists (std::initializer_list<T> list) {
			for (const T& ele : list) {
				add (ele);
			}
		}

		T& operator[] (size_t index) {
			if (index < BASE)
				return subexpressions[index];
			return moreExpressions[index - BASE];
		}
		void add (T ele) {
			if (subexprcount < BASE) {
				subexpressions[subexprcount++] = ele;
			} else {
				moreExpressions.push_back (ele);
				subexprcount++;
			}
		}
		size_t size() {
			return subexprcount;
		}
	};

	extern HVisibilityType gh_visibilityPublic;
	extern HVisibilityType gh_visibilityProtected;
	extern HVisibilityType gh_visibilityPrivate;

	void printIndent (int indent);
}

#endif // H_GENEHAL_H
