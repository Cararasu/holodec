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
	
	template <typename Key, typename Value>
	class HIdMap : public HMap<Key,Value>{
	public:
		HIdMap(std::initializer_list<Value> list){
			for(Value val : list){
				insert(val);
			}
		}
		void insert(Value& val){
			std::pair<const Key,Value> pair = std::pair<const Key,Value>(val.id,val);
			HMap<Key,Value>::insert(pair);
		}
	};
	
	
	template<typename T, size_t BASE>
	struct HLocalBackedList {
		uint64_t subexprcount = 0;
		T subexpressions[BASE];
		HList<T> moreExpressions = HList<T> (0);

		HLocalBackedList() = default;
		HLocalBackedList (std::initializer_list<T> list) {
			for (const T& ele : list) {
				push_back (ele);
			}
		}

		T& operator[] (size_t index) {
			if (index < BASE)
				return subexpressions[index];
			return moreExpressions[index - BASE];
		}
		void push_back (const T ele) {
			if (subexprcount < BASE) {
				subexpressions[subexprcount++] = ele;
			} else {
				moreExpressions.push_back (ele);
				subexprcount++;
			}
		}
		void pop_back () {
			if (subexprcount < BASE && subexprcount > 0) {
				subexprcount--;
			} else if(subexprcount >= BASE) {
				moreExpressions.pop_back ();
				subexprcount--;
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
