#ifndef HIDGENEHATOH_H
#define HIDGENEHATOH_H

#include <stdint.h>
#include <functional>
#include <algorithm>
#include "HGeneral.h"
#include <vector>

namespace holodec {

	typedef uint32_t HId;

	class HIdGenerator {
	private:
		HId val = 1;
	public:
		HId next() {
			return val++;
		}
		void clear() {
			val = 1;
		}
	};

/**
 * Needs id member and relabel function
 * 
 */
	template<typename T>
	struct HIdList {
		HIdGenerator gen;
		HList<T> list;
		
		typedef typename HList<T>::iterator iterator;

		HIdList() {}
		HIdList (std::initializer_list<T> list) : list (list) {
			relabel();
		}
		HIdList (HList<T> list) : list (list) {
			relabel();
		}

		HId push_back (T& ele) {
			ele.id = gen.next();
			list.push_back (ele);
			return ele.id;
		}
		void relabel (std::function<void (HId, HId) > replacer = nullptr) {
			for (T& ele : list) {
				ele.relabel(&gen,replacer);
			}
		}
		auto begin() -> decltype(list.begin()){
			return list.begin();
		}
		auto end() -> decltype(list.end()){
			return list.end();
		}
		auto size() -> decltype(list.size()){
			return list.size();
		}
		auto back() -> decltype(list.back()){
			return list.back();
		}
		void erase(iterator it){
			list.erase(it);
		}
		T* get (HId id) {
			if(!id)
				return nullptr;
			int lowerbound = 0, upperbound = list.size();
			if (upperbound >= id) {//optimization for quick access
				T& val = list[id - 1];
				if (val.id == id) //quick return
					return &list[id - 1];
			}
			
			while(lowerbound <= upperbound) {// binary seach
				int middle = lowerbound + ((upperbound - lowerbound) / 2);
				HId middleId = list[middle].id;
				if(middleId == id)
					return &(list[middle]);
				if(middleId < id)
					lowerbound = middle + 1;
				else
					upperbound = middle - 1;
			}
			return nullptr;
		}
		T& operator[] (HId id) {
			return *get(id);
		}
		void clear() {
			gen.clear();
			list.clear();
		}

	};
}


#endif // HIDGENEHATOH_H
