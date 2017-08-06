#ifndef HIDGENEHATOH_H
#define HIDGENEHATOH_H

#include <stdint.h>
#include <functional>
#include <algorithm>
#include "HGeneral.h"

namespace holodec {

	typedef uint64_t HId;

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

		HIdList() {}
		HIdList (std::initializer_list<T> list) : list (list) {
			relabel();
		}
		HIdList (HList<T> list) : list (list) {
			relabel();
		}

		HId add (T& ele) {
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
		T* get (HId id) {
			size_t count = list.size();
			if (count >= id) {//optimization for access
				T& val = list[id - 1];
				if (val.id == id)//quick return
					return &list[id - 1];

				if (val.id < id) {
					auto it = list.begin() + id;
					for (; it != list.end(); it++) {
						if ( (*it).id == id)
							return &*it;
					}
				}
				if (val.id > id) {//should not happen but still...
					auto it = list.rbegin() + (count - id);
					for (; it != list.rend(); it++) {
						if ( (*it).id == id)
							return &*it;
					}
				}
			}
			for (T& ele : list) {
				if (ele.id == id)
					return &ele;
			}
			return nullptr;
		}
		void clear() {
			gen.clear();
			list.clear();
		}

	};
}


#endif // HIDGENEHATOH_H
