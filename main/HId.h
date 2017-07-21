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

	template<typename T>
	class HIdList {
	private:
		HIdGenerator gen;
		HList<T> list;
	public:
		HId add ( T& ele ) {
			ele.id = gen.next();
			list.push_back ( ele );
			return ele.id;
		}
		void sort ( std::function<void ( HId,HId ) > replacer = nullptr ) {
			std::sort(list.begin(),list.end(),[](T& lhs,T& rhs){return lhs.id < rhs.id;});
		}
		void relabel ( std::function<void ( HId,HId ) > replacer = nullptr ) {
			gen.clear();
			for ( T& ele : list ) {
				HId id = gen.next();
				if ( replacer )
					replacer ( ele.id,id );
				ele.id = id;
			}
		}
		T* get ( HId id ) const {
			if(list.count() >= id && list[id - 1].id == id)
				return &list[id - 1];
			for ( T& ele : list ) {
				if ( ele.id == id )
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
