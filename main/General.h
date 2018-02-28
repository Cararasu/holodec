#ifndef H_GENEHAL_H
#define H_GENEHAL_H

#include <stdint.h>
#include <cinttypes>
#include <vector>
#include <set>
#include <map>

#include "HString.h"
#include "CHolodecHeader.h"


namespace holodec {

	typedef uint32_t HId;

	template <typename T>
	using HList = std::vector<T>;

	template <typename T>
	using HSet = std::set<T>;

	template <typename Key, typename Value>
	using HMap = std::map<Key, Value>;

	template <typename Value>
	using HStringMap = std::map<HString, Value>;

	template <typename Key, typename Value>
	using HMap = std::map<Key, Value>;

	enum class Endianess {
		eLittle,
		eBig
	};

	extern const HString emptyString;

	struct StringRef {
		HString name;
		HId refId;
		StringRef() : name(emptyString), refId(0) {}
		StringRef(const char* name) : name(name), refId(0) {}
		StringRef (HString name) : name (name), refId (0) {}
		StringRef(HId refId) : name(emptyString), refId(refId) {}
		StringRef(HString name, HId refId) : name(name), refId(refId) {}

		explicit operator bool() {
			return name;
		}
		explicit operator HString() {
			return name;
		}
		explicit operator HId() {
			return refId;
		}
	};
	inline bool operator== (StringRef& lhs, StringRef& rhs) {
		if (lhs.refId && lhs.refId == rhs.refId)
			return true;
		if (lhs.name && lhs.name == rhs.name)
			return true;
		return false;
	}

	template <typename Key, typename Value>
	class HIdMap : public HMap<Key, Value> {
	public:
		HIdMap (std::initializer_list<Value> list) {
			for (Value val : list) {
				insert (val);
			}
		}
		void insert (Value& val) {
			std::pair<const Key, Value> pair = std::pair<const Key, Value> (val.id, val);
			HMap<Key, Value>::insert (pair);
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
			} else if (subexprcount >= BASE) {
				moreExpressions.pop_back ();
				subexprcount--;
			}
		}
		size_t size() {
			return subexprcount;
		}
	};
	template <typename FlagEnum>
	struct Flags {
		uint64_t mask;
		Flags()
			: mask (0) {
		}

		Flags (FlagEnum bit)
			: mask (static_cast<uint64_t> (bit)) {
		}

		Flags (Flags<FlagEnum> const& rhs)
			: mask (rhs.mask) {
		}

		Flags<FlagEnum> & operator= (Flags<FlagEnum> const& rhs) {
			mask = rhs.mask;
			return *this;
		}

		Flags<FlagEnum> & operator|= (Flags<FlagEnum> const& rhs) {
			mask |= rhs.mask;
			return *this;
		}

		Flags<FlagEnum> & operator&= (Flags<FlagEnum> const& rhs) {
			mask &= rhs.mask;
			return *this;
		}

		Flags<FlagEnum> & operator^= (Flags<FlagEnum> const& rhs) {
			mask ^= rhs.mask;
			return *this;
		}

		Flags<FlagEnum> operator| (Flags<FlagEnum> const& rhs) const {
			Flags<FlagEnum> result (*this);
			result |= rhs;
			return result;
		}

		Flags<FlagEnum> operator& (Flags<FlagEnum> const& rhs) const {
			Flags<FlagEnum> result (*this);
			result &= rhs;
			return result;
		}

		Flags<FlagEnum> operator^ (Flags<FlagEnum> const& rhs) const {
			Flags<FlagEnum> result (*this);
			result ^= rhs;
			return result;
		}

		bool operator!() const {
			return !mask;
		}

		Flags<FlagEnum> operator~() const {
			Flags<FlagEnum> result (*this);
			result.mask = ~result.mask;
			return result;
		}

		bool operator== (Flags<FlagEnum> const& rhs) const {
			return mask == rhs.mask;
		}

		bool operator!= (Flags<FlagEnum> const& rhs) const {
			return mask != rhs.mask;
		}

		explicit operator bool() const {
			return !!mask;
		}

		explicit operator uint64_t() const {
			return mask;
		}
	};

	void printIndent (int indent);
}

#endif // H_GENEHAL_H
