#ifndef _RTEURIUYO_H_
#define _RTEURIUYO_H_

#include <immintrin.h>
#include <utility>

namespace d {
	typedef unsigned __int64 t1; typedef unsigned long t2; typedef unsigned long long t3;

	template<t1 s>
	__forceinline constexpr t1 f1() { return ((s / 16) + (s % 16 != 0)) * 2; }

	template<t2 s>
	__forceinline constexpr t2 f2() noexcept {
		t2 a1 = s;
		for (char c : __TIME__) a1 = static_cast<t2>((a1 ^ c) * 82046221ULL);
		return a1;
	}

	template<t1 s>
	__forceinline constexpr t3 f3() {
		constexpr auto a1 = f2<9785201287 + s>();
		constexpr auto a2 = f2<a1>();
		return (static_cast<t3>(a1) << 32) | a2;
	}

	template<t1 N, class CharT>
	__forceinline constexpr t3 f4(t3 key, t1 idx, const CharT* str) noexcept {
		using cast_type = typename std::make_unsigned<CharT>::type;
		constexpr auto a1 = sizeof(CharT);
		constexpr auto a2 = 8 / a1;
		t3 a3 = key;
		for (t1 i = 0; i < a2 && i + idx * a2 < N; ++i) a3 ^= (t3{ static_cast<cast_type>(str[i + idx * a2]) } << ((i % a2) * 8 * a1));
		return a3;
	}

	__forceinline t3 f5(t3 value) noexcept { volatile t3 a1 = value; return a1; }

	template<class CharT, t1 Size, class Keys, class Indices>
	class spizjeno;

	template<class z1, t1 z2, t3... z4, t1... z5>
	class spizjeno<z1, z2, std::integer_sequence<t3, z4...>, std::index_sequence<z5...>>
	{
		constexpr static inline t3 l1 = ((z2 > 16) ? 32 : 16);
		alignas(l1) t3 v1[sizeof...(z4)];

	public:
		template<class L>
		__forceinline spizjeno(L l, std::integral_constant<t1, z2>, std::index_sequence<z5...>) noexcept
			: v1{ f5((std::integral_constant<t3, f4<z2>(z4, z5, l())>::value))... } {
		}

		__forceinline z1* f6() noexcept
		{
			alignas(l1) t3 a1[]{ f5(z4)... };

			((z5 >= sizeof(v1) / 32 ? static_cast<void>(0) : _mm256_store_si256(
				reinterpret_cast<__m256i*>(v1) + z5, _mm256_xor_si256(
					_mm256_load_si256(reinterpret_cast<const __m256i*>(v1) + z5),
					_mm256_load_si256(reinterpret_cast<const __m256i*>(a1) + z5)))), ...);

			if constexpr (sizeof(v1) % 32 != 0) _mm_store_si128(
				reinterpret_cast<__m128i*>(v1 + sizeof...(z4) - 2),
				_mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(v1 + sizeof...(z4) - 2)),
					_mm_load_si128(reinterpret_cast<const __m128i*>(a1 + sizeof...(z4) - 2))));

			return (z1*)(v1);
		}
	};

	template<class L, t1 z1, t1... z2>
	spizjeno(L l, std::integral_constant<t1, z1>, std::index_sequence<z2...>) -> spizjeno<
		std::remove_const_t<std::remove_reference_t<decltype(l()[0])>>, z1,
		std::integer_sequence<t3, d::f3<z2>()...>, std::index_sequence<z2...>>;
}

#define zxc_impl(str) d::spizjeno([]() { return str; }, std::integral_constant<d::t1, sizeof(str) / sizeof(*str)>{}, std::make_index_sequence<d::f1<sizeof(str)>()>{})
#define zxc(str) zxc_impl(str).f6()

#endif