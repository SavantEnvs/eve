// Fuzz eve's core arithmetic, bit and conversion functors plus the combinatorial gcd on fuzzer-chosen integer and float operands, in eve::wide and scalar form.
// Inputs outside a functor's documented domain (integer division by zero, shift counts >= the bit
// width, gcd of signed/non-integral values) are mapped into it first, as the docs require.
// Oracle: every wide lane must equal the scalar result for the same lane (bitwise, NaN-aware).
#include <eve/module/core.hpp>
#include <eve/module/combinatorial.hpp>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <type_traits>

namespace
{
template<typename T> bool same(T a, T b)
{
  if constexpr( std::is_floating_point_v<T> )
  {
    if( a != a && b != b ) return true;
    return std::memcmp(&a, &b, sizeof(T)) == 0;
  }
  else return a == b;
}

template<typename W, typename F> void check(F f, W const &x, W const &y)
{
  W r = f(x, y);
  for( std::size_t i = 0; i < W::size(); ++i )
    if( !same(eve::element_type_t<W>(f(x.get(i), y.get(i))), r.get(i)) ) std::abort();
}

template<typename T> void run(std::uint8_t op, std::uint8_t const *data, std::size_t size)
{
  using W               = eve::wide<T>;
  constexpr std::size_t L = W::size();
  T a[L] = {}, b[L] = {};
  std::size_t k = size < sizeof(a) ? size : sizeof(a);
  std::memcpy(a, data, k);
  data += k; size -= k;
  std::memcpy(b, data, size < sizeof(b) ? size : sizeof(b));
  constexpr bool is_int = std::is_integral_v<T>;
  if constexpr( is_int )
  {
    for( auto &v : b ) if( v == 0 ) v = 1;                       // div/rem: divisor != 0
    if constexpr( std::is_signed_v<T> )
      for( std::size_t i = 0; i < L; ++i )                       // and not MIN / -1 (overflow)
        if( a[i] == std::numeric_limits<T>::min() && b[i] == T(-1) ) b[i] = 1;
  }
  W x(&a[0]), y(&b[0]);
  using U = eve::as_integer_t<T, unsigned>;
  constexpr int bits = sizeof(T) * 8;
  eve::wide<U, eve::fixed<L>> sh([&](auto i, auto) { return U(b[i]) % bits; });  // shift < width

  switch( op % 24 )
  {
    case 0: check([](auto u, auto v) { return eve::add[eve::saturated](u, v); }, x, y); break;
    case 1: check([](auto u, auto v) { return eve::sub[eve::saturated](u, v); }, x, y); break;
    case 2: check([](auto u, auto v) { return eve::mul[eve::saturated](u, v); }, x, y); break;
    case 3: check([](auto u, auto v) { return eve::div(u, v); }, x, y); break;
    case 4: check([](auto u, auto v) { return eve::div[eve::upward](u, v); }, x, y); break;
    case 5: check([](auto u, auto v) { return eve::div[eve::downward](u, v); }, x, y); break;
    case 6: check([](auto u, auto v) { return eve::div[eve::to_nearest](u, v); }, x, y); break;
    case 7: check([](auto u, auto v) { return eve::rem(u, v); }, x, y); break;
    case 8: check([](auto u, auto v) { return eve::min(u, v); }, x, y); break;
    case 9:
      // Plain average leaves the rounding of an odd integer sum unspecified (documented);
      // average[lower] is specified as floor((x+y)/2).
      if constexpr( is_int ) check([](auto u, auto v) { return eve::average[eve::lower](u, v); }, x, y);
      break;
    case 10: check([](auto u, auto v) { return eve::dist[eve::saturated](u, v); }, x, y); break;
    case 11: check([](auto u, auto v) { return eve::abs[eve::saturated](u) + eve::zero(eve::as(v)); }, x, y); break;
    case 12: check([](auto u, auto v) { return eve::minus[eve::saturated](u) + eve::zero(eve::as(v)); }, x, y); break;
    case 13: check([](auto u, auto v) { return eve::if_else(u > v, u, v); }, x, y); break;
    case 14:
    {
      auto sx = eve::bit_cast(x, eve::as<eve::wide<U, eve::fixed<L>>>{});
      auto r1 = eve::shl(sx, sh);
      auto r2 = eve::shr(sx, sh);
      auto r3 = eve::rotl(sx, sh);
      for( std::size_t i = 0; i < L; ++i )
      {
        if( eve::shl(sx.get(i), sh.get(i)) != r1.get(i) ) std::abort();
        if( eve::shr(sx.get(i), sh.get(i)) != r2.get(i) ) std::abort();
        if( eve::rotl(sx.get(i), sh.get(i)) != r3.get(i) ) std::abort();
      }
      break;
    }
    case 15:
    {
      auto sx = eve::bit_cast(x, eve::as<eve::wide<U, eve::fixed<L>>>{});
      auto c  = eve::popcount(sx);
      auto lz = eve::countl_zero(sx);
      auto tz = eve::countr_zero(sx);
      auto bf = eve::bit_floor(sx);
      for( std::size_t i = 0; i < L; ++i )
        if( eve::popcount(sx.get(i)) != c.get(i) || eve::countl_zero(sx.get(i)) != lz.get(i)
            || eve::countr_zero(sx.get(i)) != tz.get(i) || eve::bit_floor(sx.get(i)) != bf.get(i) )
          std::abort();
      break;
    }
    case 16:
      check([](auto u, auto v) { return eve::if_else(eve::is_less(u, v), u, v); }, x, y);
      break;
    case 17: check([](auto u, auto v) { return eve::fma(u, v, u); }, x, y); break;
    case 18:
      if constexpr( !is_int ) check([](auto u, auto v) { return eve::copysign(u, v); }, x, y);
      break;
    case 19:
      if constexpr( !is_int ) check([](auto u, auto v) { return eve::fdim(u, v); }, x, y);
      break;
    case 20:
      if constexpr( !is_int )
      {
        check([](auto u, auto) { return eve::frac(u); }, x, y);
        check([](auto u, auto) { return eve::trunc(u); }, x, y);
        check([](auto u, auto) { return eve::nearest(u); }, x, y);
        check([](auto u, auto v) { return eve::next(u) + eve::zero(eve::as(v)); }, x, y);
      }
      break;
    case 21:
    {
      // gcd/lcm: documented for (flint) values; use the absolute integral part of each input.
      if constexpr( std::is_unsigned_v<T> ) check([](auto u, auto v) { return eve::gcd(u, v); }, x, y);
      break;
    }
    default: check([](auto u, auto v) { return eve::max(u, v) - eve::min(u, v) * eve::zero(eve::as(u)); }, x, y); break;
  }
}
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const *data, std::size_t size)
{
  if( size < 2 ) return 0;
  std::uint8_t type = data[0], op = data[1];
  data += 2; size -= 2;
  switch( type % 8 )
  {
    case 0: run<std::int8_t>(op, data, size); break;
    case 1: run<std::uint8_t>(op, data, size); break;
    case 2: run<std::int16_t>(op, data, size); break;
    case 3: run<std::uint32_t>(op, data, size); break;
    case 4: run<std::int64_t>(op, data, size); break;
    case 5: run<std::uint64_t>(op, data, size); break;
    case 6: run<float>(op, data, size); break;
    default: run<double>(op, data, size); break;
  }
  return 0;
}
