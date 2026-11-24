// Fuzz eve's math module (trigonometric with their range reductions incl. the large-argument
// rem_pio2 table path, exponentials, logarithms, powers, hyperbolic and inverse functions) on
// fuzzer-chosen float/double inputs, in eve::wide and scalar form. UBSan (float-cast-overflow,
// shifts, signed overflow in the bit-twiddling reductions) and ASan (table lookups) are the oracle;
// results are consumed so nothing is optimized away.
#include <eve/module/core.hpp>
#include <eve/module/math.hpp>

#include <cstdint>
#include <cstring>

namespace
{
template<typename T> volatile T sink;

template<typename W, typename F> void both(F f, W const &x, W const &y)
{
  using T = eve::element_type_t<W>;
  W r     = f(x, y);
  T acc   = r.get(0);
  for( std::size_t i = 0; i < W::size(); ++i ) acc += f(x.get(i), y.get(i));
  sink<T> = acc;
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
  W x(&a[0]), y(&b[0]);

#define EVE_U(F) both([](auto u, auto) { return F(u); }, x, y); break
#define EVE_B(F) both([](auto u, auto v) { return F(u, v); }, x, y); break
  switch( op % 48 )
  {
    case 0: EVE_U(eve::sin);
    case 1: EVE_U(eve::cos);
    case 2: EVE_U(eve::tan);
    case 3: EVE_U(eve::sin[eve::quarter_circle]);
    case 4: EVE_U(eve::cos[eve::half_circle]);
    case 5: EVE_U(eve::tan[eve::full_circle]);
    case 6: EVE_U(eve::sinpi);
    case 7: EVE_U(eve::cospi);
    case 8: EVE_U(eve::tanpi);
    case 9: EVE_U(eve::sind);
    case 10: EVE_U(eve::cosd);
    case 11: EVE_U(eve::sec);
    case 12: EVE_U(eve::csc);
    case 13: EVE_U(eve::cot);
    case 14: EVE_U(eve::asin);
    case 15: EVE_U(eve::acos);
    case 16: EVE_U(eve::atan);
    case 17: EVE_B(eve::atan2);
    case 18: EVE_U(eve::exp);
    case 19: EVE_U(eve::exp2);
    case 20: EVE_U(eve::exp10);
    case 21: EVE_U(eve::expm1);
    case 22: EVE_U(eve::log);
    case 23: EVE_U(eve::log2);
    case 24: EVE_U(eve::log10);
    case 25: EVE_U(eve::log1p);
    case 26: EVE_B(eve::pow);
    case 27: EVE_B(eve::pow_abs);
    case 28: EVE_B(eve::hypot);
    case 29: EVE_U(eve::cbrt);
    case 30: EVE_U(eve::sinh);
    case 31: EVE_U(eve::cosh);
    case 32: EVE_U(eve::tanh);
    case 33: EVE_U(eve::asinh);
    case 34: EVE_U(eve::acosh);
    case 35: EVE_U(eve::atanh);
    case 36: EVE_U(eve::sinc);
    case 37: EVE_U(eve::expx2);
    case 38: EVE_U(eve::expmx2);
    case 39: EVE_U(eve::gd);
    case 40: EVE_U(eve::agd);
    case 41: EVE_B(eve::logspace_add);
    case 42: EVE_B(eve::powm1);
    case 43: EVE_U(eve::radinpi);
    case 44: EVE_U(eve::log_abs);
    case 45: EVE_U(eve::sigmoid);
    case 46: both([](auto u, auto) { auto [s, c] = eve::sincos(u); return s + c; }, x, y); break;
    default: both([](auto u, auto) { auto [n, r, dr] = eve::rempio2(u); return n + r + dr; }, x, y); break;
  }
#undef EVE_U
#undef EVE_B
}
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const *data, std::size_t size)
{
  if( size < 2 ) return 0;
  std::uint8_t type = data[0], op = data[1];
  data += 2; size -= 2;
  if( type & 1 ) run<double>(op, data, size);
  else run<float>(op, data, size);
  return 0;
}
