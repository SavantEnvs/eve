// Fuzz eve's special, bessel, elliptic and polynomial modules: gamma family, beta, erf/erf_inv,
// zeta, digamma, lambert, Bessel J/Y/I/K and Airy, elliptic integrals and Carlson forms, and the
// orthogonal polynomials (Legendre, Hermite, Laguerre, Tchebytchev, Gegenbauer) with
// fuzzer-chosen integer orders. These are series/continued-fraction loops and coefficient
// tables; a non-terminating iteration shows as a Mayhem timeout, memory errors under ASan and
// float/int conversions under UBSan.
#include <eve/module/core.hpp>
#include <eve/module/math.hpp>
#include <eve/module/bessel.hpp>
#include <eve/module/elliptic.hpp>
#include <eve/module/polynomial.hpp>
#include <eve/module/special.hpp>

#include <cstdint>
#include <cstring>

namespace
{
template<typename T> volatile T sink;

template<typename W, typename F> void both(F f, W const &x, W const &y, W const &z)
{
  using T = eve::element_type_t<W>;
  W r     = f(x, y, z);
  T acc   = r.get(0);
  for( std::size_t i = 0; i < W::size(); ++i ) acc += f(x.get(i), y.get(i), z.get(i));
  sink<T> = acc;
}

template<typename T> void run(std::uint8_t op, std::uint8_t order, std::uint8_t const *data, std::size_t size)
{
  using W               = eve::wide<T>;
  constexpr std::size_t L = W::size();
  T a[3][L] = {};
  std::memcpy(a, data, size < sizeof(a) ? size : sizeof(a));
  W x(&a[0][0]), y(&a[1][0]), z(&a[2][0]);
  // Integer orders: the polynomial/Bessel recurrences loop `n` times, so keep n small (<= 63).
  unsigned n = order % 64;
  int      ni = int(n);

#define EVE_1(EXPR) both([&](auto u, auto, auto) { return EXPR; }, x, y, z); break
#define EVE_2(EXPR) both([&](auto u, auto v, auto) { return EXPR; }, x, y, z); break
#define EVE_3(EXPR) both([&](auto u, auto v, auto w) { return EXPR; }, x, y, z); break
  switch( op % 44 )
  {
    case 0: EVE_1(eve::tgamma(u));
    case 1: EVE_1(eve::log_gamma(u));
    case 2: EVE_1(eve::log_abs_gamma(u));
    case 3: EVE_1(eve::digamma(u));
    case 4: EVE_1(eve::erf(u));
    case 5: EVE_1(eve::erfc(u));
    case 6: EVE_1(eve::erf_inv(u));
    case 7: EVE_1(eve::erfcx(u));
    case 8: EVE_1(eve::zeta(u));
    case 9: EVE_1(eve::dawson(u));
    case 10: EVE_1(eve::exp_int(u));
    case 11: EVE_2(eve::beta(u, v));
    case 12: EVE_2(eve::lbeta(u, v));
    case 13: EVE_3(eve::betainc(u, v, w));
    case 14: EVE_2(eve::gamma_p(u, v));
    case 15: EVE_2(eve::gamma_p_inv(u, v));
    case 16: EVE_2(eve::rising_factorial(u, v));
    case 17: EVE_1(get<0>(eve::lambert(u)));
    case 18: EVE_1(eve::omega(u));
    case 19: EVE_1(eve::sin_int(u));
    case 20: EVE_1(eve::cos_int(u));
    case 21: EVE_2(eve::bessel_j(u, v));
    case 22: EVE_2(eve::bessel_y(u, v));
    case 23: EVE_2(eve::bessel_i(u, v));
    case 24: EVE_2(eve::bessel_k(u, v));
    case 25: EVE_1(eve::bessel_j(ni, u));
    case 26: EVE_1(eve::bessel_y(ni, u));
    case 27: EVE_1(eve::airy_ai(u));
    case 28: EVE_1(eve::airy_bi(u));
    case 29: EVE_1(eve::ellint_1(u));
    case 30: EVE_1(eve::ellint_2(u));
    case 31: EVE_2(eve::ellint_1(u, v));
    case 32: EVE_3(eve::ellint_rf(u, v, w));
    case 33: EVE_3(eve::ellint_rd(u, v, w));
    case 34: EVE_2(eve::ellint_rc(u, v));
    case 35: EVE_2(eve::am(u, v));
    case 36: EVE_1(eve::legendre(n, u));
    case 37: EVE_1(eve::hermite(n, u));
    case 38: EVE_1(eve::laguerre(n, u));
    case 39: EVE_1(eve::tchebytchev(n, u));
    case 40: EVE_2(eve::gegenbauer(n, v, u));
    case 41: EVE_2(get<0>(eve::jacobi_elliptic(u, v)));
    case 42: EVE_2(eve::polygamma(T(n), u));
    default: EVE_1(eve::stirling(u));
  }
#undef EVE_1
#undef EVE_2
#undef EVE_3
}
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const *data, std::size_t size)
{
  if( size < 3 ) return 0;
  std::uint8_t type = data[0], op = data[1], order = data[2];
  data += 3; size -= 3;
  if( type & 1 ) run<double>(op, order, data, size);
  else run<float>(op, order, data, size);
  return 0;
}
