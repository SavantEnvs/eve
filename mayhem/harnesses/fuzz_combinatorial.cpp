// Fuzz eve::nth_prime / prime_floor / prime_ceil (combinatorial module) through the public API,
// in scalar and eve::wide form for every unsigned element width. The wide overloads gather from
// the 10000-entry prime table: that is where upstream fixed an ASan out-of-bounds read
// (jfalcou/eve 59d7e6108b, "ASAN fix for nth_prime"), so every lane value is left unrestricted.
// Oracle: each wide lane must equal the scalar result for the same input.
#include <eve/module/core.hpp>
#include <eve/module/combinatorial.hpp>
#include <eve/wide.hpp>

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace
{
template<typename T> void run(std::uint8_t const *data, std::size_t size)
{
  using W               = eve::wide<T>;
  constexpr std::size_t L = W::size();
  T buf[L] = {};
  std::memcpy(buf, data, size < sizeof(buf) ? size : sizeof(buf));

  W w(&buf[0]);
  W np = eve::nth_prime(w);
  W pf = eve::prime_floor(w);
  W pc = eve::prime_ceil(w);
  auto npf = eve::nth_prime(w, eve::as<float>{});
  auto npd = eve::nth_prime(w, eve::as<double>{});
  auto pff = eve::prime_floor(w, eve::as<double>{});
  auto pcf = eve::prime_ceil(w, eve::as<float>{});

  for( std::size_t i = 0; i < L; ++i )
  {
    if( eve::nth_prime(buf[i]) != np.get(i) ) std::abort();
    if( eve::prime_floor(buf[i]) != pf.get(i) ) std::abort();
    if( eve::prime_ceil(buf[i]) != pc.get(i) ) std::abort();
    // Out-of-range inputs yield NaN for floating results (documented), so compare NaN-aware.
    double sd = eve::nth_prime(buf[i], eve::as<double>{});
    double wd = npd.get(i);
    if( !(sd == wd || (sd != sd && wd != wd)) ) std::abort();
  }
  volatile float sink = npf.get(0) + pcf.get(L - 1) + static_cast<float>(pff.get(0));
  (void)sink;

  // Narrower result types (as<uintN>) for the scalar path.
  volatile auto s8  = eve::nth_prime(buf[0], eve::as<std::uint8_t>{});
  volatile auto s16 = eve::nth_prime(buf[0], eve::as<std::uint16_t>{});
  volatile auto s32 = eve::nth_prime(buf[0], eve::as<std::uint32_t>{});
  (void)s8; (void)s16; (void)s32;
}
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const *data, std::size_t size)
{
  if( size < 1 ) return 0;
  std::uint8_t sel = data[0];
  ++data; --size;
  switch( sel % 4 )
  {
    case 0: run<std::uint8_t>(data, size); break;
    case 1: run<std::uint16_t>(data, size); break;
    case 2: run<std::uint32_t>(data, size); break;
    default: run<std::uint64_t>(data, size); break;
  }
  return 0;
}
