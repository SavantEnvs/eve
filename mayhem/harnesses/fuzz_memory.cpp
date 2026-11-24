// Fuzz eve's core memory operations on eve::wide: conditional loads/stores (keep_first, keep_last,
// ignore_first, ignore_last, keep_between, ignore_extrema), compress_store and compress_copy
// (safe), gather and scatter. Every buffer holds exactly the elements the operation is allowed to
// touch, so ASan reports any lane read or written outside the conditional's contract.
// Oracle: loaded/stored/compressed lanes must equal a scalar recomputation.
#include <eve/module/core.hpp>
#include <eve/wide.hpp>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace
{
[[noreturn]] void mismatch_found() { std::abort(); }

struct reader
{
  std::uint8_t const *p;
  std::size_t         n;
  std::uint8_t        byte()
  {
    if( !n ) return 0;
    --n;
    return *p++;
  }
  template<typename T> T value()
  {
    T v {};
    std::size_t k = n < sizeof(T) ? n : sizeof(T);
    std::memcpy(&v, p, k);
    p += k;
    n -= k;
    return v;
  }
};

template<typename T> bool same(T a, T b) { return std::memcmp(&a, &b, sizeof(T)) == 0; }

// Load and store through one conditional. Only lanes [first, first+count) may be touched, so the
// buffer is exactly that range and the pointer handed to eve is offset back by `first`, as in
// eve's own conditional load tests.
template<typename W, typename C> void cond_load_store(C c, reader &r)
{
  using T                 = eve::element_type_t<W>;
  constexpr std::ptrdiff_t L = W::size();
  std::ptrdiff_t first = c.offset(eve::as<W>{});
  std::ptrdiff_t count = c.count(eve::as<W>{});
  // A zero-lane conditional still gets a real (1-element) buffer: eve is not handed a null pointer.
  std::vector<T> buf(count ? count : 1);
  for( auto &x : buf ) x = r.template value<T>();
  T const *base = buf.data() - first;

  W v = eve::load[c](base, eve::as<W>{});
  for( std::ptrdiff_t i = 0; i < count; ++i )
    if( !same(v.get(first + i), buf[i]) ) mismatch_found();

  W alt(r.template value<T>());
  W v2 = eve::load[c.else_(alt)](base, eve::as<W>{});
  for( std::ptrdiff_t i = 0; i < L; ++i )
  {
    bool kept = i >= first && i < first + count;
    if( !same(v2.get(i), kept ? buf[i - first] : alt.get(i)) ) mismatch_found();
  }

  std::vector<T> out(count ? count : 1);
  T *obase = out.data() - first;
  eve::store[c](v, obase);
  for( std::ptrdiff_t i = 0; i < count; ++i )
    if( !same(out[i], buf[i]) ) mismatch_found();
}

template<typename T> void run(reader &r)
{
  using W                 = eve::wide<T>;
  constexpr std::ptrdiff_t L = W::size();
  std::uint8_t op = r.byte();
  std::ptrdiff_t a = r.byte() % (L + 1);
  std::ptrdiff_t b = r.byte() % (L + 1);
  if( a + b > L ) b = L - a;   // documented domain: offsets within the register

  switch( op % 8 )
  {
    case 0: cond_load_store<W>(eve::keep_first(a), r); break;
    case 1: cond_load_store<W>(eve::keep_last(a), r); break;
    case 2: cond_load_store<W>(eve::ignore_first(a), r); break;
    case 3: cond_load_store<W>(eve::ignore_last(a), r); break;
    case 4: cond_load_store<W>(eve::ignore_extrema(a, b), r); break;
    case 5:
    {
      std::ptrdiff_t lo = a < b ? a : b, hi = a < b ? b : a;
      cond_load_store<W>(eve::keep_between(lo, hi), r);
      break;
    }
    case 6:
    {
      // compress_store[safe] and compress_copy[safe] write only the selected lanes.
      T in[L];
      bool sel[L];
      for( std::ptrdiff_t i = 0; i < L; ++i ) in[i] = r.template value<T>();
      std::uint64_t bits = r.template value<std::uint64_t>();
      std::size_t   cnt  = 0;
      for( std::ptrdiff_t i = 0; i < L; ++i ) cnt += (sel[i] = (bits >> (i % 64)) & 1);
      W x(&in[0]);
      eve::logical<W> m([&](auto i, auto) { return sel[i]; });
      std::vector<T> out(cnt ? cnt : 1);
      T *end = eve::compress_store[eve::safe](x, m, out.data());
      if( std::size_t(end - out.data()) != cnt ) mismatch_found();
      std::size_t j = 0;
      for( std::ptrdiff_t i = 0; i < L; ++i )
        if( sel[i] && !same(out[j++], in[i]) ) mismatch_found();

      std::vector<T> src(in, in + L);
      std::vector<T> out2(cnt ? cnt : 1);
      T *end2 = eve::compress_copy[eve::safe][eve::sparse](src.data(), m, out2.data());
      if( std::size_t(end2 - out2.data()) != cnt ) mismatch_found();
      j = 0;
      for( std::ptrdiff_t i = 0; i < L; ++i )
        if( sel[i] && !same(out2[j++], in[i]) ) mismatch_found();
      std::vector<T> out3(cnt ? cnt : 1);
      eve::compress_copy[eve::safe][eve::dense](src.data(), m, out3.data());
      if( out3 != out2 && !std::is_floating_point_v<T> ) mismatch_found();
      break;
    }
    default:
    {
      // gather/scatter: indices are reduced modulo the table size (precondition: in bounds).
      std::size_t tn = 1 + r.byte();
      std::vector<T> table(tn);
      for( auto &x : table ) x = r.template value<T>();
      using I = eve::wide<std::int32_t, eve::fixed<L>>;
      std::int32_t idx[L];
      for( std::ptrdiff_t i = 0; i < L; ++i ) idx[i] = std::int32_t(r.template value<std::uint16_t>() % tn);
      I iw(&idx[0]);
      auto g = eve::gather(table.data(), iw);
      for( std::ptrdiff_t i = 0; i < L; ++i )
        if( !same(g.get(i), table[idx[i]]) ) mismatch_found();
      std::vector<T> dst(tn);
      eve::scatter(g, dst.data(), iw);
      for( std::ptrdiff_t i = 0; i < L; ++i )
        if( !same(dst[idx[i]], table[idx[i]]) ) mismatch_found();
      break;
    }
  }
}
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const *data, std::size_t size)
{
  reader r {data, size};
  switch( r.byte() % 8 )
  {
    case 0: run<std::int8_t>(r); break;
    case 1: run<std::uint16_t>(r); break;
    case 2: run<std::int32_t>(r); break;
    case 3: run<std::uint64_t>(r); break;
    case 4: run<float>(r); break;
    case 5: run<double>(r); break;
    case 6: run<std::uint8_t>(r); break;
    default: run<std::int64_t>(r); break;
  }
  return 0;
}
