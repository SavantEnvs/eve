// Fuzz the eve::algo SIMD range algorithms on fuzzer-chosen element types, lengths and unaligned
// starting offsets. The data lives in an exact-size heap buffer, so ASan sees any over-read or
// over-write by the aligned/unaligned loads with ignore masks, the page-boundary tail handling in
// for_each_iteration and the compress-store used by copy_if/remove_if.
// Oracle: each algorithm must agree with its std:: counterpart.
#include <eve/module/algo.hpp>
#include <eve/module/core.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <vector>

namespace
{
[[noreturn]] void mismatch_found() { std::abort(); }

template<typename T> bool same(T a, T b)
{
  if constexpr( std::is_floating_point_v<T> ) return std::memcmp(&a, &b, sizeof(T)) == 0;
  else return a == b;
}

template<typename T> void run(std::uint8_t op, std::size_t off, std::uint8_t const *data, std::size_t size)
{
  std::size_t n = size / sizeof(T);
  if( n == 0 ) return;
  // Exact-size heap buffer: no slack after the last element.
  std::vector<T> storage(n);
  std::memcpy(storage.data(), data, n * sizeof(T));
  if( off > n ) off = n;
  std::span<T> v(storage.data() + off, n - off);

  if constexpr( std::is_floating_point_v<T> )
  {
    // Comparisons below need a strict weak order: NaN breaks it, so map NaNs to 0 (input
    // normalization, not a skip: every other value is kept).
    for( auto &x : storage )
      if( x != x ) x = T(0);
  }
  // Read after the NaN normalization, so the key is never NaN.
  T const key = storage[0];

  auto pred = [key](auto x) { return x > key; };

  switch( op % 14 )
  {
    case 0:
    {
      auto r = eve::algo::find_if(v, pred);
      auto e = std::find_if(v.begin(), v.end(), [key](T x) { return x > key; });
      if( (r - v.begin()) != (e - v.begin()) ) mismatch_found();
      break;
    }
    case 1:
    {
      auto r = eve::algo::find(v, key);
      auto e = std::find(v.begin(), v.end(), key);
      if( (r - v.begin()) != (e - v.begin()) ) mismatch_found();
      break;
    }
    case 2:
    {
      std::size_t half = v.size() / 2;
      std::span<T> a(v.data(), half), b(v.data() + half, half);
      bool r = eve::algo::equal(a, b);
      bool e = std::equal(a.begin(), a.end(), b.begin());
      if( r != e ) mismatch_found();
      auto m = eve::algo::mismatch(a, b);
      auto em = std::mismatch(a.begin(), a.end(), b.begin());
      if( (get<0>(m) - a.begin()) != (em.first - a.begin()) ) mismatch_found();
      break;
    }
    case 3:
    {
      std::size_t nl = v.empty() ? 0 : 1 + (static_cast<std::size_t>(op) / 14) % v.size();
      std::span<T> needle(v.data() + v.size() - nl, nl);
      std::vector<T> nv(needle.begin(), needle.end());
      auto r = eve::algo::search(v, nv);
      auto e = std::search(v.begin(), v.end(), nv.begin(), nv.end());
      if( (r - v.begin()) != (e - v.begin()) ) mismatch_found();
      break;
    }
    case 4:
    {
      std::vector<T> out(v.size());
      auto r = eve::algo::copy_if(v, out, pred);
      std::vector<T> exp;
      std::copy_if(v.begin(), v.end(), std::back_inserter(exp), [key](T x) { return x > key; });
      std::size_t cnt = r - out.begin();
      if( cnt != exp.size() ) mismatch_found();
      for( std::size_t i = 0; i < cnt; ++i )
        if( !same(out[i], exp[i]) ) mismatch_found();
      break;
    }
    case 5:
    {
      std::vector<T> exp(v.begin(), v.end());
      auto ee = std::remove_if(exp.begin(), exp.end(), [key](T x) { return x > key; });
      auto r = eve::algo::remove_if(v, pred);
      std::size_t cnt = r - v.begin();
      if( cnt != std::size_t(ee - exp.begin()) ) mismatch_found();
      for( std::size_t i = 0; i < cnt; ++i )
        if( !same(v[i], exp[i]) ) mismatch_found();
      break;
    }
    case 6:
    {
      std::vector<T> exp(v.rbegin(), v.rend());
      eve::algo::reverse(v);
      for( std::size_t i = 0; i < v.size(); ++i )
        if( !same(v[i], exp[i]) ) mismatch_found();
      break;
    }
    case 7:
    {
      std::vector<T> out(v.size());
      eve::algo::reverse_copy(v, out);
      for( std::size_t i = 0; i < v.size(); ++i )
        if( !same(out[i], v[v.size() - 1 - i]) ) mismatch_found();
      break;
    }
    case 8:
    {
      // Compare positions, per eve's documented tie rules: min_element returns the FIRST of
      // equal minima (like std::min_element); max_element returns the LAST of equal maxima
      // (like std::minmax_element's .second, unlike std::max_element). For floats -0.0 and
      // +0.0 are equal, so comparing values bit-for-bit would flag a correct tie choice.
      auto r = eve::algo::min_element(v);
      auto e = std::min_element(v.begin(), v.end());
      if( (r - v.begin()) != (e - v.begin()) ) mismatch_found();
      auto rm = eve::algo::max_element(v);
      auto em = std::minmax_element(v.begin(), v.end()).second;
      if( (rm - v.begin()) != (em - v.begin()) ) mismatch_found();
      break;
    }
    case 9:
    {
      eve::algo::transform_inplace(v, [](auto x) { return eve::max(x, eve::zero(eve::as(x))); });
      for( auto x : v )
        if( x < T(0) ) mismatch_found();
      break;
    }
    case 10:
    {
      bool any = eve::algo::any_of(v, pred);
      bool all = eve::algo::all_of(v, pred);
      bool none = eve::algo::none_of(v, pred);
      auto sp = [key](T x) { return x > key; };
      if( any != std::any_of(v.begin(), v.end(), sp) ) mismatch_found();
      if( all != std::all_of(v.begin(), v.end(), sp) ) mismatch_found();
      if( none != std::none_of(v.begin(), v.end(), sp) ) mismatch_found();
      break;
    }
    case 11:
    {
      if constexpr( std::is_unsigned_v<T> )
      {
        // Unsigned arithmetic wraps (no UB), so the scan and the sum are exact.
        std::vector<T> exp(v.begin(), v.end());
        T acc = 0;
        for( auto &x : exp ) { acc = T(acc + x); x = acc; }
        T s = eve::algo::reduce(v, T(0));
        if( v.size() && s != acc ) mismatch_found();
        eve::algo::inclusive_scan_inplace(v, T(0));
        for( std::size_t i = 0; i < v.size(); ++i )
          if( v[i] != exp[i] ) mismatch_found();
      }
      else
      {
        volatile auto s = eve::algo::reduce(v, T(0));
        (void)s;
      }
      break;
    }
    case 12:
    {
      std::size_t half = v.size() / 2;
      std::vector<T> a(v.begin(), v.begin() + half), b(v.begin() + half, v.end());
      std::sort(a.begin(), a.end());
      std::sort(b.begin(), b.end());
      a.erase(std::unique(a.begin(), a.end()), a.end());
      b.erase(std::unique(b.begin(), b.end()), b.end());
      std::vector<T> out(std::min(a.size(), b.size()));
      std::vector<T> exp;
      std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(exp));
      auto r = eve::algo::set_intersection(a, b, out);
      std::size_t cnt = r.out - out.begin();
      if( cnt != exp.size() ) mismatch_found();
      // eve may write a matching element from either range (documented), and for floats -0.0
      // == +0.0 can match across ranges, so compare by value, not bits (no NaNs remain).
      for( std::size_t i = 0; i < cnt; ++i )
        if( !(out[i] == exp[i]) ) mismatch_found();
      break;
    }
    default:
    {
      std::size_t half = v.size() / 2;
      std::span<T> a(v.data(), half), b(v.data() + half, half);
      std::vector<T> ea(a.begin(), a.end()), eb(b.begin(), b.end());
      eve::algo::swap_ranges(a, b);
      for( std::size_t i = 0; i < half; ++i )
        if( !same(a[i], eb[i]) || !same(b[i], ea[i]) ) mismatch_found();
      eve::algo::fill(a, key);
      for( auto x : a )
        if( !same(x, key) ) mismatch_found();
      break;
    }
  }
}
}

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const *data, std::size_t size)
{
  if( size < 3 ) return 0;
  std::uint8_t type = data[0], op = data[1];
  std::size_t off = data[2] % 64;
  data += 3;
  size -= 3;
  switch( type % 8 )
  {
    case 0: run<std::int8_t>(op, off, data, size); break;
    case 1: run<std::uint8_t>(op, off, data, size); break;
    case 2: run<std::int16_t>(op, off, data, size); break;
    case 3: run<std::uint16_t>(op, off, data, size); break;
    case 4: run<std::int32_t>(op, off, data, size); break;
    case 5: run<std::uint64_t>(op, off, data, size); break;
    case 6: run<float>(op, off, data, size); break;
    default: run<double>(op, off, data, size); break;
  }
  return 0;
}
