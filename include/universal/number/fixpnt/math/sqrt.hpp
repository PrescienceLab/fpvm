#pragma once
// sqrt.hpp: sqrt functions for fixed-points
//
// Copyright (C) 2017-2021 Stillwater Supercomputing, Inc.
//
// This file is part of the universal numbers project, which is released under an MIT Open Source license.
#include <universal/native/ieee754.hpp>
#include <universal/number/fixpnt/math/sqrt_tables.hpp>

#ifndef FIXPNT_NATIVE_SQRT
#define FIXPNT_NATIVE_SQRT 0
#endif

namespace sw::universal {

/*
	// straight Babylonian
	inline double babylonian(double v) {
		double x_n = 0.5 * v; // initial guess
		const double eps = 1.0e-7;   // 
		do {
			x_n = (x_n + v / x_n) / 2.0;
		} while (std::abs(x_n * x_n - v) > eps);

		return x_n;
	}
*/

	template<size_t nbits, size_t rbits, bool arithmetic, typename bt>
	inline fixpnt<nbits, rbits, arithmetic, bt> BabylonianMethod(const fixpnt<nbits, rbits, arithmetic, bt>& v) {
		const double eps = 1.0e-5;
		fixpnt<nbits, rbits, arithmetic, bt> half(0.5);
		fixpnt<nbits, rbits, arithmetic, bt> x_next;
		fixpnt<nbits, rbits, arithmetic, bt> x_n = half * v;
		fixpnt<nbits, rbits, arithmetic, bt> diff;
		do {
			x_next = (x_n + v / x_n) * half;
			diff = x_next - x_n;
			   std::cout << " x_n+1: " << x_next << " x_n: " << x_n << " diff " << diff << std::endl;
			x_n = x_next;
		} while (double(sw::universal::abs(diff)) > eps);
		return x_n;
	}

	/*
	- Consider the function argument, x, in floating-point form, with a base
	(or radix) B, exponent e, and a fraction, f , such that 1/B <= f < 1.
	Then we have x = f Be. The number of bits in the exponent and
	fraction, and the value of the base, depends on the particular floating
	point arithmetic system chosen.

	- Use properties of the elementary function to range reduce the argument
	x to a small fixed interval.

	- Use a small polynomial approximation to produce an initial estimate,
	y0, of the function on the small interval. Such an estimate may
	be good to perhaps 5 to 10 bits.

	- Apply Newton iteration to refine the result. This takes the form yk =
	yk?1/2 + (f /2)/yk?1. In base 2, the divisions by two can be done by
	exponent adjustments in floating-point computation, or by bit shifting
	in fixed-point computation.

	Convergence of the Newton method is quadratic, so the number of
	correct bits doubles with each iteration. Thus, a starting point correct
	to 7 bits will produce iterates accurate to 14, 28, 56, ... bits. Since the
	number of iterations is very small, and known in advance, the loop is
	written as straight-line code.

	- Having computed the function value for the range-reduced argument,
	make whatever adjustments are necessary to produce the function value
	for the original argument; this step may involve a sign adjustment,
	and possibly a single multiplication and/or addition.
	*/


#if FIXPNT_NATIVE_SQRT
	// sqrt for arbitrary cfloat
	template<size_t nbits, size_t rbits, bool arithmetic, typename bt>
	inline fixpnt<nbits, rbits, arithmetic, bt> sqrt(const fixpnt<nbits, rbits, arithmetic, bt>& a) {
// TBD
		return a;
	}
#else
	template<size_t nbits, size_t rbits, bool arithmetic, typename bt>
	inline fixpnt<nbits, rbits, arithmetic, bt> sqrt(const fixpnt<nbits, rbits, arithmetic, bt>& a) {
		return fixpnt<nbits, rbits, arithmetic, bt>(std::sqrt((double)a));
	}
#endif

	// reciprocal sqrt
	template<size_t nbits, size_t rbits, bool arithmetic, typename bt>
	inline fixpnt<nbits, rbits, arithmetic, bt> rsqrt(const fixpnt<nbits, rbits, arithmetic, bt>& a) {
		fixpnt<nbits, rbits, arithmetic, bt> v = sqrt(a);
		return v.reciprocate();
	}

	///////////////////////////////////////////////////////////////////
	// specialized sqrt configurations

} // namespace sw::universal
