#pragma once
// posit.hpp: definition of arbitrary posit number configurations
//
// Copyright (C) 2017-2021 Stillwater Supercomputing, Inc.
//
// This file is part of the universal numbers project, which is released under an MIT Open Source license.
#include <cmath>
#include <cassert>
#include <iostream>
#include <iomanip>
#include <limits>
#include <regex>
#include <type_traits>

#if POSIT_THROW_ARITHMETIC_EXCEPTION
// propagate this behavior down to constituent classes
#ifndef BITBLOCK_THROW_ARITHMETIC_EXCEPTION
#define BITBLOCK_THROW_ARITHMETIC_EXCEPTION 1
#endif
#endif

// calling environment should define behavioral flags
// typically set in the library aggregation include file <posit>
// but can be set by individual programs when including posit.hpp
// For example:
// - define to non-zero if you want to enable arithmetic and logic literals
// #define POSIT_ENABLE_LITERALS 1
// - define to non-zero if you want to throw exceptions on arithmetic errors
// #define POSIT_THROW_ARITHMETIC_EXCEPTION 1

#if POSIT_THROW_ARITHMETIC_EXCEPTION
// Posits encode error conditions as NaR (Not a Real)
// propagating the error through arithmetic operations is preferred
#include "exceptions.hpp"
#endif // POSIT_THROW_ARITHMETIC_EXCEPTION

#include <universal/native/bit_functions.hpp>
// TODO: these need to be redesigned to enable constexpr and improve performance: roadmap V3 Q1 2021
#include <universal/internal/bitblock/bitblock.hpp>
#include <universal/internal/value/value.hpp>
#include <universal/number/shared/specific_value_encoding.hpp>
// posit environment
#include <universal/number/posit/posit_fwd.hpp>
#include <universal/number/posit/trace_constants.hpp>
#include <universal/number/posit/fraction.hpp>
#include <universal/number/posit/exponent.hpp>
#include <universal/number/posit/regime.hpp>
#include <universal/number/posit/attributes.hpp>

namespace sw::universal {

// inject internal namespace
using namespace sw::universal::internal;

// specialized configuration constants
constexpr size_t NBITS_IS_2   =   2;
constexpr size_t NBITS_IS_3   =   3;
constexpr size_t NBITS_IS_4   =   4;
constexpr size_t NBITS_IS_5   =   5;
constexpr size_t NBITS_IS_6   =   6;
constexpr size_t NBITS_IS_7   =   7;
constexpr size_t NBITS_IS_8   =   8;
constexpr size_t NBITS_IS_10  =  10;
constexpr size_t NBITS_IS_12  =  12;
constexpr size_t NBITS_IS_14  =  14;
constexpr size_t NBITS_IS_16  =  16;
constexpr size_t NBITS_IS_20  =  20;
constexpr size_t NBITS_IS_24  =  24;
constexpr size_t NBITS_IS_28  =  28;
constexpr size_t NBITS_IS_32  =  32;
constexpr size_t NBITS_IS_40  =  40;
constexpr size_t NBITS_IS_48  =  48;
constexpr size_t NBITS_IS_56  =  56;
constexpr size_t NBITS_IS_64  =  64;
constexpr size_t NBITS_IS_80  =  80;
constexpr size_t NBITS_IS_96  =  96;
constexpr size_t NBITS_IS_128 = 128;
constexpr size_t NBITS_IS_256 = 256;
constexpr size_t ES_IS_0 = 0;
constexpr size_t ES_IS_1 = 1;
constexpr size_t ES_IS_2 = 2;
constexpr size_t ES_IS_3 = 3;
constexpr size_t ES_IS_4 = 4;
constexpr size_t ES_IS_5 = 5;

// Not A Real is the posit encoding for INFINITY and arithmetic errors that can propagate
// The symbol NAR can be used to initialize a posit, i.e., posit<nbits,es>(NAR), or posit<nbits,es> p = NAR
#define NAR INFINITY

///////////////////////////////////////////////////////////////////////////////////////////////
// key posit algorithms

// special case check for projecting values between (0, minpos] to minpos and [maxpos, inf) to maxpos
// Returns true if the scale is too small or too large for this posit config
// DO NOT USE the k value for this, as the k value encodes the useed regions
// and thus is too coarse to make this decision.
// Using the scale directly is the simplest expression of the inward projection test.
template<size_t nbits, size_t es>
bool check_inward_projection_range(int scale) {
	// calculate the min/max k factor for this posit config
	int posit_size = nbits;
	int k = scale < 0 ? -(posit_size - 2) : (posit_size - 2);
	return scale < 0 ? scale < k*(1 << es) : scale > k*(1 << es);
}

// decode_regime measures the run-length of the regime and returns the k value associated with that run-length
// how many shifts represent the regime?
// regime = useed ^ k = (2 ^ (2 ^ es)) ^ k = 2 ^ (k*(2 ^ es))
// scale  = useed ^ k * 2^e = k*(2 ^ es) + e 
template<size_t nbits>
int decode_regime(const internal::bitblock<nbits>& raw_bits) {
	// let m be the number of identical bits in the regime
	int m = 0;   // regime runlength counter
	int k = 0;   // converted regime scale
	if (raw_bits[nbits - 2] == 1) {   // run length of 1's
		m = 1;   // if a run of 1's k = m - 1
		int start = (nbits == 2 ? nbits - 2 : nbits - 3);
		for (int i = start; i >= 0; --i) {
			if (raw_bits[size_t(i)] == 1) {
				m++;
			}
			else {
				break;
			}
		}
		k = m - 1;
	}
	else {
		m = 1;  // if a run of 0's k = -m
		int start = (nbits == 2 ? nbits - 2 : nbits - 3);
		for (int i = start; i >= 0; --i) {
			if (raw_bits[size_t(i)] == 0) {
				m++;
			}
			else {
				break;
			}
		}
		k = -m;
	}
	return k;
}

// extract_fields takes a raw posit encoding and extracts the sign, regime, exponent, and fraction components
template<size_t nbits, size_t es, size_t fbits>
void extract_fields(const bitblock<nbits>& raw_bits, bool& _sign, regime<nbits, es>& _regime, exponent<nbits, es>& _exponent, fraction<fbits>& _fraction) {
	// check special case
	bitblock<nbits> zero;
	if (raw_bits == zero) {
		_sign = false;
		_regime.setzero();
		_exponent.setzero();
		_fraction.setzero();
		return;
	}
	bitblock<nbits> tmp(raw_bits);
	_sign = raw_bits[nbits - 1];
	if (_sign) tmp = twos_complement(tmp);
	size_t nrRegimeBits = _regime.assign_regime_pattern(decode_regime(tmp));

	// get the exponent bits
	// start of exponent is nbits-1 - (sign_bit + regime_bits)
	int msb = static_cast<int>(nbits - 1ul - (1ul + nrRegimeBits));
	size_t nrExponentBits = 0;
	if (es > 0) {
		bitblock<es> _exp;
		if (msb >= 0 && es > 0) {
			nrExponentBits = (msb >= static_cast<int>(es - 1ull)) ? es : static_cast<size_t>(msb + 1ll);
			for (size_t i = 0; i < nrExponentBits; ++i) {
				_exp[es - size_t{1} - i] = tmp[static_cast<size_t>(msb) - i];
			}
		}
		_exponent.set(_exp, nrExponentBits);
	}

	// finally, set the fraction bits
	// we do this so that the fraction is right extended with 0;
	// The max fraction is <nbits - 3 - es>, but we are setting it to <nbits - 3> and right-extent
	// The msb bit of the fraction represents 2^-1, the next 2^-2, etc.
	// If the fraction is empty, we have a fraction of nbits-3 0 bits
	// If the fraction is one bit, we have still have fraction of nbits-3, with the msb representing 2^-1, and the rest are right extended 0's
	bitblock<fbits> _frac;
	msb = msb - int(nrExponentBits);
	size_t nrFractionBits = (msb < 0 ? 0ull : static_cast<size_t>(msb) + 1ull);
	if (msb >= 0) {
		for (int i = msb; i >= 0; --i) {
			_frac[fbits - size_t{ 1 } - static_cast<size_t>(msb - i)] = tmp[static_cast<size_t>(i)];
		}
	}
	_fraction.set(_frac, nrFractionBits);
}

// decode takes the raw bits representing a posit coming from memory
// and decodes the sign, regime, the exponent, and the fraction.
// This function has the functionality of the posit register-file load.
template<size_t nbits, size_t es, size_t fbits>
void decode(const bitblock<nbits>& raw_bits, bool& _sign, regime<nbits, es>& _regime, exponent<nbits, es>& _exponent, fraction<fbits>& _fraction) {
	//_raw_bits = raw_bits;	// store the raw bits for reference
	// check special cases
	_sign = raw_bits.test(nbits - 1);
	if (_sign) {
		bitblock<nbits> tmp(raw_bits);
		tmp.reset(nbits - 1);
		if (tmp.none()) {
			// setnar();   special case = NaR (Not a Real)
			_sign = true;
			_regime.setinf();
			_exponent.reset();
		}
		else {
			extract_fields(raw_bits, _sign, _regime, _exponent, _fraction);
		}
	}
	else {
		if (raw_bits.none()) {
			// setzero();  special case = 0
			_sign = false;
			_regime.setzero();  // <-- all the 0's end up in the regime
			_exponent.reset();
			_fraction.reset();
		}
		else {
			extract_fields(raw_bits, _sign, _regime, _exponent, _fraction);
		}
	}
	//if (_trace_decode) std::cout << "raw bits: " << raw_bits << " posit bits: " << (_sign ? "1|" : "0|") << _regime << "|" << _exponent << "|" << _fraction << " posit value: " << *this << std::endl;
	if (_trace_decode) std::cout << "raw bits: " << raw_bits << " posit bits: " << (_sign ? "1|" : "0|") << _regime << "|" << _exponent << "|" << _fraction << std::endl;

	// we are storing both the raw bit representation and the decoded form
	// so no need to transform back via 2's complement of regime/exponent/fraction
}

// needed to avoid double rounding situations during arithmetic: TODO: does that mean the condensed version below should be removed?
template<size_t nbits, size_t es, size_t fbits>
inline bitblock<nbits>& convert_to_bb(bool _sign, int _scale, const bitblock<fbits>& fraction_in, bitblock<nbits>& ptt) {
	if (_trace_conversion) std::cout << "------------------- CONVERT ------------------" << std::endl;
	if (_trace_conversion) std::cout << "sign " << (_sign ? "-1 " : " 1 ") << "scale " << std::setw(3) << _scale << " fraction " << fraction_in << std::endl;

	ptt.reset(); // ptt will yield the final bits of the posit
	// construct the posit
	// interpolation rule checks
	if (check_inward_projection_range<nbits, es>(_scale)) {    // regime dominated
		if (_trace_conversion) std::cout << "inward projection" << std::endl;
		// we are projecting to minpos/maxpos
		int k = calculate_unconstrained_k<nbits, es>(_scale);
		ptt = k < 0 ? minpos_pattern<nbits, es>(_sign) : maxpos_pattern<nbits, es>(_sign);
		// we are done
		if (_trace_rounding) std::cout << "projection  rounding ";
	}
	else {
		const size_t pt_len = nbits + 3 + es;
		bitblock<pt_len> pt_bits;
		bitblock<pt_len> regime;
		bitblock<pt_len> exponent;
		bitblock<pt_len> fraction;
		bitblock<pt_len> sticky_bit;

		bool s = _sign;
		int e = _scale;
		bool r = (e >= 0);

		size_t run = static_cast<size_t>(r ? 1ll + (e >> es) : -(e >> es));
		regime.set(0, 1 ^ r);  // TODO: this expression can be improved 1 ^ r is the same as !r as r is a boolean, no need for a bitwise operator
		for (size_t i = 1; i <= run; i++) regime.set(i, r);

		size_t esval = e % (size_t(1) << static_cast<int>(es));
		exponent = convert_to_bitblock<pt_len>(esval);
		size_t nf = size_t(std::max<int>(0, (static_cast<int>(nbits) + 1) - (2 + int(run) + static_cast<int>(es))));
		// TODO: what needs to be done if nf > fbits?
		//assert(nf <= input_fbits);
		// copy the most significant nf fraction bits into fraction
		size_t lsb = nf <= fbits ? 0 : nf - fbits;
		for (size_t i = lsb; i < nf; i++) fraction[i] = fraction_in[fbits - nf + i];

		bool sb = anyAfter(fraction_in, static_cast<int>(fbits) - 1 - int(nf));

		// construct the untruncated posit
		// pt    = BitOr[BitShiftLeft[reg, es + nf + 1], BitShiftLeft[esval, nf + 1], BitShiftLeft[fv, 1], sb];
		regime <<= es + nf + 1;
		exponent <<= nf + 1;
		fraction <<= 1;
		sticky_bit.set(0, sb);

		pt_bits |= regime;
		pt_bits |= exponent;
		pt_bits |= fraction;
		pt_bits |= sticky_bit;

		size_t len = 1 + std::max<size_t>((nbits + 1), (2 + run + es));
		bool blast = pt_bits.test(len - nbits);
		bool bafter = pt_bits.test(len - nbits - 1);
		bool bsticky = anyAfter(pt_bits, int(len) - static_cast<int>(nbits) - 1 - 1);

		bool rb = (blast & bafter) | (bafter & bsticky);

		pt_bits <<= pt_len - len;
		truncate(pt_bits, ptt);
		if (rb) increment_bitset(ptt);
		if (s) ptt = twos_complement(ptt);
	}
	return ptt;
}

// needed to avoid double rounding situations during arithmetic: TODO: does that mean the condensed version below should be removed?
template<size_t nbits, size_t es, size_t fbits>
inline posit<nbits, es>& convert_(bool _sign, int _scale, const bitblock<fbits>& fraction_in, posit<nbits, es>& p) {
	if (_trace_conversion) std::cout << "------------------- CONVERT ------------------" << std::endl;
	if (_trace_conversion) std::cout << "sign " << (_sign ? "-1 " : " 1 ") << "scale " << std::setw(3) << _scale << " fraction " << fraction_in << std::endl;

	p.clear();
	// construct the posit
	// interpolation rule checks
	if (check_inward_projection_range<nbits, es>(_scale)) {    // regime dominated
		if (_trace_conversion) std::cout << "inward projection" << std::endl;
		// we are projecting to minpos/maxpos
		int k = calculate_unconstrained_k<nbits, es>(_scale);
		k < 0 ? p.setBitblock(minpos_pattern<nbits, es>(_sign)) : p.setBitblock(maxpos_pattern<nbits, es>(_sign));
		// we are done
		if (_trace_rounding) std::cout << "projection  rounding ";
	}
	else {
		constexpr size_t pt_len = nbits + 3 + es;
		bitblock<pt_len> pt_bits;
		bitblock<pt_len> regime;
		bitblock<pt_len> exponent;
		bitblock<pt_len> fraction;
		bitblock<pt_len> sticky_bit;

		bool s = _sign;
		int e  = _scale;
		bool r = (e >= 0);

		size_t run = size_t(r ? 1 + (e >> es) : -(e >> es));
		regime.set(0, 1 ^ r);
		for (size_t i = 1; i <= run; i++) regime.set(i, r);

		size_t esval = e % (uint32_t(1) << es);
		exponent = convert_to_bitblock<pt_len>(esval);
		int nbits_plus_one = static_cast<int>(nbits) + 1;
		int sign_regime_es = 2 + int(run) + static_cast<int>(es);
		size_t nf = (size_t)std::max<int>(0, (nbits_plus_one - sign_regime_es));
		//size_t nf = (size_t)std::max<int>(0, (static_cast<int>(nbits + 1) - (2 + run + static_cast<int>(es))));
		// TODO: what needs to be done if nf > fbits?
		//assert(nf <= input_fbits);
		// copy the most significant nf fraction bits into fraction
		size_t lsb = nf <= fbits ? 0 : nf - fbits;
		for (size_t i = lsb; i < nf; ++i) fraction[i] = fraction_in[fbits - nf + i];

		bool sb = anyAfter(fraction_in, static_cast<int>(fbits) - 1 - int(nf));

		// construct the untruncated posit
		// pt    = BitOr[BitShiftLeft[reg, es + nf + 1], BitShiftLeft[esval, nf + 1], BitShiftLeft[fv, 1], sb];
		regime <<= es + nf + 1;
		exponent <<= nf + 1;
		fraction <<= 1;
		sticky_bit.set(0, sb);

		pt_bits |= regime;
		pt_bits |= exponent;
		pt_bits |= fraction;
		pt_bits |= sticky_bit;

		size_t len = 1 + std::max<size_t>((nbits + 1), (2 + run + es));
		bool blast = pt_bits.test(len - nbits);
		bool bafter = pt_bits.test(len - nbits - 1);
		bool bsticky = anyAfter(pt_bits, int(len) - static_cast<int>(nbits) - 1 - 1);

		bool rb = (blast & bafter) | (bafter & bsticky);

		bitblock<nbits> ptt;
		pt_bits <<= pt_len - len;
		truncate(pt_bits, ptt);
		if (rb) increment_bitset(ptt);
		if (s) ptt = twos_complement(ptt);
		p.setBitblock(ptt);
	}
	return p;
}

// convert a floating point value to a specific posit configuration. Semantically, p = v, return reference to p
template<size_t nbits, size_t es, size_t fbits>
inline posit<nbits, es>& convert(const internal::value<fbits>& v, posit<nbits, es>& p) {
	if (_trace_conversion) std::cout << "------------------- CONVERT ------------------" << std::endl;
	if (_trace_conversion) std::cout << "sign " << (v.sign() ? "-1 " : " 1 ") << "scale " << std::setw(3) << v.scale() << " fraction " << v.fraction() << std::endl;

	if (v.iszero()) {
		p.setzero();
		return p;
	}
	if (v.isnan() || v.isinf()) {
		p.setnar();
		return p;
	}
	return convert_<nbits, es, fbits>(v.sign(), v.scale(), v.fraction(), p);
}
	
// quadrant returns a two character string indicating the quadrant of the projective reals the posit resides: from 0, SE, NE, NaR, NW, SW
template<size_t nbits, size_t es>
std::string quadrant(const posit<nbits,es>& p) {
	posit<nbits, es> pOne(1), pMinusOne(-1);
	if (sign(p)) {
		// west
		if (p > pMinusOne) {
			return "SW";
		}
		else {
			return "NW";
		}
	}
	else {
		// east
		if (p < pOne) {
			return "SE";
		}
		else {
			return "NE";
		}
	}
}

// collect the posit components into a bitset: TODO: do we enforce fbits to be the same size as the posit::fbits?
template<size_t nbits, size_t es, size_t fbits>
bitblock<nbits> collect(bool _sign, const regime<nbits, es>& _regime, const exponent<nbits, es>& _exponent, const fraction<fbits>& _fraction) {
	bitblock<nbits-1> r = _regime.get();
	size_t nrRegimeBits = _regime.nrBits();
	bitblock<es> e = _exponent.get();
	size_t nrExponentBits = _exponent.nrBits();
	bitblock<fbits> f = _fraction.get();
	size_t nrFractionBits = _fraction.nrBits();
	bitblock<nbits> raw_bits;
	raw_bits.set(nbits - 1, _sign);
	int msb = int(nbits) - 2;
	for (size_t i = 0; i < nrRegimeBits; i++) {
		raw_bits.set(msb--, r[nbits - 2 - i]);
	}
	if (msb >= 0) {
		for (size_t i = 0; i < nrExponentBits; i++) {
			raw_bits.set(msb--, e[es - 1 - i]);
		}
	}
	if (msb >= 0) {
		for (size_t i = 0; i < nrFractionBits; i++) {
			raw_bits.set(msb--, f[fbits - 1 - i]);
		}
	}
	return raw_bits;
}

// Construct posit from its components
template<size_t nbits, size_t es, size_t fbits>
posit<nbits, es>& construct(bool s, const regime<nbits, es>& r, const exponent<nbits, es>& e, const fraction<fbits>& f, posit<nbits,es>& p) {
	// generate raw bit representation
	bitblock<nbits> _raw_bits = s ? twos_complement(collect(s, r, e, f)) : collect(s, r, e, f);
	_raw_bits.set(nbits - 1, s);
	p.set(_raw_bits);
	return p;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// class posit represents posit numbers of arbitrary configuration and their basic arithmetic operations (add/sub, mul/div)
template<size_t _nbits, size_t _es>
class posit {

//	static_assert(sizeof(long double) == 16, "Posit library requires compiler support for 128 bit long double.");
//	static_assert((sizeof(long double) == 16) && (std::numeric_limits<long double>::digits < 113), "C++ math library for long double does not support 128-bit quad precision floats.");
  
public:
	static constexpr size_t nbits   = _nbits;
	static constexpr size_t es      = _es;
	static constexpr size_t sbits   = 1;                          // number of sign bits:     specified
	static constexpr size_t rbits   = nbits - sbits;              // maximum number of regime bits:   derived
	static constexpr size_t ebits   = es;                         // maximum number of exponent bits: specified
	static constexpr size_t fbits   = (es + 2 >= nbits ? 0 : nbits - 3 - es);             // maximum number of fraction bits: derived
	static constexpr size_t fhbits  = fbits + 1;                  // maximum number of fraction + one hidden bit

	static constexpr size_t abits   = fhbits + 3;                 // size of the addend
	static constexpr size_t mbits   = 2 * fhbits;                 // size of the multiplier output
	static constexpr size_t divbits = 3 * fhbits + 4;             // size of the divider output

	// constexpr posit() { setzero();  }
	constexpr posit() : _raw_bits{} {}
	
	constexpr posit(const posit&) = default;
	constexpr posit(posit&&) = default;
	
	posit& operator=(const posit&) = default;
	posit& operator=(posit&&) = default;

	/// Construct posit from another posit
	template<size_t nnbits, size_t ees>
	posit(const posit<nnbits, ees>& a) {
		*this = a.to_value();
	}

	// specific value constructor
	constexpr posit(const SpecificValue code) {
		switch (code) {
		case SpecificValue::infpos:
		case SpecificValue::maxpos:
			maxpos();
			break;
		case SpecificValue::minpos:
			minpos();
			break;
		case SpecificValue::zero:
		default:
			zero();
			break;
		case SpecificValue::minneg:
			minneg();
			break;
		case SpecificValue::infneg:
		case SpecificValue::maxneg:
			maxneg();
			break;
		case SpecificValue::snan:
		case SpecificValue::qnan:
		case SpecificValue::nar:
			setnar();
			break;
		}
	}

	// initializers for native types, allow for implicit conversion (Peter)
	constexpr posit(signed char initial_value)        { *this = initial_value; }
	constexpr posit(short initial_value)              { *this = initial_value; }
	constexpr posit(int initial_value)                { *this = initial_value; }
	constexpr posit(long initial_value)               { *this = initial_value; }
	constexpr posit(long long initial_value)          { *this = initial_value; }
	constexpr posit(char initial_value)               { *this = initial_value; }
	constexpr posit(unsigned short initial_value)     { *this = initial_value; }
	constexpr posit(unsigned int initial_value)       { *this = initial_value; }
	constexpr posit(unsigned long initial_value)      { *this = initial_value; }
	constexpr posit(unsigned long long initial_value) { *this = initial_value; }
	constexpr posit(float initial_value)              { *this = initial_value; }
	constexpr posit(double initial_value)             { *this = initial_value; }
	constexpr posit(long double initial_value)        { *this = initial_value; }

	// assignment operators for native types
	posit& operator=(signed char rhs) {
		internal::value<8*sizeof(signed char)-1> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(short rhs) {
		internal::value<8*sizeof(short)-1> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(int rhs) {
		internal::value<8*sizeof(int)-1> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(long rhs) {
		internal::value<8*sizeof(long)> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(long long rhs) {
		internal::value<8*sizeof(long long)-1> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(char rhs) {
		internal::value<8*sizeof(char)> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(unsigned short rhs) {
		internal::value<8*sizeof(unsigned short)> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(unsigned int rhs) {
		internal::value<8*sizeof(unsigned int)> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(unsigned long rhs) {
		internal::value<8*sizeof(unsigned long)> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(unsigned long long rhs) {
		internal::value<8*sizeof(unsigned long long)> v(rhs);
		if (v.iszero()) {
			setzero();
			return *this;
		}
		else {
			convert(v, *this);
		}
		return *this;
	}
	posit& operator=(float rhs) {
		return float_assign(rhs);
	}
	constexpr posit& operator=(double rhs) & {
            float_assign(rhs);
            return *this; 
	}
	posit& operator=(long double rhs) {
       	return float_assign(rhs);
	}

#ifdef ADAPTER_POSIT_AND_INTEGER
	// INTEGER_TYPE_CONCEPT_GENERALIZATION
	// TODO: SFINAE to assure we only match an integer<nbits> concept
	template<typename IntegerType>
	posit& operator=(const IntegerType& rhs) {
		convert_i2p(rhs, *this);
		return *this;
	}
#endif

	// assignment for value type
	template<size_t vbits>
	posit& operator=(const internal::value<vbits>& rhs) {
		clear();
		convert(rhs, *this);
		return *this;
	}
	
	// negation operator
	posit operator-() const {
		if (iszero()) {
			return *this;
		}
		if (isnar()) {
			return *this;
		}
		posit<nbits, es> negated(0);  // TODO: artificial initialization to pass -Wmaybe-uninitialized
		bitblock<nbits> raw_bits = twos_complement(_raw_bits);
		negated.setBitblock(raw_bits);
		return negated;
	}
	// prefix/postfix operators
	posit& operator++() {
		increment_posit();
		return *this;
	}
	posit operator++(int) {
		posit tmp(*this);
		operator++();
		return tmp;
	}
	posit& operator--() {
		decrement_posit();
		return *this;
	}
	posit operator--(int) {
		posit tmp(*this);
		operator--();
		return tmp;
	}

	// we model a hw pipeline with register assignments, functional block, and conversion
	posit& operator+=(const posit& rhs) {
		if (_trace_add) std::cout << "---------------------- ADD -------------------" << std::endl;
		// special case handling of the inputs
#if POSIT_THROW_ARITHMETIC_EXCEPTION
		if (isnar() || rhs.isnar()) {
			throw operand_is_nar{};
		}
#else
		if (isnar() || rhs.isnar()) {
			setnar();
			return *this;
		}
#endif
		if (iszero()) {
			*this = rhs;
			return *this;
		}
		if (rhs.iszero()) return *this;

		// arithmetic operation
		internal::value<abits + 1> sum;
		internal::value<fbits> a, b;
		// transform the inputs into (sign,scale,fraction) triples
		normalize(a);
		rhs.normalize(b);
		module_add<fbits,abits>(a, b, sum);		// add the two inputs

		// special case handling of the result
		if (sum.iszero()) {
			setzero();
		}
		else if (sum.isinf()) {
			setnar();
		}
		else {
			convert(sum, *this);
		}
		return *this;                
	}
	posit& operator+=(double rhs) {
		return *this += posit<nbits, es>(rhs);
	}
	posit& operator-=(const posit& rhs) {
		if (_trace_sub) std::cout << "---------------------- SUB -------------------" << std::endl;
		// special case handling of the inputs
#if POSIT_THROW_ARITHMETIC_EXCEPTION
		if (isnar() || rhs.isnar()) {
			throw operand_is_nar{};
		}
#else
		if (isnar() || rhs.isnar()) {
			setnar();
			return *this;
		}
#endif
		if (iszero()) {
			*this = -rhs;
			return *this;
		}
		if (rhs.iszero()) return *this;

		// arithmetic operation
		internal::value<abits + 1> difference;
		internal::value<fbits> a, b;
		// transform the inputs into (sign,scale,fraction) triples
		normalize(a);
		rhs.normalize(b);
		module_subtract<fbits, abits>(a, b, difference);	// add the two inputs

		// special case handling of the result
		if (difference.iszero()) {
			setzero();
		}
		else if (difference.isinf()) {
			setnar();
		}
		else {
			convert(difference, *this);
		}
		return *this;
	}
	posit& operator-=(double rhs) {
		return *this -= posit<nbits, es>(rhs);
	}
	posit& operator*=(const posit& rhs) {
		static_assert(fhbits > 0, "posit configuration does not support multiplication");
		if (_trace_mul) std::cout << "---------------------- MUL -------------------" << std::endl;
		// special case handling of the inputs
#if POSIT_THROW_ARITHMETIC_EXCEPTION
		if (isnar() || rhs.isnar()) {
			throw operand_is_nar{};
		}
#else
		if (isnar() || rhs.isnar()) {
			setnar();
			return *this;
		}
#endif
		if (iszero() || rhs.iszero()) {
			setzero();
			return *this;
		}

		// arithmetic operation
		internal::value<mbits> product;
		internal::value<fbits> a, b;
		// transform the inputs into (sign,scale,fraction) triples
		normalize(a);
		rhs.normalize(b);

		module_multiply(a, b, product);    // multiply the two inputs

		// special case handling on the output
		if (product.iszero()) {
			setzero();
		}
		else if (product.isinf()) {
			setnar();
		}
		else {
			convert(product, *this);
		}
		return *this;
	}
	posit& operator*=(double rhs) {
		return *this *= posit<nbits, es>(rhs);
	}
	posit& operator/=(const posit& rhs) {
		if (_trace_div) std::cout << "---------------------- DIV -------------------" << std::endl;
#if POSIT_THROW_ARITHMETIC_EXCEPTION
		if (rhs.iszero()) {
			throw divide_by_zero{};    // not throwing is a quiet signalling NaR
		}
		if (rhs.isnar()) {
			throw divide_by_nar{};
		}
		if (isnar()) {
			throw numerator_is_nar{};
		}
		if (iszero() || isnar()) {
			return *this;
		}
#else
		// not throwing is a quiet signalling NaR
		if (rhs.iszero()) {
			setnar();
			return *this;
		}
		if (rhs.isnar()) {
			setnar();
			return *this;
		}
		if (iszero() || isnar()) {
			return *this;
		}
#endif
		internal::value<divbits> ratio;
		internal::value<fbits> a, b;
		// transform the inputs into (sign,scale,fraction) triples
		normalize(a);
		rhs.normalize(b);

		module_divide(a, b, ratio);

		// special case handling on the output
#if POSIT_THROW_ARITHMETIC_EXCEPTION
		if (ratio.iszero()) {
			throw division_result_is_zero{};
		}
		else if (ratio.isinf()) {
			throw division_result_is_infinite{};
		}
		else {
			convert<nbits, es, divbits>(ratio, *this);
		}
#else
		if (ratio.iszero()) {
			setzero();  // this shouldn't happen as we should project back onto minpos
		}
		else if (ratio.isinf()) {
			setnar();  // this shouldn't happen as we should project back onto maxpos
		}
		else {
			convert<nbits, es, divbits>(ratio, *this);
		}
#endif

		return *this;
	}
	posit& operator/=(double rhs) {
		return *this /= posit<nbits, es>(rhs);
	}
	
	posit reciprocate() const {
		if (_trace_reciprocate) std::cout << "-------------------- RECIPROCATE ----------------" << std::endl;
		posit<nbits, es> p;
		// special case of NaR (Not a Real)
		if (isnar()) {
			p.setnar();
			return p;
		}
		if (iszero()) {
			p.setnar();
			return p;
		}
		// compute the reciprocal
		bool old_sign = _raw_bits[nbits-1];
		internal::bitblock<nbits> raw_bits;
		if (ispowerof2()) {
			raw_bits = twos_complement(_raw_bits);
			raw_bits.set(nbits-1, old_sign);
			p.setBitblock(raw_bits);
		}
		else {
			bool s{ false };
			regime<nbits, es> r;
			exponent<nbits, es> e;
			fraction<fbits> f;
			decode(_raw_bits, s, r, e, f);

			constexpr size_t operand_size = fhbits;
			internal::bitblock<operand_size> one;
			one.set(operand_size - 1, true);
			internal::bitblock<operand_size> frac;
			copy_into(f.get(), 0, frac);
			frac.set(operand_size - 1, true);
			constexpr size_t reciprocal_size = 3 * fbits + 4;
			internal::bitblock<reciprocal_size> reciprocal;
			divide_with_fraction(one, frac, reciprocal);
			if (_trace_reciprocate) {
				std::cout << "one    " << one << std::endl;
				std::cout << "frac   " << frac << std::endl;
				std::cout << "recip  " << reciprocal << std::endl;
			}

			// radix point falls at operand size == reciprocal_size - operand_size - 1
			reciprocal <<= operand_size - 1;
			if (_trace_reciprocate) std::cout << "frac   " << reciprocal << std::endl;
			int new_scale = -scale(*this);
			int msb = findMostSignificantBit(reciprocal);
			if (msb > 0) {
				int shift = static_cast<int>(reciprocal_size - static_cast<size_t>(msb));
				reciprocal <<= static_cast<size_t>(shift);
				new_scale -= (shift-1);
				if (_trace_reciprocate) std::cout << "result " << reciprocal << std::endl;
			}
			//std::bitset<operand_size> tr;
			//truncate(reciprocal, tr);
			//std::cout << "tr     " << tr << std::endl;

			// the following is failing for some reason
			// value<reciprocal_size> v(old_sign, new_scale, reciprocal);
			// convert(v, p);
			// instead the following works
			convert_<nbits,es, reciprocal_size>(old_sign, new_scale, reciprocal, p);
		}
		return p;
	}
	// absolute value is simply the 2's complement when negative
	posit abs() const {
		posit p;
		if (isneg()) {
			p.setBitblock(twos_complement(_raw_bits));
		}
		else {
			p.setBitblock(_raw_bits);
		}
		return p;
	}

	// conversion operators
	// Maybe remove explicit, MTL compiles, but we have lots of double computation then
	explicit operator unsigned short() const { return to_ushort(); }
	explicit operator unsigned int() const { return to_uint(); }
	explicit operator unsigned long() const { return to_ulong(); }
	explicit operator unsigned long long() const { return to_ulong_long(); }
	explicit operator short() const { return to_short(); }
	explicit operator int() const { return to_int(); }
	explicit operator long() const { return to_long(); }
	explicit operator long long() const { return to_long_long(); }
	explicit operator float() const { return to_float(); }
	explicit operator double() const { return to_double(); }
	explicit operator long double() const { return to_long_double(); }

	// Selectors
	inline bool sign() const { return _raw_bits[nbits - 1]; }
	inline bool isnar() const {
		if (_raw_bits[nbits - 1] == false) return false;
		bitblock<nbits> tmp(_raw_bits);			
		tmp.reset(nbits - 1);
		return tmp.none() ? true : false;
	}
	inline bool iszero() const { return _raw_bits.none() ? true : false; }
	inline bool isone() const { // pattern 010000....
		bitblock<nbits> tmp(_raw_bits);
		tmp.set(nbits - 2, false);
		return _raw_bits[nbits - 2] & tmp.none();
	}
	inline bool isminusone() const { // pattern 110000...
		bitblock<nbits> tmp(_raw_bits);
		tmp.set(nbits - 1, false);
		tmp.set(nbits - 2, false);
		return _raw_bits[nbits - 1] & _raw_bits[nbits - 2] & tmp.none();
	}
	inline bool isneg() const { return _raw_bits[nbits - 1]; }
	inline bool ispos() const { return !_raw_bits[nbits - 1]; }
	inline bool ispowerof2() const {
		bool s{ false };
		regime<nbits, es> r;
		exponent<nbits, es> e;
		fraction<fbits> f;
		decode(_raw_bits, s, r, e, f);
		return f.none();
	}
	inline bool isinteger() const { return true; } // return (floor(*this) == *this) ? true : false; }

	bitblock<nbits>    get() const { return _raw_bits; }
	unsigned long long encoding() const { return _raw_bits.to_ullong(); }

	// Modifiers
	inline constexpr void clear() { _raw_bits.reset(); }
	inline constexpr void setzero() { clear(); }
	inline constexpr void setnar() {
		_raw_bits.reset();
		_raw_bits.set(nbits - 1, true);
	}
	// set minpos value
	inline posit& minpos() {
		clear();
		return ++(*this);
	}
	// set maxpos value
	inline posit& maxpos() {
		setnar();
		return --(*this);
	}
	// set zero value
	inline posit& zero() {
		clear();
		return *this;
	}
	// set minneg value
	inline posit& minneg() {
		clear();
		return --(*this);
	}
	// set maxneg value
	inline posit& maxneg() {
		setnar();
		return ++(*this);
	}

	// set the posit bits explicitely
	constexpr posit<nbits, es>& setBitblock(const bitblock<nbits>& raw_bits) {
		_raw_bits = raw_bits;
		return *this;
	}
	// Set the raw bits of the posit given an unsigned value starting from the lsb. Handy for enumerating a posit state space
	constexpr posit<nbits,es>& setbits(uint64_t value) {
		clear();
		bitblock<nbits> raw_bits;
		uint64_t mask = 1;
		for ( size_t i = 0; i < nbits; i++ ) {
			raw_bits.set(i,(value & mask));
			mask <<= 1;
		}
		_raw_bits = raw_bits;
		return *this;
	}

	// currently, size is tied to fbits size of posit config. Is there a need for a case that captures a user-defined sized fraction?
	internal::value<fbits> to_value() const {
		using namespace sw::universal::internal;
		bool		     	 _sign{ false };
		regime<nbits, es>    _regime;
		exponent<nbits, es>  _exponent;
		fraction<fbits>      _fraction;
		decode(_raw_bits, _sign, _regime, _exponent, _fraction);
		return internal::value<fbits>(_sign, _regime.scale() + _exponent.scale(), _fraction.get(), iszero(), isnar());
	}
	void normalize(internal::value<fbits>& v) const {
		using namespace sw::universal::internal;
		bool		     	 _sign{ false };
		regime<nbits, es>    _regime;
		exponent<nbits, es>  _exponent;
		fraction<fbits>      _fraction;
		decode(_raw_bits, _sign, _regime, _exponent, _fraction);
		v.set(_sign, _regime.scale() + _exponent.scale(), _fraction.get(), iszero(), isnar());
	}
	template<size_t tgt_fbits>
	void normalize_to(internal::value<tgt_fbits>& v) const {
		using namespace sw::universal::internal;
		bool		     	 _sign{ false };
		regime<nbits, es>    _regime;
		exponent<nbits, es>  _exponent;
		fraction<fbits>      _fraction;
		decode(_raw_bits, _sign, _regime, _exponent, _fraction);
		bitblock<tgt_fbits> _fr;
		bitblock<fbits> _src = _fraction.get();
		int tgt, src;
		for (tgt = int(tgt_fbits) - 1, src = int(fbits) - 1; tgt >= 0 && src >= 0; tgt--, src--) _fr[tgt] = _src[src];
		v.set(_sign, _regime.scale() + _exponent.scale(), _fr, iszero(), isnar());
	}
	
	// step up to the next posit in a lexicographical order
	void increment_posit() {
		increment_bitset(_raw_bits);
	}
	// step down to the previous posit in a lexicographical order
	void decrement_posit() {
		decrement_bitset(_raw_bits);
	}
	
	// return human readable type configuration for this posit
	inline std::string cfg() {
		std::stringstream ss;
		ss << "posit<" << nbits << ", " << es << ">";
		return ss.str();
	}

private:
	internal::bitblock<nbits>      _raw_bits;	// raw bit representation

	// HELPER methods

	// Conversion functions
#if POSIT_THROW_ARITHMETIC_EXCEPTION
	short to_short() const {
		if (iszero()) return 0;
		if (isnar()) throw not_a_real{};
		return short(to_float());
	}
	int to_int() const {
		if (iszero()) return 0;
		if (isnar()) throw not_a_real{};
		return int(to_double());
	}
	long to_long() const {
		if (iszero()) return 0;
		if (isnar()) throw not_a_real{};
		return long(to_long_double());
	}
	long long to_long_long() const {
		if (iszero()) return 0;
		if (isnar()) throw not_a_real{};
		return (long long)(to_long_double());
	}
	unsigned short to_ushort() const {
		if (iszero()) return 0;
		if (isnar()) throw not_a_real{};
		return (unsigned short)(to_float());
	}
	unsigned int to_uint() const {
		if (iszero()) return 0;
		if (isnar()) throw not_a_real{};
		return (unsigned int)(to_double());
	}
	unsigned long to_ulong() const {
		if (iszero()) return 0;
		if (isnar()) throw not_a_real{};
		return (unsigned long)(to_long_double());
	}
	unsigned long long to_ulong_long() const {
		if (iszero()) return 0;
		if (isnar()) throw not_a_real{};
		return (unsigned long long)(to_long_double());
	}
#else
	short to_short() const                   { return short(to_float()); }
	int to_int() const                       { return int(to_double()); }
	long to_long() const                     { return long(to_long_double()); }
	long long to_long_long() const           { return (long long)(to_long_double()); }
	unsigned short to_ushort() const         { return (unsigned short)(to_float()); }
	unsigned int to_uint() const             { return (unsigned int)(to_double()); }
	unsigned long to_ulong() const           { return (unsigned long)(to_long_double()); }
	unsigned long long to_ulong_long() const { return (unsigned long long)(to_long_double()); }
#endif
	float to_float() const {
		return (float)to_double();
	}
	double to_double() const {
		if (iszero())	return 0.0;
		if (isnar())	return std::numeric_limits<double>::quiet_NaN();
		bool		     	 _sign{ false };
		regime<nbits, es>    _regime;
		exponent<nbits, es>  _exponent;
		fraction<fbits>      _fraction;
		decode(_raw_bits, _sign, _regime, _exponent, _fraction);
		double s = (_sign ? -1.0 : 1.0);
		double r = double(_regime.value());
		double e = double(_exponent.value());
		double f = (1.0 + double(_fraction.value()));
		return s * r * e * f;
	}
	long double to_long_double() const {
		if (iszero())  return 0.0l;
		if (isnar())   return std::numeric_limits<double>::quiet_NaN();;
		bool		     	 _sign{ false };
		regime<nbits, es>    _regime;
		exponent<nbits, es>  _exponent;
		fraction<fbits>      _fraction;
		decode(_raw_bits, _sign, _regime, _exponent, _fraction);
		long double s = (_sign ? -1.0l : 1.0l);
		long double r = _regime.value();
		long double e = _exponent.value();
		long double f = (1.0l + _fraction.value());
		return s * r * e * f;
	}
	template <typename T>
	constexpr posit<nbits, es>& float_assign(const T& rhs) {
		constexpr int dfbits = std::numeric_limits<T>::digits - 1;
		internal::value<dfbits> v(static_cast<T>(rhs));

		// special case processing
		if (v.iszero()) {
			setzero();
			return *this;
		}
		if (v.isinf() || v.isnan()) {  // posit encode for FP_INFINITE and NaN as NaR (Not a Real)
			setnar();
			return *this;
		}

		convert(v, *this);
		return *this;
	}

	// friend functions
	// template parameters need names different from class template parameters (for gcc and clang)
	template<size_t nnbits, size_t ees>
	friend std::ostream& operator<< (std::ostream& ostr, const posit<nnbits, ees>& p);
	template<size_t nnbits, size_t ees>
	friend std::istream& operator>> (std::istream& istr, posit<nnbits, ees>& p);

	// posit - posit logic functions
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, const posit<nnbits, ees>& rhs);

#if POSIT_ENABLE_LITERALS
	// posit - literal logic functions

	// posit - signed char
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, signed char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, signed char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, signed char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, signed char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, signed char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, signed char rhs);

	// posit - char
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, char rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, char rhs);

	// posit - short
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, short rhs);

	// posit - unsigned short
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, unsigned short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, unsigned short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, unsigned short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, unsigned short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, unsigned short rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, unsigned short rhs);

	// posit - int
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, int rhs);

	// posit - unsigned int
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, unsigned int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, unsigned int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, unsigned int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, unsigned int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, unsigned int rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, unsigned int rhs);

	// posit - long
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, long rhs);

	// posit - unsigned long long
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, unsigned long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, unsigned long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, unsigned long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, unsigned long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, unsigned long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, unsigned long rhs);

	// posit - long long
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, long long rhs);

	// posit - unsigned long long
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, unsigned long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, unsigned long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, unsigned long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, unsigned long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, unsigned long long rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, unsigned long long rhs);

	// posit - float
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, float rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, float rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, float rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, float rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, float rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, float rhs);

	// posit - double
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, double rhs);

	// posit - long double
	template<size_t nnbits, size_t ees>
	friend bool operator==(const posit<nnbits, ees>& lhs, long double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(const posit<nnbits, ees>& lhs, long double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (const posit<nnbits, ees>& lhs, long double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (const posit<nnbits, ees>& lhs, long double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(const posit<nnbits, ees>& lhs, long double rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(const posit<nnbits, ees>& lhs, long double rhs);

	// literal - posit logic functions

	// signed char - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(signed char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(signed char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (signed char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (signed char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(signed char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(signed char lhs, const posit<nnbits, ees>& rhs);

	// char - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(char lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(char lhs, const posit<nnbits, ees>& rhs);

	// short - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(short lhs, const posit<nnbits, ees>& rhs);

	// unsigned short - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(unsigned short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(unsigned short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (unsigned short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (unsigned short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(unsigned short lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(unsigned short lhs, const posit<nnbits, ees>& rhs);

	// int - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(int lhs, const posit<nnbits, ees>& rhs);

	// unsigned int - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(unsigned int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(unsigned int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (unsigned int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (unsigned int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(unsigned int lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(unsigned int lhs, const posit<nnbits, ees>& rhs);

	// long - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(long lhs, const posit<nnbits, ees>& rhs);

	// unsigned long - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(unsigned long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(unsigned long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (unsigned long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (unsigned long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(unsigned long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(unsigned long lhs, const posit<nnbits, ees>& rhs);

	// long long - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(long long lhs, const posit<nnbits, ees>& rhs);

	// unsigned long long - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(unsigned long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(unsigned long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (unsigned long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (unsigned long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(unsigned long long lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(unsigned long long lhs, const posit<nnbits, ees>& rhs);

	// float - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(float lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(float lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (float lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (float lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(float lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(float lhs, const posit<nnbits, ees>& rhs);

	// double - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(double lhs, const posit<nnbits, ees>& rhs);

	// long double - posit
	template<size_t nnbits, size_t ees>
	friend bool operator==(long double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator!=(long double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator< (long double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator> (long double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator<=(long double lhs, const posit<nnbits, ees>& rhs);
	template<size_t nnbits, size_t ees>
	friend bool operator>=(long double lhs, const posit<nnbits, ees>& rhs);

#endif // POSIT_ENABLE_LITERALS

};

////////////////// convenience/shim functions

template<size_t nbits, size_t es>
inline bool isnar(const posit<nbits, es>& p) {
	return p.isnar();
}
template<size_t nbits, size_t es>
inline bool iszero(const posit<nbits, es>& p) {
	return p.iszero();
}
template<size_t nbits, size_t es>
inline bool ispos(const posit<nbits, es>& p) {
	return p.ispos();
}
template<size_t nbits, size_t es>
inline bool isneg(const posit<nbits, es>& p) {
	return p.isneg();
}
template<size_t nbits, size_t es>
inline bool isone(const posit<nbits, es>& p) {
	return p.isone();
}		
template<size_t nbits, size_t es>
inline bool isminusone(const posit<nbits, es>& p) {
	return p.isminusone();
}
template<size_t nbits, size_t es>
inline bool ispowerof2(const posit<nbits, es>& p) {
	return p.ispowerof2();
}

////////////////// POSIT operators

// stream operators

// generate a posit format ASCII format nbits.esxNN...NNp
template<size_t nbits, size_t es>
inline std::ostream& operator<<(std::ostream& ostr, const posit<nbits, es>& p) {
	// to make certain that setw and left/right operators work properly
	// we need to transform the posit into a string
	std::stringstream ss;
#if POSIT_ROUNDING_ERROR_FREE_IO_FORMAT
	ss << nbits << '.' << es << 'x' << to_hex(p.get()) << 'p';
#else
	std::streamsize prec = ostr.precision();
	std::streamsize width = ostr.width();
	std::ios_base::fmtflags ff;
	ff = ostr.flags();
	ss.flags(ff);
//	ss << std::showpos << std::setw(width) << std::setprecision(prec) << (long double)p;
	// TODO: how do you react to fmtflags being set, such as hexfloat or showpos?
	// it appears that the fmtflags are opaque and not a user-visible feature
	ss << std::setw(width) << std::setprecision(prec);
	ss << to_string(p, prec);  // TODO: we need a true native serialization function
#endif
	return ostr << ss.str();
}

// read an ASCII float or posit format: nbits.esxNN...NNp, for example: 32.2x80000000p
template<size_t nbits, size_t es>
inline std::istream& operator>> (std::istream& istr, posit<nbits, es>& p) {
	std::string txt;
	istr >> txt;
	if (!parse(txt, p)) {
		std::cerr << "unable to parse -" << txt << "- into a posit value\n";
	}
	return istr;
}

// generate a posit format ASCII format nbits.esxNN...NNp
template<size_t nbits, size_t es>
inline std::string hex_format(const posit<nbits, es>& p) {
	// we need to transform the posit into a string
	std::stringstream ss;
	ss << nbits << '.' << es << 'x' << to_hex(p.get()) << 'p';
	return ss.str();
}

template<typename Float>
inline std::string hex_format(Float f) {
	std::stringstream ss;
	ss << std::hexfloat << std::setprecision(std::numeric_limits<Float>::digits10) << f;
	return ss.str();
}

// convert a posit value to a string using "nar" as designation of NaR
template<size_t nbits, size_t es>
inline std::string to_string(const posit<nbits, es>& p, std::streamsize precision = 17) {
	if (p.isnar()) {
		return std::string("nar");
	}
	std::stringstream ss;
	ss << std::setprecision(precision) << (long double)p;
	return ss.str();
}

// binary representation of a posit with delimiters: i.e. 0.10.00.000000 => sign.regime.exp.fraction
template<size_t nbits, size_t es>
inline std::string to_binary(const posit<nbits, es>& number, bool nibbleMarker = false) {
	constexpr size_t fbits = (es + 2 >= nbits ? 0 : nbits - 3 - es);             // maximum number of fraction bits: derived
	bool s{ false };
	regime<nbits, es> r;
	exponent<nbits, es> e;
	fraction<fbits> f;
	bitblock<nbits> raw = number.get();
	std::stringstream ss;
	extract_fields(raw, s, r, e, f);

	ss << (s ? "0b1." : "0b0.");
	ss << to_string(r, false) << "."
		<< to_string(e, false) << "."
		<< to_string(f, false);

	return ss.str();
}

// numerical helpers

template<size_t nbits, size_t es>
inline posit<nbits, es> ulp(const posit<nbits, es>& a) {
	posit<nbits, es> b(a);
	return ++b - a;
}

// binary exponent representation: i.e. 1.0101010e2^-37
template<size_t nbits, size_t es>
inline std::string to_base2_scientific(const posit<nbits, es>& number) {
	constexpr size_t fbits = (es + 2 >= nbits ? 0 : nbits - 3 - es);             // maximum number of fraction bits: derived
	bool s{ false };
	scale(number);
	regime<nbits, es> r;
	exponent<nbits, es> e;
	fraction<fbits> f;
	bitblock<nbits> raw = number.get();
	std::stringstream ss;
	extract_fields(raw, s, r, e, f);
	ss << (s ? "-" : "+") << "1." << to_string(f, true) << "e2^" << std::showpos << r.scale() + e.scale();
	return ss.str();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
// posit - posit binary logic operators

template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	return lhs._raw_bits == rhs._raw_bits;
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	return !operator==(lhs, rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(lhs._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	return operator< (rhs, lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	return operator< (lhs, rhs) || operator==(lhs, rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	return !operator< (lhs, rhs);
}

// posit - posit binary arithmetic operators
// BINARY ADDITION
template<size_t nbits, size_t es>
inline posit<nbits, es> operator+(const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> sum = lhs;
	return sum += rhs;
}
// BINARY SUBTRACTION
template<size_t nbits, size_t es>
inline posit<nbits, es> operator-(const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> diff = lhs;
	return diff -= rhs;
}
// BINARY MULTIPLICATION
template<size_t nbits, size_t es>
inline posit<nbits, es> operator*(const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> mul = lhs;
	return mul *= rhs;
}
// BINARY DIVISION
template<size_t nbits, size_t es>
inline posit<nbits, es> operator/(const posit<nbits, es>& lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> ratio(lhs);
	return ratio /= rhs;
}

#if POSIT_ENABLE_LITERALS

// posit - signed char logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, signed char rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, signed char rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, signed char rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, signed char rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, signed char rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, signed char rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// signed char - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(signed char lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(signed char lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (signed char lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (signed char lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(signed char lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(signed char lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - char logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, char rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, char rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, char rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, char rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, char rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, char rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// char - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(char lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(char lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (char lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (char lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(char lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(char lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - short logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, short rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, short rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, short rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, short rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, short rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, short rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// short - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(short lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(short lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (short lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (short lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(short lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(short lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - unsigned short logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, unsigned short rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, unsigned short rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, unsigned short rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, unsigned short rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, unsigned short rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, unsigned short rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// unsigned short - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(unsigned short lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(unsigned short lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (unsigned short lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (unsigned short lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(unsigned short lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(unsigned short lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - int logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, int rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, int rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, int rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, int rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, int rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, int rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// int - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(int lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(int lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (int lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (int lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(int lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(int lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - unsigned int logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, unsigned int rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, unsigned int rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, unsigned int rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, unsigned int rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, unsigned int rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, unsigned int rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// unsigned int - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(unsigned int lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(unsigned int lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (unsigned int lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (unsigned int lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(unsigned int lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(unsigned int lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - long logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, long rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, long rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, long rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, long rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, long rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, long rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// long - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(long lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(long lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (long lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (long lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(long lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(long lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - unsigned long logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, unsigned long rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, unsigned long rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, unsigned long rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, unsigned long rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, unsigned long rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, unsigned long rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// unsigned long - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(unsigned long lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(unsigned long lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (unsigned long lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (unsigned long lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(unsigned long lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(unsigned long lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - unsigned long long logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, unsigned long long rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, unsigned long long rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, unsigned long long rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, unsigned long long rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, unsigned long long rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, unsigned long long rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// unsigned long long - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(unsigned long long lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(unsigned long long lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (unsigned long long lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (unsigned long long lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(unsigned long long lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(unsigned long long lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - long long logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, long long rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, long long rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, long long rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, long long rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, long long rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, long long rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// long long - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(long long lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(long long lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (long long lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (long long lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(long long lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(long long lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - float logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, float rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, float rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, float rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, float rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, float rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, float rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// float  - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(float lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(float lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (float lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (float lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(float lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(float lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - double logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, double rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, double rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, double rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, double rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, double rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, double rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// double  - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(double lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(double lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (double lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (double lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(double lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(double lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// posit - long double logic operators
template<size_t nbits, size_t es>
inline bool operator==(const posit<nbits, es>& lhs, long double rhs) {
	return lhs == posit<nbits, es>(rhs);
}
template<size_t nbits, size_t es>
inline bool operator!=(const posit<nbits, es>& lhs, long double rhs) {
	return !operator==(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator< (const posit<nbits, es>& lhs, long double rhs) {
	return twosComplementLessThan(lhs._raw_bits, posit<nbits, es>(rhs)._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (const posit<nbits, es>& lhs, long double rhs) {
	return operator< (posit<nbits, es>(rhs), lhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(const posit<nbits, es>& lhs, long double rhs) {
	return !operator>(lhs, posit<nbits, es>(rhs));
}
template<size_t nbits, size_t es>
inline bool operator>=(const posit<nbits, es>& lhs, long double rhs) {
	return !operator<(lhs, posit<nbits, es>(rhs));
}

// long double  - posit logic operators
template<size_t nbits, size_t es>
inline bool operator==(long double lhs, const posit<nbits, es>& rhs) {
	return posit<nbits, es>(lhs) == rhs;
}
template<size_t nbits, size_t es>
inline bool operator!=(long double lhs, const posit<nbits, es>& rhs) {
	return !operator==(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator< (long double lhs, const posit<nbits, es>& rhs) {
	return twosComplementLessThan(posit<nbits, es>(lhs)._raw_bits, rhs._raw_bits);
}
template<size_t nbits, size_t es>
inline bool operator> (long double lhs, const posit<nbits, es>& rhs) {
	return operator< (posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator<=(long double lhs, const posit<nbits, es>& rhs) {
	return !operator>(posit<nbits, es>(lhs), rhs);
}
template<size_t nbits, size_t es>
inline bool operator>=(long double lhs, const posit<nbits, es>& rhs) {
	return !operator<(posit<nbits, es>(lhs), rhs);
}

// BINARY ADDITION
template<size_t nbits, size_t es>
inline posit<nbits, es> operator+(const posit<nbits, es>& lhs, double rhs) {
	posit<nbits, es> sum = lhs;
	sum += posit<nbits, es>(rhs);
	return sum;
}

// TODO: need to find a place in traits
// non-posit: native integer and floating point types
template <typename T>
constexpr bool is_intrinsic_numerical = std::is_integral<T>::value || std::is_floating_point<T>::value;

template <typename T, typename U = void>
using enable_intrinsic_numerical = std::enable_if_t<is_intrinsic_numerical<T>, U>;

// More generic alternative to avoid ambiguities with intrinsic +
template<size_t nbits, size_t es, typename Value, typename = enable_intrinsic_numerical<Value> >
inline posit<nbits, es> operator+(const posit<nbits, es>& lhs, Value rhs) {
	posit<nbits, es> sum = lhs;
	sum += posit<nbits, es>(rhs);
	return sum;
}

template<size_t nbits, size_t es>
inline posit<nbits, es> operator+(double lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> sum(lhs);
	sum += rhs;
	return sum;
}

// BINARY SUBTRACTION
template<size_t nbits, size_t es>
inline posit<nbits, es> operator-(double lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> diff(lhs);
	diff -= rhs;
	return diff;
}

// More generic alternative to avoid ambiguities with intrinsic +
template<size_t nbits, size_t es, typename Value, typename = enable_intrinsic_numerical<Value> >
inline posit<nbits, es> operator-(const posit<nbits, es>& lhs, Value rhs) {
	posit<nbits, es> diff = lhs;
	diff -= posit<nbits, es>(rhs);
	return diff;
}

template<size_t nbits, size_t es>
inline posit<nbits, es> operator-(const posit<nbits, es>& lhs, double rhs) {
	posit<nbits, es> diff(lhs);
	diff -= posit<nbits, es>(rhs);
	return diff;
}
// BINARY MULTIPLICATION
template<size_t nbits, size_t es>
inline posit<nbits, es> operator*(double lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> mul(lhs);
	mul *= rhs;
	return mul;
}

template<size_t nbits, size_t es, typename Value, typename = enable_intrinsic_numerical<Value> >
inline posit<nbits, es> operator*(Value lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> mul(lhs);
	mul *= rhs;
	return mul;
}
    
template<size_t nbits, size_t es>
inline posit<nbits, es> operator*(const posit<nbits, es>& lhs, double rhs) {
	posit<nbits, es> mul(lhs);
	mul *= posit<nbits, es>(rhs);
	return mul;
}

// BINARY DIVISION
template<size_t nbits, size_t es>
inline posit<nbits, es> operator/(double lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> ratio(lhs);
	ratio /= rhs;
	return ratio;
}

template<size_t nbits, size_t es, typename Value, typename = enable_intrinsic_numerical<Value> >
inline posit<nbits, es> operator/(Value lhs, const posit<nbits, es>& rhs) {
	posit<nbits, es> ratio(lhs);
	ratio /= rhs;
	return ratio;
}

template<size_t nbits, size_t es>
inline posit<nbits, es> operator/(const posit<nbits, es>& lhs, double rhs) {
	posit<nbits, es> ratio(lhs);
	ratio /= posit<nbits, es>(rhs);
	return ratio;
}

template<size_t nbits, size_t es, typename Value, typename = enable_intrinsic_numerical<Value> >
inline posit<nbits, es> operator/(const posit<nbits, es>& lhs, Value rhs) {
	posit<nbits, es> ratio(lhs);
	ratio /= posit<nbits, es>(rhs);
	return ratio;
}

#endif // POSIT_ENABLE_LITERALS

// Magnitude of a posit (equivalent to turning the sign bit off).
template<size_t nbits, size_t es> 
posit<nbits, es> abs(const posit<nbits, es>& p) {
	return p.abs();
}
template<size_t nbits, size_t es>
posit<nbits, es> fabs(const posit<nbits, es>& p) {
	return p.abs();
}
template<typename Scalar>
Scalar fabs(Scalar s) {
	return std::fabs(s);
}

// Atomic fused operators

// FMA: fused multiply-add:  a*b + c
template<size_t nbits, size_t es>
internal::value<1 + 2 * (nbits - es)> fma(const posit<nbits, es>& a, const posit<nbits, es>& b, const posit<nbits, es>& c) {
	constexpr size_t fbits = nbits - 3 - es;
	constexpr size_t fhbits = fbits + 1;      // size of fraction + hidden bit
	constexpr size_t mbits = 2 * fhbits;      // size of the multiplier output
	constexpr size_t abits = mbits + 4;       // size of the addend

	internal::value<mbits> product;
	internal::value<abits + 1> sum;
	internal::value<fbits> va, vb, ctmp;

	// special case handling of input arguments
	if (a.isnar() || b.isnar() || c.isnar()) {
		sum.setnan();
		return sum;
	}

	if (a.iszero() || b.iszero()) {  // product will only become non-zero if neither a and b are zero
		if (c.iszero()) {
			sum.setzero();
		}
		else {
			ctmp.set(sign(c), scale(c), extract_fraction<nbits, es, fbits>(c), c.iszero(), c.isnar());
			sum.template right_extend<fbits, abits + 1>(ctmp); // right-extend the c input argument and assign to sum
		}
	}
	else { // else clause guarantees that the product is non-zero	
		// first, the multiply: transform the inputs into (sign,scale,fraction) triples
		va.set(sign(a), scale(a), extract_fraction<nbits, es, fbits>(a), a.iszero(), a.isnar());;
		vb.set(sign(b), scale(b), extract_fraction<nbits, es, fbits>(b), b.iszero(), b.isnar());;

		module_multiply(va, vb, product);    // multiply the two inputs

		// second, the add : at this point we are guaranteed that product is non-zero and non-nar
		if (c.iszero()) {				
			sum.template right_extend<mbits, abits + 1>(product);   // right-extend the product and assign to sum
		}
		else {
			ctmp.set(sign(c), scale(c), extract_fraction<nbits, es, fbits>(c), c.iszero(), c.isnar());
			internal::value<mbits> vc;
			vc.template right_extend<fbits, mbits>(ctmp); // right-extend the c argument and assign to adder input
			module_add<mbits, abits>(product, vc, sum);
		}
	}

	return sum;
}

// FAM: fused add-multiply: (a + b) * c
template<size_t nbits, size_t es>
internal::value<2 * (nbits - 2 - es)> fam(const posit<nbits, es>& a, const posit<nbits, es>& b, const posit<nbits, es>& c) {
	constexpr size_t fbits = nbits - 3 - es;
	constexpr size_t abits = fbits + 4;       // size of the addend
	constexpr size_t fhbits = fbits + 1;      // size of fraction + hidden bit
	constexpr size_t mbits = 2 * fhbits;      // size of the multiplier output

	internal::value<fbits> va, vb;
	internal::value<abits+1> sum, vc;
	internal::value<mbits> product;

	// special case
	if (c.iszero()) return product;

	// first the add
	if (!a.iszero() || !b.iszero()) {
		// transform the inputs into (sign,scale,fraction) triples
		va.set(sign(a), scale(a), extract_fraction<nbits, es, fbits>(a), a.iszero(), a.isnar());;
		vb.set(sign(b), scale(b), extract_fraction<nbits, es, fbits>(b), b.iszero(), b.isnar());;

		module_add(va, vb, sum);    // multiply the two inputs
		if (sum.iszero()) return product;  // product is still zero
	}
	// second, the multiply		
	vc.set(c.get_size(), scale(c), extract_fraction<nbits, es, fbits>(c), c.iszero(), c.isnar());
	module_multiply(sum, vc, product);
	return product;
}

// FMMA: fused multiply-multiply-add: (a * b) +/- (c * d)
template<size_t nbits, size_t es>
internal::value<nbits> fmma(const posit<nbits, es>& a, const posit<nbits, es>& b, const posit<nbits, es>& c, const posit<nbits, es>& d, bool opIsAdd = true)
{
	// todo: implement
	internal::value<nbits> result;
	return result;
}

// Standard posit short-hand types
/*
TODO: how do we use the same names as the posit C-types?
right now, because we pull in the C++ as run-time to the C functions this causes a redefinition error
using posit8_t   = posit<8, 0>;
using posit16_t  = posit<16, 1>;
using posit32_t  = posit<32, 2>;
using posit64_t  = posit<64, 3>;
using posit128_t = posit<128, 4>;
using posit256_t = posit<256, 5>;
*/


}  // namespace sw::universal


