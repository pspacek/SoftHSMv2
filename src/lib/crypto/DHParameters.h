/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 DHParameters.h

 Diffie-Hellman parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DHPARAMETERS_H
#define _SOFTHSM_V2_DHPARAMETERS_H

#include "config.h"
#include "ByteString.h"
#include "AsymmetricParameters.h"

class DHParameters : public AsymmetricParameters
{
public:
	// Base constructors
	DHParameters() : bitLen(0) { }

	// The type
	static const char* type;

	// Set the public prime p
	void setP(const ByteString& p);

	// Set the generator g
	void setG(const ByteString& g);

	// Set the optional bit length
	void setXBitLength(const size_t bitLen);

	// Get the public prime p
	const ByteString& getP() const;

	// Get the generator g
	const ByteString& getG() const;

	// Get the optional bit length
	size_t getXBitLength() const;

	// Are the parameters of the given type?
	virtual bool areOfType(const char* type);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	ByteString p;
	ByteString g;
	size_t bitLen;
};

#endif // !_SOFTHSM_V2_DHPARAMETERS_H

