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
 OSSLAES.cpp

 OpenSSL AES implementation
 *****************************************************************************/

#include "config.h"
#include "OSSLAES.h"
#include <algorithm>
#include <openssl/aes.h>
#include "salloc.h"

// Wrap/Unwrap keys
bool OSSLAES::wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	// RFC 3394 input checks do not apply to RFC 5649 mode with padding
	if (mode == SymWrap::AES_KEYWRAP)
	{
		if (in.size() < 16)
		{
			ERROR_MSG("key data to wrap too small");

			return false;
		}
		if ((in.size() % 8) != 0)
		{
			ERROR_MSG("key data to wrap not aligned");

			return false;
		}
	}

	// Determine the cipher method
	const EVP_CIPHER* cipher = getWrapCipher(mode, key);
	if (cipher == NULL)
	{
		ERROR_MSG("Failed to get EVP wrap cipher");
		return false;
	}

	// Allocate the EVP context
	EVP_CIPHER_CTX* pWrapCTX = (EVP_CIPHER_CTX*) salloc(sizeof(EVP_CIPHER_CTX));
	if (pWrapCTX == NULL)
	{
		ERROR_MSG("Failed to allocate space for EVP_CIPHER_CTX");
		return false;
	}
	EVP_CIPHER_CTX_init(pWrapCTX);
	EVP_CIPHER_CTX_set_flags(pWrapCTX, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	int rv = EVP_EncryptInit_ex(pWrapCTX, cipher, NULL, (unsigned char*) key->getKeyBits().const_byte_str(), NULL);
	if (rv)
		// Padding is handled by cipher mode separately
		rv = EVP_CIPHER_CTX_set_padding(pWrapCTX, 0);
	if (!rv)
	{
		ERROR_MSG("Failed to initialise EVP encrypt operation");

		EVP_CIPHER_CTX_cleanup(pWrapCTX);
		sfree(pWrapCTX);
		return false;
	}

	// 1 input byte could be expanded to two AES blocks
	out.resize(in.size() + 2 * EVP_CIPHER_CTX_block_size(pWrapCTX) - 1);
	int outLen = 0;
	int curBlockLen = 0;
	rv = EVP_EncryptUpdate(pWrapCTX, &out[0], &curBlockLen, in.const_byte_str(), in.size());
	if (rv == 1) {
		outLen = curBlockLen;
		rv = EVP_EncryptFinal_ex(pWrapCTX, &out[0], &curBlockLen);
	}
	if (rv != 1)
	{
		ERROR_MSG("Failed EVP encrypt operation during key wrapping");

		EVP_CIPHER_CTX_cleanup(pWrapCTX);
		sfree(pWrapCTX);
		return false;
	}
	outLen += curBlockLen;
	out.resize(outLen);
	return true;
}

bool OSSLAES::unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	// Check key bit length; AES only supports 128, 192 or 256 bit keys
	if ((key->getBitLen() != 128) &&
	    (key->getBitLen() != 192) &&
	    (key->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES key length (%d bits)", key->getBitLen());

		return false;
	}

	// Determine the unwrapping mode
	if (mode == SymWrap::AES_KEYWRAP)
	{
		// RFC 3394 AES key wrap
		if (in.size() < 24)
		{
			ERROR_MSG("key data to unwrap too small");

			return false;
		}
		if ((in.size() % 8) != 0)
		{
			ERROR_MSG("key data to unwrap not aligned");

			return false;
		}

		AES_KEY aesKey;
		if (AES_set_decrypt_key(key->getKeyBits().const_byte_str(),
					key->getBitLen(), &aesKey))
		{
			ERROR_MSG("fail to setup AES unwrapping key");

			return false;
		}
		out.resize(in.size() - 8);
		if (AES_unwrap_key(&aesKey, NULL, &out[0], in.const_byte_str(), in.size()) != (int)out.size())
		{
			ERROR_MSG("AES key unwrap failed");

			out.wipe();
			return false;
		}

		return  true;
	}
#ifdef HAVE_AES_KEY_WRAP_PAD
	else if (mode == SymWrap::AES_KEYWRAP_PAD)
	{
		// RFC 5649 AES key wrap with pad
		if (in.size() < 16)
		{
			ERROR_MSG("key data to unwrap too small");

			return false;
		}
		if ((in.size() % 8) != 0)
		{
			ERROR_MSG("key data to unwrap not aligned");

			return false;
		}

		AES_KEY aesKey;
		if (AES_set_decrypt_key(key->getKeyBits().const_byte_str(),
					key->getBitLen(), &aesKey))
		{
			ERROR_MSG("fail to setup AES unwrapping key");

			return false;
		}
		out.resize(in.size() - 8);
		int ret = AES_unwrap_key_withpad(&aesKey, NULL, &out[0], in.const_byte_str(), in.size());
		if (ret <= 0)
		{
			ERROR_MSG("AES key unwrap failed");

			out.wipe();
			return false;
		}
		out.resize(ret);

		return  true;
	}
#endif
	else
	{
		ERROR_MSG("unknown AES key wrap mode %i", mode);

		return false;
	}
}

const EVP_CIPHER* OSSLAES::getCipher() const
{
	if (currentKey == NULL) return NULL;

	// Check currentKey bit length; AES only supports 128, 192 or 256 bit keys
	if ((currentKey->getBitLen() != 128) &&
	    (currentKey->getBitLen() != 192) &&
            (currentKey->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES currentKey length (%d bits)", currentKey->getBitLen());

		return NULL;
	}

	// Determine the cipher mode
	if (currentCipherMode == SymMode::CBC)
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return EVP_aes_128_cbc();
			case 192:
				return EVP_aes_192_cbc();
			case 256:
				return EVP_aes_256_cbc();
		};
	}
	else if (currentCipherMode == SymMode::ECB)
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return EVP_aes_128_ecb();
			case 192:
				return EVP_aes_192_ecb();
			case 256:
				return EVP_aes_256_ecb();
		};
	}

	ERROR_MSG("Invalid AES cipher mode %i", currentCipherMode);

	return NULL;
}

const EVP_CIPHER* OSSLAES::getWrapCipher(const SymWrap::Type mode, const SymmetricKey* key) const
{
	if (key == NULL)
		return NULL;

	// Check currentKey bit length; AES only supports 128, 192 or 256 bit keys
	if ((key->getBitLen() != 128) &&
	    (key->getBitLen() != 192) &&
            (key->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES currentKey length (%d bits)", key->getBitLen());

		return NULL;
	}

	// Determine the cipher mode
	if (mode == SymWrap::AES_KEYWRAP)
	{
		switch(key->getBitLen())
		{
			case 128:
				return EVP_aes_128_wrap();
			case 192:
				return EVP_aes_192_wrap();
			case 256:
				return EVP_aes_256_wrap();
		};
	}
	else if (mode == SymWrap::AES_KEYWRAP_PAD)
	{
		switch(key->getBitLen())
		{
			case 128:
				return EVP_aes_128_wrap_pad();
			case 192:
				return EVP_aes_192_wrap_pad();
			case 256:
				return EVP_aes_256_wrap_pad();
		};
	}

	ERROR_MSG("Invalid AES cipher wrap mode %i", mode);

	return NULL;
}

size_t OSSLAES::getBlockSize() const
{
	// The block size is 128 bits
	return 128 >> 3;
}

