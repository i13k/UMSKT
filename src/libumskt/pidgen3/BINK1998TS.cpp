/**
 * This file is a part of the UMSKT Project
 *
 * Copyleft (C) 2019-2023 UMSKT Contributors (et.al.)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @FileCreated by Andrew on 01/06/2023
 * @Maintainer Andrew
 *
  * @History {
 *   Algorithm was initially written and open sourced by z22
 *   and uploaded to GitHub by TheMCHK in August of 2019
 *
 *   Endermanch (Andrew) rewrote the algorithm in May of 2023
 * }
 */

#include "BINK1998TS.h"

void PIDGEN3::BINK1998TS::Pack(
	QWORD (&pRaw)[4],
	QWORD &pData,
	QWORD &pHash,
	QWORD (&pSignature)[2]
) {
	pRaw[0] =
		(pData & 0x00FFFFFFFFFFFFFFULL) |
		(pHash << 56);

	pRaw[1] =
		(pHash >> 8) |
		(pSignature[0] << 27);

	pRaw[2] =
		(pSignature[0] >> 37) |
		(pSignature[1] << 27);

	pRaw[3] = 0;
}
/* Generates a Windows XP-like Product Key. */
void PIDGEN3::BINK1998TS::Generate(
        EC_GROUP *eCurve,
        EC_POINT *basePoint,
		BIGNUM *genOrder,
		BIGNUM *privateKey,
		QWORD keyData,
		std::string PID,
        char (&pKey)[35]
) {
    BN_CTX *numContext = BN_CTX_new();

    BIGNUM *c = BN_new(),
           *s = BN_new(),
           *x = BN_new(),
           *y = BN_new();

    QWORD pRaw[4]{},
          pSignature = 0;
	EC_POINT *r = EC_POINT_new(eCurve);

	// Generate a random number c consisting of 384 bits without any constraints.
	UMSKT::umskt_bn_rand(c, FIELD_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

	// Pick a random derivative of the base point on the elliptic curve.
	// R = cG;
	EC_POINT_mul(eCurve, r, nullptr, basePoint, c, numContext);

	// Acquire its coordinates.
	// x = R.x; y = R.y;
	EC_POINT_get_affine_coordinates(eCurve, r, x, y, numContext);

	BYTE    msgDigest[SHA_DIGEST_LENGTH]{},
			msgBuffer[2*FIELD_BYTES+8]{},
			xBin[FIELD_BYTES]{},
			yBin[FIELD_BYTES]{};

	// Convert coordinates to bytes.
	BN_bn2lebin(x, xBin, FIELD_BYTES);
	BN_bn2lebin(y, yBin, FIELD_BYTES);

	// Assemble the SHA message.
	memcpy((void *)&msgBuffer[0], (void *)&keyData, 8);
	memcpy((void *)&msgBuffer[8], (void *)xBin, FIELD_BYTES);
	memcpy((void *)&msgBuffer[8 + FIELD_BYTES], (void *)yBin, FIELD_BYTES);

	// pHash = SHA1(pSerial || R.x || R.y)
	SHA1(msgBuffer, 2*FIELD_BYTES+8, msgDigest);
	QWORD pHash =
		(((QWORD)(
			((DWORD)msgDigest[4] |
			 ((DWORD)msgDigest[5] << 8) |
			 ((DWORD)msgDigest[6] << 16) |
			 ((DWORD)msgDigest[7] << 24)
			) >> 29
		)) << 32)
		|
		((DWORD)msgDigest[0] |
		 ((DWORD)msgDigest[1] << 8) |
		 ((DWORD)msgDigest[2] << 16) |
		 ((DWORD)msgDigest[3] << 24));

	/*
	 *
	 * Scalars:
	 *  c = Random multiplier
	 *  e = Hash
	 *  s = Signature
	 *  n = Order of G
	 *  k = Private Key
	 *
	 * Points:
	 *  G(x, y) = Generator (Base Point)
	 *  R(x, y) = Random derivative of the generator
	 *  K(x, y) = Public Key
	 *
	 * We need to find the signature s that satisfies the equation with a given hash:
	 *  P = sG + eK
	 *  s = ek + c (mod n) <- computation optimization
	 */

	// s = ek;
	BN_copy(s, privateKey);
	BN_mul_word(s, pHash);

	// s += c (mod n)
	BN_mod_add(s, s, c, genOrder, numContext);

	BN_bn2lebinpad(s, (BYTE *)&pSignature, BN_num_bytes(s));
	
	pSignature[1] &= 0x1f;
	pHash &= 0x7ffffffff;

	// Pack product key.
	Pack(pRaw, keyData, pHash, pSignature);

	EC_POINT_free(r);
	BN_free(c);
    BN_free(s);
    BN_free(x);
    BN_free(y);

    BN_CTX_free(numContext);
	
    // Convert bytecode to Base24 TS key.
	BYTE* bRaw = (BYTE*) &pRaw;
	BYTE bRes[21];
	BYTE bRes20[20];
	BYTE s[256];
	int i = 0, j = 0, pidLen = PID.size();
	int keyLen = 2*pidLen;
	BYTE *key = new BYTE[keyLen];
	for (int i = 0; i < keyLen; i++) {
		if (i % 2 == 0) key[i] = PID[i/2];
		else key[i] = 0;
	}
	BYTE s[256];
	for (i = 0; i < 256; i++) s[i] = i;
	
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % keyLen]) % 256;
		BYTE temp = s[i];
		s[i] = s[j];
		s[j] = temp;
	}
	i = 0, j = 0;
	for (int k = 0; k < 21; k++) {
		i = (i+1) % 256;
		j = (j + s[i]) % 256;
		BYTE temp = s[i];
		s[i] = s[j];
		s[j] = temp;
		int t = (s[i] + s[j]) % 256;
		bRes[k] = bRaw[k] ^ s[t];
	}
	
	delete[] key;
	
	memcpy(bRes20, bRes, 20);
	
    base24_ts(pKey, bRes20);
}
