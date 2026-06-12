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
 * @FileCreated by Neo on 6/6/2023
 * @Maintainer Neo
 */

#ifndef UMSKT_BINK1998TS_H
#define UMSKT_BINK1998TS_H

#include "PIDGEN3.h"

EXPORT class PIDGEN3::BINK1998TS {
public:
	static void Pack(
		QWORD (&pRaw)[3],
		QWORD &pData,
		QWORD &pHash,
		QWORD (&pSignature)[2]
	);
	
    static void Generate(
            EC_GROUP *eCurve,
            EC_POINT *basePoint,
              BIGNUM *genOrder,
              BIGNUM *privateKey,
               QWORD keyData,
		 std::string PID,
		        bool isSPK,
                char (&pKey)[35]
    );
};

#endif //UMSKT_BINK1998TS_H
