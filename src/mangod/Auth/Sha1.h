/*
 * Copyright (C) 2005-2012 MaNGOS <http://getmangos.com/>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _AUTH_SHA1_H
#define _AUTH_SHA1_H

#include "mangod/Common.h"

typedef struct SHAstate_st2 {
    unsigned int h0, h1, h2, h3, h4;
    unsigned int Nl, Nh;
    unsigned int data[16];
    unsigned int num;
} SHA_CTX2;

class BNumber;
typedef unsigned char uint8;
class Sha1Hash
{
    public:
        Sha1Hash();
        ~Sha1Hash();

        void UpdateBigNumbers(BNumber* bn0, ...);

        void UpdateData(uint8 const* dta, int len);
        void UpdateData(std::string const& str);
        void UpdateData(std::vector<uint8> const& data);

        void Initialize();
        void Finalize();

        uint8* GetDigest(void) { return mDigest; };
        static int GetLength(void) { return 20; };

    private:
        SHA_CTX2 mC;
        uint8 mDigest[20];
};
#endif
