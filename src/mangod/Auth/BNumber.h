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

#pragma once
#include "base/define.h"
#include "mangod/Common.h"
#include <memory>

struct bignum_st;

class BNumber
{
    public:
        BNumber();
        BNumber(BNumber const& bn);
        BNumber(uint32);
        ~BNumber();

        void SetDword(uint32);
        void SetQword(uint64);
        void SetBinary(unsigned char const* bytes, int len);
        int SetHexStr(char const* str);

        void SetRand(int numbits);

        BNumber operator=(BNumber const& bn);

        BNumber operator+=(BNumber const& bn);
        BNumber operator+(BNumber const& bn)
        {
            BNumber t(*this);
            return t += bn;
        }
        BNumber operator-=(BNumber const& bn);
        BNumber operator-(BNumber const& bn)
        {
            BNumber t(*this);
            return t -= bn;
        }
        BNumber operator*=(BNumber const& bn);
        BNumber operator*(BNumber const& bn)
        {
            BNumber t(*this);
            return t *= bn;
        }
        BNumber operator/=(BNumber const& bn);
        BNumber operator/(BNumber const& bn)
        {
            BNumber t(*this);
            return t /= bn;
        }
        BNumber operator%=(BNumber const& bn);
        BNumber operator%(BNumber const& bn)
        {
            BNumber t(*this);
            return t %= bn;
        }

        bool isZero() const;

        BNumber ModExp(BNumber const& bn1, BNumber const& bn2);
        BNumber Exp(BNumber const&);

        int GetNumBytes(void) const;

        struct bignum_st* BN() { return _bn; }

        uint32 AsDword();
        std::vector<unsigned char> AsByteArray(int minSize = 0, bool reverse = true) const;

        char const* AsHexStr();
        char const* AsDecStr();

    private:
        struct bignum_st* _bn;
};
