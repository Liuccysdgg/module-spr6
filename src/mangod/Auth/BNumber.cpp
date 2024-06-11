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
#include "mangod/Auth/BNumber.h"
#include <openssl/bn.h>
#include <algorithm>

BNumber::BNumber()
{
    _bn = BN_new();
}

BNumber::BNumber(BNumber const& bn)
{
    _bn = BN_dup(bn._bn);
}

BNumber::BNumber(uint32 val)
{
    _bn = BN_new();
    BN_set_word(_bn, val);
}

BNumber::~BNumber()
{
    BN_free(_bn);
}

void BNumber::SetDword(uint32 val)
{
    BN_set_word(_bn, val);
}

void BNumber::SetQword(uint64 val)
{
    BN_add_word(_bn, (uint32)(val >> 32));
    BN_lshift(_bn, _bn, 32);
    BN_add_word(_bn, (uint32)(val & 0xFFFFFFFF));
}

void BNumber::SetBinary(unsigned char const* bytes, int len)
{
    unsigned char t[1000];
    for (int i = 0; i < len; i++)
        t[i] = bytes[len - 1 - i];
    BN_bin2bn(t, len, _bn);
}

int BNumber::SetHexStr(const char* str)
{
    return BN_hex2bn(&_bn, str);
}

void BNumber::SetRand(int numbits)
{
    BN_rand(_bn, numbits, 0, 1);
}

BNumber BNumber::operator=(BNumber const& bn)
{
    BN_copy(_bn, bn._bn);
    return *this;
}

BNumber BNumber::operator+=(BNumber const& bn)
{
    BN_add(_bn, _bn, bn._bn);
    return *this;
}

BNumber BNumber::operator-=(BNumber const& bn)
{
    BN_sub(_bn, _bn, bn._bn);
    return *this;
}

BNumber BNumber::operator*=(BNumber const& bn)
{
    BN_CTX *bnctx;

    bnctx = BN_CTX_new();
    BN_mul(_bn, _bn, bn._bn, bnctx);
    BN_CTX_free(bnctx);

    return *this;
}

BNumber BNumber::operator/=(BNumber const& bn)
{
    BN_CTX *bnctx;

    bnctx = BN_CTX_new();
    BN_div(_bn, nullptr, _bn, bn._bn, bnctx);
    BN_CTX_free(bnctx);

    return *this;
}

BNumber BNumber::operator%=(BNumber const& bn)
{
    BN_CTX *bnctx;

    bnctx = BN_CTX_new();
    BN_mod(_bn, _bn, bn._bn, bnctx);
    BN_CTX_free(bnctx);

    return *this;
}

BNumber BNumber::Exp(BNumber const& bn)
{
    BNumber ret;
    BN_CTX *bnctx;

    bnctx = BN_CTX_new();
    BN_exp(ret._bn, _bn, bn._bn, bnctx);
    BN_CTX_free(bnctx);

    return ret;
}

BNumber BNumber::ModExp(BNumber const& bn1, BNumber const& bn2)
{
    BNumber ret;
    BN_CTX *bnctx;

    bnctx = BN_CTX_new();
    BN_mod_exp(ret._bn, _bn, bn1._bn, bn2._bn, bnctx);
    BN_CTX_free(bnctx);

    return ret;
}

int BNumber::GetNumBytes(void) const
{
    return BN_num_bytes(_bn);
}

uint32 BNumber::AsDword()
{
    return (uint32)BN_get_word(_bn);
}

bool BNumber::isZero() const
{
    return BN_is_zero(_bn)!=0;
}

std::vector<unsigned char> BNumber::AsByteArray(int minSize, bool reverse) const
{
    int length = (minSize >= GetNumBytes()) ? minSize : GetNumBytes();

    std::vector<unsigned char> byteArray(length);
    
    // If we need more bytes than length of BNumber set the rest to 0
    if (length > GetNumBytes())
        memset((void*)byteArray.data(), 0, length);

    // Padding should add leading zeroes, not trailing
    int paddingOffset = length - GetNumBytes();

    BN_bn2bin(_bn, (unsigned char*)byteArray.data() + paddingOffset);

    if (reverse)
        std::reverse(byteArray.begin(), byteArray.end());


    return byteArray;
}

char const* BNumber::AsHexStr()
{
    return BN_bn2hex(_bn);
}

char const* BNumber::AsDecStr()
{
    return BN_bn2dec(_bn);
}