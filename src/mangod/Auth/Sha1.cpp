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
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include "mangod/Auth/Sha1.h"
#include "mangod/Auth/BNumber.h"
#include <stdarg.h>

Sha1Hash::Sha1Hash()
{
    SHA1_Init((SHA_CTX*)&mC);
}

Sha1Hash::~Sha1Hash()
{
    SHA1_Init((SHA_CTX*)&mC);
}

void Sha1Hash::UpdateData(uint8 const* dta, int len)
{
    SHA1_Update((SHA_CTX*)&mC, dta, len);
}

void Sha1Hash::UpdateData(std::vector<uint8> const& data)
{
    SHA1_Update((SHA_CTX*)&mC, data.data(), data.size());
}

void Sha1Hash::UpdateData(std::string const& str)
{
    UpdateData((uint8 const*)str.c_str(), str.length());
}

void Sha1Hash::UpdateBigNumbers(BNumber* bn0, ...)
{
    va_list v;
    BNumber* bn;

    va_start(v, bn0);
    bn = bn0;
    while (bn)
    {
        UpdateData(bn->AsByteArray());
        bn = va_arg(v, BNumber*);
    }
    va_end(v);
}

void Sha1Hash::Initialize()
{
    SHA1_Init((SHA_CTX*)&mC);
}

void Sha1Hash::Finalize(void)
{
    SHA1_Final(mDigest, (SHA_CTX*)&mC);
}