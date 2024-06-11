// MIT License
// Copyright(c) 2024 FastWeb - fwlua.com - nianhua
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// ## Additional Terms for Commercial Use
// This software is licensed for personal, educational, and non - commercial use.
// For commercial use or use within a company, organization, or institution, a
// separate commercial license is required.To obtain a commercial license,
// please contact
// EMail：1585346868@qq.com
// Mobile：17367918735
// QQ：1585346868

#include "interface.h"
#include "spr6/SRP6.h"
#include <exception>
#include "dll_interface.h"
#include "sol/sol.hpp"
#include "mangod/SRP6.h"
#include "util/file.h"
void hexEncodeByteArray(uint8* bytes, uint32 arrayLen, std::string& result)
{
	std::ostringstream ss;
	for (uint32 i = 0; i < arrayLen; ++i)
	{
		for (uint8 j = 0; j < 2; ++j)
		{
			unsigned char nibble = 0x0F & (bytes[i] >> ((1 - j) * 4));
			char encodedNibble;
			if (nibble < 0x0A)
				encodedNibble = '0' + nibble;
			else
				encodedNibble = 'A' + nibble - 0x0A;
			ss << encodedNibble;
		}
	}
	result = ss.str();
}
std::string CalculateShaPassHash(std::string name, std::string password)
{
	Sha1Hash sha;
	sha.Initialize();
	sha.UpdateData(name);
	sha.UpdateData(":");
	sha.UpdateData(password);
	sha.Finalize();

	std::string encoded;
	hexEncodeByteArray(sha.GetDigest(), sha.GetLength(), encoded);

	return encoded;
}

class spr6
{
public:
	static sol::table spr6_make(bool mangod,const std::string& username, const std::string& password,sol::this_state ts)
	{
		sol::state_view lua(ts);
		sol::table result_table = lua.create_table();

		if (mangod)
		{
			SRP6 srp;
			srp.CalculateVerifier(CalculateShaPassHash(username, password));
			const char* s_hex = srp.GetSalt().AsHexStr();
			const char* v_hex = srp.GetVerifier().AsHexStr();
			std::string result;
			result_table["salt"] = s_hex;
			result_table["verifier"] = v_hex;

			OPENSSL_free((void*)s_hex);
			OPENSSL_free((void*)v_hex);
		}
		else
		{
			auto [salt, verifier] = Acore::Crypto::SRP6::MakeRegistrationData(username, password);
			result_table["salt"] = salt;
			result_table["verifier"] = verifier;
		}
		return result_table;
	}

	static bool spr6_check_password(bool mangod, const std::string& username, const std::string& password, const std::string_view& salt_str, const std::string_view& verifier_str)
	{
		if (mangod)
		{
			SRP6 srp;
			bool calcv = srp.CalculateVerifier(CalculateShaPassHash(username, password), salt_str.data());
			if (calcv && srp.ProofVerifier(verifier_str.data()))
				return true;
			return false;
		}
		else
		{
			if (salt_str.size() != 32)
				throw std::exception("the salt length must be equal to 32");
			if (verifier_str.size() != 32)
				throw std::exception("the verifier length must be equal to 32");

			std::array<unsigned char, 32> salt;
			std::array<unsigned char, 32> verifier;

			for (size_t i = 0; i < 32; i++)
				salt[i] = salt_str[i];
			for (size_t i = 0; i < 32; i++)
				verifier[i] = verifier_str[i];
			return Acore::Crypto::SRP6::CheckLogin(username, password, salt, verifier);
		}
		
	}
};


extern "C" {
#ifdef _WIN32
	DLL_EXPORT
#endif
		int fastweb_module_regist(void* sol2, void* lua)
	{
		sol::state* state = static_cast<sol::state*>(sol2);
		
		state->new_usertype<spr6>("spr6",
			"check", &spr6::spr6_check_password,
			"make", &spr6::spr6_make
		);
		return 0;
	}
}