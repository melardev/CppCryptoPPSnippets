#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <Cryptopp/config.h>
#include <cryptopp/md5.h>
#include <Cryptopp/filters.h>
#include <Cryptopp/hex.h>

namespace Md5Truncated
{
	int main()
	{
		CryptoPP::Weak1::MD5 md5_hasher;

		std::string message = "This is a very cool message, but I don't wanna see it anymore, so hash it";
		std::string digest;
		std::cout << "Message" << std::endl
			<< message << std::endl << std::endl;

		md5_hasher.Update((const CryptoPP::byte*)message.data(), message.size());
		digest.resize(md5_hasher.DigestSize() / 2);
		md5_hasher.TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size());


		std::string encoded;
		// CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encoded), false);
		CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));

		std::cout << "Hex(Hash)" << std::endl;
		std::cout << encoded << std::endl << std::endl;

		return 0;
	}
}
