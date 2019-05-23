#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <Cryptopp/rsa.h>
#include <Cryptopp/hex.h>

namespace MD5Usage
{
	int main()
	{
		std::string message = "This is a very cool message, but I don't wanna see it anymore, so hash it";
		std::string digest;

		CryptoPP::Weak1::MD5 md5Hasher;
		md5Hasher.Update((const CryptoPP::byte*)message.data(), message.size());
		digest.resize(md5Hasher.DigestSize());
		md5Hasher.Final((CryptoPP::byte*)digest.data());

		std::cout << "Message" << std::endl
			<< message << std::endl << std::endl;


		// CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
		std::string encoded;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encoded), false);
		CryptoPP::StringSource ss(digest, true, new CryptoPP::Redirector(encoder));

		std::cout << "Hex(Hash)" << std::endl;
		std::cout << encoded << std::endl;
		std::cout << std::endl;
		return 0;
	}
}
