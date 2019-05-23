#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <ostream>
#include <iostream>
#include <Cryptopp/filters.h>
#include <Cryptopp/hex.h>
#include <cryptopp/md5.h>


namespace Md5HashWithFilter
{
	int main()
	{
		const std::string message = "This is a very cool message, but I don't wanna see it anymore, so hash it";
		std::string digest;

		CryptoPP::Weak1::MD5 md5Hasher;

		// The advantage of using filters is not having to call update and final manually as we did in other demo
		CryptoPP::StringSource ss(message, true,
		                          new CryptoPP::HashFilter(md5Hasher, new CryptoPP::StringSink(digest)));

		std::cout << "Message: " << std::endl
			<< message << std::endl << std::endl;


		// CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
		std::string encoded;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encoded), false);
		CryptoPP::StringSource ss2(digest, true, new CryptoPP::Redirector(encoder));

		std::cout << "Digest: " << std::endl;
		std::cout << encoded << std::endl << std::endl;

		return 0;
	}
}
