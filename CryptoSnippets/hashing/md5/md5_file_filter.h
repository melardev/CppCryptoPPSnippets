#pragma once
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/md5.h>

namespace Md5FileFilter
{
	int main()
	{
		CryptoPP::Weak1::MD5 md5Hasher;
		std::string message = "Hash me with MD5";

		const auto fileSink = new CryptoPP::FileSink("./md5_hex_sum.txt");
		const auto encoder = new CryptoPP::HexEncoder(fileSink, false);
		const auto filter = new CryptoPP::HashFilter(md5Hasher, encoder);
		new CryptoPP::StringSource(message.data(), true, filter);

		std::cout << "Hex(Hash) is written into ./md5_hex_sum.txt" << std::endl;

		return 0;
	}
}
