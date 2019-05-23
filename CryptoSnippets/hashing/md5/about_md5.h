#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <CryptoPP/md5.h>
#include <iostream>


namespace AboutMd5
{
	int main()
	{
		CryptoPP::Weak1::MD5 hasher;

		std::cout
			<< "Name : " << hasher.AlgorithmName() << std::endl
			<< "Digest size: " << hasher.DigestSize() << std::endl
			<< "Block size: " << hasher.BlockSize() << std::endl;
		return 0;
	}
}
