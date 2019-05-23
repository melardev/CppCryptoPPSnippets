#pragma once
#include <CryptoPP/config.h>
#include <cryptopp/osrng.h>
#include <iomanip>

namespace RandomByteString
{
	void putRandomBytesOnStr(std::string& str)
	{
		CryptoPP::OS_GenerateRandomBlock(true, (CryptoPP::byte*)str.data(), str.size());
	}

	int main()
	{
		std::cout << "\t\t\t\tRandom bytes into string Snippet" << std::endl << std::endl;

		std::string key;
		key.resize(16);
		putRandomBytesOnStr(key);

		int i = 0;
		for (const auto& element : key)
		{
			if (i != 0 && i % 8 == 0)
				std::cout << std::endl;
			std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
				<< (int(element) & 0xff) << ", ";
			i++;
		}

		std::cout << std::endl << std::endl;

		return 0;
	}
}
