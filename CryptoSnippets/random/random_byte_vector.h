#pragma once
#include <vector>
#include <CryptoPP/config.h>
#include <cryptopp/osrng.h>
#include <iomanip>

namespace RandomVectorByte
{
	void generateRandomBytesInVector(std::vector<CryptoPP::byte>& vectorToBeFilled)
	{
		CryptoPP::OS_GenerateRandomBlock(true, vectorToBeFilled.data(), vectorToBeFilled.size());
	}

	int main()
	{
		std::cout << "\t\t\t\tRandom bytes into std::vector Snippet" << std::endl << std::endl;

		const size_t vectorLength = 8;
		std::vector<CryptoPP::byte> key(vectorLength);
		generateRandomBytesInVector(key);

		for (unsigned int i = 0; i < key.size(); i++)
		{
			std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
				<< (0xff & int(key.at(i))) << ", ";
		}
		std::cout << std::endl << std::endl;

		return 0;
	}
}
