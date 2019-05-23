#pragma once
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <vector>
#include <CryptoPP/config.h>
#include <CryptoPP/arc4.h>
#include <iomanip>
#include <cassert>
#include <cryptopp/osrng.h>

namespace RC4Usage
{
	void generateRandomBytesInVector(std::vector<CryptoPP::byte>& vectorToBeFilled)
	{
		CryptoPP::OS_GenerateRandomBlock(true, vectorToBeFilled.data(), vectorToBeFilled.size());
	}

	void printHex(const std::string& str)
	{
		for (int i = 0; i < str.size(); i++)
		{
			if (i != 0 && i % 8 == 0)
				std::cout << std::endl;
			std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (0xff & static_cast<CryptoPP::byte>(
				str[i])) << " ";
		}
		std::cout << std::endl;
		std::cout << std::endl;
	}

	int main()
	{
		std::cout << "\t\t\t\tRC4 Snippet" << std::endl << std::endl;

		std::string plainText = "Encrypt me with the very very weak RC4 please please please";
		std::vector<CryptoPP::byte> key(8); // Key size used for this example will be 8
		generateRandomBytesInVector(key);
		std::cout << "Hex(Key)" << std::endl;
		printHex(std::string(key.begin(), key.end()));

		std::vector<CryptoPP::byte> plainTextVector;
		std::copy(plainText.begin(), plainText.end(), std::back_inserter(plainTextVector));

		// MAX_KEYLENGTH is 256(bytes), meaning 2048 bits, that is the max key length for RC4
		assert(key.size() >= CryptoPP::Weak::ARC4::MIN_KEYLENGTH &&
			key.size() <= CryptoPP::Weak::ARC4::MAX_KEYLENGTH);

		// The reason why we copy plainTextVector to encrypted is because ProcessString mutate
		// the vector passed as argument, so if we want to keep both the plaintextVector and the 
		// encrypted vector, we have to create both with the same value, and not only use one.

		// Encrypt
		auto encrypted = plainTextVector;
		CryptoPP::Weak1::ARC4 rc4(key.data(), key.size());
		rc4.ProcessString(encrypted.data(), encrypted.size());

		std::cout << "Hex(encrypted)" << std::endl;
		printHex(std::string(encrypted.cbegin(), encrypted.cend()));

		// Reset state since we are using the same rc4 object for encrypt and decrypt
		rc4.SetKey(key.data(), key.size());

		// Decrypt
		auto restored = encrypted;
		rc4.ProcessString(restored.data(), restored.size());
		std::cout << "Decrypted" << std::endl;
		std::cout << std::string(restored.cbegin(), restored.cend()) << std::endl;
		return 0;
	}
}
