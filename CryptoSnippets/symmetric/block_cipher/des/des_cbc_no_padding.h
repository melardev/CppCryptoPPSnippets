#pragma once

#include <vector>
#include <CryptoPP/config.h>
#include <Cryptopp/des.h>
#include <cassert>
#include <Cryptopp/filters.h>
#include <Cryptopp/modes.h>
#include <array>

namespace DES_CBC_NoPaddingSnippet
{
	std::map<std::string, std::vector<CryptoPP::byte>> setupSnippet();
	void encrypt(const std::vector<CryptoPP::byte>& IV,
	             const std::vector<CryptoPP::byte>& key,
	             const std::vector<CryptoPP::byte>& plainText,
	             std::string& cipherText
	);

	void decrypt(
		const std::vector<CryptoPP::byte>& IV,
		const std::vector<CryptoPP::byte>& key,
		const std::vector<CryptoPP::byte>& cipherText,
		std::string& decrypted
	);

	template <class VectorOrStr>
	void generateRandomBytes(VectorOrStr& vectorOrString)
	{
		CryptoPP::OS_GenerateRandomBlock(true, (CryptoPP::byte*)vectorOrString.data(), vectorOrString.size());
	}

	template <class VectorOrStr>
	void printHex(const VectorOrStr& vectorOrString)
	{
		for (unsigned int i = 0; i < vectorOrString.size(); i++)
		{
			if (i != 0 && i % 8 == 0)
				std::cout << std::endl;
			std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (0xff & static_cast<CryptoPP::byte>(
				vectorOrString[i])) << " ";
		}
		std::cout << std::endl;
		std::cout << std::endl;
	}

	int main()
	{
		std::cout << "\t\t\t\tDES Snippet No padding" << std::endl << std::endl;
		std::map<std::string, std::vector<CryptoPP::byte>> info = setupSnippet();

		std::string encryptedStr;
		encrypt(info["iv"], info["key"], info["plain_text"], encryptedStr);

		std::cout << "Hex(encrypted)" << std::endl;
		printHex(encryptedStr);

		std::string decrypted;
		std::vector<CryptoPP::byte> cipherTextVector;
		std::copy(encryptedStr.begin(), encryptedStr.end(), std::back_inserter(cipherTextVector));
		// cipherTextVector.push_back('\0'); // string terminator
		decrypt(info["iv"], info["key"], cipherTextVector, decrypted);

		std::cout << "Decrypted " << std::endl
			<< decrypted << std::endl;
		return 0;
	}

	std::map<std::string, std::vector<CryptoPP::byte>> setupSnippet()
	{
		// Initialize an array of 3 vector<byte>(initialized to 0)
		std::map<std::string, std::vector<CryptoPP::byte>> result;

		// Strings
		// When No padding is used, the block size to encrypt has to be a multiple of
		// CryptoPP::DES::BLOCKSIZE which is 8, so you have to make sure this applies.
		// I know, it is not very convenient, look at des_cbc_pkcs5.h snippet
		// where I used PKCS5 where we don't have this constraint because padding is performed

		std::string plainTextStr = "12345678"; // String to encrypt
		std::string keyStr;
		keyStr.resize(CryptoPP::DES::KEYLENGTH); // Key used in DES algorithm
		generateRandomBytes(keyStr);


		// Vectors
		std::vector<CryptoPP::byte> plainTextVector;
		std::vector<CryptoPP::byte> desKeyVector;

		// Initialization vector, used in DES algorithm
		std::vector<CryptoPP::byte> IVVector(CryptoPP::DES::BLOCKSIZE);
		generateRandomBytes(IVVector);

		// Strings to vectors
		std::copy(plainTextStr.begin(), plainTextStr.end(), std::back_inserter(plainTextVector));
		// plainTextVector.push_back('\0'); // string terminator, not included in encryption

		std::copy(keyStr.begin(), keyStr.end(), std::back_inserter(desKeyVector));

		const int keyLen = CryptoPP::DES::KEYLENGTH;

		// assertions
		assert(desKeyVector.size() == keyLen);
		assert(IVVector.size() == CryptoPP::DES::BLOCKSIZE);
		assert(plainTextVector.size() % CryptoPP::DES::BLOCKSIZE == 0);

		result["iv"] = IVVector;
		result["key"] = desKeyVector;
		result["plain_text"] = plainTextVector;

		std::cout << "Hex(IV)" << std::endl;
		printHex(IVVector);
		std::cout << "Hex(Key)" << std::endl;
		printHex(desKeyVector);


		return result;
	}

	void encrypt(const std::vector<CryptoPP::byte>& IV,
	             const std::vector<CryptoPP::byte>& key,
	             const std::vector<CryptoPP::byte>& plainText,
	             std::string& cipherTextStr)
	{
		assert(key.size() == CryptoPP::DES::KEYLENGTH);
		assert(IV.size() == CryptoPP::DES::BLOCKSIZE);
		assert(plainText.size() % CryptoPP::DES::BLOCKSIZE == 0);

		// Encryption
		auto destination = new CryptoPP::StringSink(cipherTextStr);

		CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption streamTransformation(
			key.data(),
			key.size(),
			IV.data());

		auto filter = new CryptoPP::StreamTransformationFilter(
			streamTransformation,
			destination,
			CryptoPP::StreamTransformationFilter::NO_PADDING);

		CryptoPP::StringSource ss(
			// Plain text as std::string
			std::string(plainText.begin(), plainText.end()),
			true,
			filter
		);
	}

	void decrypt(
		const std::vector<CryptoPP::byte>& IV,
		const std::vector<CryptoPP::byte>& key,
		const std::vector<CryptoPP::byte>& cipherText,
		std::string& decrypted
	)
	{
		assert(key.size() == CryptoPP::DES::KEYLENGTH);
		assert(IV.size() == CryptoPP::DES::BLOCKSIZE);
		assert(cipherText.size() % CryptoPP::DES::BLOCKSIZE == 0);

		auto destinationString = new CryptoPP::StringSink(decrypted);
		CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption transformation(key.data(), key.size(), IV.data());
		auto filter = new CryptoPP::StreamTransformationFilter(
			transformation,
			destinationString,
			CryptoPP::StreamTransformationFilter::NO_PADDING
		);

		CryptoPP::StringSource(
			std::string(cipherText.begin(), cipherText.end()), true, filter);
	}
}
