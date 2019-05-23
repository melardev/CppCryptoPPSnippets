#pragma once

#include <vector>
#include <CryptoPP/config.h>
#include <Cryptopp/des.h>
#include <cassert>
#include <Cryptopp/filters.h>
#include <Cryptopp/modes.h>
#include <array>

namespace DES_CBC_PKCS5ManualPadding
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

	void padPKCS5(std::vector<CryptoPP::byte>& toBePadded);
	void unPadPKCS5(std::vector<CryptoPP::byte>& toBeUnPadded);

	void fillVectorWithRandomBytes(std::vector<CryptoPP::byte>& vectorToBeFilled)
	{
		CryptoPP::OS_GenerateRandomBlock(true, vectorToBeFilled.data(), vectorToBeFilled.size());
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
		std::map<std::string, std::vector<CryptoPP::byte>> info = setupSnippet();

		std::string cipherText;
		encrypt(info["iv"], info["key"], info["plain_text"], cipherText);

		std::cout << "Encrypted " << std::endl;
		printHex(cipherText);

		std::string decrypted;
		std::vector<CryptoPP::byte> cipherTextVector;
		std::copy(cipherText.begin(), cipherText.end(), std::back_inserter(cipherTextVector));
		// cipherTextVector.push_back('\0'); // string terminator
		decrypt(info["iv"], info["key"], cipherTextVector, decrypted);

		std::cout << "Decrypted " << std::endl;
		std::cout << decrypted << std::endl;
		return 0;
	}

	std::map<std::string, std::vector<CryptoPP::byte>> setupSnippet()
	{
		// Initialization vector, used in DES algorithm
		std::vector<CryptoPP::byte> IVVector(CryptoPP::DES::BLOCKSIZE, 0);
		fillVectorWithRandomBytes(IVVector);

		std::vector<CryptoPP::byte> desKeyVector(CryptoPP::DES::KEYLENGTH);
		fillVectorWithRandomBytes(desKeyVector);

		// Strings
		std::string plainTextStr = "Please encrypt this message with DES CBC PKCS5Padding please please";

		// Vectors
		std::vector<CryptoPP::byte> plainTextVector;

		// Strings to vectors
		std::copy(plainTextStr.begin(), plainTextStr.end(), std::back_inserter(plainTextVector));
		// We will not include the null byte terminator into the plaintext
		// plainTextVector.push_back('\0'); // string terminator

		// Perform the padding
		padPKCS5(plainTextVector);


		// assertions
		assert(desKeyVector.size() == CryptoPP::DES::KEYLENGTH);
		assert(IVVector.size() == CryptoPP::DES::BLOCKSIZE);

		// Do not perform this assertion because now the algorithm will perform the needed padding
		// if size is not the appropriate
		// assert(plainTextVector.size() % CryptoPP::DES::BLOCKSIZE == 0);

		std::cout << "Hex(IV)" << std::endl;
		printHex(IVVector);

		std::cout << "Hex(Key)" << std::endl;
		printHex(desKeyVector);

		// Initialize an array of 3 vector<byte>(initialized to 0)
		std::map<std::string, std::vector<CryptoPP::byte>> result;

		result["iv"] = IVVector;
		result["key"] = desKeyVector;
		result["plain_text"] = plainTextVector;
		return result;
	}

	void padPKCS5(std::vector<CryptoPP::byte>& toBePadded)
	{
		const size_t bytesToPad = CryptoPP::DES::BLOCKSIZE - (toBePadded.size() % CryptoPP::DES::BLOCKSIZE);
		const CryptoPP::byte paddingByte = static_cast<CryptoPP::byte>(bytesToPad & 0xff);

		// From the end of the vector, add n bytes(bytesToPad), the value of those bytes will be paddingByte
		toBePadded.insert(toBePadded.end(), bytesToPad, paddingByte);
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
			CryptoPP::StreamTransformationFilter::NO_PADDING); // We already did the padding

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

		std::string decryptedPadded;
		auto destinationString = new CryptoPP::StringSink(decryptedPadded);
		CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption transformation(key.data(), key.size(), IV.data());
		auto filter = new CryptoPP::StreamTransformationFilter(
			transformation,
			destinationString,
			CryptoPP::StreamTransformationFilter::NO_PADDING // We will perform the un-padding ourselves
		);

		CryptoPP::StringSource(
			std::string(cipherText.begin(), cipherText.end()), true, filter);


		std::vector<CryptoPP::byte> decryptedVector;
		std::copy(decryptedPadded.begin(), decryptedPadded.end(), std::back_inserter(decryptedVector));
		unPadPKCS5(decryptedVector);

		decrypted = std::string(decryptedVector.begin(), decryptedVector.end());
	}

	void unPadPKCS5(std::vector<CryptoPP::byte>& toBeUnPadded)
	{
		const CryptoPP::byte lastByte = toBeUnPadded.back();
		const int paddingByte = lastByte & 0xff;

		const size_t start = toBeUnPadded.size() - paddingByte;
		toBeUnPadded.resize(start);
	}
}
