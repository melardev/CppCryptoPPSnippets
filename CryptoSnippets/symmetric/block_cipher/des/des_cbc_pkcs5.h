#pragma once

#include <vector>
#include <CryptoPP/config.h>
#include <Cryptopp/des.h>
#include <cassert>
#include <Cryptopp/filters.h>
#include <Cryptopp/modes.h>
#include <array>
#include <Cryptopp/hex.h>

namespace DES_CBC_PKCS5PaddingSnippet
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

	std::string getHexEncoded(const std::string& message)
	{
		const bool upperCase = true;
		std::string messageHexEncoded;
		const auto destinationString = new CryptoPP::StringSink(messageHexEncoded);
		const auto encoder = new CryptoPP::HexEncoder(destinationString, upperCase);
		CryptoPP::StringSource(message, true, encoder);

		return messageHexEncoded;
	}

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

		std::string encryptedString;
		encrypt(info["iv"], info["key"], info["plain_text"], encryptedString);

		std::cout << "Encrypted" << std::endl;
		printHex(encryptedString);

		std::string decrypted;
		std::vector<CryptoPP::byte> cipherTextVector;
		std::copy(encryptedString.begin(), encryptedString.end(), std::back_inserter(cipherTextVector));
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
		std::string plainTextStr = "Please encrypt this message with DES CBC PKCS5Padding please please";


		// Vectors
		std::vector<CryptoPP::byte> plainTextVector;
		std::vector<CryptoPP::byte> desKeyVector(CryptoPP::DES::KEYLENGTH);
		fillVectorWithRandomBytes(desKeyVector);

		// Initialization vector, used in DES algorithm
		std::vector<CryptoPP::byte> IVVector(CryptoPP::DES::BLOCKSIZE, 0);
		fillVectorWithRandomBytes(IVVector);


		// Strings to vectors
		std::copy(plainTextStr.begin(), plainTextStr.end(), std::back_inserter(plainTextVector));
		// We will not include the null byte terminator into the plaintext
		// plainTextVector.push_back('\0'); // string terminator


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

		result["iv"] = IVVector;
		result["key"] = desKeyVector;
		result["plain_text"] = plainTextVector;
		return result;
	}

	void encrypt(const std::vector<CryptoPP::byte>& IV,
	             const std::vector<CryptoPP::byte>& key,
	             const std::vector<CryptoPP::byte>& plainText,
	             std::string& cipherTextStr)
	{
		// Encryption
		assert(key.size() == CryptoPP::DES::KEYLENGTH);
		assert(IV.size() == CryptoPP::DES::BLOCKSIZE);

		auto destination = new CryptoPP::StringSink(cipherTextStr);

		CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption streamTransformation(
			key.data(),
			key.size(),
			IV.data());

		auto filter = new CryptoPP::StreamTransformationFilter(
			streamTransformation,
			destination,
			CryptoPP::StreamTransformationFilter::PKCS_PADDING);

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
			CryptoPP::StreamTransformationFilter::PKCS_PADDING
		);

		CryptoPP::StringSource(
			std::string(cipherText.begin(), cipherText.end()), true, filter);
	}
}
