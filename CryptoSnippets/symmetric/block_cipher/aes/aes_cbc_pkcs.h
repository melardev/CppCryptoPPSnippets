#pragma once
#include <CryptoPP/config.h>
#include <map>
#include <vector>
#include <string>
#include <Cryptopp/aes.h>
#include <Cryptopp/filters.h>
#include <Cryptopp/hex.h>
#include <cassert>
#include <cryptopp/osrng.h>
#include <Cryptopp/modes.h>
#include <iomanip>

namespace AES_CBC_PKCS5
{
	enum class KeySize
	{
		// each byte has 8 bits, so 128 bits is 16 bytes,
		// That means the keys may be 16, 24, or 32 bytes long
		AES_128 = 128 / 8,
		AES_192 = 192 / 8,
		AES_256 = 256 / 8,
	};

	std::map<std::string, std::vector<CryptoPP::byte>> setupSnippet();


	void encrypt(const std::vector<CryptoPP::byte>& IV,
	             const std::vector<CryptoPP::byte>& key,
	             const std::string& plainText,
	             std::string& cipherText
	);

	void decrypt(
		const std::vector<CryptoPP::byte>& IV,
		const std::vector<CryptoPP::byte>& key,
		const std::string& encryptedText,
		std::string& decrypted
	);

	void fillVectorWithRandomBytes(std::vector<CryptoPP::byte>& vectorToBeFilled)
	{
		CryptoPP::OS_GenerateRandomBlock(true, vectorToBeFilled.data(), vectorToBeFilled.size());
	}

	std::vector<CryptoPP::byte> getRandomIV()
	{
		std::vector<CryptoPP::byte> iv(CryptoPP::AES::BLOCKSIZE);
		fillVectorWithRandomBytes(iv);
		return iv;
	}

	std::vector<CryptoPP::byte> getRandomKey()
	{
		std::vector<CryptoPP::byte> key((size_t)KeySize::AES_256);
		fillVectorWithRandomBytes(key);
		return key;
	}


	std::vector<CryptoPP::byte> getRandomKey(KeySize key_size)
	{
		switch (key_size)
		{
		case KeySize::AES_128:
		case KeySize::AES_192:
		case KeySize::AES_256:
			break;
		default:
			throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::random_key(KeySize): {key_size}.");
		}
		std::vector<CryptoPP::byte> key(static_cast<size_t>(key_size));
		CryptoPP::OS_GenerateRandomBlock(true, key.data(), key.size());
		return key;
	}

	std::string getHexEncoded(const std::string& message)
	{
		const bool upperCase = true;
		std::string messageHexEncoded;
		const auto destinationString = new CryptoPP::StringSink(messageHexEncoded);
		const auto encoder = new CryptoPP::HexEncoder(destinationString, upperCase);
		CryptoPP::StringSource(message, true, encoder);

		return messageHexEncoded;
	}

	template <class StrOrVector>
	void printHex(const StrOrVector& strOrVector)
	{
		for (unsigned int i = 0; i < strOrVector.size(); i++)
		{
			if (i != 0 && i % 8 == 0)
				std::cout << std::endl;
			std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (0xff & static_cast<CryptoPP::byte>(
				strOrVector[i])) << " ";
		}
		std::cout << std::endl;
		std::cout << std::endl;
	}

	int main()
	{
		std::cout << "\t\t\t\tAES 256 Snippet" << std::endl << std::endl;

		std::map<std::string, std::vector<CryptoPP::byte>> info = setupSnippet();
		std::string encrypted;
		std::string plainText = "Please encrypt me with AES please please";
		encrypt(info["iv"], info["key"], plainText, encrypted);

		std::cout << "Hex(Encrypted)" << std::endl;
		printHex(encrypted);

		std::string decrypted;

		std::vector<CryptoPP::byte> encryptedVector;
		std::copy(encrypted.begin(), encrypted.end(), std::back_inserter(encryptedVector));
		decrypt(info["iv"], info["key"], encrypted, decrypted);

		std::cout << "Decrypted" << std::endl;
		std::cout << decrypted << std::endl << std::endl;

		return 0;
	}

	inline std::map<std::string, std::vector<CryptoPP::byte>> setupSnippet()
	{
		// Key can be: 128, 192 or 256 bits, one character is 8 bytes so a key may be:
		// 16, 24 or 32 characters long
		std::vector<CryptoPP::byte> keyVector = getRandomKey();
		std::vector<CryptoPP::byte> IV = getRandomIV();


		std::cout << "Hex(IV)" << std::endl;
		printHex(IV);
		std::cout << "Hex(KeyVector)" << std::endl;
		printHex(keyVector);


		// Uncomment the below for more readability
		return // std::map<std::string, std::vector<CryptoPP::byte>>
		{
			{"key", keyVector},
			{"iv", IV},
		};
	}

	void encrypt(const std::vector<CryptoPP::byte>& IV,
	             const std::vector<CryptoPP::byte>& key,
	             const std::string& plainText,
	             std::string& cipherText
	)
	{
		assert(IV.size() == CryptoPP::AES::BLOCKSIZE);
		assert(key.size() == 16 || key.size() == 24 || key.size() == 32);


		const auto destinationStringSink = new CryptoPP::StringSink(cipherText);
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption transformation(key.data(), key.size(), IV.data());

		const auto filter = new CryptoPP::StreamTransformationFilter(
			transformation, // operation to be performed
			destinationStringSink, // destination wrapper
			CryptoPP::StreamTransformationFilter::PKCS_PADDING
		);

		CryptoPP::StringSource(
			plainText, // to be encrypted
			true,
			filter // filter to use
		);
	}

	void decrypt(
		const std::vector<CryptoPP::byte>& IV,
		const std::vector<CryptoPP::byte>& key,
		const std::string& cipherText,
		std::string& decrypted
	)
	{
		assert(IV.size() == CryptoPP::AES::BLOCKSIZE);
		assert(key.size() == 16 || key.size() == 24 || key.size() == 32);

		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption operation(key.data(), key.size(), IV.data());
		CryptoPP::StringSource(
			cipherText,
			true,
			new CryptoPP::StreamTransformationFilter(
				operation,
				new CryptoPP::StringSink(decrypted),
				CryptoPP::StreamTransformationFilter::PKCS_PADDING
			)
		);
	}
}
