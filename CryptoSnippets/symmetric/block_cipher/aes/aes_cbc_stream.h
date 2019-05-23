#pragma once
#include <iostream>
#include <string>
#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cassert>
#include <cryptopp/osrng.h>
#include <iomanip>

/// I called this snippet stream because you keep pushing data
/// to be encrypted and decrypted, then finally you call MessageEnd()
/// to make it happen
namespace AES_CBC_STREAM
{
	enum class KeySize
	{
		// each byte has 8 bits, so 128 bits is 16 bytes,
		// That means the keys may be 16, 24, or 32 bytes long
		AES_128 = 128 / 8,
		AES_192 = 192 / 8,
		AES_256 = 256 / 8,
	};

	void encrypt(const std::string& IV, const std::string& key,
	             const std::string& plaintextString,
	             std::string& encryptedString);

	void decrypt(const std::string& iv, const std::string& key,
	             const std::string& encryptedString,
	             std::string& decryptedString);

	void putRandomBytesOnStr(CryptoPP::byte* buffer, size_t size)
	{
		CryptoPP::OS_GenerateRandomBlock(true, buffer, size);
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
		std::cout << "\t\t\t\tAES CBC 256 As Stream Snippet" << std::endl << std::endl;
		// AES is a blocking cipher
		// Key and IV setup
		// AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
		// bit). This key is secretly exchanged between two parties before communication
		// begins. DEFAULT_KEYLENGTH= 16 bytes

		std::string key;
		key.resize((size_t)KeySize::AES_256);
		putRandomBytesOnStr((CryptoPP::byte*)key.data(), (size_t)KeySize::AES_256);

		std::cout << "Hex(Key)" << std::endl;
		printHex(key);

		std::string iv;
		iv.resize(CryptoPP::AES::BLOCKSIZE);
		putRandomBytesOnStr((CryptoPP::byte*)iv.data(), CryptoPP::AES::BLOCKSIZE);

		std::cout << "Hex(IV)" << std::endl;
		printHex(iv);

		const std::string plainTextString = "Please encrypt me with AES please please";
		std::string encryptedString;
		std::string decryptedString;

		std::cout << "Plain Text" << std::endl;
		std::cout << plainTextString;
		std::cout << std::endl << std::endl;

		encrypt(iv, key, plainTextString, encryptedString);
		std::cout << "Hex(Encrypted)" << std::endl;
		printHex(encryptedString);

		decrypt(iv, key, encryptedString, decryptedString);

		std::cout << "Decrypted:" << std::endl;
		std::cout << decryptedString << std::endl;


		return 0;
	}

	void encrypt(const std::string& IV, const std::string& key,
	             const std::string& plaintextString,
	             std::string& encryptedString)
	{
		assert(IV.size() == CryptoPP::AES::BLOCKSIZE);
		assert(key.size() == static_cast<size_t>(KeySize::AES_128)||
			key.size() == static_cast<size_t>(KeySize::AES_192) ||
			key.size() == static_cast<size_t>(KeySize::AES_256));

		CryptoPP::AES::Encryption aesEncryption((CryptoPP::byte *)key.c_str(),
		                                        CryptoPP::AES::DEFAULT_KEYLENGTH);

		CryptoPP::CBC_Mode_ExternalCipher::Encryption operation(aesEncryption, (CryptoPP::byte *)IV.c_str());

		const auto encryptedStringWrapper = new CryptoPP::StringSink(encryptedString);

		CryptoPP::StreamTransformationFilter filter(operation,
		                                            encryptedStringWrapper);

		filter.Put(reinterpret_cast<const unsigned char*>(plaintextString.c_str()), plaintextString.length() + 1);
		filter.MessageEnd();
	}

	void decrypt(const std::string& IV, const std::string& key,
	             const std::string& encryptedString, std::string& decryptedString)
	{
		assert(IV.size() == CryptoPP::AES::BLOCKSIZE);
		assert(key.size() == 16 || key.size() == 24 || key.size() == 32);

		CryptoPP::AES::Decryption aesDecryption((CryptoPP::byte *)key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte *)IV.c_str());

		CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedString));
		stfDecryptor.Put(reinterpret_cast<const unsigned char*>(encryptedString.c_str()), encryptedString.size());
		stfDecryptor.MessageEnd();
	}
}
