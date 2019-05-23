#pragma once
#include <string>
#include <Cryptopp/cryptlib.h>
#include <Cryptopp/filters.h>
#include <Cryptopp/hex.h>

namespace HexEncoding
{
	std::string getHexEncoded(const std::string& message);
	std::string getHexDecoded(const std::string& hexEncoded);

	// TODO: the below function does not work as expected, fix it.
	CryptoPP::SecByteBlock getHexDecoded2(const char* hexEncoded);

	int main()
	{
		const std::string message = "I have a message to be hex encoded";
		std::cout << "Original text" << std::endl;
		std::cout << message << std::endl << std::endl;

		const std::string messageHexEncoded = getHexEncoded(message);
		std::cout << "Hex(text)" << std::endl;
		std::cout << messageHexEncoded << std::endl << std::endl;

		const std::string messageHexDecoded = getHexDecoded(messageHexEncoded);
		std::cout << "Decoded from hex" << std::endl;
		std::cout << messageHexDecoded << std::endl;


		// Not working as expected
		// std::cout << "Decoded from hex 2" << std::endl;
		// CryptoPP::SecByteBlock messageHexDecoded2 = getHexDecoded2(messageHexEncoded.c_str());
		// std::cout << std::string((char*)messageHexDecoded2.BytePtr()) << std::endl;


		return 0;
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

	std::string getHexDecoded(const std::string& hexEncoded)
	{
		const bool upperCase = true;
		std::string messageHexDecoded;
		const auto destinationString = new CryptoPP::StringSink(messageHexDecoded);
		const auto decoder = new CryptoPP::HexDecoder(destinationString);
		CryptoPP::StringSource(hexEncoded, true, decoder);
		return messageHexDecoded;
	}

	CryptoPP::SecByteBlock getHexDecoded2(const char* hexEncoded)
	{
		CryptoPP::StringSource ss(hexEncoded, true, new CryptoPP::HexDecoder);
		CryptoPP::SecByteBlock result((size_t)ss.MaxRetrievable());
		ss.Get(result, result.size());

		return result;
	}
}
