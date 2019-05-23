#pragma once
#include <cryptopp/config.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>


namespace Base64Encoding
{
	inline std::string encodeBase64(const std::string& plainText)
	{
		std::string encoded;
		const auto result = new CryptoPP::StringSink(encoded);
		const auto encoder = new CryptoPP::Base64Encoder(result, false);
		CryptoPP::StringSource ss((CryptoPP::byte*)plainText.data(), plainText.size(), true, encoder);
		return encoded;
	}

	inline std::string decodeBase64(std::string& encodedText)
	{
		std::string decoded;
		const auto filter = new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded));
		CryptoPP::StringSource ss(encodedText, true, filter);
		// return std::vector<CryptoPP::byte>(decoded.begin(), decoded.end());
		return decoded;
	}

	inline std::string encodeBase64Url(const std::string& plainText)
	{
		std::string encoded; // create the result object
		const auto result = new CryptoPP::StringSink(encoded); // Wrap it into what CryptoPP may use
		// Create encoder
		auto encoder = new CryptoPP::Base64URLEncoder(result, false);
		// Perform the encoding
		CryptoPP::StringSource ss((CryptoPP::byte *)plainText.data(), plainText.size(), true, encoder);
		return encoded;
	}

	inline std::string decodeBase64Url(std::string& encodedText)
	{
		std::string decoded;
		const auto decoder = new CryptoPP::Base64URLDecoder(new CryptoPP::StringSink(decoded));
		// Create a StringSource with the corresponding filter
		CryptoPP::StringSource ss(encodedText, true, decoder);
		// return std::vector<CryptoPP::byte>(decoded.begin(), decoded.end());
		return decoded;
	}

	int main()
	{
		std::cout << "Base 64 encoding" << std::endl;
		const std::string message = "Please please encode me with base64";
		std::string encoded = encodeBase64(message);
		std::cout << "Encoded" << std::endl
			<< encoded << std::endl << std::endl;

		const auto decoded = decodeBase64(encoded);
		std::cout << "Decoded" << std::endl
			<< decoded << std::endl << std::endl;


		std::cout << "Base64 Url Encoded" << std::endl;
		std::string encodedUrl = encodeBase64Url(message);
		std::cout << "Encoded" << std::endl
			<< encodedUrl << std::endl << std::endl;

		const auto decodedUrl = decodeBase64(encodedUrl);
		std::cout << "Decoded" << std::endl
			<< decodedUrl << std::endl;


		return 0;
	}
}
