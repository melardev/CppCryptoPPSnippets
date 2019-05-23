#pragma once
#include <Cryptopp/config.h>
#include <Cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <Cryptopp/files.h>

namespace Base64FileEncoding
{
	int main()
	{
		// Binary data
		const std::string message = "Please please encode me with base64\nThis line encode it also please";
		std::cout << "Original message" << std::endl << message << std::endl << std::endl;

		// Encode with line breaks (default).
		// Ordinarily, we would now have to call MessageEnd() to flush
		// Base64Encoder's buffer. However, the 'true' parameter will cause
		// the StringSource::PumpAll() method to be called, and that method
		// will cause MessageEnd() to be triggered implicitly.
		CryptoPP::StringSource((CryptoPP::byte*)message.data(), message.size(),
		                       true,
		                       new CryptoPP::Base64Encoder(
			                       new CryptoPP::FileSink("./base64_encoding.bin")));


		std::cout << "File contents" << std::endl;
		std::ifstream file("./base64_encoding.bin");
		if (file.is_open())
		{
			std::string line;
			while (std::getline(file, line))
			{
				std::cout << line << std::endl;
			}
			file.close();
			std::cout << std::endl << std::endl;
		}
		else
		{
			std::cout << "Could not open the file" << std::endl;
			return 1;
		}

		// Encode without line breaks.
		CryptoPP::StringSource((CryptoPP::byte*)message.data(),
		                       message.size(), true,
		                       new CryptoPP::Base64Encoder(
			                       new CryptoPP::FileSink("./base64_encoding_br.bin"),
			                       false));

		std::cout << "File contents (Without line breaks)" << std::endl;
		file.open("./base64_encoding_br.bin");
		if (file.is_open())
		{
			std::string line;
			while (std::getline(file, line))
			{
				std::cout << line << std::endl;
			}
			file.close();
			std::cout << std::endl << std::endl;
		}
		else
		{
			std::cout << "Could not open the file" << std::endl;
			return 1;
		}

		std::string decoded;
		CryptoPP::FileSource(L"./base64_encoding.bin",
		                     true,
		                     new CryptoPP::Base64Decoder(
			                     new CryptoPP::StringSink(decoded)));

		std::cout << "Decoded" << std::endl;
		std::cout << decoded << std::endl << std::endl;


		std::string decodedNoLineBreaks;
		CryptoPP::FileSource(L"./base64_encoding_br.bin",
		                     true,
		                     new CryptoPP::Base64Decoder(
			                     new CryptoPP::StringSink(decodedNoLineBreaks)));

		std::cout << "Decoded without Line Breaks" << std::endl;
		std::cout << decodedNoLineBreaks << std::endl << std::endl;

		return 0;
	}
}
