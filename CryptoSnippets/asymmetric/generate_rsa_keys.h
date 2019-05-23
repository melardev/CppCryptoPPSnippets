#pragma once
#include <CryptoPP/rsa.h>
#include <cryptopp/osrng.h>
#include <Cryptopp/files.h>

namespace GenerateRSAKeys
{
	std::string filePublicKey = "./key.pub";
	std::string filePrivateKey = "./key.priv";

	template <typename Key>
	void SaveKey(const std::string& fileName, const Key& key)
	{
		CryptoPP::ByteQueue queue;
		// Save key content into the Queue
		key.Save(queue);
		CryptoPP::FileSink file(fileName.c_str());
		// Copy into the Destination which is a File in this case
		queue.CopyTo(file);
		file.MessageEnd();
	}

	int main()
	{
		std::cout << "\t\t\t\tRSA Generate Keys Snippet" << std::endl << std::endl;

		CryptoPP::InvertibleRSAFunction parameters;

		// Create random number generator
		CryptoPP::AutoSeededRandomPool seededRandomPool;

		// Generate random Key with size 2048
		parameters.GenerateRandomWithKeySize(seededRandomPool, 2048);

		const CryptoPP::RSA::PublicKey publicKey(parameters);
		const CryptoPP::RSA::PrivateKey privateKey(parameters);

		SaveKey(filePublicKey, publicKey);
		SaveKey(filePrivateKey, privateKey);

		return 0;
	}
}
