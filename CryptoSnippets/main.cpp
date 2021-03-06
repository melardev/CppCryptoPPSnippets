// Encoding
#include "encoding/hex_encoding.h"
#include "encoding/base64_encoding.h"
#include "encoding/base64_file.h"


// Random
#include "random/random_byte_string.h"
#include "random/random_byte_vector.h"


// Symmetric cryptography
#include "symmetric/block_cipher/aes/aes_cbc_pkcs.h"
#include "symmetric/block_cipher/des/des_cbc_no_padding.h"
#include "symmetric/block_cipher/des/des_cbc_pkcs5.h"
#include "symmetric/block_cipher/des/des_cbc_pkcs5_manual.h"
#include "symmetric/block_cipher/aes/aes_cbc_stream.h"
#include "symmetric/stream_cipher/rc4_usage.h"


// Asymmetric
#include "asymmetric/generate_rsa_keys.h"


// Hashing
#include "hashing/md5/about_md5.h"
#include "hashing/md5/md5_usage.h"
#include "hashing/md5/md5_truncate.h"
#include "hashing/md5/md5_filter.h"
#include "hashing/md5/md5_file_filter.h"
// #include "hashing/md5/not_ready/read_md5_bytes_from_file.h"


int main()
{
	std::cout << "======================== CryptoPP Snippets ========================" << std::endl;

	// Encoding
	// HexEncoding::main();
	// Base64Encoding::main();
	// Base64FileEncoding::main();


	// Randomness
	// RandomVectorByte::main();
	// RandomByteString::main();


	// Hashing
	// AboutMd5::main();
	MD5Usage::main();
	// Md5Truncated::main();
	// Md5HashWithFilter::main();
	// Md5FileFilter::main();
	// MD5ReadBinaryHashFromFileAsHex::main();


	// Symmetric cryptography

	//		Stream ciphers
	// RC4Usage::main();

	//		Block ciphers
	// DES_CBC_NoPaddingSnippet::main();
	// DES_CBC_PKCS5PaddingSnippet::main();
	// DES_CBC_PKCS5ManualPadding::main();
	// AES_CBC_PKCS5::main();
	// AES_CBC_STREAM::main();


	// Asymmetric Cryptography
	// GenerateRSAKeys::main();

	getc(stdin);
}
