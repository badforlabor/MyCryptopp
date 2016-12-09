
#include <iostream>
#include "randpool.h"
#include "rsa.h"
#include "hex.h"
#include "files.h"


#include "config.h"
#include "stdcpp.h"
#include "modes.h"
#include"base64.h"


using namespace std;
using namespace CryptoPP;


//#pragma comment(lib, "cryptlib.lib")
// 加密

string encrypt(const std::string& str_in, const std::string& key, const std::string& iv)
{
	std::string str_out;
	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());

	CryptoPP::StringSource encryptor(str_in, true,
		new CryptoPP::StreamTransformationFilter(encryption,
			new CryptoPP::Base64Encoder(
				new CryptoPP::StringSink(str_out),
				false // do not append a newline
			)
		)
	);
	return str_out;
}
//解密

//------------------------
string decrypt(const std::string& str_in, const std::string& key, const std::string& iv)
{


	std::string str_out;
	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());


	CryptoPP::StringSource decryptor(str_in, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StreamTransformationFilter(decryption,
				new CryptoPP::StringSink(str_out)
			)
		)
	);
	return str_out;
}
// Main函数

void main()
{
	std::string str = "123456789012345";  //加密的字符串
	std::string key = "01234567891234560123456789123456"; // 32 bytes
	std::string iv = "0123456789123456"; // 16 bytes
	std::string str_encrypted = encrypt(str, key, iv);   //加密后密文

	std::string str_decrypted = decrypt(str_encrypted, key, iv);  //解密后明文
	std::cout << "str_encrypted: " << str_encrypted << std::endl;
	std::cout << "str_decrypted: " << str_decrypted << std::endl;
	int a;
	cin >> a;
}