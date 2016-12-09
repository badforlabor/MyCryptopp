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



extern "C" __declspec(dllexport) const char* encrypt(int& outlength, const char* bindata, int data_length, const char* key_str, const char* iv_str)
{
	static std::string str_out;

	str_out.clear();

	std::string str_in, key, iv;
	str_in.append(bindata, data_length);
	key.append(key_str);
	iv.append(iv_str);


	// 不足16位的，补位！
	const int padcount = 16;
	int mod = data_length % padcount;
	if (mod != 0)
	{
		for (int i = 0; i < padcount - mod; i++)
			str_in.insert(str_in.end(), 0);
	}

	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());

	CryptoPP::StringSource encryptor(str_in, true,
		new CryptoPP::StreamTransformationFilter(encryption,
			new CryptoPP::StringSink(str_out)
		)
	);

	outlength = str_out.size();	

	return str_out.c_str();
}
extern "C" __declspec(dllexport) const char* decrypt(int& outlength, const char* bindata, int data_length, const char* key_str, const char* iv_str)
{
	static std::string str_out;

	str_out.clear();

	std::string str_in, key, iv;
	str_in.append(bindata, data_length);
	key.append(key_str);
	iv.append(iv_str);

	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());

	CryptoPP::StringSource encryptor(str_in, true,
		new CryptoPP::StreamTransformationFilter(decryption,
			new CryptoPP::StringSink(str_out)
		)
	);

	outlength = str_out.size();

	return str_out.c_str();
}