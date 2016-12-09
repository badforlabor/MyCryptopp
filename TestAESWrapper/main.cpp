#include <windows.h>
#include <iostream>
#include <string>

typedef const char* (*func_encrypt)(int& outlength, const char* bindata, int data_length, const char* key_str, const char* iv_str);
typedef const char* (*func_decrypt)(int& outlength, const char* bindata, int data_length, const char* key_str, const char* iv_str);

int main()
{
	HINSTANCE hdll = LoadLibraryA("AESWrapper.dll");
	if (hdll != NULL)
	{
		func_decrypt decrypt = (func_decrypt)GetProcAddress(hdll, "decrypt");
		func_encrypt encrypt = (func_encrypt)GetProcAddress(hdll, "encrypt");

		std::string str = "123456789012345";  //¼ÓÃÜµÄ×Ö·û´®
		std::string key = "01234567891234560123456789123456"; // 32 bytes
		std::string iv = "0123456789123456"; // 16 bytes

		int outelength = 0;
		std::string oute = encrypt(outelength, str.c_str(), str.size(), key.c_str(), iv.c_str());
		std::string outd = decrypt(outelength, oute.c_str(), oute.size(), key.c_str(), iv.c_str());

		std::cout << outd.c_str() << std::endl;
	}

	system("pause");
}