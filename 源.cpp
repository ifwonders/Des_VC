#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<iostream>
#include<string>
using namespace std;
typedef unsigned longULONG;


void rc4_init(unsigned char* s, unsigned char* key, unsigned long Len)
{
	int i = 0, j = 0;
	char k[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++)
	{
		s[i] = i;
		k[i] = key[i % Len];
	}
	for (i = 0; i < 256; i++)
	{
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
}


void rc4_crypt(unsigned char* s, unsigned char* Data, unsigned long Len)
{
	unsigned long i = 0, j = 0, t = 0;
	int a;
	unsigned long k = 0;
	unsigned char tmp;
	unsigned char r[256] = { 0 };
	for (k = 0; k < Len; k++)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		r[k] = s[(s[i] + s[j]) % 256];
	}
	for (a = 0; a < Len; a++) {
		Data[a] = (Data[a] ^ r[a]);
	}

}

int main()
{
	unsigned char s[256] = { 0 }, s2[256] = { 0 };
	char key[256] = { 0 };
	char text[512] = { 0 };
	unsigned long len = strlen(text);
	int i;
	cout << "请输入原文：" << endl;
	cin.getline(text, 512);
	cout << "请输入密钥：" << endl;
	cin.getline(key, 256);
	rc4_init(s, (unsigned char*)key, strlen(key));
	for (i = 0; i < 256; i++)
	{
		s2[i] = s[i];
	}
	cout << "加密后密文为:";
	rc4_crypt(s, (unsigned char*)text, len); // 加密
	cout << text << endl;
	cout << "解密结果为:";
	rc4_crypt(s2, (unsigned char*)text, len); // 解密
	cout << text;
	return 0;
}