#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <iostream>
#include<gmpxx.h>
#include<gmp.h>
#include<time.h>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string>
#include "cryptopp/integer.h"
#include <cryptopp/aes.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/default.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
using namespace std;
using namespace CryptoPP;
mpz_t p, g, k, kk;
mpz_t xa;
mpz_t xb;
mpz_t ya;
mpz_t yb;
mpz_t shared_keyBC;//相同的私钥
mpz_t ma, mb;
mpz_t yaa, ybb;
mpz_t c1a, c1b;
mpz_t c2a, c2b;
mpz_t Getma, Getmb;
mpz_t g_DH;
mpz_t c1a_1, c1a_2, c1b_1, c1b_2;
mpz_t c2a_1, c2a_2, c2b_1, c2b_2;
mpz_t Getc1a, Getc2a, Getc1b, Getc2b;
mpz_t shared_keyBack;
mpz_t GetResult;
mpz_t c1, c2;
int init1()
{
	mpz_init(p);
	mpz_init(g);
	mpz_init(g_DH);
	mpz_init(ma);
	mpz_init(k);
	mpz_init(kk);
	mpz_init(xa);
	mpz_init(xb);
	mpz_init(ya);
	mpz_init(yb);
	mpz_init(yaa);
	mpz_init(ybb);
	mpz_init(c1a);
	mpz_init(c1b);
	mpz_init(c2a);
	mpz_init(c2b);
	mpz_init(c1a_1);
	mpz_init(c1a_2);
	mpz_init(c2a_1);
	mpz_init(c2a_2);
	mpz_init(c1b_1);
	mpz_init(c1b_2);
	mpz_init(c2b_1);
	mpz_init(c2b_2);
	mpz_init(Getc1a);
	mpz_init(Getc1b);
	mpz_init(Getc2a);
	mpz_init(Getc2b);
	mpz_init(shared_keyBC);
	char tmp1[1024];
	char tmp2[1024];
	char tmp3[1024];
	char tmp4[1024];
	char tmp5[1024];
	ifstream in1("B_Elgamal.txt", ios::in);
	//判断文件是否正常打开
	if (!in1) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 39 个
	in1.getline(tmp1, 1024);
	in1.getline(tmp2, 1024);
	in1.getline(tmp3, 1024);
	in1.getline(tmp4, 1024);
	in1.getline(tmp5, 1024);
	in1.close();
	mpz_set_str(xb, tmp1, 37);
	mpz_set_str(yb, tmp2, 37);
	mpz_set_str(k, tmp3, 37);
	mpz_set_str(g, tmp4, 37);
	mpz_set_str(p, tmp5, 37);
	char tmp6[1024];
	//以二进制模式打开 in.txt 文件
	ifstream in3("DH_g.txt", ios::in);
	//判断文件是否正常打开
	if (!in3) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 1024 个
	in3.getline(tmp6, 1024);
	in3.close();
	mpz_set_str(g_DH, tmp6, 37);
	char tmp7[10];
	//以二进制模式打开 in.txt 文件
	ifstream in4("mb.txt", ios::in);
	//判断文件是否正常打开
	if (!in4) {
		cout << "error" << endl;
		return 0;
	}
	in4.getline(tmp7, 10);
	in4.close();
	mpz_set_str(mb, tmp7, 37);
}
int init2()
{
	mpz_init(GetResult);
	mpz_init(shared_keyBack);
	char tmp1[1024];
	char tmp2[1024];
	char tmp3[1024];
	char tmp4[1024];
	char tmp5[1024];
	ifstream in1("C2B.txt", ios::in);
	//判断文件是否正常打开
	if (!in1) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 39 个
	in1.getline(tmp1, 1024);
	in1.getline(tmp2, 1024);
	in1.getline(tmp3, 1024);
	in1.getline(tmp4, 1024);
	in1.getline(tmp5, 1024);
	in1.close();
	mpz_set_str(c1, tmp1, 37);
	mpz_set_str(c2, tmp2, 37);
	mpz_set_str(shared_keyBack, tmp3, 37);
	mpz_set_str(p, tmp4, 37);
	mpz_set_str(g, tmp5, 37);
	char tmp6[1024];
	//以二进制模式打开 in.txt 文件
	ifstream in3("DH_g.txt", ios::in);
	//判断文件是否正常打开
	if (!in3) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 1024 个
	in3.getline(tmp6, 1024);
	in3.close();
	mpz_set_str(g_DH, tmp6, 37);
}
void DH_SharedKeyGen(mpz_t p_, mpz_t g_, mpz_t* shared_key)
{
	clock_t time = clock();
	gmp_randstate_t grt;
	gmp_randinit_default(grt); //设置随机数生成算法为默认
	gmp_randseed_ui(grt, time); //设置随机化种子为当前时间
	mpz_t xa, xb, ya, yb, k;
	mpz_t p1;
	mpz_init(ya);
	mpz_init(yb);
	mpz_init(p1);
	mpz_init(k);
	mpz_init(xa);
	mpz_init(xb);
	mpz_sub_ui(p1, p_, 1);
	mpz_urandomm(xa, grt, p1);
	mpz_urandomm(xb, grt, p1);
	mpz_powm(ya, g_, xa, p_);
	mpz_powm(yb, g_, xb, p_);
	mpz_powm(*shared_key, yb, xa, p_);
	mpz_clear(p1);
	mpz_clear(ya);
	mpz_clear(yb);
	mpz_clear(xa);
	mpz_clear(xb);
	mpz_clear(k);
}
//公钥私钥生成
void PublicKeyGen(mpz_t p, mpz_t g, mpz_t* x, mpz_t* y, mpz_t* k)
{
	clock_t time = clock();
	gmp_randstate_t grt;
	gmp_randinit_default(grt); //设置随机数生成算法为默认
	gmp_randseed_ui(grt, time); //设置随机化种子为当前时间
	mpz_t p1;
	mpz_init(p1);
	mpz_sub_ui(p1, p, 1);
	mpz_urandomm(*x, grt, p1);
	mpz_powm(*y, g, *x, p);
	mpz_urandomm(*k, grt, p1);
}
//加密算法
void Elgamal_Encryption(mpz_t m_, mpz_t y_, mpz_t k_, mpz_t p_, mpz_t g_, mpz_t* c1, mpz_t* c2)
{
	mpz_t tmp1, tmp2;
	mpz_init(tmp1);
	mpz_init(tmp2);
	mpz_powm(*c1, g_, k_, p_);
	mpz_powm(tmp1, y_, k_, p);
	mpz_mul(tmp2, m_, tmp1);
	mpz_mod(*c2, tmp2, p);
	mpz_clear(tmp1);
	mpz_clear(tmp2);
	//*c1 = pow_mod(g, k, p);
	//*c2 = m * pow_mod(pub, k, p) % p;
}
//解密算法
void Elgamal_Decryption(mpz_t c1, mpz_t c2, mpz_t x, mpz_t p, mpz_t g, mpz_t* GetM)
{
	mpz_t tmp1, tmp2, tmp3, p1;
	mpz_init(*GetM);
	mpz_init(tmp1);
	mpz_init(tmp2);
	mpz_init(tmp3);
	mpz_init(p1);
	mpz_powm(tmp1, c1, x, p);
	mpz_invert(tmp2, tmp1, p);
	mpz_mul(tmp3, c2, tmp2);
	mpz_mod(*GetM, tmp3, p);
	mpz_clear(tmp1);
	mpz_clear(tmp2);
	mpz_clear(tmp3);
	mpz_clear(p1);
	/*mpz_sub_ui(p1, p, 2);
	mpz_powm(tmp1, c1, p1, p);
	mpz_powm(tmp2, tmp1, x, p);
	mpz_mul(tmp3, c2, tmp2);
	mpz_mod(GetM, tmp3, p);*/
	//int m;
	//int c1_ = pow_mod(c1, p - 2, p);
	//m = c2 * pow_mod(c1_, x, p) % p;
	//return m;
}
int SendMsg2Third()
{
	ofstream out("B_Msg.txt", ios::out);
	if (!out)
	{
		out.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	char c1b1[1024];
	char c1b2[1024];
	char c2b1[1024];
	char c2b2[1024];
	char sharedkey[1024];
	char pp[1024];
	char gg[1024];
	mpz_get_str(c1b1, 37, c1b_1);
	mpz_get_str(c1b2, 37, c1b_2);
	mpz_get_str(c2b1, 37, c2b_1);
	mpz_get_str(c2b2, 37, c2b_2);
	mpz_get_str(sharedkey, 37, shared_keyBC);
	mpz_get_str(pp, 37, p);
	mpz_get_str(gg, 37, g);
	int i = 0;
	while (i < strlen(c1b1))
	{
		out << c1b1[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(c1b2))
	{
		out << c1b2[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(c2b1))
	{
		out << c2b1[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(c2b2))
	{
		out << c2b2[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(sharedkey))
	{
		out << sharedkey[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(pp))
	{
		out << pp[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(gg))
	{
		out << gg[i];
		i++;
	}
	out.close();
}
int main()
{
	init1();
	DH_SharedKeyGen(p, g_DH, &shared_keyBC);
	PublicKeyGen(p, g, &shared_keyBC, &ybb, &kk);
	clock_t startTime, endTime;
	startTime = clock();
	Elgamal_Encryption(mb, yb, k, p, g, &c1b, &c2b);
	/*Elgamal_Decryption(c1a, c2a, xa, p, g, &Getc1a);
	gmp_printf("%Zd\n", ma);
	gmp_printf("%Zd",Getc1a);*/
	
	Elgamal_Encryption(c1b, ybb, kk, p, g, &c1b_1, &c1b_2);
	Elgamal_Encryption(c2b, ybb, kk, p, g, &c2b_1, &c2b_2);
	/*Elgamal_Decryption(c1a_1, c1a_2, shared_keyBC, p, g, &Getc1a);
	Elgamal_Decryption(c2a_1, c2a_2, shared_keyBC, p, g, &Getc2a);
	gmp_printf("%Zd\n", c1a);
	gmp_printf("%Zd\n", Getc1a);
	gmp_printf("%Zd\n", c2a);
	gmp_printf("%Zd\n", Getc2a);*/
	//gmp_printf("%Zd\n\n", c2b_1);
	//gmp_printf("%Zd\n\n", c2b_2);
	//gmp_printf("%Zd\n\n", shared_keyBC);
	//gmp_printf("%Zd\n\n", p);
	//gmp_printf("%Zd\n", g);
	SendMsg2Third();
	endTime = clock();//计时结束
	cout << "该程序运行时间: " << (double)(endTime - startTime) / CLOCKS_PER_SEC << "s" << endl;
	system("pause");
	mpz_t zero, one;
	mpz_init_set_ui(zero, 0);
	mpz_init_set_ui(one, 1);
	init2();
	clock_t startTime1, endTime1;
	startTime1 = clock();
	Elgamal_Decryption(c1, c2, shared_keyBack, p, g, &GetResult);
	if (mpz_cmp(GetResult, zero) == 0)
		cout << "不一致" << endl;
	else
		cout << "一致" << endl;
	endTime1 = clock();//计时结束
	cout << "该程序运行时间: " << (double)(endTime1 - startTime1) / CLOCKS_PER_SEC << "s" << endl;
	system("pause");
}