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
mpz_t c1a_1, c1a_2;
mpz_t c2a_1, c2a_2;
mpz_t c1b_1, c1b_2;
mpz_t c2b_1, c2b_2;
mpz_t shared_KeyAC, shared_KeyBC;
mpz_t pa, pb;
mpz_t ga, gb;
mpz_t Getc1a, Getc2a;
mpz_t Getc1b, Getc2b;
mpz_t y, Shared_KeyBack;
mpz_t g_DH, p, k, g;
mpz_t c1, c2;
int init()
{
	mpz_init(c1a_1);
	mpz_init(c1a_2);
	mpz_init(c2a_1);
	mpz_init(c2a_2);
	mpz_init(c1b_1);
	mpz_init(c1b_2);
	mpz_init(c2b_1);
	mpz_init(c2b_2);
	mpz_init(shared_KeyAC);
	mpz_init(shared_KeyBC);
	mpz_init(pa);
	mpz_init(pb);
	mpz_init(ga);
	mpz_init(gb);
	mpz_init(Getc1a);
	mpz_init(Getc2a);
	mpz_init(Getc1b);
	mpz_init(Getc2b);
	mpz_init(y);
	mpz_init(Shared_KeyBack);
	mpz_init(g_DH);
	mpz_init(p);
	mpz_init(k);
	mpz_init(g);
	mpz_init(c1);
	mpz_init(c2);
	char tmp[1024];
	ifstream in3("Elgamal_g.txt", ios::in);
	if (!in3) {
		cout << "error" << endl;
		return 0;
	}
	in3.getline(tmp, 1024);
	in3.close();
	mpz_set_str(g, tmp, 37);
	char temp[1024];
	ifstream in4("DH_g.txt", ios::in);
	if (!in4) {
		cout << "error" << endl;
		return 0;
	}
	in4.getline(temp, 1024);
	in4.close();
	mpz_set_str(g_DH, temp, 37);
	char pp[1024];
	ifstream in5("p.txt", ios::in);
	if (!in5) {
		cout << "error" << endl;
		return 0;
	}
	in5.getline(pp, 1024);
	in5.close();
	mpz_set_str(p, pp, 37);
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
void PublicKeyGen2(mpz_t p, mpz_t g, mpz_t x, mpz_t* y, mpz_t* k)
{
	clock_t time = clock();
	gmp_randstate_t grt;
	gmp_randinit_default(grt); //设置随机数生成算法为默认
	gmp_randseed_ui(grt, time); //设置随机化种子为当前时间
	mpz_t p1;
	mpz_init(p1);
	mpz_sub_ui(p1, p, 1);
	mpz_powm(*y, g, x, p);
	mpz_urandomm(*k, grt, p1);
}
int main()
{
	init();
	DH_SharedKeyGen(p, g_DH, &shared_KeyAC);
	PublicKeyGen2(p, g, shared_KeyAC, &y, &k);
	ofstream out("DHSharedKeyAC.txt", ios::out);
	if (!out)
	{
		out.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	char tmp1[1024];
	char tmp2[1024];
	char tmp3[1024];
	mpz_get_str(tmp1, 37, shared_KeyAC);
	mpz_get_str(tmp2, 37, y);
	mpz_get_str(tmp3, 37, k);
	int i = 0;
	while (i < strlen(tmp1))
	{
		out << tmp1[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(tmp2))
	{
		out << tmp2[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(tmp3))
	{
		out << tmp3[i];
		i++;
	}
	out.close();
}