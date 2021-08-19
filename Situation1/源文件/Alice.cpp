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
mpz_t c1x,c2x,c1y,c2y,c1k,c2k;
mpz_t c1a, c2a;
mpz_t c1a_1, c1a_2;
mpz_t c2a_1, c2a_2;
mpz_t shared_KeyAC, shared_KeyAB;
mpz_t pa, pb;
mpz_t ga, gb;
mpz_t Getc1a, Getc2a;
mpz_t Getc1b, Getc2b;
mpz_t y, Shared_KeyBack;
mpz_t g_DH, p, k, g,x;
mpz_t c1, c2;
mpz_t ma;
mpz_t y_DH,k_DH;
mpz_t Getc1b_1, Getc1b_2, Getc2b_1, Getc2b_2;
int init1()
{
	mpz_init(c1a);
	mpz_init(c2a);
	mpz_init(c1a_1);
	mpz_init(c1a_2);
	mpz_init(c2a_1);
	mpz_init(c2a_2);
	mpz_init(shared_KeyAC);
	mpz_init(shared_KeyAB);
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
	mpz_init(x);
	mpz_init(g);
	mpz_init(c1);
	mpz_init(c2);
	mpz_init(ma);
	mpz_init(y_DH);
	mpz_init(k_DH);
	char tmp1[1024];
	char tmp2[1024];
	char tmp3[1024];
	char tmp4[1024];
	char tmp5[1024];
	char tmp6[1024];
	char tmp7[1024];
	ifstream in1("A_Msg.txt", ios::in);
	if (!in1) {
		cout << "error" << endl;
		return 0;
	}
	in1.getline(tmp1, 1024);
	in1.getline(tmp2, 1024);
	in1.getline(tmp3, 1024);
	in1.getline(tmp4, 1024);
	in1.getline(tmp5, 1024);
	in1.getline(tmp6, 1024);
	in1.getline(tmp7, 1024);
	in1.close();
	mpz_set_str(c1x, tmp1, 37);
	mpz_set_str(c2x, tmp2, 37);
	mpz_set_str(c1y, tmp3, 37);
	mpz_set_str(c2y, tmp4, 37);
	mpz_set_str(c1k, tmp5, 37);
	mpz_set_str(c2k, tmp6, 37);
	mpz_set_str(shared_KeyAC, tmp7, 37);
	char temp1[1024];
	char temp2[1024];
	char temp3[1024];
	ifstream in2("SharedKeyAB.txt", ios::in);
	if (!in2) {
		cout << "error" << endl;
		return 0;
	}
	in2.getline(temp1, 1024);
	in2.getline(temp2, 1024);
	in2.getline(temp3, 1024);
	in2.close();
	mpz_set_str(shared_KeyAB, temp1, 37);
	mpz_set_str(y_DH, temp2, 37);
	mpz_set_str(k_DH, temp3, 37);
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
	char m[1024];
	ifstream in6("ma.txt", ios::in);
	if (!in6) {
		cout << "error" << endl;
		return 0;
	}
	in6.getline(m, 1024);
	in6.close();
	mpz_set_str(ma, m, 37);
}
int init2()
{
	mpz_init(Getc1b_1);
	mpz_init(Getc1b_2);
	mpz_init(Getc2b_1);
	mpz_init(Getc2b_2);
	char tmp1[1024];
	char tmp2[1024];
	char tmp3[1024];
	char tmp4[1024];
	ifstream in1("B2A.txt", ios::in);
	if (!in1) {
		cout << "error" << endl;
		return 0;
	}
	in1.getline(tmp1, 1024);
	in1.getline(tmp2, 1024);
	in1.getline(tmp3, 1024);
	in1.getline(tmp4, 1024);
	in1.close();
	mpz_set_str(Getc1b_1, tmp1, 37);
	mpz_set_str(Getc1b_2, tmp2, 37);
	mpz_set_str(Getc2b_1, tmp3, 37);
	mpz_set_str(Getc2b_2, tmp4, 37);
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
int ExchangeMsg()
{
	ofstream out("A2B.txt", ios::out);
	if (!out)
	{
		out.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	char c1a1[1024];
	char c1a2[1024];
	char c2a1[1024];
	char c2a2[1024];
	mpz_get_str(c1a1, 37, c1a_1);
	mpz_get_str(c1a2, 37, c1a_2);
	mpz_get_str(c2a1, 37, c2a_1);
	mpz_get_str(c2a2, 37, c2a_2);
	int i = 0;
	while (i < strlen(c1a1))
	{
		out << c1a1[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(c1a2))
	{
		out << c1a2[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(c2a1))
	{
		out << c2a1[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(c2a2))
	{
		out << c2a2[i];
		i++;
	}
	out.close();
}
int main()
{
	init1();
	Elgamal_Decryption(c1x,c2x,shared_KeyAC,p,g,&x);
	Elgamal_Decryption(c1y, c2y, shared_KeyAC, p, g, &y);
	Elgamal_Decryption(c1k, c2k, shared_KeyAC, p, g, &k);
	clock_t startTime, endTime;
	startTime = clock();
	Elgamal_Encryption(ma, y,k, p, g, &c1a, &c2a);
	Elgamal_Encryption(c1a,y_DH,k_DH,p,g,&c1a_1,&c1a_2);
	Elgamal_Encryption(c2a, y_DH, k_DH, p, g, &c2a_1, &c2a_2);
	ExchangeMsg();
	endTime = clock();//计时结束
	cout << "该程序运行时间: " << (double)(endTime - startTime) / CLOCKS_PER_SEC << "s" << endl;
	system("pause");
	clock_t startTime1, endTime1;
	startTime1 = clock();
	init2();
	Elgamal_Decryption(Getc1b_1, Getc1b_2, shared_KeyAB, p, g, &Getc1b);
	Elgamal_Decryption(Getc2b_1, Getc2b_2, shared_KeyAB, p, g, &Getc2b);
	if ((mpz_cmp(c1a, Getc1b) == 0) && (mpz_cmp(c2a, Getc2b) == 0))
		cout << "一致" << endl;
	else
		cout << "不一致" << endl;
	endTime1 = clock();//计时结束
	cout << "该程序运行时间: " << (double)(endTime1 - startTime1) / CLOCKS_PER_SEC << "s" << endl;
	system("pause");
}