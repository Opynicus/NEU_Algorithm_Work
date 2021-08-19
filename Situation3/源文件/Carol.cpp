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
mpz_t g_DH, p,k,g;
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
	mpz_set_str(c1a_1, tmp1, 37);
	mpz_set_str(c1a_2, tmp2, 37);
	mpz_set_str(c2a_1, tmp3, 37);
	mpz_set_str(c2a_2, tmp4, 37);
	mpz_set_str(shared_KeyAC, tmp5, 37);
	mpz_set_str(pa, tmp6, 37);
	mpz_set_str(ga, tmp7, 37);
	char temp1[1024];
	char temp2[1024];
	char temp3[1024];
	char temp4[1024];
	char temp5[1024];
	char temp6[1024];
	char temp7[1024];
	ifstream in2("B_Msg.txt", ios::in);
	if (!in2) {
		cout << "error" << endl;
		return 0;
	}
	in2.getline(temp1, 1024);
	in2.getline(temp2, 1024);
	in2.getline(temp3, 1024);
	in2.getline(temp4, 1024);
	in2.getline(temp5, 1024);
	in2.getline(temp6, 1024);
	in2.getline(temp7, 1024);
	in2.close();
	mpz_set_str(c1b_1, temp1, 37);
	mpz_set_str(c1b_2, temp2, 37);
	mpz_set_str(c2b_1, temp3, 37);
	mpz_set_str(c2b_2, temp4, 37);
	mpz_set_str(shared_KeyBC, temp5, 37);
	mpz_set_str(pb, temp6, 37);
	mpz_set_str(gb, temp7, 37);
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
int compare()
{
	Elgamal_Decryption(c1a_1, c1a_2, shared_KeyAC, pa, ga, &Getc1a);
	Elgamal_Decryption(c2a_1, c2a_2, shared_KeyAC, pa, ga, &Getc2a);
	Elgamal_Decryption(c1b_1, c1b_2, shared_KeyBC, pb, gb, &Getc1b);
	Elgamal_Decryption(c2b_1, c2b_2, shared_KeyBC, pb, gb, &Getc2b);
	//gmp_printf("%Zd\n\n", Getc1a);
	//gmp_printf("%Zd\n\n", Getc2a);
	//gmp_printf("%Zd\n\n", Getc1b);
	//gmp_printf("%Zd\n\n", Getc2b);
	if ((mpz_cmp(Getc1a, Getc1b) == 0) && (mpz_cmp(Getc2a, Getc2b) == 0))
		return 1;
	else
		return 0;
}
int SendMsgBack2A()
{
	ofstream out("C2A.txt", ios::out);
	if (!out)
	{
		out.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	char c_1[1024];
	char c_2[1024];
	char xx[1024];
	char pp[1024];
	char gg[1024];
	mpz_get_str(c_1, 37, c1);
	mpz_get_str(c_2, 37, c2);
	mpz_get_str(xx, 37, Shared_KeyBack);
	mpz_get_str(pp, 37, p);
	mpz_get_str(gg, 37, g);
	int i = 0;
	while (i < strlen(c_1))
	{
		out << c_1[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(c_2))
	{
		out << c_2[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(xx))
	{
		out << xx[i];
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
int SendMsgBack2B()
{
	ofstream out("C2B.txt", ios::out);
	if (!out)
	{
		out.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	char c_1[1024];
	char c_2[1024];
	char xx[1024];
	char pp[1024];
	char gg[1024];
	mpz_get_str(c_1, 37, c1);
	mpz_get_str(c_2, 37, c2);
	mpz_get_str(xx, 37, Shared_KeyBack);
	mpz_get_str(pp, 37, p);
	mpz_get_str(gg, 37, g);
	int i = 0;
	while (i < strlen(c_1))
	{
		out << c_1[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(c_2))
	{
		out << c_2[i];
		i++;
	}
	out << endl;
	i = 0;
	while (i < strlen(xx))
	{
		out << xx[i];
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
void Elgamal_Encryption(mpz_t m_, mpz_t y_, mpz_t k_, mpz_t p_, mpz_t g_, mpz_t* c1, mpz_t* c2)
{
	mpz_t tmp1, tmp2;
	mpz_init(tmp1);
	mpz_init(tmp2);
	mpz_powm(*c1, g_, k_, p_);
	mpz_powm(tmp1, y_, k_, p_);
	mpz_mul(tmp2, m_, tmp1);
	mpz_mod(*c2, tmp2, p_);
	mpz_clear(tmp1);
	mpz_clear(tmp2);
	//*c1 = pow_mod(g, k, p);
	//*c2 = m * pow_mod(pub, k, p) % p;
}
int main()
{
	
	int i;
	mpz_t result;
	init();
	DH_SharedKeyGen(pa, g_DH, &Shared_KeyBack);
	PublicKeyGen(pa, g, &Shared_KeyBack, &y, &k);
	clock_t startTime, endTime;
	startTime = clock();
	i=compare();
	if (i == 1)
	{
		mpz_init_set_ui(result,1);
		Elgamal_Encryption(result, y, k, pa, g, &c1, &c2);
		SendMsgBack2A();
		SendMsgBack2B();
	}
	else
	{
		mpz_init_set_ui(result, 0);
		Elgamal_Encryption(result, y, k, pa, g, &c1, &c2);
		SendMsgBack2A();
		SendMsgBack2B();
	}
	endTime = clock();//计时结束
	  cout << "该程序运行时间: " << (double)(endTime - startTime) / CLOCKS_PER_SEC << "s" << endl;
	  system("pause");
}