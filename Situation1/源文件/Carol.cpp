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
mpz_t p, g, k, kk1,yy1,kk2,yy2;
mpz_t xa;
mpz_t xb;
mpz_t ya;
mpz_t yb;
mpz_t shared_keyAC, shared_keyBC;//相同的私钥
mpz_t ma, mb;
mpz_t yaa, ybb;
mpz_t c1a, c1b;
mpz_t c2a, c2b;
mpz_t Getma, Getmb;
mpz_t g_DH;
mpz_t c1a_1, c1a_2, c1b_1, c1b_2;
mpz_t c2a_1, c2a_2, c2b_1, c2b_2;
mpz_t Getc1a, Getc2a, Getc1b, Getc2b;
mpz_t x1,x2,x3,x4;
mpz_t y_1,y_2,y_3,y_4;
mpz_t k1,k2,k3,k4;
mpz_t c1_pa, c2_pa, c1_ga, c2_ga, c1_pb, c2_pb, c1_gb, c2_gb;
mpz_t c1_xa, c2_xa, c1_ya, c2_ya, c1_ka, c2_ka;
mpz_t c1_xb, c2_xb, c1_yb, c2_yb, c1_kb, c2_kb;
int init()
{
	mpz_init(p);
	mpz_init(g);
	mpz_init(g_DH);
	mpz_init(ma);
	mpz_init(k);
	mpz_init(kk1);
	mpz_init(yy1);
	mpz_init(kk2);
	mpz_init(yy2);
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
	mpz_init(shared_keyAC);
	mpz_init(shared_keyBC);
	mpz_init(x1);
	mpz_init(x2);
	mpz_init(x3);
	mpz_init(x4);
	mpz_init(y_1);
	mpz_init(y_2);
	mpz_init(y_3);
	mpz_init(y_4);
	mpz_init(k1);
	mpz_init(k2);
	mpz_init(k3);
	mpz_init(k4);
	mpz_init(c1_pa);
	mpz_init(c2_pa);
	mpz_init(c1_ga);
	mpz_init(c2_ga);
	mpz_init(c1_pb);
	mpz_init(c2_pb);
	mpz_init(c1_gb);
	mpz_init(c2_gb);
	mpz_init(c1_xa);
	mpz_init(c2_xa);
	mpz_init(c1_ya);
	mpz_init(c2_ya);
	mpz_init(c1_ka);
	mpz_init(c2_ka);
	mpz_init(c1_xb);
	mpz_init(c2_xb);
	mpz_init(c1_yb);
	mpz_init(c2_yb);
	mpz_init(c1_kb);
	mpz_init(c2_kb);
	char tmp1[1024];
	ifstream in1("Elgamal_g.txt", ios::in);
	//判断文件是否正常打开
	if (!in1) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 39 个
	in1.getline(tmp1, 1024);
	in1.close();
	mpz_set_str(g, tmp1, 37);
	char tmp2[1024];
	//以二进制模式打开 in.txt 文件
	ifstream in2("DH_g.txt", ios::in);
	//判断文件是否正常打开
	if (!in2) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 1024 个
	in2.getline(tmp2, 1024);
	in2.close();
	mpz_set_str(g_DH, tmp2, 37);
	char tmp3[1024];
	//以二进制模式打开 in.txt 文件
	ifstream in3("p.txt", ios::in);
	//判断文件是否正常打开
	if (!in3) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 1024 个
	in3.getline(tmp3, 1024);
	in3.close();
	mpz_set_str(p, tmp3, 37);
	char tmp7[10];
	//以二进制模式打开 in.txt 文件
	ifstream in4("ma.txt", ios::in);
	//判断文件是否正常打开
	if (!in4) {
		cout << "error" << endl;
		return 0;
	}
	in4.getline(tmp7, 10);
	in4.close();
	mpz_set_str(ma, tmp7, 37);
	char tmp8[10];
	//以二进制模式打开 in.txt 文件
	ifstream in5("mb.txt", ios::in);
	//判断文件是否正常打开
	if (!in5) {
		cout << "error" << endl;
		return 0;
	}
	in5.getline(tmp8, 10);
	in5.close();
	mpz_set_str(mb, tmp8, 37);
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
int SendMsg2A()
{
	ofstream out1("A_Msg.txt", ios::out);
	if (!out1)
	{
		out1.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	/*char tmp1[1024];
	char tmp2[1024];
	char tmp3[1024];
	char tmp4[1024];*/
	char tmp5[1024];
	char tmp6[1024];
	char tmp7[1024];
	char tmp8[1024];
	char tmp9[1024];
	char tmp10[1024];
	char tmp11[1024];
	/*mpz_get_str(tmp1, 37, c1_pa);
	mpz_get_str(tmp2, 37, c2_pa);
	mpz_get_str(tmp3, 37, c1_ga);
	mpz_get_str(tmp4, 37, c2_ga);*/
	mpz_get_str(tmp5, 37, c1_xa);
	mpz_get_str(tmp6, 37, c2_xa);
	mpz_get_str(tmp7, 37, c1_ya);
	mpz_get_str(tmp8, 37, c2_ya);
	mpz_get_str(tmp9, 37, c1_ka);
	mpz_get_str(tmp10, 37, c2_ka);
	mpz_get_str(tmp11, 37, shared_keyAC);
	int i = 0;
	/*while (i < strlen(tmp1))
	{
		out1 << tmp1[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp2))
	{
		out1 << tmp2[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp3))
	{
		out1 << tmp3[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp4))
	{
		out1 << tmp4[i];
		i++;
	}
	out1 << endl;
	i = 0;*/
	while (i < strlen(tmp5))
	{
		out1 << tmp5[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp6))
	{
		out1 << tmp6[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp7))
	{
		out1 << tmp7[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp8))
	{
		out1 << tmp8[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp9))
	{
		out1 << tmp9[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp10))
	{
		out1 << tmp10[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp11))
	{
		out1 << tmp11[i];
		i++;
	}
	out1.close();

}
int SendMsg2B()
{
	ofstream out1("B_Msg.txt", ios::out);
	if (!out1)
	{
		out1.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	/*char tmp1[1024];
	char tmp2[1024];
	char tmp3[1024];
	char tmp4[1024];*/
	char tmp5[1024];
	char tmp6[1024];
	char tmp7[1024];
	char tmp8[1024];
	char tmp9[1024];
	char tmp10[1024];
	char tmp11[1024];
	/*mpz_get_str(tmp1, 37, c1_pb);
	mpz_get_str(tmp2, 37, c2_pb);
	mpz_get_str(tmp3, 37, c1_gb);
	mpz_get_str(tmp4, 37, c2_gb);*/
	mpz_get_str(tmp5, 37, c1_xb);
	mpz_get_str(tmp6, 37, c2_xb);
	mpz_get_str(tmp7, 37, c1_yb);
	mpz_get_str(tmp8, 37, c2_yb);
	mpz_get_str(tmp9, 37, c1_kb);
	mpz_get_str(tmp10, 37, c2_kb);
	mpz_get_str(tmp11, 37, shared_keyBC);
	int i = 0;
	/*while (i < strlen(tmp1))
	{
		out1 << tmp1[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp2))
	{
		out1 << tmp2[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp3))
	{
		out1 << tmp3[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp4))
	{
		out1 << tmp4[i];
		i++;
	}
	out1 << endl;
	i = 0;*/
	while (i < strlen(tmp5))
	{
		out1 << tmp5[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp6))
	{
		out1 << tmp6[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp7))
	{
		out1 << tmp7[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp8))
	{
		out1 << tmp8[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp9))
	{
		out1 << tmp9[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp10))
	{
		out1 << tmp10[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(tmp11))
	{
		out1 << tmp11[i];
		i++;
	}
	out1.close();

}
int main()
{
	mpz_t one, two, three, four;
	mpz_init_set_ui(one,1);
	mpz_init_set_ui(two,2);
	mpz_init_set_ui(three,3);
	mpz_init_set_ui(four,4);
	init();
	PublicKeyGen(p, g, &x1, &y_1, &k1);
	PublicKeyGen(p, g, &x2, &y_2, &k2);
	PublicKeyGen(p, g, &x3, &y_3, &k3);
	PublicKeyGen(p, g, &x4, &y_4, &k4);
	DH_SharedKeyGen(p, g_DH, &shared_keyAC);
	DH_SharedKeyGen(p, g_DH, &shared_keyBC);
	PublicKeyGen2(p, g, shared_keyAC, &yy1, &kk1);
	PublicKeyGen2(p, g, shared_keyBC, &yy2, &kk2);
	clock_t startTime, endTime;
	startTime = clock();
	if (mpz_cmp(ma, one) == 0)
	{
		/*Elgamal_Encryption(p, yy1, kk1, p, g, &c1_pa, &c2_pa);
		Elgamal_Encryption(g, yy1, kk1, p, g, &c1_ga, &c2_ga);*/
		Elgamal_Encryption(x1, yy1, kk1, p, g, &c1_xa, &c2_xa);
		Elgamal_Encryption(y_1, yy1, kk1, p, g, &c1_ya, &c2_ya);
		Elgamal_Encryption(k1, yy1, kk1, p, g, &c1_ka, &c2_ka);
	}
	else if (mpz_cmp(ma, two) == 0)
	{
		/*Elgamal_Encryption(p, yy1, kk1, p, g, &c1_pa, &c2_pa);
		Elgamal_Encryption(g, yy1, kk1, p, g, &c1_ga, &c2_ga);*/
		Elgamal_Encryption(x2, yy1, kk1, p, g, &c1_xa, &c2_xa);
		Elgamal_Encryption(y_2, yy1, kk1, p, g, &c1_ya, &c2_ya);
		Elgamal_Encryption(k2, yy1, kk1, p, g, &c1_ka, &c2_ka);
	}
	else if (mpz_cmp(ma, three) == 0)
	{
		/*Elgamal_Encryption(p, yy1, kk1, p, g, &c1_pa, &c2_pa);
		Elgamal_Encryption(g, yy1, kk1, p, g, &c1_ga, &c2_ga);*/
		Elgamal_Encryption(x3, yy1, kk1, p, g, &c1_xa, &c2_xa);
		Elgamal_Encryption(y_3, yy1, kk1, p, g, &c1_ya, &c2_ya);
		Elgamal_Encryption(k3, yy1, kk1, p, g, &c1_ka, &c2_ka);
	}
	else
	{
		/*Elgamal_Encryption(p, yy1, kk1, p, g, &c1_pa, &c2_pa);
		Elgamal_Encryption(g, yy1, kk1, p, g, &c1_ga, &c2_ga);*/
		Elgamal_Encryption(x4, yy1, kk1, p, g, &c1_xa, &c2_xa);
		Elgamal_Encryption(y_4, yy1, kk1, p, g, &c1_ya, &c2_ya);
		Elgamal_Encryption(k4, yy1, kk1, p, g, &c1_ka, &c2_ka);
	}
	if (mpz_cmp(mb, one) == 0)
	{
		/*Elgamal_Encryption(p, yy2, kk2, p, g, &c1_pb, &c2_pb);
		Elgamal_Encryption(g, yy2, kk2, p, g, &c1_gb, &c2_gb);*/
		Elgamal_Encryption(x1, yy2, kk2, p, g, &c1_xb, &c2_xb);
		Elgamal_Encryption(y_1, yy2, kk2, p, g, &c1_yb, &c2_yb);
		Elgamal_Encryption(k1, yy2, kk2, p, g, &c1_kb, &c2_kb);
	}
	else if (mpz_cmp(mb, two) == 0)
	{
		/*Elgamal_Encryption(p, yy2, kk2, p, g, &c1_pb, &c2_pb);
		Elgamal_Encryption(g, yy2, kk2, p, g, &c1_gb, &c2_gb);*/
		Elgamal_Encryption(x2, yy2, kk2, p, g, &c1_xb, &c2_xb);
		Elgamal_Encryption(y_2, yy2, kk2, p, g, &c1_yb, &c2_yb);
		Elgamal_Encryption(k2, yy2, kk2, p, g, &c1_kb, &c2_kb);
	}
	else if (mpz_cmp(mb, three) == 0)
	{
		/*Elgamal_Encryption(p, yy2, kk2, p, g, &c1_pb, &c2_pb);
		Elgamal_Encryption(g, yy2, kk2, p, g, &c1_gb, &c2_gb);*/
		Elgamal_Encryption(x3, yy2, kk2, p, g, &c1_xb, &c2_xb);
		Elgamal_Encryption(y_3, yy2, kk2, p, g, &c1_yb, &c2_yb);
		Elgamal_Encryption(k3, yy2, kk2, p, g, &c1_kb, &c2_kb);
	}
	else
	{
		/*Elgamal_Encryption(p, yy2, kk2, p, g, &c1_pb, &c2_pb);
		Elgamal_Encryption(g, yy2, kk2, p, g, &c1_gb, &c2_gb);*/
		Elgamal_Encryption(x4, yy2, kk2, p, g, &c1_xb, &c2_xb);
		Elgamal_Encryption(y_4, yy2, kk2, p, g, &c1_yb, &c2_yb);
		Elgamal_Encryption(k4, yy2, kk2, p, g, &c1_kb, &c2_kb);
	}
	SendMsg2A();
	SendMsg2B();
	endTime = clock();//计时结束
	cout << "该程序运行时间: " << (double)(endTime - startTime) / CLOCKS_PER_SEC << "s" << endl;
	system("pause");
}