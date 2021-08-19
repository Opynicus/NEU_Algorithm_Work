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
int main()
{
	char tmp1[1024];
	mpz_t k,p,g,x,ya,yb,g_DH;
	mpz_init(k);
	mpz_init(p);
	mpz_init(g);
	mpz_init(x);
	mpz_init(ya);
	mpz_init(yb);
	mpz_init(g_DH);
	ifstream in1("p.txt", ios::in);
	//判断文件是否正常打开
	if (!in1) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 39 个
	in1.getline(tmp1, 1024);
	in1.close();
	mpz_set_str(p, tmp1, 37);
	char tmp2[1024];
	//以二进制模式打开 in.txt 文件
	ifstream in2("Elgamal_g.txt", ios::in);
	//判断文件是否正常打开
	if (!in2) {
		cout << "error" << endl;
		return 0;
	}
	//从 in.txt 文件中读取一行字符串，最多不超过 1024 个
	in2.getline(tmp2, 1024);
	in2.close();
	mpz_set_str(g, tmp2, 37);
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
	DH_SharedKeyGen(p, g_DH, &x);
	clock_t time = clock();
	gmp_randstate_t grt;
	gmp_randinit_default(grt); //设置随机数生成算法为默认
	gmp_randseed_ui(grt, time); //设置随机化种子为当前时间
	mpz_t p1;
	mpz_init(p1);
	mpz_sub_ui(p1, p, 1);
	mpz_powm(ya, g, x, p);
	mpz_powm(yb, g, x, p);
	mpz_urandomm(k, grt, p1);
	clock_t startTime, endTime;
	startTime = clock();
	ofstream out1("A_Elgamal.txt", ios::out);
	if (!out1)
	{
		out1.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	char xaa[1024];
	char yaa[1024];
	char ka[1024];
	char ga[1024];
	char pa[1024];
	mpz_get_str(xaa, 37, x);
	mpz_get_str(yaa, 37, ya);
	mpz_get_str(ka, 37, k);
	mpz_get_str(ga, 37, g);
	mpz_get_str(pa, 37, p);
	int i = 0;
	while (i < strlen(xaa))
	{
		out1 << xaa[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(yaa))
	{
		out1 << yaa[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(ka))
	{
		out1 << ka[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(ga))
	{
		out1 << ga[i];
		i++;
	}
	out1 << endl;
	i = 0;
	while (i < strlen(pa))
	{
		out1 << pa[i];
		i++;
	}
	out1.close();
	ofstream out2("B_Elgamal.txt", ios::out);
	if (!out2)
	{
		out2.close(); //程序结束前不能忘记关闭以前打开过的文件
		cout << "error" << endl;
		return 0;
	}
	char xbb[1024];
	char ybb[1024];
	char kb[1024];
	char gb[1024];
	char pb[1024];
	mpz_get_str(xbb, 37, x);
	mpz_get_str(ybb, 37, yb);
	mpz_get_str(kb, 37, k);
	mpz_get_str(gb, 37, g);
	mpz_get_str(pb, 37, p);
	i = 0;
	while (i < strlen(xbb))
	{
		out2 << xbb[i];
		i++;
	}
	out2 << endl;
	i = 0;
	while (i < strlen(ybb))
	{
		out2 << ybb[i];
		i++;
	}
	out2 << endl;
	i = 0;
	while (i < strlen(kb))
	{
		out2 << kb[i];
		i++;
	}
	out2 << endl;
	i = 0;
	while (i < strlen(gb))
	{
		out2 << gb[i];
		i++;
	}
	out2 << endl;
	i = 0;
	while (i < strlen(pb))
	{
		out2 << pb[i];
		i++;
	}
	out2.close();
	endTime = clock();//计时结束
	cout << "该程序运行时间: " << (double)(endTime - startTime) / CLOCKS_PER_SEC << "s" << endl;
	system("pause");
}