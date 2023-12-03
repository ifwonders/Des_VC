#include <stdio.h>
#include <windows.h>
#include <math.h>
#include <stdlib.h>
#include <iostream>
using namespace std;

//计算16个子密钥
int DES_Trans[56] = { 57,49,41,33,25,17,9 ,1 ,58,50,42,34,26,18,
                     10,2 ,59,51,43,35,27,19,11,3 ,60,52,44,36,
                     63,55,47,39,31,23,15,7 ,62,54,46,38,30,22,
                     14,6 ,61,53,45,37,29,21,13,5 ,28,20,12,4 };

int* DesTransform(int (*init_key)[8])
{
    static int key56[56] = { 0 };
    for (int i = 0; i < 56; ++i) {
        key56[i] = init_key[(DES_Trans[i]-1)/8][(DES_Trans[i] - 1) % 8];
    }

    return key56;
}



int DES_Rotation[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
int Despermuted[48] = { 14,17,11,24,1 ,5 ,3 ,28,15,6 ,21,10,
                       23,19,12,4 ,26,8 ,16,7 ,27,20,13,2 ,
                       41,52,31,37,47,55,30,40,51,45,33,48,
                       44,49,39,56,34,53,46,42,50,36,29,32 };
void Rotate(int rotate, int* subkey)
{
    int rotated_subkey[28] = { 0 };
    for (int i = 0; i < 28; ++i) {
        rotated_subkey[i] = subkey[(i + rotate) % 28];
    }
    for (int i = 0; i < 28; ++i)
        subkey[i] = rotated_subkey[i];
}
void Subkey(int sk_count,const int* key56, int* key48) {
    //56位初始密钥分为2组28位子密钥
    int lsk[28] = { 0 };
    int rsk[28] = { 0 };

    int* LeftSubkey=lsk;
    for (int i = 0; i < 28; ++i)
        LeftSubkey[i] = key56[i];

    int* RightSubkey=rsk;
    for (int i = 28; i < 56; ++i)
        RightSubkey[i - 28] = key56[i];

    //子密钥旋转
    Rotate(DES_Rotation[sk_count], LeftSubkey);
    Rotate(DES_Rotation[sk_count], RightSubkey);

    //旋转后子密钥重新合并放回key0
    int _key56[56] = { 0 };
    for (int i = 0; i < 28; ++i)
        _key56[i] = LeftSubkey[i];
    for (int i = 28; i < 56; ++i)
        _key56[i] = RightSubkey[i - 28];

    //对56位密钥置换选择得到48位密钥
    int _key48[48] = { 0 };
    for (int i = 0; i < 48; ++i) {
        _key48[i] = _key56[Despermuted[i] - 1];
    }

    for (int i = 0; i < 48; ++i) 
        key48[i] = _key48[i];
    
}

//加密和解密模块
int DesInitial[64] = { 58,50,42,34,26,18,10, 2,60,52,44,36,28,20,12, 4,
                      62,54,46,38,30,22,14, 6,64,56,48,40,32,24,16, 8,
                      57,49,41,33,25,17, 9, 1,59,51,43,35,27,19,11, 3,
                      61,53,45,37,29,21,13, 5,63,55,47,39,31,23,15, 7 };
int DesExpansion[48] = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
                         8, 9,10,11,12,13,12,13,14,15,16,17,
                        16,17,18,19,20,21,20,21,22,23,24,25,
                        24,25,26,27,28,29,28,29,30,31,32, 1 };
int SBox1[4][16] =
{ {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,},
{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,},
{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,},
{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} };
int SBox2[4][16] =
{{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,},
{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,},
{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,},
{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} };
int SBox3[4][16] =
{ {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,},
{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,},
{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,},
{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }};
int SBox4[4][16] =
{ {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,},
{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,},
{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,},
{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};
int SBox5[4][16] =
{ {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,},
{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,},
{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,},
{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} };
int SBox6[4][16] =
{ {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,},
{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,},
{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,},
{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }};
int SBox7[4][16] =
{ {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,},
{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,},
{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,},
{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} };
int SBox8[4][16] =
{ {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,},
{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,},
{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,},
{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} };
int PBox[32] =
{ 16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25 };
int DesFinal[] =
{ 40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25 };

typedef int(*_SBoxOutput)[4];
void S_box(int (*Rint)[6],_SBoxOutput pSBO) {
    //将48bit转化成8个S盒对应的数组
    typedef int (*Sboxes)[16];
    Sboxes SBoxes[8] = {SBox1,SBox2,SBox3,SBox4,SBox5,SBox6,SBox7,SBox8};
   int SBoxOutput[8][4] = { 0 };
    //_SBoxOutput SBoxOutput = (_SBoxOutput)malloc(32);
    //_SBoxOutput SBoxOutput = new int[8][4];

    for (int i = 0; i < 8; ++i) {
        int row = Rint[i][0] * 2 + Rint[i][5];
        int col = Rint[i][1] * 8 + Rint[i][2] * 4 + Rint[i][3] * 2 + Rint[i][4];

        Sboxes SBox = SBoxes[i];
        int SOut_D = SBox[row][col];
        for (int j = 3; j >= 0; --j) {
            SBoxOutput[i][j] = SOut_D % 2;
            SOut_D /= 2;
        }
    }

    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j)
            pSBO[i][j] = SBoxOutput[i][j];
}
typedef int(*DESOutput)[8];
void DEScode(int (*bit_text)[8],const int* key56,int choice, DESOutput pRT) {
    int LeftText0[32] = { 0 };
    int RightText0[32] = { 0 };

    //初始置换
    for (int i = 0; i < 32; ++i)
        LeftText0[i] = bit_text[(DesInitial[i] - 1)/8][(DesInitial[i] - 1) % 8];
    for (int i = 0; i < 32; ++i)
        RightText0[i] = bit_text[(DesInitial[i+32] - 1) / 8][(DesInitial[i+32] - 1) % 8];

    int cnt = 0;
    if (choice == 1)
        cnt = 0;
    else if (choice==0)
        cnt = 15;

    while(cnt>=0 && cnt<=15){
        //循环16次
            //以下表示f函数
            //对R扩展置换
        int ExpandedRightText[48] = { 0 };
        for (int i = 0; i < 48; ++i)
            ExpandedRightText[i] = RightText0[DesExpansion[i] - 1];

        //计算48位结果值与这一轮 子密钥 的异或值
        //先计算子密钥
        //if (cnt == 15)
        //    system("pause");

        int key48[48] = { 0 };
        Subkey(cnt, key56,key48);
        //计算异或
        int Rint[8][6] = { 0 };
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 6; ++j) {
                Rint[i][j] = ExpandedRightText[i * 6 + j] ^ key48[i * 6 + j];
            }
        //此时Rint中应该只有0 1

        //S盒置换
        int SBoxOutput[8][4] = { 0 };
        _SBoxOutput pSBoxOutput = SBoxOutput;
        S_box(Rint,pSBoxOutput);

        //P盒置换
        int PBoxOutput[32] = { 0 };
        for (int i = 0; i < 32; ++i)
            PBoxOutput[i] = SBoxOutput[(PBox[i] - 1)/4][(PBox[i] - 1) % 4];

        int RightText1[32] = { 0 };
        int LeftText1[32] = { 0 };

        //交换L0 R0  得到L1 R1
        for (int i = 0; i < 32; ++i) {
            RightText1[i] = LeftText0[i] ^ PBoxOutput[i];
            LeftText1[i] = RightText0[i];
        }

        //将L1R1 放回L0R0中
        for (int i = 0; i < 32; ++i) {
            RightText0[i] = RightText1[i];
            LeftText0[i] = LeftText1[i];
        }
        //循环16次
        if (choice == 1)cnt++;
        else if (choice == 0)cnt--;
    }

    //将L0R0放回64位text
    int tmpText[64] = { 0 };
    for (int i = 0; i < 32; ++i) {
        tmpText[i] = RightText0[i];
        tmpText[i + 32] = LeftText0[i];
    }
    int RawText[8][8] = {0};
    //DESOutput RawText = (DESOutput)malloc(64);
    //DESOutput RawText = new int[8][8];
    //最终置换
    for (int i = 0; i < 64; i++)
        RawText[i/8][i%8] = tmpText[DesFinal[i] - 1];

    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j)
            pRT[i][j] = RawText[i][j];
    //return RawText;
    ////将64bit值变回8byte值
    //static char DesText[8];
    //for (int i = 0; i < 8; ++i) {
    //    DesText[i] = RawText[i * 8] * 128 + RawText[i * 8 + 1] * 64 + RawText[i * 8 + 2] * 32
    //        + RawText[i * 8 + 3] * 16 + RawText[i * 8 + 4] * 8 + RawText[i * 8 + 5] * 4
    //        + RawText[i * 8 + 6] * 2 + RawText[i * 8 + 7];
    //}

    //return DesText;
}
typedef int(*Byte8)[8];
void DtoB(char* D,Byte8 BitText) {
    //将8byte值转化成64bit值 二维数组
    int B[8][8] = { 0 };
    //Byte8 B = (Byte8)malloc(64);
    //Byte8 B = new int[8][8];
    for (int i = 0; i < 8; ++i) {
        char ch = D[i];
        for (int j = 7; j >= 0; --j) {
            B[i][j] = ch % 2;
            ch /= 2;
        }
    }

    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j)
            BitText[i][j] = B[i][j];
}
void BtoD(Byte8 B,char* pD) {
    char D[8] = { 0 };
    //char* D = (char*)malloc(8);
    //char* D = new char[8];
    for (int i = 0; i < 8; ++i) {
        int ch = 0;
        for (int j = 0; j < 8; ++j) {
            ch += B[i][j] * pow(2, 7 - j);
        }
        D[i] = ch;
    }
    for (int i = 0; i < 8; ++i)
        pD[i] = D[i];
}
void Show(DESOutput text) {
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            printf("%d ", text[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}
int main() {
    char key[8] = { 0 };
    char text[8] = { 0 };
    char text2[8] = { 0 };

    printf("请输入密钥:\n");
    char ch = 0;
    for (int i = 0; i < 8; ++i) {
        ch = getchar();
        if (ch == '\n')
            break;
        key[i] = ch;
    }

    getchar();
    printf("请输入明文:\n");
    char ming = 0;
    for (int i = 0; i < 16; ++i) {
        ming = getchar();
        if (ming == '\n')
            break;
        if (i < 8)
            text[i] = ming;
        else
            text2[i - 8] = ming;
    }

    printf("明文是\n");
    for (int i = 0; i < 8; ++i)printf("%c", text[i]);
    for (int i = 0; i < 8; ++i)printf("%c", text2[i]);
    printf("\n"); printf("\n");
    
    int KEY[8][8] = { 0 };
    int(*key64)[8] = KEY;
    DtoB(key,key64);

    int bitText[8][8] = { 0 };
    int(*bit_text)[8] = bitText;
    DtoB(text,bit_text);

    int bitText2[8][8] = { 0 };
    int(*bit_text2)[8] = bitText2;
    DtoB(text2, bit_text2);
    //Show(bit_text);

    const int* key56 = DesTransform(key64);

    //加密
    int bit_ciphertext[8][8] = { 0 };
    DESOutput p_bit_ciphertext = bit_ciphertext;
    DEScode(bit_text, key56, 1,p_bit_ciphertext);

    int bit_ciphertext2[8][8] = { 0 };
    DESOutput p_bit_ciphertext2 = bit_ciphertext2;
    DEScode(bit_text2, key56, 1, p_bit_ciphertext2);
    //Show(bit_ciphertext);
    //bit转换
    char ciphertext[8] = { 0 };
    char* p_ciphertext = ciphertext;
    BtoD(bit_ciphertext,p_ciphertext);
    char ciphertext2[8] = { 0 };
    char* p_ciphertext2 = ciphertext2;
    BtoD(bit_ciphertext2, p_ciphertext2);

    printf("密文是:\n");
    for (int i = 0; i < 8; ++i)printf("%c", ciphertext[i]);
    for (int i = 0; i < 8; ++i)printf("%c", ciphertext2[i]);
    printf("\n"); printf("\n");

    //解密
    int bit_cleartext[8][8] = { 0 };
    DESOutput p_bit_cleartext = bit_cleartext;
    DEScode(bit_ciphertext, key56, 0,p_bit_cleartext);

    int bit_cleartext2[8][8] = { 0 };
    DESOutput p_bit_cleartext2 = bit_cleartext2;
    DEScode(bit_ciphertext2, key56, 0, p_bit_cleartext2);
    //Show(bit_cleartext);
    //bit转换
    char cleartext[8] = { 0 };
    char* p_cleartext = cleartext;
    BtoD(bit_cleartext,p_cleartext);

    char cleartext2[8] = { 0 };
    char* p_cleartext2 = cleartext2;
    BtoD(bit_cleartext2, p_cleartext2);
    printf("密文解密得到明文是:\n");
    for (int i = 0; i < 8; ++i)printf("%c", cleartext[i]);
    for (int i = 0; i < 8; ++i)printf("%c", cleartext2[i]);
    printf("\n"); printf("\n");

    return 0;
}