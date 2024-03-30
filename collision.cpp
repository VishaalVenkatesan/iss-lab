/*
Reference
Ronald Rivest: The MD5 Message Digest Algorithm, RFC1321, April 1992,ftp://ftp.rfc-editor.org/in-notes/rfc1321.txt
*/
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstdio>
#include <string.h>
#include <string>
using namespace std;

/* Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

typedef unsigned char Byte;
typedef unsigned int Word;
typedef unsigned long long Length;

Byte PADDING[64] = { //  64*8 = 512bit , �ִ� padding ����
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
*/
void FF(Word &a, Word b, Word c, Word d, Word x, Word s, Word ac)
{
    (a) += F((b), (c), (d)) + (x) + (Word)(ac);
    (a) = ROTATE_LEFT((a), (s));
    (a) += (b);
}
void GG(Word &a, Word b, Word c, Word d, Word x, Word s, Word ac)
{
    (a) += G((b), (c), (d)) + (x) + (Word)(ac);
    (a) = ROTATE_LEFT((a), (s));
    (a) += (b);
}
void HH(Word &a, Word b, Word c, Word d, Word x, Word s, Word ac)
{
    (a) += H((b), (c), (d)) + (x) + (Word)(ac);
    (a) = ROTATE_LEFT((a), (s));
    (a) += (b);
}
void II(Word &a, Word b, Word c, Word d, Word x, Word s, Word ac)
{
    (a) += I((b), (c), (d)) + (x) + (Word)(ac);
    (a) = ROTATE_LEFT((a), (s));
    (a) += (b);
}

class MD5
{
public:
    Byte *input;
    Byte output[16];
    Length inputLen = 0; // input block ����

    Word state[4];

    MD5(const char *input)
    {
        this->input = (Byte *)input;
        memset(output, 0, 16);
        this->inputLen = strlen(input);
        this->state[0] = 0x67452301;
        this->state[1] = 0xefcdab89;
        this->state[2] = 0x98badcfe;
        this->state[3] = 0x10325476;
    }

    void Encode(Byte *output, Word *input, unsigned int len)
    { // little endian���� ����
        for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
        {
            output[j] = (Byte)(input[i] && 0xff);
            output[j + 1] = (Byte)((input[i] >> 8) & 0xff);
            output[j + 2] = (Byte)((input[i] >> 16) & 0xff);
            output[j + 3] = (Byte)((input[i] >> 24) & 0xff);
        }
    }
    void Decode(Word *output, Byte *input, unsigned int len)
    { // little endian�� byte �迭 input�� word�� �ٲ۴�.
        unsigned int i, j;
        for (i = 0, j = 0; j < len; i++, j += 4)
            output[i] = ((Word)input[j]) | (((Word)input[j + 1]) << 8) | // input�� little-endian �������� �ν��Ѵ�.
                        (((Word)input[j + 2]) << 16) | (((Word)input[j + 3]) << 24);
    }

    void MD5Transform(Byte *block)
    { // MD5 Compress Function
        Word a = state[0], b = state[1], c = state[2], d = state[3], x[16];
        Decode(x, block, 64);
        /* Round 1 */
        FF(a, b, c, d, x[0], S11, 0xd76aa478);  /* 1 */
        FF(d, a, b, c, x[1], S12, 0xe8c7b756);  /* 2 */
        FF(c, d, a, b, x[2], S13, 0x242070db);  /* 3 */
        FF(b, c, d, a, x[3], S14, 0xc1bdceee);  /* 4 */
        FF(a, b, c, d, x[4], S11, 0xf57c0faf);  /* 5 */
        FF(d, a, b, c, x[5], S12, 0x4787c62a);  /* 6 */
        FF(c, d, a, b, x[6], S13, 0xa8304613);  /* 7 */
        FF(b, c, d, a, x[7], S14, 0xfd469501);  /* 8 */
        FF(a, b, c, d, x[8], S11, 0x698098d8);  /* 9 */
        FF(d, a, b, c, x[9], S12, 0x8b44f7af);  /* 10 */
        FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
        FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
        FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
        FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
        FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
        FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
        /* Round 2 */
        GG(a, b, c, d, x[1], S21, 0xf61e2562);  /* 17 */
        GG(d, a, b, c, x[6], S22, 0xc040b340);  /* 18 */
        GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
        GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);  /* 20 */
        GG(a, b, c, d, x[5], S21, 0xd62f105d);  /* 21 */
        GG(d, a, b, c, x[10], S22, 0x2441453);  /* 22 */
        GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
        GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);  /* 24 */
        GG(a, b, c, d, x[9], S21, 0x21e1cde6);  /* 25 */
        GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
        GG(c, d, a, b, x[3], S23, 0xf4d50d87);  /* 27 */
        GG(b, c, d, a, x[8], S24, 0x455a14ed);  /* 28 */
        GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
        GG(d, a, b, c, x[2], S22, 0xfcefa3f8);  /* 30 */
        GG(c, d, a, b, x[7], S23, 0x676f02d9);  /* 31 */
        GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
        /* Round 3 */
        HH(a, b, c, d, x[5], S31, 0xfffa3942);  /* 33 */
        HH(d, a, b, c, x[8], S32, 0x8771f681);  /* 34 */
        HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
        HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
        HH(a, b, c, d, x[1], S31, 0xa4beea44);  /* 37 */
        HH(d, a, b, c, x[4], S32, 0x4bdecfa9);  /* 38 */
        HH(c, d, a, b, x[7], S33, 0xf6bb4b60);  /* 39 */
        HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
        HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
        HH(d, a, b, c, x[0], S32, 0xeaa127fa);  /* 42 */
        HH(c, d, a, b, x[3], S33, 0xd4ef3085);  /* 43 */
        HH(b, c, d, a, x[6], S34, 0x4881d05);   /* 44 */
        HH(a, b, c, d, x[9], S31, 0xd9d4d039);  /* 45 */
        HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
        HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
        HH(b, c, d, a, x[2], S34, 0xc4ac5665);  /* 48 */
        /* Round 4 */
        II(a, b, c, d, x[0], S41, 0xf4292244);  /* 49 */
        II(d, a, b, c, x[7], S42, 0x432aff97);  /* 50 */
        II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
        II(b, c, d, a, x[5], S44, 0xfc93a039);  /* 52 */
        II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
        II(d, a, b, c, x[3], S42, 0x8f0ccc92);  /* 54 */
        II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
        II(b, c, d, a, x[1], S44, 0x85845dd1);  /* 56 */
        II(a, b, c, d, x[8], S41, 0x6fa87e4f);  /* 57 */
        II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
        II(c, d, a, b, x[6], S43, 0xa3014314);  /* 59 */
        II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
        II(a, b, c, d, x[4], S41, 0xf7537e82);  /* 61 */
        II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
        II(c, d, a, b, x[2], S43, 0x2ad7d2bb);  /* 63 */
        II(b, c, d, a, x[9], S44, 0xeb86d391);  /* 64 */
        // Q61= a, Q62 = d, Q63 = c, Q64 = b
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    void MD5Hash()
    {
        unsigned int index, padLen, block_num, i, k, b_cur, p_cur;
        Byte block[2][64];
        Length nbit = (inputLen << 3);
        block_num = (unsigned int)(inputLen >> 6);
        for (i = 0; i < block_num; i++)
        {
            MD5Transform(&input[i * 64]);
        }
        index = (unsigned int)(inputLen & 0x3f);

        // index == 56�̸�, input�� �������κ��� ���̰� 448bit��� ���̰�, �׷� �е��� ���̴� 512bit, 120-56=64 byte
        padLen = (index < 56) ? (56 - index) : (120 - index);
        for (b_cur = 0; b_cur < 64 && (input[i * 64 + b_cur] != NULL); b_cur++)
            block[0][b_cur] = input[i * 64 + b_cur];
        for (p_cur = 0; p_cur < padLen && b_cur < 64; p_cur++, b_cur++)
            block[0][b_cur] = PADDING[p_cur];

        if (p_cur < padLen)
        {
            MD5Transform(block[0]);
            for (b_cur = 0; p_cur < padLen; p_cur++, b_cur++)
                block[1][b_cur] = PADDING[p_cur];
            for (k = 0; k < 8; k++, b_cur++)
                block[1][b_cur] = (Byte)((nbit >> (8 * k)) & 0xff);
            MD5Transform(block[1]);
        }
        else
        {
            for (k = 0; k < 8; k++, b_cur++) // ���̵� little-endian
                block[0][b_cur] = (Byte)((nbit >> (8 * k)) & 0xff);
            MD5Transform(block[0]);
        }

        for (unsigned int i = 0, j = 0; j < 16; i++, j += 4)
        {
            output[j] = (Byte)(state[i] & 0xff);
            output[j + 1] = (Byte)((state[i] >> 8) & 0xff);
            output[j + 2] = (Byte)((state[i] >> 16) & 0xff);
            output[j + 3] = (Byte)((state[i] >> 24) & 0xff);
        }
        cout << "=> ";
        for (i = 0; i < 16; i++)
            printf("%02x", output[i]);
        cout << "\n";
    }
};
int getInt(char in)
{
    if ('0' <= in && in <= '9')
        return in - '0';
    else
        return in - 'a' + 10;
}
////////////////////////////////////////////////////////////////////////////////
// Compare benign.exe hash value and malicious.exe hash value
string make_MD5_input(string input)
{
    string temp = "";
    for (int i = 0; i < input.size(); i += 2)
    {
        temp += (char)(getInt(input[i]) * 16 + getInt(input[i + 1]));
    }
    return temp;
}
void compare_two_program()
{
    int ch;
    unsigned int cnt = 0;
    char arr[3];

    string benign = "";
    string malicious = "";

    FILE *file = fopen("./program/benign.exe", "rb");
    while ((ch = fgetc(file)) != EOF)
    {
        cnt++;
        sprintf(arr, "%02x", ch);
        benign += arr;
    }
    fclose(file);

    file = fopen("./program/malicious.exe", "rb");
    cnt = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        cnt++;
        sprintf(arr, "%02x", ch);
        malicious += arr;
    }
    fclose(file);

    cout << "Benign program MD5 hash: \n";
    MD5 *a = new MD5(make_MD5_input(benign).c_str());
    a->MD5Hash();
    cout << "Malicios program MD5 hash: \n";
    MD5 *b = new MD5(make_MD5_input(malicious).c_str());
    b->MD5Hash();
}
////////////////////////////////////////////////////////////////////////////////
int main(void)
{
    string input;
    while (cin >> input)
    {
        string temp = "";
        for (int i = 0; i < input.size(); i += 2)
        {
            temp += (char)(getInt(input[i]) * 16 + getInt(input[i + 1]));
        }
        MD5 *a = new MD5(temp.c_str());
        a->MD5Hash();
        delete a;
    }
    //	compare_two_program();
}