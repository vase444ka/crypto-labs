#ifndef LAB3_MD4_H
#define LAB3_MD4_H

#include <cstdint>
#include <string>
#include <vector>

#define F(X,Y,Z) (((X)&(Y))|((~(X))&(Z)))
#define G(X,Y,Z) (((X)&(Y))|((X)&(Z))|((Y)&(Z)))
#define H(X,Y,Z) ((X)^(Y)^(Z))

#define LEFTROTATE(A,N) ((A)<<(N))|((A)>>(32-(N)))

#define MD4ROUND1(a,b,c,d,x,s) a += F(b,c,d) + x; a = LEFTROTATE(a, s);
#define MD4ROUND2(a,b,c,d,x,s) a += G(b,c,d) + x + (uint32_t)0x5A827999; a = LEFTROTATE(a, s);
#define MD4ROUND3(a,b,c,d,x,s) a += H(b,c,d) + x + (uint32_t)0x6ED9EBA1; a = LEFTROTATE(a, s);

namespace MD4 {
    namespace {
        static const char *BASE16 = "0123456789abcdef=";

        static uint32_t A = 0x67452301;
        static uint32_t B = 0xefcdab89;
        static uint32_t C = 0x98badcfe;
        static uint32_t D = 0x10325476;

        std::string toHex(std::string in){
            std::string out(in.size()*2, NULL);
            for(int i = 0, j = 0; i<in.size(); i++){
                out[j++] = BASE16[((in[i] & 0xF0)>>4)];
                out[j++] = BASE16[(in[i] & 0x0F)];
            }
            return out;
        }


        std::string uint32ToString(uint32_t l){
            std::string s(4,NULL);
            for(int i=0; i<4; i++){
                s[i] = (l >> (8*(3-i))) & 0xFF;
            }
            return s;
        }

        uint32_t stringToUint32(std::string s){
            uint32_t l = 0;
            for(int i=0; i<4; i++){
                l = l|(((uint32_t)((unsigned char)s[i]))<<(8*(3-i)));
            }
            return l;
        }

        void setMD4Registers(uint32_t AA, uint32_t BB, uint32_t CC, uint32_t DD){
            A=AA;
            B=BB;
            C=CC;
            D=DD;
        }

        void resetMD4Registers(){
            setMD4Registers(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
        }

        std::vector<uint32_t> MD4Digest(const std::vector<uint32_t> &w) {
            //assumes message.len is a multiple of 64 bytes.
            uint32_t X[16];
            std::vector<uint32_t> digest(sizeof(uint32_t)*4);
            uint32_t AA, BB, CC, DD;

            for(int i=0; i<w.size()/16; i++){
                for(int j=0; j<16; j++){
                    X[j]=w[i*16+j];
                }

                AA=A;
                BB=B;
                CC=C;
                DD=D;

                MD4ROUND1(A,B,C,D,X[0],3);
                MD4ROUND1(D,A,B,C,X[1],7);
                MD4ROUND1(C,D,A,B,X[2],11);
                MD4ROUND1(B,C,D,A,X[3],19);
                MD4ROUND1(A,B,C,D,X[4],3);
                MD4ROUND1(D,A,B,C,X[5],7);
                MD4ROUND1(C,D,A,B,X[6],11);
                MD4ROUND1(B,C,D,A,X[7],19);
                MD4ROUND1(A,B,C,D,X[8],3);
                MD4ROUND1(D,A,B,C,X[9],7);
                MD4ROUND1(C,D,A,B,X[10],11);
                MD4ROUND1(B,C,D,A,X[11],19);
                MD4ROUND1(A,B,C,D,X[12],3);
                MD4ROUND1(D,A,B,C,X[13],7);
                MD4ROUND1(C,D,A,B,X[14],11);
                MD4ROUND1(B,C,D,A,X[15],19);

                MD4ROUND2(A,B,C,D,X[0],3);
                MD4ROUND2(D,A,B,C,X[4],5);
                MD4ROUND2(C,D,A,B,X[8],9);
                MD4ROUND2(B,C,D,A,X[12],13);
                MD4ROUND2(A,B,C,D,X[1],3);
                MD4ROUND2(D,A,B,C,X[5],5);
                MD4ROUND2(C,D,A,B,X[9],9);
                MD4ROUND2(B,C,D,A,X[13],13);
                MD4ROUND2(A,B,C,D,X[2],3);
                MD4ROUND2(D,A,B,C,X[6],5);
                MD4ROUND2(C,D,A,B,X[10],9);
                MD4ROUND2(B,C,D,A,X[14],13);
                MD4ROUND2(A,B,C,D,X[3],3);
                MD4ROUND2(D,A,B,C,X[7],5);
                MD4ROUND2(C,D,A,B,X[11],9);
                MD4ROUND2(B,C,D,A,X[15],13);

                MD4ROUND3(A,B,C,D,X[0],3);
                MD4ROUND3(D,A,B,C,X[8],9);
                MD4ROUND3(C,D,A,B,X[4],11);
                MD4ROUND3(B,C,D,A,X[12],15);
                MD4ROUND3(A,B,C,D,X[2],3);
                MD4ROUND3(D,A,B,C,X[10],9);
                MD4ROUND3(C,D,A,B,X[6],11);
                MD4ROUND3(B,C,D,A,X[14],15);
                MD4ROUND3(A,B,C,D,X[1],3);
                MD4ROUND3(D,A,B,C,X[9],9);
                MD4ROUND3(C,D,A,B,X[5],11);
                MD4ROUND3(B,C,D,A,X[13],15);
                MD4ROUND3(A,B,C,D,X[3],3);
                MD4ROUND3(D,A,B,C,X[11],9);
                MD4ROUND3(C,D,A,B,X[7],11);
                MD4ROUND3(B,C,D,A,X[15],15);

                A+=AA;
                B+=BB;
                C+=CC;
                D+=DD;
            }

            digest[0]=A;
            digest[1]=B;
            digest[2]=C;
            digest[3]=D;
            resetMD4Registers();
            return digest;
        }

        inline uint32_t changeEndianness(uint32_t x){
            return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8) | ((x & 0xFF000000) >> 24);
        }

    }

    std::string hash(std::string str) {
        uint64_t msg_length = str.size()*CHAR_BIT;//in bits

        char oneBit = -128;
        str = str + oneBit;

        //append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
        //	is congruent to −64 ≡ 448 (mod 512)4
        int appendix_len=((56 - int(str.size())) % 64);
        if(appendix_len < 0) appendix_len+=64;
        str = str + std::string(appendix_len, NULL);

        std::vector<uint32_t> w(str.size() / 4);

        for(int i=0; i < str.size() / 4; i++){
            w[i]= changeEndianness(stringToUint32(str.substr(4 * i, 4)));
        }
        //append length, least significant word first
        w.push_back(msg_length & 0xFFFFFFFF);
        w.push_back((msg_length >> 32) & 0xFFFFFFFF);

        std::vector<uint32_t> hash = MD4Digest(w);

        std::string digest;
        for(int i=0; i<4; i++){
            hash[i] = changeEndianness(hash[i]);
            digest += uint32ToString(hash[i]);
        }

        return toHex(digest);
    }
};



#endif //LAB3_MD4_H
