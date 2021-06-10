#include <iostream>
#include <random>
#include <chrono>
#include <bitset>

class DES_CBC {
    std::uint64_t _key, _init_vector;
    static const int _S_TRANSFORM_N = 8, _S_TRANSFORM_LEN = 6, _STEPS = 16;
    uint64_t _step_keys[_STEPS];

    constexpr static int bits_perm_table[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
                                      62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
                                      57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
                                      61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
    constexpr static int bits_inverse_perm_table[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                                                        39, 7, 47, 15, 55, 23, 63, 31,
                                                        38, 6, 46, 14, 54, 22, 62, 30,
                                                        37, 5, 45, 13, 53, 21, 61, 29,
                                                        36, 4, 44, 12, 52, 20, 60, 28,
                                                        35, 3, 43, 11, 51, 19, 59, 27,
                                                        34, 2, 42, 10, 50, 18, 58, 26,
                                                        33, 1, 41, 9, 49, 17, 57, 25 };
    constexpr static int widen_permutation[64] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,
                                                  13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,
                                                  24,25,24,25,26,27,28,29,28,29,30,31,32,1,1,1,
                                                  1,1,1,1,1,1,1,1,1,1,1,1,1};
    constexpr static int P_permutation[32] = {8,29,22,11,27,3,20,14,24,30,6,1,19,9,25,31,23,2,15,28,7,10,18,32,16,5,21,4,12,13,26,17};
    constexpr static int key_permutation[64] = {57,49,41,33,25,17,9,8,1,58,50,42,34,26,18,16,
                                                10,2,59,51,43,35,27,24,19,11,3,60,52,44,36,32,
                                                63,55,47,39,31,23,15,40,7,62,54,46,38,30,22,48,
                                                14,6,61,53,45,37,29,56,21,13,5,28,20,12,4,64};
    constexpr static int step_key_permutation[64] = {15,19,12,27,1,5,3,31,17,6,23,11,26,21,13,4,
                                                     29,9,18,7,30,22,14,2,46,59,35,42,53,62,34,
                                                     45,58,51,37,54,50,55,44,63,38,60,52,47,57,
                                                     41,33,36,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};

    //perm[i]th bit takes i-th place

    constexpr static int step_shift[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
    constexpr static int S_transform_matrix[8][4][16] = {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                                                          {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                                                          {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                                                          {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
                                                         {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                                                          {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                                                          {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                                                          {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
                                                         {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                                                          {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                                                          {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                                                          {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
                                                         {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                                                          {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                                                          {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                                                          {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
                                                         {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                                                          {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                                                          {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                                                          {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
                                                         {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                                                          {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                                                          {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                                                          {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
                                                         {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                                                          {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                                                          {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                                                          {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
                                                         {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                                                          {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                                                          {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                                                          {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};

    static inline uint32_t extract(uint32_t subkey){
        uint32_t ans = 0;
        for (int i = 0; i < sizeof(subkey); i++){
            uint32_t curr_byte = ((128 << (CHAR_BIT * i)) & subkey);
            ans |= (curr_byte<<(7*i));
        }
        return ans;
    }

    static inline uint64_t merged(uint32_t shifted, uint64_t key){
        uint64_t ans = 0;
        for (int i = 0; i<sizeof(key)/2; i++){
            uint64_t curr_byte = (shifted&(((1<<7) - 1))<<(i*7))>>(i*7);
            ans |= (curr_byte<<(CHAR_BIT*i));
            ans |= (key&(1<<(CHAR_BIT*i - 1)));
        }
        return ans;
    }

    static uint64_t cyclic_shift(uint64_t key, int shift){
        uint32_t C = extract(key>>(sizeof(key)*CHAR_BIT/2));
        uint32_t D = extract(uint32_t(key));
        C = ((C<<shift) | (C>>(sizeof(C)*CHAR_BIT - shift)));
        D = ((D<<shift) | (D>>(sizeof(C)*CHAR_BIT - shift)));
        return ((merged(C, (key>>(sizeof(key)*CHAR_BIT/2))))<<(sizeof(key)*CHAR_BIT/2) | (merged(D, key)));
    }

    void generate_keys(uint64_t key){
        for (int i = 0; i < sizeof(key); i++){
            uint64_t curr_byte = ((255 << (CHAR_BIT * i)) & key);
            if (std::bitset<64>(curr_byte).count() % 2 == 0){
                key = (key^(1<<(CHAR_BIT*(i + 1) - 1)));
            }
        }

        key = bits_permutation(key, key_permutation);

        for (int i = 0; i < _STEPS; i++){
            key = cyclic_shift(key, step_shift[i]);
            _step_keys[i] = bits_permutation(key, step_key_permutation);
        }
    }

    [[nodiscard]] static std::uint32_t S_transformation(uint64_t x) {
        uint32_t res = 0;
        for (int i = 0; i < _S_TRANSFORM_N; i++){
            uint64_t shifter = (uint64_t (63)<<(i * _S_TRANSFORM_LEN));
            uint32_t block = ((x&shifter)>>(i * _S_TRANSFORM_LEN));
            uint32_t S_row = (block&1)|((block&32)>>4);
            uint32_t S_col = ((block>>1)&15);
            uint32_t curr_block = (S_transform_matrix[_S_TRANSFORM_N - i - 1][S_row][S_col])<<(i*4);
            res = (res | curr_block);
        }
        return res;
    }

    //perm should be of same size as x
    template <typename T>
    T bits_permutation(T x, const int* perm) const{
        T ans = 0;
        for (int i = 0; i < sizeof(T)*CHAR_BIT; i++){
            T new_bit = ((T (1)<<(perm[i] - 1)) & x);
            if (new_bit != 0){
                new_bit = (T (1)<<i);
            }
            ans = (ans | new_bit);
        }
        return ans;
    }

    [[nodiscard]]
    std::uint32_t feistel(std::uint32_t x, std::uint64_t curr_key) const{
        uint64_t new_x = bits_permutation(uint64_t(x), widen_permutation);
        new_x = (curr_key ^ new_x);
        uint32_t S_transformed = S_transformation(new_x);
        return bits_permutation(S_transformed, P_permutation);
    }

public:
    explicit DES_CBC(std::uint64_t key) : _key(key) {
        generate_keys(_key);
        static std::mt19937 gen{std::random_device{}()};
        std::uniform_int_distribution<std::uint64_t> dist{};
        _init_vector = dist(gen);
    }

    [[nodiscard]]
    std::vector<std::uint64_t> encrypt(const std::vector<std::uint64_t> &pt) const
    {
        std::vector <std::uint64_t> crypted;
        for (auto p:pt) {
            uint64_t x;
            if (!crypted.empty()){
                x = (p^crypted.back());
            }
            else{
                x = (p^_init_vector);
            }
            x = bits_permutation(x, bits_perm_table);
            auto[l, r] = std::pair{std::uint32_t(x >> 32), std::uint32_t(x)};
            for (uint64_t _step_key : _step_keys) {
                auto prev_r = r;
                r = (l ^ feistel(r, _step_key));
                l = prev_r;
            }
            std::swap(l, r);
            crypted.push_back(bits_permutation((std::uint64_t{l} << 32 | r), bits_inverse_perm_table));
        }
        return crypted;
    }

    [[nodiscard]]
    std::vector<std::uint64_t> decrypt(const std::vector<std::uint64_t> &cipher) const
    {
        std::vector <std::uint64_t> decrypted;
        for (int i = 0; i<cipher.size(); i++) {
            auto x = bits_permutation(cipher[i], bits_perm_table);
            auto[l, r] = std::pair{std::uint32_t(x >> 32), std::uint32_t(x)};
            for (int i = _STEPS - 1; i >= 0; i--) {
                auto prev_r = r;
                r = (l ^ feistel(r, _step_keys[i]));
                l = prev_r;
            }
            std::swap(l, r);
            if (i >  0) {
                decrypted.push_back(
                        bits_permutation((std::uint64_t{l} << 32 | r), bits_inverse_perm_table) ^ cipher[i - 1]);
            } else{
                decrypted.push_back(
                        bits_permutation((std::uint64_t{l} << 32 | r), bits_inverse_perm_table) ^ _init_vector);
            }
        }
        return decrypted;
    }
};

template <typename Int>
auto random_int() -> Int
{
    static std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<Int> dist{};
    return dist(gen);
}

int main() {
    namespace chr = std::chrono;

    DES_CBC des_cbc(random_int<uint64_t>());//TODO CBC

    auto print_and_check = [&] (auto x) {
        const auto start_time = chr::steady_clock::now();
        const auto crypted = des_cbc.encrypt(x);
        const auto decrypted = des_cbc.decrypt(crypted);
        const auto elapsed_time = chr::duration_cast<chr::nanoseconds>(chr::steady_clock::now() - start_time);

        std::cout<<"Input vector: ";
        for (auto block:x){
            std::cout<<block<<" ";
        }
        std::cout<<"\nEncrypted vector: ";
        for (auto block:crypted){
            std::cout<<block<<" ";
        }
        std::cout<<"\nDecrypted vector: ";
        for (auto block:decrypted){
            std::cout<<block<<" ";
        }
        std::cout<<"\nElapsed time: "<<std::dec<<elapsed_time.count()<<std::endl;

        if (x == decrypted) {
            std::cout<<"---------OK---------"<<std::endl;
        } else {
            std::cout<<"-------NOT OK-------"<<std::endl;
        }
    };

    for (auto i = 0; i < 42; ++i) {
        std::vector<uint64_t> test = {random_int<std::uint64_t>(),
                                      random_int<std::uint64_t>(),
                                      random_int<std::uint64_t>()};
        print_and_check(test);
    };

    return 0;
}
