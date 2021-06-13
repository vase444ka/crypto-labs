#include <iostream>
#include <string>
#include "MD4.h"

int main(){
    std::string test;
    while(std::cin>>test){
        std::cout<<(MD4::hash(test));
    }

    return 0;
}