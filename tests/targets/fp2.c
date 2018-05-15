#include<stdio.h>
#include <stdlib.h>

// {"s":{"length": 4}}
int main(int argc, char **argv) {
    int symvar = argv[1][0] - 48;
    float x = symvar + 0.0000005;
    if(x != 7){
        float x = symvar + 1;
        if (x == 8)
            return 1;
    }
    return 0;
}
