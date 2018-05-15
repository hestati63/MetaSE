/*
TOY:
Solution: 30
*/
#include <string.h> 
#include <math.h>

#define PI 3.14159265358979323846264338327


// {"s":{"length": 4}}
int main(int argc, char **argv) {
    int symvar = argv[1][0];
    float v = sin(symvar*PI/30);
    if(v > 0.5){
        return 0;
    }else{
        return 1;
    }
}
