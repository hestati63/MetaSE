 
 
#include <stdio.h>
#include <math.h>
#include <complex.h>
// a17287278 
double PI;
typedef double complex cplx;
 
void _fft(cplx buf[], cplx out[], int n, int step)
{
	if (step < n) {
		_fft(out, buf, n, step * 2);
		_fft(out + step, buf + step, n, step * 2);
 
		for (int i = 0; i < n; i += 2 * step) {
			cplx t = cexp(-I * PI * i / n) * out[i + step];
			buf[i / 2]     = out[i] + t;
			buf[(i + n)/2] = out[i] - t;
		}
	}
}
 
void fft(cplx buf[], int n)
{
	cplx out[n];
	for (int i = 0; i < n; i++) out[i] = buf[i];
 
	_fft(buf, out, n, 1);
}
 
 
double calc(cplx buf[]) {
    double r = 0;
    for (int i = 0; i < 8; i++) r += creal(buf[i]);
    return r;
}

int main(int argc, char **argv)
{
	PI = atan2(1, 1) * 4;
	cplx buf[] = {argv[1][0], argv[1][1], argv[1][2], argv[1][3], argv[1][4], argv[1][5], argv[1][5], argv[1][6]};
	fft(buf, 7);
    int r = calc(buf);
    if (r < 731.0)
        return 0;
    else {
        if (r > 732)
            return 1;
        else
            return 2;
    }
}
 
 
