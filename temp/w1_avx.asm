; vim: ft=nasm ts=8 sw=8 noet

[section .text]
[bits 64]

dabs:
	vmovq	xmm1, [dabsc]
	vandpd	xmm0, xmm0, xmm1
	ret
dneg:
	vmovq	xmm1, [dnegc]
	vxorpd	xmm0, xmm0, xmm1
	ret
sabs:
	vmovd	xmm1, [sabsc]
	vandps	xmm0, xmm0, xmm1
	ret
sneg:
	vmovd	xmm1, [snegc]
	vxorps	xmm0, xmm0, xmm1
	ret

dadd:
	vaddsd	xmm0, xmm0, xmm1
	ret
dsub:
	vsubsd	xmm0, xmm0, xmm1
	ret
dmul:
	vmulsd	xmm0, xmm0, xmm1
	ret
ddiv:
	vdivsd	xmm0, xmm0, xmm1
	ret
sadd:
	vaddss	xmm0, xmm0, xmm1
	ret
ssub:
	vsubss	xmm0, xmm0, xmm1
	ret
smul:
	vmulss	xmm0, xmm0, xmm1
	ret
sdiv:
	vdivss	xmm0, xmm0, xmm1
	ret

[section .rodata]

dabsc	dq	0x7fffffffffffffff
dnegc	dq	0x8000000000000000
sabsc	dd	0x7fffffff
snegc	dd	0x80000000
