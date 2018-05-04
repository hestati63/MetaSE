; vim: ft=nasm ts=8 sw=8 noet

[section .text]
[bits 64]

dabs:
	movq	xmm1, [dabsc]
	andpd	xmm0, xmm1
	ret
dneg:
	movq	xmm1, [dnegc]
	xorpd	xmm0, xmm1
	ret
sabs:
	movd	xmm1, [sabsc]
	andps	xmm0, xmm1
	ret
sneg:
	movd	xmm1, [snegc]
	xorps	xmm0, xmm1
	ret

dadd:
	addsd	xmm0, xmm1
	ret
dsub:
	subsd	xmm0, xmm1
	ret
dmul:
	mulsd	xmm0, xmm1
	ret
ddiv:
	divsd	xmm0, xmm1
	ret
sadd:
	addss	xmm0, xmm1
	ret
ssub:
	subss	xmm0, xmm1
	ret
smul:
	mulss	xmm0, xmm1
	ret
sdiv:
	divss	xmm0, xmm1
	ret

[section .rodata]

dabsc	dq	0x7fffffffffffffff
dnegc	dq	0x8000000000000000
sabsc	dd	0x7fffffff
snegc	dd	0x80000000
