from sage.matrix.matrix_integer_dense_hnf import hnf as hermite_normal_form

def hadamard_ratio(A):
	return ( sqrt((A.T*A).determinant()) / mul(map(norm, A)) )^(1/A.nrows())

def babai(B, Bgs, w):
	v = w
	for i in range(B.nrows()-1, -1, -1):
		ci = round((v * Bgs[i]) / (Bgs[i] * Bgs[i]))
		v -= ci * B[i]
	return w - v