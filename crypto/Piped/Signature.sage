load('utils.sage')

class Signature:
	def __init__(self, n, l, skom=0.5):
		self.keygen(n, l, skom)
		
	def setkeys(self, sk, pk):
		self.sk = sk
		self.pk = pk
		
	def keygen(self, n, l, skom, max_it=10^4):
		i = 0
		while True:
			R = random_matrix(ZZ, n, x = -l, y = l)
			if hadamard_ratio(R) > skom:
				break
			i += 1
			if i > max_it:
				raise Exception('Max iteration is reached')
		self.sk = R.LLL()
		self.skGS = self.sk.gram_schmidt()[0]

		self.pk = hermite_normal_form(self.sk)[0]

	def sign(self, m):
		return babai(self.sk, self.skGS, m)
	
	def verify(self, s, m, tau):
		s_in_latticeQ = all(map(lambda x: x in ZZ, s * self.pk.inverse()))
		if s_in_latticeQ and norm(m - s) <= tau: 
			return True
		return False
