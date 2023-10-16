from Crypto.Util.number import *
from tqdm import tqdm
import itertools

def coppersmith(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    k = ZZ(f.coefficients().pop(0))
    g = gcd(k, N)
    k = R(k/g)
    f *= 1/k
    f = f.change_ring(ZZ)
    vars = f.variables()
    G = Sequence([], f.parent())
    for k in range(m):
        for i in range(m-k+1):
            for subvars in itertools.combinations_with_replacement(vars[1:], i):
                g = f**k * prod(subvars) * N**(max(d-k, 0))
                G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, Integer(1)/factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots


n = 11742206979753913400078905437620927239312100143683561348559706888059517073501671270442035616069475401885800940840637461394966138444212863329550296096810174302908081343771425078438812757409932271641752815483140192761424479138101387474201617656145465256702869988096437111555784211113202855842154079692916855005550988249260708218478587798010585134893419758238821108429545314594619421542208056788562789883731944916338735303238896789106540878203202248016648110162713043051468195684141071629960620191976496526670427951196712644013281971583458932987201292465241722540584076749537703699225966144871369883097865992662187088551
c = 11175857349202502979905495339173488503809875205519195451391183778759633781611936183718835115129271354595826223814714036609569168454855035997378784246667677790850227846451743310996421511359777473727771131114868036554258398571727740119318946749122706658409825265831145602771766961944849523074925796388789479437473489810800979476634470855351007257284346941669187960042712212552297897619326415849091631061996678203711093907678968497674704656220332058764707097701805067323497738496983107060690965213691205793923576820214922393938355093143903430280533993633928014215827172391809659926836733387599638290073202460533114288796


p = 0x9e5675d8e41aa7ac7f05847aab69a685ebbe3d1c587139e3e4695d71dbe37ed72dd9a3176cc0ca6f6fb3ef309ffd2e6e7539d7ffd1cfada6e2bfb4905aa4e3cd782f2b0817c433003a5737fae8e82625fed05c42b156247a0a9dd43ac5bfd21a238ec136477ed81bce70be8cc62ae053286945b7271691741a2eaa20a2dafee5
q = n//p
e = 12721
d = pow(e, -1, (p-1)*(q-1))
d_low = 0x4443b9e8a46a89efba588e8dca4608b9f8a74d836bdd57518556070703843499
p_high = 0x9e5675d8e41aa7ac7f05847aab69a685ebbe3d1c587139e3e4695d71dbe37ed7
p_mid = 0x7539d7ffd1cfada6e2bfb4905aa4e3cd782f2b0817c433003a5737fae8e82625f

t = len(bin(d_low)) - 2
for k in tqdm(range(1, e)):
    PR.<x> = PolynomialRing(Zp(2, t))
    f = x + k*(n*x - x**2 - n + x) - x*e*d_low 
    for p_low, _ in f.roots():
        p_low = ZZ(p_low)
        PR.<x0, x1> = PolynomialRing(Zmod(n), 2)
        f = p_low + 16**192*p_high + 16**95*p_mid + 16**64*x0 + 16**160*x1
        roots = coppersmith(f, bounds=(16**32, 16**31), m=4)
        if roots == []:
            continue
        p = int(f(roots[0]))
        q = n//p
        d = pow(e, -1, (p-1)*(q-1))
        flag = int(pow(c, d, n))
        print(long_to_bytes(flag))
        quit()


