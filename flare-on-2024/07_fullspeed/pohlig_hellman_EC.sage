#!/usr/bin/env sage
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 07 - fullspeed
# ----------------------------------------------------------------------------------------
# Our attack is based on the following code: 
#   https://github.com/pwang00/Cryptographic-Attacks/blob/master/Public%20Key/Diffie%20Hellman/pohlig_hellman_EC.sage
# ----------------------------------------------------------------------------------------


# Elliptic Curve parameters.
q = 0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd
a = 0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
b = 0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380

# A random point G on the curve
x = 0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
y = 0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182
 

# ----------------------------------------------------------------------------------------
def baby_step_giant_step(G, PA, n, E):
    """Baby-step Giant-step algorithm.

    The Baby-Step Giant-Step (BSGS) algorithm helps reducing the complexity of
    calculating the discrete logarithm `g_i*x_i mod p_i = h_i` to `O(sqrt(p_i))`
    instead of `O(p_i)` with traditional brute forcing.

    The way BSGS works is that we rewrite the discrete logarithm `x_i` in terms
    of `i*m + j`, where `m = ceil(sqrt(n))`. This allows for a meet-in-the-middle
    style calculation. We first calculate `g^j mod p` for every `0 <= j < m`, and
    then `g^i mod p` for `0 <= i <= p`, multiplying by `a^-m` for every `y` not
    equal to `PA`.

    For more details: https://en.wikipedia.org/wiki/Baby-step_giant-step
    """
    M = ceil(sqrt(n)) + 1
    y = PA
    log_table = {}
    
    for j in range(M):
        log_table[j] = (j, j * G)

    inv = -M * G
    
    for i in range(M):
        for x in log_table:
            if log_table[x][1] == y:
                return i * M + log_table[x][0]
    
        y += inv
        
    return None


# ----------------------------------------------------------------------------------------
def my_pohlig_hellman_ec(G, PA, E, debug=True):
    """Use Pohlig-Hellman to **almost** compute the discrete logarithm `k` of k*G = PA.

    The order of the group of the Elliptic Curve (which in Diffie-Hellman is
    p - 1 due to prime modulus), can be factored (which by construction here
    is B-smooth) into small primes. By Lagrange's theorem, we have that the
    order (number of elements) of every subgroup divides the order of group G.
    Thus, if we find the discrete logarithm for every subgroup (e.g., prime
    factor) we can use the Chinese Remainder Theorem (CRT) to find the discrete
    logarithm of the group.

    If a factor is too big, we cannot find its discrete logarithm, so we skip it.
    At the end we will return a `k` which is close to the discrete logarithm.
    """
    n = E.order() 
    factors = []

    for p_i in [p_i ^ e_i for (p_i, e_i) in factor(n)]:
        print(f'[+] Elliptic Curve factor: {p_i}')

        # If a factor is too big, it will take forever to factor it, so we skip it.
        if p_i > 0x10000000:
            print(f'[!] Warning: factor {p_i} is too big. Skipping it ...')
        else:
            factors.append(p_i  )

    crt_array = []  # Array for the Chinese Remainder Theorem (CRT).

    for p_i in factors:
        g_i = G * (n // p_i)
        h_i = PA * (n // p_i)

        x_i = baby_step_giant_step(g_i, h_i, p_i, E)

        # g_i ^ x_i mod p_i = h_i 
        if x_i is not None:
            print(f'[+] Found discrete logarithm {x_i} for factor {p_i}')
            crt_array += [x_i]
        else:
            print(f'[!] Error. Could not find discrete logarithm for factor {p_i}')

    
    k = crt(crt_array, factors)
    print(f'[+] Recovered k from CRT: {k}')

    return k


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] fullspeed Pohlig-Hellman attack started.')

    # Here's how the ECDH works:
    #
    # Both sides start with a known point G = (x, y)
    # One   side chooses a random 128-bit number k1 and computes s1 = k1*G
    # Other side chooses a random 128-bit number k2 and computes s2 = k2*G
    #
    # One   side sends (x1, y1) ~> the coordinates of s1 = k1*G (first 2 packets)
    # Other side sends (x2, y2) ~> the coordinates of s2 = k2*G (next 2 packets)
    #
    # Both sides compute the shared secret s = k1*k2*G
    #
    # We know k1*G and k2*G. Our goal is to find k1*k2*G.
    #
    # NOTE: The coordinates must be XORed with 13371337...1337.

    # Define the Elliptic Curve.
    F = GF(q)
    E = EllipticCurve(F, [a, b])
    G = E(x, y)

    # s1 and s2 taken from `capture.pcapng`.
    x1 = 0x195B46A760ED5A425DADCAB37945867056D3E1A50124FFFAB78651193CEA7758D4D590BED4F5F62D4A291270F1DCF499
    y1 = 0x357731EDEBF0745D081033A668B58AAA51FA0B4FC02CD64C7E8668A016F0EC1317FCAC24D8EC9F3E75167077561E2A15
    x2 = 0xB3E5F89F04D49834DE312110AE05F0649B3F0BBE2987304FC4EC2F46D6F036F1A897807C4E693E0BB5CD9AC8A8005F06
    y2 = 0x85944D98396918741316CD0109929CB706AF0CCA1EAF378219C5286BDC21E979210390573E3047645E1969BDBCB667EB #E145C67B22B11C

    print(f'[+] Point G ({G[0]}, {G[1]})')

    PA = E(x1, y1)  # == kA * G
    PB = E(x2, y2)  # == kB * G   

    # Verify that point verifies the EC equation.
    assert (y1^2) % q == (x1^3 + a*x1 + b) % q
    assert (y2^2) % q == (x2^3 + a*x2 + b) % q


    print(f'[+] E  order: {E.order()}')
    print(f'[+] PA order: {PA.order()}')
    print(f'[+] PB order: {PB.order()}')

    print(f'[+] Checking if q is prime: {q.is_prime()}')
    print(f'[+] Checking if a is prime: {a.is_prime()}')
    print(f'[+] Checking if b is prime: {b.is_prime()}')

    # Parameters `a` and `b` are not prime numbers, so we can do the Pohlig-Hellman attack.
    print( '[+] Trying Pohlig-Hellman factorization with:')
    print(f'[+] G  = {G}')
    print(f'[+] PA = {PA}')
    print(f'[+] E  = {E}')


    # Do the Pohlig-Hellman and recover a secret `k` which is close to `kA`
    k = my_pohlig_hellman_ec(G, PA, E)
    # assert kA * G == PA

    # such that PA = G * kA
    print(f'[+] Recovered k from Pohlig-Hellman: {k}')

    # Now the most important part:
    #
    # We know that `kA` is 128 bits. The `k` we recovered is 3914004671535485983675163411331184,
    # or 112 bits. We are still missing 16 bits.
    # 
    # Here's the trick:
    #   We know that `k` satisfies all the solutions from CRT:
    #       k == 11872 mod 35809
    #       k == 42485 mod 46027
    #       k == 12334 mod 56369
    #       k == 45941 mod 57301
    #       k == 27946 mod 65063
    #       k == 43080 mod 111659
    #       k == 57712 mod 113111
    #
    # However we are missing the last equation. We cannot find the discrete logarithm because
    # the number is too big:
    #       k == ? mod 7072010737074051173701300310820071551428959987622994965153676442076542799542912293
    #
    # We found that the solution 3914004671535485983675163411331184 satisfies all the above 
    # equations. However, the following solution will **also** satisfies all the equations:
    #   3914004671535485983675163411331184 + 35809*46027*56369*57301*65063*111659*113111 = 
    #   3914004671535485983675163411331184 + 4374617177662805965808447230529629
    #
    # In fact, all `3914004671535485983675163411331184 + 4374617177662805965808447230529629*i`
    # are valid solutions.
    #
    # 4374617177662805965808447230529629 is a big number, so eventually our solutions will exceed
    # 128-bit bits. For every k, we check if `k*G == PA`. That is, we should find the correct
    # solution before that.    
    #
    # Essentially, we brute-force the remaining bits from `kA` but in a clever way.
    #
    step = 35809*46027*56369*57301*65063*111659*113111
    kA = 3914004671535485983675163411331184 # == k

    print(f'[+] Brute forcing remaining bits of kA (step: {step})....')
    while kA < 0xffffffffffffffffffffffffffffffff:        
        if kA*G == PA:
            print(f'[+] FOUND kA: {kA}')
            break

        kA += 35809*46027*56369*57301*65063*111659*113111

    if kA >= 0xffffffffffffffffffffffffffffffff:
        raise Exception('Could not find kA :(')
    
    # At this point we have recovered the secret number kA,
    # so we can compute the secret key:
    shared_secret1 = kA*PB  # == kA*kB*G

    print(f'[+] Secret key x: {shared_secret1[0]}')
    print(f'[+] Secret key y: {shared_secret1[1]}')


    # ---------------------------------------------------------------
    # We don't need this, it's just for bonus.
    # ---------------------------------------------------------------
    print('[+] BONUS: Recovering shared secret from the other point.')

    k2 = my_pohlig_hellman_ec(G, PB, E)
    print(f'[+] Recovered k2 from Pohlig-Hellman: {k2}')
    
    kB = k2
    print(f'[+] Brute forcing remaining bits of kB (step: {step})....')
    while kB < 0xffffffffffffffffffffffffffffffff:
        if kB*G == PB:
            print(f'[+] FOUND kB: {kB}')
            break

        kB += 35809*46027*56369*57301*65063*111659*113111

    if kB >= 0xffffffffffffffffffffffffffffffff:
        raise Exception('Could not find kB :(')


    # At this point we have recovered the secret number kA,
    # so we can compute the secret key:
    shared_secret2 = kB*PA  # == kA*kB*G

    print(f'[+] Secret key #2 x: {shared_secret2[0]}')
    print(f'[+] Secret key #2 y: {shared_secret2[1]}')

    # Shared secrets should match.
    assert shared_secret1 == shared_secret2

    # Verification with hardcoded constants.
    shared1 = 168606034648973740214207039875253762473*PB
    shared2 = 153712271226962757897869155910488792420*PA
    assert shared1 == shared2

    shared_x = 9285933189458587360370996409965684516994278319709076885861327850062567211786910941012004843231232528920376385508032
    shared_y = 380692327439186423832217831462830789200626503899948375582964334293932372864029888872966411054442434800585116270210

    print('[+] Program finished successfully. Bye bye :)')


# ----------------------------------------------------------------------------------------
r"""
┌─[22:07:18]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/07_fullspeed]
└──> time ./pohlig_hellman_EC.sage 
[+] fullspeed Pohlig-Hellman attack started.
[+] Point G (1305488802776637960515697387274764814560693662216913070824404729088258519836180992623611650289275235949409735080408, 2840284555446760004012395483787208388204705580027573689198385753943125520419959469842139003551394700125370894549378)
[+] PA order: 30937339651019945892244794266256713890440922455872051984762505561763526780311616863989511376879697740787911484829297
[+] PB order: 30937339651019945892244794266256713890440922455872051984762505561763526780311616863989511376879697740787911484829297
[+] Checking if q is prime: True
[+] Checking if a is prime: False
[+] Checking if b is prime: False
[+] Trying Pohlig-Hellman factorization with:
[+] G  = (1305488802776637960515697387274764814560693662216913070824404729088258519836180992623611650289275235949409735080408 : 2840284555446760004012395483787208388204705580027573689198385753943125520419959469842139003551394700125370894549378 : 1)
[+] PA = (3902729749136290727021456713077352817203141198354795319199240365158569738643238197536678384836705278431794896368793 : 8229109857867260486993831343979405488668387983876094644791511977475828392446562276759399366591204626781463052691989 : 1)
[+] E  = Elliptic Curve defined by y^2 = x^3 + 24699516740398840043612817898240834783822030109296416539052220535505263407290501127985941395251981432741860384780927*x + 24561086537518854907476957344600899117700350970429030091546712823181765905950742731855058586986320754303922826007424 over Finite Field of size 30937339651019945892244794266256713890440922455872051984768764821736576084296075471241474533335191134590995377857533
[+] Elliptic Curve factor: 35809
[+] Elliptic Curve factor: 46027
[+] Elliptic Curve factor: 56369
[+] Elliptic Curve factor: 57301
[+] Elliptic Curve factor: 65063
[+] Elliptic Curve factor: 111659
[+] Elliptic Curve factor: 113111
[+] Elliptic Curve factor: 7072010737074051173701300310820071551428959987622994965153676442076542799542912293
[!] Warning: factor 7072010737074051173701300310820071551428959987622994965153676442076542799542912293 is too big. Skipping it ...
[+] Found discrete logarithm 11872 for factor 35809
[+] Found discrete logarithm 42485 for factor 46027
[+] Found discrete logarithm 12334 for factor 56369
[+] Found discrete logarithm 45941 for factor 57301
[+] Found discrete logarithm 27946 for factor 65063
[+] Found discrete logarithm 43080 for factor 111659
[+] Found discrete logarithm 57712 for factor 113111
[+] Recovered k from CRT: 3914004671535485983675163411331184
[+] Recovered k from Pohlig-Hellman: 3914004671535485983675163411331184
[+] Brute forcing remaining bits of kA (step: 4374617177662805965808447230529629)....
[+] FOUND kA: 168606034648973740214207039875253762473
[+] Secret key x: 9285933189458587360370996409965684516994278319709076885861327850062567211786910941012004843231232528920376385508032
[+] Secret key y: 380692327439186423832217831462830789200626503899948375582964334293932372864029888872966411054442434800585116270210
[+] BONUS: Recovering shared secret from the other point.
[+] Elliptic Curve factor: 35809
[+] Elliptic Curve factor: 46027
[+] Elliptic Curve factor: 56369
[+] Elliptic Curve factor: 57301
[+] Elliptic Curve factor: 65063
[+] Elliptic Curve factor: 111659
[+] Elliptic Curve factor: 113111
[+] Elliptic Curve factor: 7072010737074051173701300310820071551428959987622994965153676442076542799542912293
[!] Warning: factor 7072010737074051173701300310820071551428959987622994965153676442076542799542912293 is too big. Skipping it ...
[+] Found discrete logarithm 26132 for factor 35809
[+] Found discrete logarithm 27202 for factor 46027
[+] Found discrete logarithm 25870 for factor 56369
[+] Found discrete logarithm 52801 for factor 57301
[+] Found discrete logarithm 26868 for factor 65063
[+] Found discrete logarithm 60997 for factor 111659
[+] Found discrete logarithm 95883 for factor 113111
[+] Recovered k from CRT: 1347455424744677257745571369218247
[+] Recovered k2 from Pohlig-Hellman: 1347455424744677257745571369218247
[+] Brute forcing remaining bits of kB (step: 4374617177662805965808447230529629)....
[+] FOUND kB: 153712271226962757897869155910488792420
[+] Secret key #2 x: 9285933189458587360370996409965684516994278319709076885861327850062567211786910941012004843231232528920376385508032
[+] Secret key #2 y: 380692327439186423832217831462830789200626503899948375582964334293932372864029888872966411054442434800585116270210
[+] Program finished successfully. Bye bye :)

real    4m12.434s
user    4m12.209s
sys 0m0.199s
"""
# ----------------------------------------------------------------------------------------
