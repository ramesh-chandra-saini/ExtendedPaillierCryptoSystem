# ExtendedPaillierCryptoSystem
------------------------------------------------------------------------------------------
                  Number Theory Project
          Implementation of Public-Key Cryptosystems 
          Based on Composite Degree Residuosity Classes
                  13CO237	Ramesh Chandra
            
------------------------------------------------------------------------------------------


This project investigates a novel computational problem, namely the Composite Residuosity Class Problem, and its applications to public-key cryptography. We propose a new trapdoor mechanism and derive from this technique three encryption schemes : a trapdoor permutation and two homomorphic probabilistic encryption schemes computationally comparable to RSA. The cryptosystems, based on usual modular arithmetics, are provably secure under appropriate assumptions in the 
standard model.

The technique conjugates the polynomial-time extraction of roots of polynomials over a finite field with the intractability of factoring large numbers. It is worthwhile 
pointing out that among cryptosystems belonging to this family, only Rabin- Williams has been proven equivalent to the factoring problem so far.

Performance evaluations. For each |n| = 512, · · · , 2048, the modular multiplication of bitsize |n| is taken as the unitary operation, we assume that the execution time of a modular multiplication is quadratic in the operand size and that modular squares are computed by the same routine. Chinese remaindering, as well as random number generation for probabilistic schemes, is considered to be negligible. The RSA public exponent is taken equal to F4 = 2^16 + 1. The parameter g is set to 2 in our main scheme, as well as in the trapdoor permutation. Other parameters, secret exponents or messages are assumed to contain about the same number of ones and zeroes in their binary representation.
