//References: 
//[1] Pascal Paillier, "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes," EUROCRYPT'99.
//[2] Introduction to Paillier cryptosystem from Wikipedia.


/****************************************Standard Paillier Encryption System***********************************************************/
/*
* Algorithm : 
*
* The scheme works as follows:
*
* Key generation
*
* 1). Choose two large prime numbers p and q randomly and independently of each other such that gcd(pq, (p-1)(q-1))=1.
*          This property is assured if both primes are of equal length.
*
* 2). Compute n=p.q and lambda=lcm(p-1,q-1).
*
* 3).Select random integer g where g belongs  Z*_n^2
*
* 4).Ensure n divides the order of g by checking the existence of the following modular multiplicative inverse: 
*		mu = (L(g^lambda mod n^2))^(-1) mod n,
*                  where function L is defined as L(u) = (u-1)/(n) , Legendre Symbol.
*
* 5).Note that the notation (a/b)[Legendre Symbol] does not denote the modular multiplication of a times the modular 
*     multiplicative inverse of b but rather the quotient of a divided by b.
* 
* 6). The public (encryption) key is (n, g).
*
* 7). The private (decryption) key is (lambda, mu).
*
* 8).If using p,q of equivalent length, a simpler variant of the above key generation steps would be to set g = n+1, 
*               lambda = phi(n), and mu = phi(n)^(-1) mod n, where phi(n) = (p-1)(q-1) 
*
*
* Encryption
*
* 1). Let m be a message to be encrypted where m belongs to Z_n
*
* 2). Select random r where r belong Z*_n 
*
* 3). Compute ciphertext as:  c=g^m.r^n mod n^2 
*
*
* Decryption
*
* 1). Let c be the ciphertext to decrypt, where c belongs to  Z_n^2
* 
* 2). Compute the plaintext message as: m = L(c^lambda mod n^2) * mu mod n
*
*
*	Time Complexity : O(|N|^2*|lambda|)
*
*/



/****************************************Modified Paillier Encryption System***********************************************************/

/*
* Algorithm : 
*
* The scheme works as follows:
*
* Key generation
*
* 1). Choose two large prime numbers p and q randomly and independently of each other such that gcd(pq, (p-1)(q-1))=1.
*          This property is assured if both primes are of equal length.
*
* 2). Compute n=p.q and lambda=lcm(p-1,q-1).
*
* 3).Select random integer h where h belongs  Z*_n^2
*
* 4).Ensure n divides the order of h by checking the existence of the following modular multiplicative inverse: 
*		mu = (L(g^lambda mod n^2))^(-1) mod n,
*                  where function L is defined as L(u) = (u-1)/(n) , Legendre Symbol.
*
* 5).Note that the notation (a/b)[Legendre Symbol] does not denote the modular multiplication of a times the modular 
*     multiplicative inverse of b but rather the quotient of a divided by b.
* 
* 6). calculate  g = pow(h,(lambda/alpha) ) mod n^2
*
* 7). The public (encryption) key is (n, g).
*
* 8). The private (decryption) key is (alpha).
*
* 9).If using p,q of equivalent length, a simpler variant of the above key generation steps would be to set h = n+1, 
*               lambda = phi(n), and mu = phi(n)^(-1) mod n, where phi(n) = (p-1)(q-1) 
*
*
* Encryption
*
* 1). Let m be a message to be encrypted where m belongs to Z_n
*
* 2). Select random r where r belong Z*_n 
*
* 3). Compute ciphertext as:  c=g^(m+n*r) mod n^2 
*
*
* Decryption
*
* 1). Let c be the ciphertext to decrypt, where c belongs to  Z_n^2
* 
* 2). Compute the plaintext message as: m = L(c^alpha mod n^2) * ( ( g^alpha mod n^2)^(-1) ) mod n
*
*  Time Complexity : O(|N|^2*|alpha|)
*
*/


/*
*****************
*  Source Code  *
*****************
*/

//used for mathematical operation
import java.math.*;

//used for Arrays implementation
import java.util.Arrays;

//for generating random number
import java.util.Random;

//interaction with user and machine
import java.util.Scanner;

//perform input and output stuff
import java.io.*;

//used for 
import java.math.BigInteger;

//calculating running time of algo
//import java.time;
//following Package class contain version information 
//about the implementation and specification of a Java package
import java.lang.*;



public class Paillier {

	/**
	* p and q are two large primes. 
	* lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1).
	*/
	
	private BigInteger p, q, lambda;
	private BigInteger alpha,h;
	private int l = 320;//typical bit length
	
	/**
	* n = p*q, where p and q are two large primes.
	*/
	
	public BigInteger n;


	/**
	* nsquare = n*n
	*/

	public BigInteger nsquare;

	
	/**
	* a random integer in Z*_(n^2) where gcd (L(g^lambda mod n^2), n) = 1.
	*/

	private BigInteger g;

	
	/**
	* number of bits of modulus
	*/

	private int bitLength;


	/**
	* Constructs an instance of the Paillier cryptosystem.
	* @param bitLengthVal number of bits of modulus
	* @param certainty The probability that the new BigInteger 
	* represents a prime number will exceed (1 - 2^(-certainty)). 
	* The execution time of this constructor is proportional to the 
	*value of this parameter.
	*/

	public Paillier(int bitLengthVal, int certainty) {


		KeyGeneration(bitLengthVal, certainty);

	}


	/**
	* Constructs an instance of the Paillier cryptosystem with 512
	* bits of modulus and 
	* at least 1-2^(-64) certainty of primes generation.
	*/

	public Paillier() {
	
		KeyGeneration(512, 64);
		mKeyGeneration(512,64);
	
	}

	
	/**
	* Sets up the public key and private key.
	* @param bitLengthVal number of bits of modulus.
	* @param certainty The probability that the new BigInteger
	* represents a prime number 
	*will exceed (1 - 2^(-certainty)). The execution time of 
	*this constructor is proportional 
	*to the value of this parameter.
	*/
	
	public void KeyGeneration(int bitLengthVal, int certainty) {

		bitLength = bitLengthVal;
		
	
		/*Constructs two randomly generated positive BigIntegers
		* that are probably prime, with the specified bitLength 
		and certainty.*/
	
		p = new BigInteger(bitLength / 2, certainty, new Random());

		q = new BigInteger(bitLength / 2, certainty, new Random());

		n = p.multiply(q);
		
		nsquare = n.multiply(n);

		g = new BigInteger("2");

        //lambda = lcm( (p-1) , (q-1) )
        //
        //          ( (p-1)*(q-1) ) 
        // lambda= ----------------------
        //          gcd( (p-1),(q-1) )
		
		
		lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(
						BigInteger.ONE)).divide(p.subtract(
						BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
						

		/* check whether g is good.*/
		
		if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).
				divide(n).gcd(n).intValue() != 1) {
				
				System.out.println("g is not good. Choose g again.");
				
				System.exit(1);
		}
    }
	/**
	* Sets up the public key and private key.
	* @param bitLengthVal number of bits of modulus.
	* @param certainty The probability that the new BigInteger
	* represents a prime number 
	*will exceed (1 - 2^(-certainty)). The execution time of 
	*this constructor is proportional 
	*to the value of this parameter.
	*/
	
	public void mKeyGeneration(int bitLengthVal, int certainty) {

		bitLength = bitLengthVal;
		
	
		/*Constructs two randomly generated positive BigIntegers
		* that are probably prime, with the specified bitLength 
		and certainty.*/
	
		p = new BigInteger(bitLength / 2, certainty, new Random());

		q = new BigInteger(bitLength / 2, certainty, new Random());

		n = p.multiply(q);
		
		nsquare = n.multiply(n);
   //lambda = lcm( (p-1) , (q-1) )
        //
        //          ( (p-1)*(q-1) ) 
        // lambda= ----------------------
        //          gcd( (p-1),(q-1) )
		
		
		lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(
						BigInteger.ONE)).divide(p.subtract(
						BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
			
			//System.out.println("lambda"+alpha);
		do{
			//alpha = new BigInteger(l,new Random());
			alpha = new BigInteger(320, new Random());
			alpha = p.subtract(BigInteger.ONE);
            //System.out.println("alpha divides lambda"+alpha);
			
		} while(lambda.mod(alpha)!= BigInteger.ZERO && lambda.compareTo(alpha) != 0 );
		
		
		h = new BigInteger("2");
    
        g = new BigInteger("0");
        g=h.modPow( lambda.divide(alpha) , nsquare).mod(nsquare);
        
        
     			

		/* check whether g is good.*/
		
		if (h.modPow(lambda, nsquare).subtract(BigInteger.ONE).
				divide(n).gcd(n).intValue() != 1) {
				
				System.out.println("g is not good. Choose g again.");
				
				System.exit(1);
		}
	
	}


/**
* Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. 
* This function explicitly requires random input r to help 
* with encryption.
* @param m plaintext as a BigInteger
* @param r random plaintext to help with encryption
* @return ciphertext as a BigInteger
*/

public BigInteger Encryption(BigInteger m, BigInteger r) {
    
    //Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. 
    
	return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).
									mod(nsquare);
}


/**
* Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. 
* This function automatically generates random input r 
*(to help with encryption).
* @param m plaintext as a BigInteger
* @return ciphertext as a BigInteger
*/

public BigInteger Encryption(BigInteger m) {

    //generate random number
	BigInteger r = new BigInteger(bitLength, new Random());
	
	//Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. 
	return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

}


/**
* Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n,
* where u = (L(g^lambda mod n^2))^(-1) mod n.
* @param c ciphertext as a BigInteger
* @return plaintext as a BigInteger
*/

public BigInteger Decryption(BigInteger c) {


/*
*    c =  cipher text

                              ( c^lambda -1 )
                              ---------------  mod(n^2)
                                    n
 message =             -----------------------------------   mod (n)
                             ( g^lambda - 1)
                            ----------------  mod(n^2)
                                    n     

                           L(c^lambda mode n^2 )
          =             -------------------------- mod(n)
                           L(g^lambda mode n^2 )

  
          =       L(c^lambda mode n^2 ) * ( L(g^lambda mode n^2 )^ (-1) ) mod (n)
          
*/
	BigInteger mu = g.modPow(lambda, nsquare).subtract(BigInteger.ONE)
								.divide(n).modInverse(n);
	return c.modPow(lambda, nsquare).subtract(BigInteger.ONE)
							.divide(n).multiply(mu).mod(n);
}


/**
* Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. 
* This function explicitly requires random input r to help 
* with encryption.
* @param m plaintext as a BigInteger
* @param r random plaintext to help with encryption
* @return ciphertext as a BigInteger
*/

public BigInteger mEncryption(BigInteger m, BigInteger r) {
    
									int result;
	//ramdom number should always less than  2^l
	BigInteger checker = new BigInteger("2");
	        checker = checker.pow(l);
	/*
	*    create int object
    *    int result;
    *
    *   compare checker with r
	*   result = checker.compareTo(r);
    *
    *  String str1 = "Both values are equal ";
	*  String str2 = "First Value is greater ";
	*  String str3 = "Second value is greater";
    *
	*  if( result == 0 ) 
	*		System.out.println( str1 );
	*  else if( result == 1 )
	*		System.out.println( str2 );
	*  else if( res == -1 )
	*		System.out.println( str3 );
	*/
	
    //generate random number

			result = r.compareTo(checker);
	
	if(result  != -1 ){
		System.out.println("Selection of r is not good, r should always less than pow(2,l) {informally less than alpha}");
		return BigInteger.ZERO;
	}
	
	//Encrypts plaintext m. ciphertext c = g^(m + n*r) mod n^2. 
	return g.modPow(m.add(n.multiply(r) ), nsquare).mod(nsquare);

}


/**
* Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. 
* This function automatically generates random input r 
*(to help with encryption).
* @param m plaintext as a BigInteger
* @return ciphertext as a BigInteger
*/

public BigInteger mEncryption(BigInteger m) {

	int result;
	//ramdom number should always less than  2^l
	BigInteger checker = new BigInteger("2");
	        checker = checker.pow(l);
	
	/*
	*    create int object
    *    int result;
    *
    *   compare checker with r
	*   result = checker.compareTo(r);
    *
    *  String str1 = "Both values are equal ";
	*  String str2 = "First Value is greater ";
	*  String str3 = "Second value is greater";
    *
	*  if( result == 0 ) 
	*		System.out.println( str1 );
	*  else if( result == 1 )
	*		System.out.println( str2 );
	*  else if( res == -1 )
	*		System.out.println( str3 );
	*/
	
    //generate random number
	BigInteger r;
	do{
		 //generate random number
			r = new BigInteger(l, new Random());
			result = r.compareTo(checker);
			//System.out.println("r<pow(2^l)");
	
	} while(result != -1 );
	
	//Encrypts plaintext m. ciphertext c = g^(m + n*r) mod n^2. 
	return g.modPow(m.add(n.multiply(r) ), nsquare).mod(nsquare);

}


/**
* Decrypts ciphertext c. plaintext m = L(c^alpha mod n^2) * u mod n,
* where u = (L(g^alpha mod n^2))^(-1) mod n.
* @param c ciphertext as a BigInteger
* @return plaintext as a BigInteger
*/
public BigInteger mDecryption(BigInteger c) {


/*
*    c =  cipher text

                              ( c^alpha -1 )
                              ---------------  mod(n^2)
                                    n
 message =             -----------------------------------   mod (n)
                             ( g^alpha - 1)
                            ----------------  mod(n^2)
                                    n     

                           L(c^alpha mode n^2 )
          =             -------------------------- mod(n)
                           L(g^alpha mode n^2 )

  
          =       L(c^alpha mode n^2 ) * ( L(g^alpha mode n^2 )^ (-1) ) mod (n)
          
*/
   System.out.println(alpha);
   System.out.println(g);
	BigInteger mu = g.modPow(alpha, nsquare).subtract(BigInteger.ONE)
								.divide(n).modInverse(n);
	return c.modPow(alpha, nsquare).subtract(BigInteger.ONE)
							.divide(n).multiply(mu).mod(n);
}

/**
* main function
* @param str intput string
*/

public static void main(String[] str) {
	
	
	/* Allow user to provide input System*/
	
	String message1,message2;
	System.out.print("******************************************************");
	System.out.println("************************************************************************");
	System.out.print("*   Problem: This code is solution to perform arithmatic operation on data");
	System.out.println(" at cloud without decrypting actual value of data  *");
    System.out.print("********************************************************************");
    System.out.println("**********************************************************\n");
	
	/*System.out.printf("Assume user have integer value(A) of some parameter stored on 
	cloud in encrypted form(XX) and user want to add or multiply integer value(B)\n");*/
	
	System.out.printf("Two solution to perform Arithmatic Operation \n\t");
	System.out.printf("1).get data(XX) from cloud and decrypt  it into A,then add data(B) again encrypt it and store to cloud\n"); 
	
	System.out.printf("\t2). simple encrypt data(B) and add to A, if user has used this encryption system\n");
	/* instantiating an object of Paillier cryptosystem*/

	Scanner inp = new Scanner(System.in);
	
	System.out.println("Enter Two Integer Values : ");
	
	System.out.print("First Value : ");
	message1 = inp.nextLine();
	 
	System.out.print("Second Value : ");
	message2 = inp.nextLine();
	
	//System.out.print("\n\n******************************************\n");
	System.out.print("\n***************  Real Messages   **********\n");
	//System.out.print("********************************************\n\n");
	
	//System.out.println("Entered Integer Value\n");
	
	System.out.println("First Value : "+message1);
	 
	System.out.println("Second Value : "+message2);

	long startTime=0,endTime=0,duration=0,mStartTime=0,mEndTime=0,mDuration=0;
	
		
	int choice;
	do{
		System.out.println("Option(To run different Encryption System )");
		System.out.println("\t1).Standard Paillier Encryption System");
		System.out.println("\t2).Modified Paillier Encryption System");
		System.out.println("\t3).RunTime Comparision Report of Both System");
		System.out.println("\t0).To stop Program(Exit)");
	    System.out.println("Enter your choice");
		Scanner in = new  Scanner(System.in);
		choice = in.nextInt();
		
		switch(choice) {
		
			case 0 :
					System.out.println("Program Stopped By User");
			break;
			case 1 :
	startTime = System.nanoTime();
	
		System.out.println("**************************Standard Paillier Encryption System**************************************");
	//methodToTime();
					
	Paillier paillier = new Paillier();
	
	/* instantiating two plaintext msgs*/
	
	//convert first message to BigInteger
	BigInteger m1 = new BigInteger(message1);
	
	//convert second message to BigInteger
	BigInteger m2 = new BigInteger(message2);
	
	/* encryption*/
	
	//perform Paillier Encryption on first message
	BigInteger em1 = paillier.Encryption(m1);

    //perform Paillier Encryption on second message
	BigInteger em2 = paillier.Encryption(m2);

	/* printout encrypted text*/
		
	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Encrypted Messages   **********\n");
	//System.out.print("**********************************************\n\n");
	
	System.out.println("Encrypted text of :"+message1);
	System.out.println(em1);
	
	System.out.println("Encrypted text of :"+message2);
	System.out.println(em2);
	
	/* printout decrypted text */
	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Decrypted Messages   **********\n");
	//System.out.print("**********************************************\n\n");
	
	System.out.println("Decrypted text of Encrypted text : "+message1);
	
	//perform decryption and print it to console 
	System.out.println(paillier.Decryption(em1).toString());
	
	System.out.println("Decrypted text of Encrypted text : "+message2);
	
	//perform decryption and print it to console
	System.out.println(paillier.Decryption(em2).toString());

	/* test homomorphic properties -> 
	* D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n */
	
	//perform multiplication on encrypted text to get sum
	BigInteger product_em1em2 = em1.multiply(em2).mod(paillier.nsquare);
	
	//perform addition on real value and check against encrypted sum value 
	BigInteger sum_m1m2 = m1.add(m2).mod(paillier.n);
	
	//System.out.print("\n\n********************************************\n");
	System.out.print("***************  Original Sum ***************\n");
	//System.out.print("\n**********************************************\n\n");
	
	System.out.println("original sum: " + 
								sum_m1m2.toString());
	
	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Decrypted Sum ***************\n");
	//System.out.print("**********************************************\n\n");
	
	System.out.println("decrypted sum: " +
					 paillier.Decryption(product_em1em2).toString());

	/* test homomorphic properties ->
	* D(E(m1)^m2 mod n^2) = (m1*m2) mod n */
	
	//perform power operation on encrypted message  
	BigInteger expo_em1m2 = em1.modPow(m2, paillier.nsquare);
	
	//perform multiplication and check against required
	BigInteger prod_m1m2 = m1.multiply(m2).mod(paillier.n);


	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Original Product ***************\n");
	//System.out.print("**********************************************\n\n");
	System.out.println("original product: " + 
									prod_m1m2.toString());
	
	
	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Decrypted Sum ***************\n");
	//System.out.print("**********************************************\n\n");
	System.out.println("decrypted product: " + 
					paillier.Decryption(expo_em1m2).toString());


	endTime = System.nanoTime();

    duration = (endTime - startTime);					

	//System.out.print(duration);

		
			break;
			
			case 2 :
    mStartTime = System.nanoTime();

	/*Implement Modified Encryption System*/
	System.out.println("**************************Modified Paillier Encryption System**************************************");
	Paillier mpaillier = new Paillier();
	
	/* instantiating two plaintext msgs*/
	
	//convert first message to BigInteger
	 		m1 = new BigInteger(message1);
	
	//convert second message to BigInteger
			 m2 = new BigInteger(message2);
	
	/* encryption*/
	
	//perform Paillier Encryption on first message
			em1 =  mpaillier.mEncryption(m1);

    //perform Paillier Encryption on second message
			 em2 =  mpaillier.mEncryption(m2);

	/* printout encrypted text*/
		
	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Encrypted Messages   **********\n");
	//System.out.print("**********************************************\n\n");
	
	System.out.println("Encrypted text of :"+message1);
	System.out.println(em1);
	
	System.out.println("Encrypted text of :"+message2);
	System.out.println(em2);
	
	/* printout decrypted text */
	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Decrypted Messages   **********\n");
	//System.out.print("**********************************************\n\n");
	
	System.out.println("Decrypted text of Encrypted text : "+message1);
	
	//perform decryption and print it to console 
	System.out.println((mpaillier.mDecryption(em1).toString()));
	
	System.out.println("Encrypted text of Encrypted text : "+message2);
	
	//perform decryption and print it to console
	System.out.println((mpaillier.mDecryption(em2).toString()));

	/* test homomorphic properties -> 
	* D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n */
	
	//perform multiplication on encrypted text to get sum
			product_em1em2 = em1.multiply(em2).mod((mpaillier.nsquare));
	
	//perform addition on real value and check against encrypted sum value 
			sum_m1m2 = m1.add(m2).mod((mpaillier.n));
	
	//System.out.print("\n\n********************************************\n");
	System.out.print("***************  Original Sum ***************\n");
	//System.out.print("\n**********************************************\n\n");
	
	System.out.println("original sum: " + 
								sum_m1m2.toString());
	
	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Decrypted Sum ***************\n");
	//System.out.print("**********************************************\n\n");
	
	System.out.println("decrypted sum: " +
					  mpaillier.mDecryption(product_em1em2).toString());

	/* test homomorphic properties ->
	* D(E(m1)^m2 mod n^2) = (m1*m2) mod n */
	
	//perform power operation on encrypted message  
	 		expo_em1m2 = em1.modPow(m2,  mpaillier.nsquare);
	
	//perform multiplication and check against required
	 		prod_m1m2 = m1.multiply(m2).mod((mpaillier.n));


	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Original Product ***************\n");
	//System.out.print("**********************************************\n\n");
	System.out.println("original product: " + 
									prod_m1m2.toString());
	
	
	//System.out.print("\n\n********************************************\n");
	System.out.print("\n***************  Decrypted Sum ***************\n");
	//System.out.print("**********************************************\n\n");
	System.out.println("decrypted product: " + 
						mpaillier.mDecryption(expo_em1m2).toString());

	mEndTime = System.nanoTime();
	mDuration = (mEndTime-mStartTime);
	
				
			break;
			
			case 3 :
	System.out.println("**************Run Time Report (Nano Seconds)*******************");					
	System.out.printf("Run Time  of Standard Sytem : "); System.out.println(duration);
	System.out.printf("Run Time  of Modified Sytem : "); System.out.println(mDuration);System.out.println();
			break;
			
			default :
				System.out.println("Invalid Option");
			break;
		}
	
	} while(choice!=0);
	
					
	
}

}
 /**********************************************The End of Source Code*********************************/
