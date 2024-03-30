package ellcurves;

import java.math.BigInteger;
import java.util.Random;

public class LenstrasFactorization {
	
	// This method performs one step of Lenstra's factorization algorithm.
	public static BigInteger lenstraFactorizStep(BigInteger N, int LoopBound, EllCurvePoint P) {
		
		// Check if the modulus of the curve is equal to N.
		if(P.getCurve().getMod().compareTo(N) != 0) {
			System.out.println("Curve in Lenstra's Factorization must have mod equal to N");
			return null;
		}
		
		// Initialize Q as P.
		EllCurvePoint Q = P;
		
		// Perform the loop for the given loop bound.
		for(int i = 1; i < LoopBound; i++) {
			// Multiply Q by i.
			Q = Q.multiply(i);
			
			// Get the z-coordinate of Q and calculate its GCD with N.
			BigInteger z = Q.getCoords()[2];
			z = z.gcd(N);
			
			// If the GCD is not 1, return it as a factor of N.
			if(z.compareTo(BigInteger.ONE) != 0)
				return z;
		}
		
		// If no factor is found, return null.
		return null;
	}
	
	// This method generates a random point on an elliptic curve.
	public static EllCurvePoint randomEllCurvePoint(BigInteger mod) {
		
		// Get the number of bits in the modulus.
		int nBits = mod.bitLength();
		
		// Generate random x, y, and A values.
		BigInteger x = new BigInteger(nBits, new Random());
		x = x.mod(mod);
		
		BigInteger y = new BigInteger(nBits, new Random());
		y = y.mod(mod);
		
		BigInteger A = new BigInteger(nBits, new Random());
		A = A.mod(mod);
		
		// Calculate B such that (x, y) is a point on the curve y^2 = x^3 + Ax + B.
		BigInteger B = (y.multiply(y)).subtract(x.multiply(x).multiply(x)).subtract(A.multiply(x));
		B = B.mod(mod);
		
		// Create a new elliptic curve with the generated A and B values.
		EllCurve curve = new EllCurve(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, A, B, mod);
		
		// Return a new point on the curve.
		return new EllCurvePoint(x, y, curve);
	}
	
	// This method performs Lenstra's factorization algorithm.
	public static BigInteger lenstraFactoriz(BigInteger N, int loopBound, int nTries) {
		
		BigInteger factor = null;
		
		// Try to find a factor of N for the given number of tries.
		for(int n = 0; n < nTries; n++) {
		
			// Generate a random point on an elliptic curve.
			EllCurvePoint P = randomEllCurvePoint(N);
			
			// Perform one step of Lenstra's algorithm.
			factor = lenstraFactorizStep(N, loopBound, P);
			
			// If a factor is found, return it.
			if(factor != null)
				return factor;		
		}
			
		// If no factor is found after all tries, return null.
		return factor;
	}
	
	// The main method.
	public static void main(String[] args) {
		
		// The number to factorize.
		BigInteger N = new BigInteger("120");
				
		// Perform Lenstra's factorization algorithm.
		BigInteger factor1 = lenstraFactoriz(N, 1000, 1000000);			
			
		// If a factor is found, print it.
		if(factor1 != null) {
			BigInteger factor2 = N.divide(factor1);
			
			System.out.print(N);
			System.out.print(" = ");
			System.out.print(factor1);
			System.out.print(" * ");
			System.out.print(factor2);
		}
		else
			System.out.println("Factor not found.");
	}
}
