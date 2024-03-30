#include <iostream>
#include <cstdlib> // rand
using u64 = uint64_t;
using u128 = __uint128_t;

// Function to calculate (base^exponent) % modulus
u64 modular_exponentiation(u64 base, u64 exponent, u64 modulus)
{
    u64 result = 1; // Initialize result
    base %= modulus; // Update base if it is more than or equal to modulus
    while (exponent)
    {
        // If exponent is odd, multiply base with result
        if (exponent & 1)
            result = (u128)result * base % modulus;
        // exponent must be even now, so we can halve it
        base = (u128)base * base % modulus;
        exponent >>= 1; // equivalent to exponent = exponent / 2;
    }
    return result;
}

// Function to check if n is composite (not prime)
bool check_composite(u64 n, u64 witness, u64 d, int s)
{
    u64 x = modular_exponentiation(witness, d, n);
    // If x is 1 or n-1, n is probably prime
    if (x == 1 || x == n - 1)
        return false;
    // Repeat the test s times
    for (int r = 1; r < s; r++)
    {
        x = (u128)x * x % n;
        // If x becomes n-1, n is probably prime
        if (x == n - 1)
            return false;
    }
    // If we reach this point, n is composite
    return true;
}

// Function to perform the Miller-Rabin primality test
bool MillerRabinPrimalityTest(u64 n, int iterations = 5)
{
    // If n is less than 4, it is prime if it is 2 or 3
    if (n < 4)
        return n == 2 || n == 3;

    // Write (n - 1) as 2^s * d
    int s = 0;
    u64 d = n - 1;
    while ((d & 1) == 0)
    {
        d >>= 1;
        s++;
    }

    // Witness loop
    for (int i = 0; i < iterations; i++)
    {
        u64 witness = 2 + rand() % (n - 3);
        if (check_composite(n, witness, d, s))
            return false; // n is definitely composite
    }
    return true; // n is probably prime
}

int main()
{
    u64 number = 17374823743289074;
    bool isPrime = MillerRabinPrimalityTest(number);
    if (isPrime)
    {
        std::cout << number << " is prime." << std::endl;
    }
    else
    {
        std::cout << number << " is not prime." << std::endl;
    }
    return 0;
}
