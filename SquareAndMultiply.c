#include <stdio.h>

int main() {
    int base, exponent;
    printf("Enter the base number: ");
    scanf("%d", &base);
    printf("Enter the exponent: ");
    scanf("%d", &exponent);
    if (exponent < 0) {
        printf("Error: Exponent cannot be negative.\n");
        return 1;
    }
    long long result = 1;
    for (int i = 0; i <= 31; i++) { 
        result *= result; 
        int bit = exponent & (1 << i);
        if (bit) {
            result *= base;  // Multiply by the base if the bit is 1
        }
    }
    printf("%d ^ %d = %lld\n", base, exponent, result);

    return 0;
}
