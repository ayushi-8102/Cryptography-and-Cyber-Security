#include <stdio.h>
#include <ctype.h>

// Function to encrypt text with Caesar Cipher
char* encrypt(char* text, int s) {
  char* result = malloc(strlen(text) + 1); // Allocate memory for encrypted text
  int i;

  // Traverse the text
  for (i = 0; text[i] != '\0'; i++) {
    // Apply transformation to each character
    if (isupper(text[i])) {
      result[i] = (char)((text[i] - 'A' + s) % 26 + 'A');
    } else if (islower(text[i])) {
      result[i] = (char)((text[i] - 'a' + s) % 26 + 'a');
    } else {
      // Handle non-alphabetic characters (optional)
      result[i] = text[i];
    }
  }

  result[i] = '\0'; // Add null terminator

  return result;
}

int main() {
  char text[] = "ATTACKATONCE";
  int s = 4;

  printf("Text: %s\n", text);
  printf("Shift: %d\n", s);

  char* cipher = encrypt(text, s);
  printf("Cipher: %s\n", cipher);

  // Free allocated memory (important in C)
  free(cipher);

  return 0;
}
