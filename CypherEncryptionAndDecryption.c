



#include <stdio.h>

#define SIZE 50	  // plaintext size
#define ROWS 5	  // the size of row of the playfair matrix
#define COLUMNS 5 // the size of columms of the playfair matrix
#define affinekey1 11 // alpha key for affine cypher
#define affinekey2 15  // beta key for affine cypher
#define shiftkey 12 // key for shift cypher anything between 0 to 25
#define  ALPHABET_SIZE 26 //there are 26 letters in the alphabet

// function for creating grid a 5X5 Matrix
void KeyTable(char key[], int ks, char keyT[5][5])
{
	int i, j, k, flag = 0, *dicty;
	dicty = (int *)calloc(26, sizeof(int));
	for (i = 0; i < ks; i++)
	{
		if (key[i] != 'j')
			dicty[key[i] - 97] = 2;
	}
	dicty['j' - 97] = 1;
	i = 0;
	j = 0;
	for (k = 0; k < ks; k++)
	{
		if (dicty[key[k] - 97] == 2)
		{
			dicty[key[k] - 97] -= 1;
			keyT[i][j] = key[k];
			j++;
			if (j == 5)
			{
				i++;
				j = 0;
			}
		}
	}
	for (k = 0; k < 26; k++)
	{
		if (dicty[k] == 0)
		{
			keyT[i][j] = (char)(k + 97);
			j++;

			if (j == 5)
			{
				i++;
				j = 0;
			}
		}
	}
}

// find_letter letter in grid put column number and row number in to array (arr[])
void find_letter(char keyT[5][5], char a, char b, int arr[])
{
	int i, j;
	if (a == 'j')
		a = 'i';
	else if (b == 'j')
		b = 'i';
	for (i = 0; i < 5; i++)
	{
		for (j = 0; j < 5; j++)
		{
			if (keyT[i][j] == a)
			{
				arr[0] = i;
				arr[1] = j;
			}
			else if (keyT[i][j] == b)
			{
				arr[2] = i;
				arr[3] = j;
			}
		}
	}
}
// function for find modulo operation of a values
int mudulo_func(int x, int y)
{
	if (x >= 0)
		return (x) % y;

	return mudulo_func(y + x, y);
}
// function to check the lenght of plain text if odd add the char "x"
int edge_check(char str[], int ptrs)
{
	if (ptrs % 2 != 0)
	{
		str[ptrs++] = 'x';
		str[ptrs] = '\0';
	}
	return ptrs;
}

// function for encrypt inputs(character array needs to convert, generated key matrix , converted plain text lenght)
void encrypt(char str[], char keyT[5][5], int ps)
{
	int i, a[4];
	for (i = 0; i < ps; i += 2)
	{
		find_letter(keyT, str[i], str[i + 1], a);
		if (a[0] == a[2])
		{
			str[i] = keyT[a[0]][mudulo_func(a[1] + 1, 5)];
			str[i + 1] = keyT[a[0]][mudulo_func(a[3] + 1, 5)];
		}
		else if (a[1] == a[3])
		{
			str[i] = keyT[mudulo_func(a[0] + 1, 5)][a[1]];
			str[i + 1] = keyT[mudulo_func(a[2] + 1, 5)][a[1]];
		}
		else
		{
			str[i] = keyT[a[0]][a[3]];
			str[i + 1] = keyT[a[2]][a[1]];
		}
	}
}
void Playfair_Encryption(char str[], char key[])
{
	char ps, ks, keyT[5][5];
	ks = strlen(key);
	ps = strlen(str);
	ps = edge_check(str, ps);
	KeyTable(key, ks, keyT);
	// showMatrix(key, ks, keyT);
	printf("Delta generated after converting j to i and checking all the edge test cases : (Task 2) %s \n\n", str);
	printf("Generated 5X5 matrix is (Task 5:): \n\n");
	for (int i = 0; i < 5; i++)
	{
		for (int j = 0; j < 5; j++)
		{
			printf("%c ", keyT[i][j]);
		}
		printf("\n");
	}
	encrypt(str, keyT, ps);
}
void decrypt(char str[], char keyT[5][5], int ps)
{
	int i, a[4];
	for (i = 0; i < ps; i += 2)
	{
		find_letter(keyT, str[i], str[i + 1], a);
		if (a[0] == a[2])
		{
			str[i] = keyT[a[0]][mudulo_func(a[1] - 1, 5)];
			str[i + 1] = keyT[a[0]][mudulo_func(a[3] - 1, 5)];
		}
		else if (a[1] == a[3])
		{
			str[i] = keyT[mudulo_func(a[0] - 1, 5)][a[1]];
			str[i + 1] = keyT[mudulo_func(a[2] - 1, 5)][a[1]];
		}
		else
		{
			str[i] = keyT[a[0]][a[3]];
			str[i + 1] = keyT[a[2]][a[1]];
		}
	}
}
void Playfair_decryption(char str[], char key[])
{
	char ps, ks, keyT[5][5];
	ks = strlen(key);
	ps = strlen(str);
	KeyTable(key, ks, keyT);
	decrypt(str, keyT, ps);
}

// function for encrypt inputs by Affine Cypher(character array needs to convert, alpha key =11, beta key =15)
void Affine_Encryption(char *plaintext, int a, int b)
{
	int i;
    for (i = 0; plaintext[i] != '\0'; i++) {
        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            plaintext[i] = (((plaintext[i] - 'a') * a) + b) % ALPHABET_SIZE + 'a';
        }
    }
}
// function for decrypt inputs by Affine Cypher(character array needs to convert, alpha key =11, beta key =15)

void Affine_Decryption(char *ciphertext, int a, int b)

{
	 int i;
    int a_inv = 0;
    for (i = 0; i < ALPHABET_SIZE; i++) {
        if ((a * i) % ALPHABET_SIZE == 1) {
            a_inv = i;
            break;
        }
    }
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            ciphertext[i] = (((ciphertext[i] - 'a' - b) * a_inv) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE + 'a';
        }
    }
}
void shift_encryption(char *ch, char *res, int key)
{

	int i;

	// for loop for convert characters in input char array(encrypt)
	// shift characters by value of key(in shift key = 12)
	for (i = 0; i < strlen(ch); i++)
	{

		// encrypt lower case letters
		 if (ch[i] >= 'a' && ch[i] <= 'z')
		{
			if (ch[i] + key > 'z')
				res[i] = 'a' - 1 + ch[i] + key - 'z';
			else
				res[i] = ch[i] + key;
		}
		else
		{
			// if character is not in alphabet
			// will not encrypt
			res[i] = ch[i];
		}
	}
	res[i] = '\0';
}

void shift_Decryption(char *ch, char *res, int key)
{

	int i;

	// for loop for convert characters in input char array(decrypt)
	// shift characters by value of key(in casesarcipher key = 3)
	for (i = 0; i < strlen(ch); i++)
	{
		// res[i] = (ch[i] - key)mod 26
		// In here im not going to use modulo oparetion
		//  (character - key) have 2 cases
		 if (ch[i] >= 'a' && ch[i] <= 'z')
		{
			if (ch[i] - key < 'a')
				res[i] = 'z' + 1 - ('a' - (ch[i] - key));
			else
				res[i] = ch[i] - key;
		}
		else
		{
			res[i] = ch[i];
		}
	}
	res[i] = '\0';
}


void main()
{
	char str[SIZE], key[SIZE], astr[SIZE];
    printf("------AYUSHI SHUKLA 202051044---------");
  printf("\n\n");
	printf("Enter plain text without any space (Task 1):");
	scanf("%s", &str);
  printf("\n");
	printf("Enter your key:(Task 3) ");
	scanf("%s", &key);
  printf("\n\n");
	printf("--------Encryption by all three ciphers------------ \n ");
  printf("\n\n");
	Playfair_Encryption(str, key);
  printf("\n\n");
	printf("PlayFair Cypher encrpyted text with key(Task 6): %s : %s\n", key, str);
  printf("\n\n");
  Affine_Encryption(str, affinekey1, affinekey2);
	printf("Affine Cypher encrypted text with alpha key(11) and beta key (15) (Task 7): %s \n", str);
	printf("\n\n");
    shift_encryption(str, str, shiftkey);
  
	printf("shift Cypher encrpyted text with key (12) (Task 8) : %s \n", str);
	printf("\n\n");
  printf("\n\n");
    
    
	printf("\n --------Decrypting The following Results------------ \n ");
    
shift_Decryption(str, str, shiftkey);
	printf("shift Cypher decrpyted text with key (12): %s \n", str);
  printf("\n\n");
	Affine_Decryption(str, affinekey1, affinekey2);
	printf("Affine Cypher decrypted text with alpha key(11) and beta key (15): %s \n", str);
printf("\n\n");
	Playfair_decryption(str, key);
	printf("playfair Cypher decrypted text with key %s (Oringal plaintext): %s \n", key, str);
  printf("\n\n");
  printf("-----THE END--------");
}
