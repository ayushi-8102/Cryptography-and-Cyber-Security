#include <stdio.h>
#include <string.h>
void secret() {
printf("You have successfully executed the secret
function!\n");
}
void vulnerable_function(char *input) { char
buffer[64];
strcpy(buffer, input);
printf("Buffer content: %s\n", buffer);
}

int main(int argc, char *argv[]) { if (argc != 2)
{ printf("Usage: %s <input>\n", argv[0]);
return 1;
}
vulnerable_function(argv[1]);
return 0;
}
