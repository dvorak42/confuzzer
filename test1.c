#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>

int strcmp2(char* a, char* b) {
  while((*a == *b) && (*a != '\0')) {
    a++;
    b++;
  }
  return *a - *b;
}


int strcmp3(const char* s1, const char* s2)
{
    while(*s1 && (*s1==*s2))
        s1++,s2++;
    return *(const unsigned char*)s1-*(const unsigned char*)s2;
}
int main(void)
{
  char key[] = "magic";
  char key2[] = "cigam";
  int fd = 0;
  char buf[16] = {0};
  char *r = buf;

  fd = open("key.txt", O_RDONLY);
  read(fd, r, 16);
  close(fd);

  if(strcmp2(key, r) == 0) {
    printf("Success!\n");
    return 0;
    //printf("Correct!\n");
  } else {
    if(strcmp2(key2, r) == 0) {
      char ptr[1] = {0};
      strcpy(ptr, "cigamcigamcigam");
      if(strcmp2(ptr, r) == 0) {
	return 2;
      }
    }
    //printf("Wrong %d. %s\n", strcmp3(key, r), ptr);
    return 1;
  }
  return 0;
}
