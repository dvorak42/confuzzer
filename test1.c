#include <stdio.h>
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

int main(void)
{
  char key[] = "magic";
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
    return 1;
    //printf("Wrong %d.\n", strcmp(key, r));
  }
  return 0;
}
