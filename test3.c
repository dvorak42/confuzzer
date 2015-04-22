#include <stdio.h>
#include <fcntl.h>

int strcmp(char* a, char* b) {
  while((*a == *b) && (*a != '\0')) {
    a++;
    b++;
  }
  return *a - *b;
}

int main(void)
{
  char buf[16] = {0};
  char* files[4] = {0};
  int fd = 0;
  int indx = 0;
  int i,j = 0;
  char *r = buf;
  fd = open("script.txt", O_RDONLY);
  read(fd, r, 16);
  close(fd);

  for(i = 0; i < 16; i++) {
    if(strcmp((char*)&buf[i], "l") == 0) {
      for(j = 0; j < indx; j++) {
	printf("file%d\n", j);
      }
    } else if(strcmp((char*)&buf[i], "w") == 0) {
      files[indx] = "WRITTEN";
      indx += 1;
    } else if(strcmp((char*)&buf[i], "d") == 0) {
      for(j = 0; j < indx; j++) {
	printf("file%d:\n\t%s\n", j, (char*)&files[j]);
      }

    }
  }
  return 0;
}
