#include <stdio.h>
#include <fcntl.h>

int main(void)
{
  int NC = 4;
  char buf[NC];
  char* files[256] = {0};
  int fd = 0;
  int indx = 0;
  int i,j = 0;
  char *r = buf;
  fd = open("script.txt", O_RDONLY);
  read(fd, r, NC);
  close(fd);

  for(i = 0; i < NC; i++) {
    if(buf[i] == 'l') {
      for(j = 0; j < indx; j++) {
	printf("file%d\n", j);
      }
    } else if(buf[i] == 'w') {
      files[256*indx] = "WRITTEN";
      indx += 1;
    } else if(buf[i] == 'd') {
      for(j = 0; j < indx; j++) {
	printf("file%d:\n\t%s\n", j, files[256*j]);
      }

    }
  }
  return 0;
}
