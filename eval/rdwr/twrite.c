#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  int nr;
  int sleeptime = 0;
  long read_size=0;
  long count=0;

  if (argc > 1) {
     sscanf(argv[1], "%ld", &count);
     if (count == 0) {
        fprintf(stderr, "Usage: %s <num_reads> (default: 1000) "
                "<read_size> (default: 32 bytes)\n", argv[0]);
        exit(1);
     }
  }
  else count=1000;

  if (argc > 2) {
     sscanf(argv[2], "%ld", &read_size);
     if (read_size == 0) {
        fprintf(stderr, "Usage: %s <num_reads> (default: 1000) "
                "<read_size> (default: 32 bytes)\n", argv[0]);
        exit(1);
     }
  }
  else read_size=32;

  const char* stime;
  if ((stime = getenv("SLEEPTIME")))
    sscanf(stime, "%d", &sleeptime);
  if (sleeptime > 0)
    fprintf(stderr, "SLEEPTIME=%d microseconds\n", sleeptime);

  char *buf = malloc(read_size);

  while ((nr = read(0, buf, read_size)) > 0) {
    if (write(1, buf, nr) <= 0) {
       perror("Write error, exiting");
       exit(1);
    }
       
    if (sleeptime > 0)
      usleep(sleeptime);

    if (--count == 0) break;
  }
}
