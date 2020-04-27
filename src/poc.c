#include <stdio.h>
#include <wchar.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
  wchar_t buf[78];
  char *addr = (void*)malloc(0x1000);

  /* Close stderr */
  close(2);

  memset(buf, 0x41, sizeof(buf));

  fwprintf(stderr, 78, "%ws", buf);

  return 0;
}