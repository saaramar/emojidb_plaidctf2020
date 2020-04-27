#include <stdio.h>
#include <locale.h>
#include <stdlib.h>

int main(void) {
  setlocale(0, "en_US.UTF-8");
  unsigned char out[0x10] = {0};
  unsigned char in[0x10] = {0};

  read(0, in, 8);
  wcstombs(out, (wchar_t*)in, 0x10);
  write(1, out, 0x10);

  return 0;
}