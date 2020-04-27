#include <stdio.h>
#include <wchar.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
   /* Close stderr */
   close(2);

   /* Output long string */
   const int sz = 4096;
   wchar_t *buff = calloc(sz+1, sizeof *buff);
   for (int i=0; i < sz; i++) buff[i] = L'x';
   fputws(buff, stderr);

   /* Output shorter string */
   for (int i=0; i < 1024; i++) {
     fputws(L"0123456789ABCDEF", stderr);

     /* Call malloc, which should not crash.
        However it will if malloc's function pointers
        have been stomped. */
     free(malloc(1));
   }
   return 0;
}