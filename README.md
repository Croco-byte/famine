42 Project : Famine

# INTRODUCTION
This repository contains two viruses : Famine, and Strife.

To make Famine :
$ make

To make Strife :
$ make strife

Both of these viruses will infect every ELF64 file in the directories /tmp/test/ and /tmp/test2/ (PDC or PIC).

When infecting the target files, the virus actually COPIES ITSELF into the target file, and patches the entry
point of the file so that the virus will be executed when launching the infected binary. The infected file effectively
became a 'host' for the virus : each time the infected file executes, it will in its turn execute the virus and infect
other files.

Once infected, the behavior of the binaries will NOT CHANGE. After the virus executed itself in the infected file, it will
redirect the execution flow of the program to the original entry point of the ELF file.

If a file was already infected, the virus ignores it.

For the moment, the virus adds a "signature" to the file, applies a chmod 777 to it and replicate itself just as described above.


# FAMINE (777 bytes)
The 'Famine' virus will attempt to write the virus in the PADDING SPACE located at the end of the text segment (segments are aligned to PAGE_SIZE
in memory, for example 4096 bytes. It is pretty rare that the segment contains exactly a multiple of PAGE_SIZE, so some NULL BYTES of padding
are added).

If there isn't enough space in the gap to contain the virus, it will not inject and go to the next file. That's why I tried to make the smallest
virus possible, in order to infect as many files as possible. The size of Famine is 777 bytes. This is small enough to infect most of the files
(80% - 90% of files).

PROS :
	> This is pretty stealthy, since the size of the file stays the same before and after infection.
	> This is a robust method of infection. No matter the structure of the ELF file, if the padding space is big enough, it will infect correctly.
CONS :
	> Might leave a small proportion of file uninfected.


# Strife (1328 bytes)
The 'Strife' virus is a little more sophisticated. With this virus, if there is enough space in the padding gap, we will inject the virus
in it, just like Famine. However, if there isn't enough space, Strife will try to extend the target file by 4096 bytes, shift everything in
the file by 4096 bytes after the injection point, and use the free space generated to inject the virus.

PROS :
	> We are able to infect files that do not have enough padding gap.
CONS :
	> Will not be able to extend certain files compiled with 4 loadable segments because of virtual address overlap (recent compilers such as
	the one used at 42, privileging security over speed). For this kind of machine, Famine is better.
	> A bit less stealthy since we modify the size of the file.


