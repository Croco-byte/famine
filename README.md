42 Project : Famine

# INTRODUCTION
This repository contains two viruses : Famine, and Strife.

To make Famine :
$ make

To make Strife :
$ make strife

Both of these viruses will infect every ELF64 file in the directories /tmp/test/ and /tmp/test2/.

When infecting the target files, the virus actually COPIES ITSELF into the target file, and patches the entry
point of the file so that the virus will be executed when launching the infected binary. The infected file effectively
became a 'host' for the virus : each time the infected file executes, it will in its turn execute the virus and infect
other files.

Once infected, the behavior of the binaries will NOT CHANGE. After the virus executed itself in the infected file, it will
redirect the execution flow of the program to the original entry point of the ELF file.

If a file was already infected, the virus ignores it.

For the moment, the virus only adds a "signature" to the file and replicate itself just as described above, nothing else.


# FAMINE (791 bytes)
The 'Famine' virus will attempt to write the virus in the PADDING SPACE located at the end of the text segment (segments are aligned to PAGE_SIZE
in memory, for example 4096 bytes. It is pretty rare that the segment contains exactly a multiple of PAGE_SIZE, so some NULL BYTES of padding
are added).

If there isn't enough space in the gap to contain the virus, it will NOT INJECT and go to the next file. That's why we are very limited in size. If
the virus is too big, it won't be able to infect a lot of files. This is the technique used by most of the people I spoke with about the project.

The size of Famine is 791 bytes. This is small enough to infect most of the files (~75%).


# Strife (1298 bytes)
The 'Strife' virus is much cleaner that the 'Famine' one. With this virus, if there is enough space in the padding gap, we will inject the virus
in it, just like Famine. However, if there isn't enough space, Strife will actually EXTEND the target file by 4096 bytes, shift everything in
the file by 4096 bytes after the injection point, and use the free space generated to inject the virus.

This is way better for several reasons :
> We are guarenteed to infect ALL THE FILES, not just the ones with enough padding space.
> We have almost no limitation in size since we don't have to worry about fitting in padding space. Which allowed us to :
	> Be much cleaner (close file descriptors and mmap properly, do a better error handling...)
	> Implement a more robust virus (executes chmod 0777 on the target file)
> This is MORE SCALABLE. At the moment, our virus only injects a signature and replicates itself. But if we want it to do some other, more useful
stuff, we will need additional space. This isn't a problem for Strife, that will extend the target binary ; this IS a problem for Famine.

The only downside would be that Strife is less stealthy since it can slightly increase the size of the target binary. But this is relatively hard to
notice.


