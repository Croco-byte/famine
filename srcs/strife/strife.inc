; Famine defines
%define		DIRENTS_BUFF_SIZE	4096
%define		PAGE_SIZE			4096
%define		PATH_MAX			1024
%define		PAD_MAX				4096
%define		VIRUS_SIZE			((_finish - _start))

; SYSCALLS defines
%define		SYS_WRITE			1
%define		SYS_OPEN			2
%define		SYS_CLOSE			3
%define		SYS_LSEEK			8
%define		SYS_MMAP			9
%define		SYS_EXIT			60
%define		SYS_FTRUNCATE		77
%define		SYS_GETENTS			78
%define		SYS_MUNMAP			91


; MMAP defines
%define		PROT_READ			0x1
%define		PROT_WRITE			0x2
%define		MAP_ANONYMOUS		0x20
%define		MAP_SHARED			0x01
%define		MAP_PRIVATE			0x02


; OPEN defines
%define		O_RDONLY			00000000
%define		O_WRONLY			00000001
%define		O_RDWR				00000002
%define		O_CREAT				64
%define		O_TRUNC				00001000
%define		O_APPEND			1024
%define		O_DIRECTORY			0q0200000

; LSEEK defines
%define		SEEK_END			2

; DIRENT defines
%define		D_INO_OFF			0x00
%define		D_OFF_OFF			0x08
%define		D_RECLEN_OFF		0x10
%define		D_NAME_OFF			0x12

; Utility defines
%define		FAM(x)				[(rbp - famine_size) + x]



; ELF structures
struc	elf64_ehdr
	.e_ident:		resb	16
	.e_type:		resw	1
	.e_machine:		resw	1
	.e_version:		resd	1
	.e_entry:		resq	1
	.e_phoff:		resq	1
	.e_shoff:		resq	1
	.e_flags:		resd	1
	.e_ehsize:		resw	1
	.e_phentsize:	resw	1
	.e_phnum:		resw	1
	.e_shentsize:	resw	1
	.e_shnum:		resw	1
	.e_shstrndx:	resw	1
endstruc

struc	elf64_phdr
	.p_type:		resd	1
	.p_flags:		resd	1
	.p_offset:		resq	1
	.p_vaddr:		resq	1
	.p_paddr:		resq	1
	.p_filesz:		resq	1
	.p_memsz:		resq	1
	.p_align:		resq	1
endstruc

struc	elf64_shdr
	.sh_name:		resd	1
	.sh_type:		resd	1
	.sh_flags:		resq	1
	.sh_addr:		resq	1
	.sh_offset:		resq	1
	.sh_size:		resq	1
	.sh_link:		resd	1
	.sh_info:		resd	1
	.sh_addralign:	resq	1
	.sh_entsize:	resq	1
endstruc

; DIRENT_WRAPPER structure
struc	dirent_wrapper
	.total_dreclen	resq	1
endstruc

; FAMINE structure
struc	famine
	.dir_fd:		resd	1
	.dirents:		resb	DIRENTS_BUFF_SIZE
	.total_dreclen:	resq	1

	.inject_in_gap:	resb	1

	.map_ptr:		resq	1
	.gap_size:		resq	1
	.txt_header:	resq	1
	.txt_offset:	resq	1
	.txt_filesz:	resq	1
	.txt_vaddr:		resq	1
	.next_offset:	resq	1
	.orig_entry:	resq	1

	.current_fpath:	resb	PATH_MAX
	.fsize:			resq	1
endstruc



; Just some debugging macros to print messages
%macro write_string 2
	mov rax, 1
	mov rdi, 0
	mov rsi, %1
	mov rdx, %2
	syscall
%endmacro

%macro write_format 2
	push rdi
	push rsi
	push rax
	mov rdi, %1
	mov rsi, %2
	mov rax, 0
	call printf
	pop rax
	pop rsi
	pop rdi
%endmacro
