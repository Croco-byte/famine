[BITS 64]

%include "famine.inc"


section .text
	global main
	extern printf

main:
	; === Placing our famine struct on the stack ===
	mov rbp, rsp
	push rbp
	mov rbp, rsp
	sub rsp, famine_size

	; === Opening the target file | O_RDWR ===
	mov rax, SYS_OPEN
	mov rdi, fname
	mov rsi, O_RDWR
	xor rdx, rdx
	syscall
	mov FAM(famine.fd), rax										; Saving the file fd in famine.fd

	; === If we couldn't open file, exit with error ===
	cmp rax, 0
	jl _error_exit
	write_format num, FAM(famine.fd)

	; === Calculate the size of the file with lseek ===
	mov rdi, rax
	mov rsi, 0
	mov rdx, 2
	mov rax, SYS_LSEEK
	syscall
	mov FAM(famine.fsize), rax									; Saving the file size in famine.fsize

	; === If the size of the file is < 4, exit with error ===
	cmp rax, 4
	jl _error_exit
	write_format num, FAM(famine.fsize)

	; === Map the file in process memory | mmap(0, famine.fsize, PROT_READ | PROT_WRITE, MAP_SHARED, famine.fd, 0) ===
	mov rdi, 0
	mov rsi, FAM(famine.fsize)
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_SHARED
	mov r8, FAM(famine.fd)
	mov r9, 0
	mov rax, 9
	syscall
	mov FAM(famine.map_ptr), rax								; Saving mapped file pointer in famine.map_ptr

	; === If the mapping failed, exit with error ===
	cmp rax, 0
	jl _error_exit
	write_format pointer, FAM(famine.map_ptr)

	; === Close the file ===
	mov rax, SYS_CLOSE
	mov rdi, FAM(famine.fd)
	syscall


	; TEST
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_ident
	mov al, [rax]
	write_format hex, al





_exit:
	; === Normal exit ===
	mov rax, SYS_EXIT
	mov rdi, 0
	syscall

_error_exit:
	; === Exit after error ===
	write_string error, error_len
	mov rax, SYS_EXIT
	mov rdi, 1
	syscall



fname		db		"./test/sample",0x0
fname_len	equ		$ - fname

debug		db		"Hi",0x0a,0x0
debug_len	equ		$ - debug

error		db		"[X] Error",0x0a,0x0
error_len	equ		$ - error

num			db		"[*] %d",0x0a,0x0
hex			db		"[*] %x",0x0a,0x0
pointer		db		"[*] %p",0x0a,0x0
char		db		"[*] %c",0x0a,0x0
