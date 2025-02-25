.code
; syscalls from windows 22H2 19045.5487

fnNtOpenProcess proc
  mov r10, rcx
  mov rax, 26h
  syscall
  ret
fnNtOpenProcess endp

fnNtClose proc
  mov r10, rcx
  mov rax, 0Fh
  syscall
  ret
fnNtClose endp

fnNtQueryInformationFile proc
  mov r10, rcx
  mov rax, 11h
  syscall
  ret
fnNtQueryInformationFile endp

fnNtReadFile proc
  mov r10, rcx
  mov rax, 6h
  syscall
  ret
fnNtReadFile endp

fnNtQueryAttributesFile proc
  mov r10, rcx
  mov rax, 3Dh
  syscall
  ret
fnNtQueryAttributesFile endp

fnNtFreeVirtualMemory proc
  mov r10, rcx
  mov rax, 1Eh
  syscall
  ret
fnNtFreeVirtualMemory endp

fnNtProtectVirtualMemory proc
  mov r10, rcx
  mov rax, 50h
  syscall
  ret
fnNtProtectVirtualMemory endp

fnNtWriteVirtualMemory proc
  mov r10, rcx
  mov rax, 3Ah
  syscall
  ret
fnNtWriteVirtualMemory endp

fnNtReadVirtualMemory proc
  mov r10, rcx
  mov rax, 3Fh
  syscall
  ret
fnNtReadVirtualMemory endp

fnNtAllocateVirtualMemory proc
  mov r10, rcx
  mov rax, 18h
  syscall
  ret
fnNtAllocateVirtualMemory endp

fnNtQueryInformationProcess proc
  mov r10, rcx
  mov rax, 19h
  syscall
  ret
fnNtQueryInformationProcess endp

end