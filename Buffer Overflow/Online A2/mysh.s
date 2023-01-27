section .text
  global _start
    _start:
      ; Store the argument string on stack
      xor ecx, ecx
      xor eax, eax
      mov al, 5
      mov cl, 7
      push ecx
      push eax
      mov ebx, 0x565562f1
      call ebx
      
      push eax	
      mov ebx, 0x5655635d
      call ebx
