section .text
  global _start
    _start:
      ; Store the argument string on stack
      xor ecx, ecx
      xor eax, eax
      
      mov al, 3
      shl eax, 8
      
      mov cl, 68
      push ecx
      push eax
      push 1
      mov ebx, 0x5655638f
      call ebx
      
