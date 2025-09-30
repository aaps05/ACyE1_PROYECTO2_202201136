.include "DataConstant.s"

//Texto quemado

.section .data 
msg_!: .asciz 


//Reserva Memoria

.section .bss

    //Matriz de estado del texto de 1128 bits 
    .global MatrizEstado
    MatrizEstado: .space 16, 0 
 
    // Matriz de llaves inicial 128 bits
    .global MatrizKey
    MatrizKey: .space 16, 0

    //Buffer de almacenamiento de encriptación 
    .global Criptografia
    Criptografia: .space 16, 0

    //Buffer para almacenar entrada
    buffer: .space 256, 0

    //Buffer temp
    bufferTemp: .space 64, 0

//INsrucciones para automatizar (macros)
.macro print fd, buffer, len 
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #64
    svc #0
.endmacro

.macro read fd, buffer, len 
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #63
    svc #0
.endmacro

//Inicio del programa

.section .text

//FUnción: Leer cadenas de exto y convertir bytes -> ASCII
