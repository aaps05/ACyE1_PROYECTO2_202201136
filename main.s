.include "DataConstant.s"

//Texto quemado

.section .data
    msg_txt: .asciz "Ingrese el texto a cifrar (max 16 caracteres): "
        lenMsgTxt = . - msg_txt

    msg_key: .asciz "Ingrese la clave (32 caracteres hex): "
        lenMsgKey = . - msg_key

    key_err_msg: .asciz "Error: Valor de clave incorrecto\n"
        lenKeyErr = . - key_err_msg

    newline: .asciz "\n"
    
    debug_state: .asciz "Matriz de Estado:\n"
        lenDebugState = . - debug_state
    
    debug_key: .asciz "Matriz de Clave:\n"
        lenDebugKey = . - debug_key

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


//---Inicio del programa---

.section .text

//FUnción: Leer cadenas de exto y convertir bytes -> ASCII
.type   readTxtInput, %function
.global readTxtInput
readTxtInput:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    //Leer entrada user
    read 0, buffer, 256
    
    //Convertir caracteres --> bytes ASCII, almacenar en matriz
    //Puntero al buffer de entrada
    ldr x1, =buffer  
    //Puntero a matriz de estado         
    ldr x2, =matState      
    //Contador de bytes procesados   
    mov x3, #0    

convert_loop:
    cmp x3, #16
    b.ge bytes_restantes      

    //Cargar caracteres
    ldrb w4, [x1, x3]
    //Verificar newline
    cmp w4, #10
    b.eq bytes_restantes
    //Verificar null terminator
    cmp w4, #0
    b.eq bytes_restantes

    //Almacenar carácter como byte ASCII en column-major --> índice: (index % 4) + (index / 4) * 4
    mov x7, #4
    //columna = index / 4
    udiv x8, x3, x7    
    //fila = index % 4       
    msub x9, x8, x7, x3       
    //offset = fila * 4
    mul x10, x9, x7           
    //offset final = fila * 4 + columna
    add x10, x10, x8          

    //Almacenar byte ASCII en matriz de estado
    strb w4, [x2, x10]        
    add x3, x3, #1
    b convert_txt_loop

bytes_restantes:
    //Rellenar bytes restantes con 0x00
    cmp x3, #16
    b.ge end_convert

    mov x7, #4
    //columna = index / 4
    udiv x8, x3, x7    
    //fila = index % 4       
    msub x9, x8, x7, x3       
    //offset = fila * 4
    mul x10, x9, x7   
    //offse final = fila * 4 + columna
    add x10, x10, x8

    //Padding con ceros
    mov w4, #0
    strb w4, [x2, x10]
    add x3, x3, #1
    b bytes_restantes

end_convert:
    //Retornar
    ldp x29, x30, [sp], #16
    ret
    .size readTxtInput, (.-readTxtInput)

//FUncion para convertir clave hexadecimal 
.type   hexKeyConvert, %function
.global hexKeyConvert
hexKeyConvert:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    //Leer clave hexadecimal
    read 0, buffer, 33
    //Puntero al buffer de entrada
    ldr x1, =buffer
    //Puntero a matriz de llaves
    ldr x2, =MatrizKey
    //Contador de bytes procesados
    mov x3, #0
    //Indice buffer
    mov x11, #0

convert_loop:
    cmp x3, #16
    b.ge end_convert

//Saltar espacios y caracteres no validos hasta encontrar hex
skip_invalid:
    ldrb w4, [x1, x11]
    //Verificar espacio
    cmp w4, #0
    b.eq end_convert
    cmp w4, #10
    b.eq end_convert

    //Verificar si es caracter hex valido
    bl is_hex_char
    cmp w0, #1
    b.eq process_hex_pair

    add x11, x11, #1
    b skip_invalid

process_hex_pair:
    //Convertir primer caracter hex a valor numerico
    //Primer nibble (para empaquetar/desempaquetar hex<->byte)
    ldrb w4, [x1, x11]
    add x11, x11, #1
    bl hex_char_to_value
    lsl w5, w0, #4   // Desplazar a la izquierda 4 bits

    //Segundo nibble (para empaquetar/desempaquetar hex<->byte)
    ldrb w4, [x1, x11]
    add x11, x11, #1
    bl hex_char_to_value
    orr w5, w5, w0   // Combinar nibbles

    //Almacenar en column-major order
    mov x7, #4
    //columna = index / 4
    udiv x8, x3, x7
    //fila = index % 4
    msub x9, x8, x7, x3
    //offset = fila * 4
    mul x10, x9, x7
    //offset final = fila * 4 + columna
    add x10, x10, x8

    strb w5, [x2, x10]
    add x3, x3, #1
    b convert_loop

end_convert:
    ldp x29, x30, [sp], #16
    ret
    .size hexKeyConvert, (.-hexKeyConvert)

//Función auxiliar: verificar si es carácter hex
is_hex_char:
    cmp w4, #'0'
    b.lt not_hex
    cmp w4, #'9'
    b.le is_hex
    
    //Convertir a minúscula
    orr w4, w4, #0x20         
    cmp w4, #'a'
    b.lt not_hex
    cmp w4, #'f'
    b.le is_hex

not_hex:
    mov w0, #0
    ret

is_hex:
    mov w0, #1
    ret

//Función auxiliar: convertir carácter hex a nibble
hex_char_to_value:
    cmp w4, #'0'
    b.lt hex_error
    cmp w4, #'9'
    b.le hex_digit

    //Convertir a minúscula
    orr w4, w4, #0x20         
    cmp w4, #'a'
    b.lt hex_error
    cmp w4, #'f'
    b.gt hex_error

    //Convertir a valor numérico
    sub w0, w4, #'a'
    add w0, w0, #10
    ret

hex_digit:
    sub w0, w4, #'0'
    ret
    
hex_error:
    print 1, key_err_msg, lenKeyErr
    mov w0, #0
    ret

 //FUnción para imprimir matriz en formato debug
.type   printMatrix, %function
.global printMatrix
printMatrix:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    //Guardar paraámetros
    //Matriz a imprimir
    str x0, [sp, #16]
    //Msj
    str x1, [sp, #24]
    //Longitud msj
    str x2, [sp, #32]

    //Imprimir mensaje
    mov x0, #1
    ldr x1, [sp, #24]
    ldr x2, [sp, #32]
    mov x8, #64
    svc #0

    //Imprimir matriz en formato debug 4x4
    mov x23, #0          // Contador de filas

print_rows:
    cmp x23, #4
    b.ge end_print

    mov x24, #0          // Contador de columnas

print_columns:
    cmp x24, #4
    b.ge next_row

    //Calcular índice column-major: fila*4 + columna
    mov x25, #4
    mul x25, x23, x25
    add x25, x25, x24

    //Cargar byte de la matriz
    //Puntero a la matriz
    ldr x0, [sp, #16]
    //Cargar byte      
    ldrb w1, [x20, x25]  
    //Imprimir byte en formato hexadecimal
    bl print_hex_byte      

    add x24, x24, #1
    b print_columns

next_row:
    print 1, newline, 1
    add x23, x23, #1
    b print_rows

end_print:
    print 1, newline, 1
    ldp x29, x30, [sp], #48
    ret
    .size printMatrix, (.-printMatrix)

//Función para imprimir byte en hexadecimal
print_hex_byte:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    //Separar nibbles
    and w1, w0, #0xF0
    lsr w1, w1, #4
    and w2, w0, #0x0F

    //Convertir nibbles a caracteres hex
    //Nibble alto
    cmp w1, #10
    b.lt hex_to_char_high
    add w1, w1, #'A' - 10
    b hex_high_done

hex_to_char_high:
    add w1, w1, #'0'

hex_high_done:
    //Nibble bajo
    cmp w2, #10
    b.lt hex_to_char_low
    add w2, w2, #'A' - 10
    b hex_low_done

hex_to_char_low:
    add w2, w2, #'0'

hex_low_done:
    //Imprimir byte en formato hexadecimal
    sub sp, sp, #16
    strb w1, [sp]
    strb w2, [sp, #1]
    mov w3, #' '
    strb w3, [sp, #2]
    
    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x8, #64
    svc #0
    
    add sp, sp, #16
    ldp x29, x30, [sp], #16
    ret

 //Función de encriptación (placeholder)
.type   encryptAES, %function
.global encryptAES

encryptAES:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // Placeholder: copiar matriz de estado a matriz de criptografía
    ldr x0, =MatrizEstado
    ldr x1, =Criptografia
    mov x2, #16
    bl memcpy

copy:
    cbz x2, done_copy
    ldrb w3, [x0], #1
    strb w3, [x1], #1
    sub x2, x2, #1
    b copy

done_copy:
    ldp x29, x30, [sp], #16
    ret
    .size encryptAES, (. - encryptAES)

//Función principal
.type   _start, %function
.global _start
_start:
    //Leer texto de entrada como cadena
    print 1, msg_txt, lenMsgTxt
    bl readTxtInput

    //Debug: mostrar matriz de estado
    ldr x0, =MatrizEstado
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix

    //Leer clave en hexadecimal
    print 1, msg_key, lenMsgKey
    bl hexKeyConvert

    //Debug: mostrar matriz de clave
    ldr x0, =MatrizKey
    ldr x1, =debug_key
    mov x2, lenDebugKey
    bl printMatrix

//Encriptar
    bl encryptAES

//Salir
    mov x0, #0
    mov x8, #93
    svc #0
    .size _start, (. - _start)