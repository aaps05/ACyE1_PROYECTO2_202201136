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

    debug_r0: .asciz "Estado tras Ronda 0 (AddRoundKey):\n"
        lenDebugR0 = . - debug_r0

    debug_sbox: .asciz "Matriz de S-Box:\n"
        lenDebugSBox = . - debug_sbox
    
    debug_sr: .asciz "Matriz tras ShiftRows:\n"
        lenDebugSR = . - debug_sr
    
    debug_mc: .asciz "Matriz tras MixColumns:\n"
        lenDebugMC = . - debug_mc
    
    debug_key: .asciz "Matriz de Clave:\n"
        lenDebugKey = . - debug_key

    debug_ar1: .asciz "Estado tras Ronda 1 (AddRoundKey):\n"
        lenDebugAR1 = . - debug_ar1

    debug_round1: .asciz "Subclave Ronda 1 "
        lenDebugRound1 = . - debug_round1

    cipher_msg: .asciz "Texto cifrado (estado final):\n"
        lenCipher = . - cipher_msg


//Reserva Memoria

.section .bss

    //Matriz de estado del texto de 128 bits 
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

    //Subclaves generadas (11 rondas * 16 bytes = 176 bytes (ronda 0-10))
    .global RoundKeys
    RoundKeys: .space 176, 0

//INsrucciones para automatizar (macros)
.macro print fd, buffer, len 
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #64
    svc #0
.endm

.macro read fd, buffer, len 
    mov x0, \fd
    ldr x1, =\buffer
    mov x2, \len
    mov x8, #63
    svc #0
.endm


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
    ldr x2, =MatrizEstado      
    //Contador de bytes procesados   
    mov x3, #0    

convert_loopTxt:
    cmp x3, #16
    b.ge bytes_restantesTxt      

    //Cargar caracteres
    ldrb w4, [x1, x3]
    //Verificar newline
    cmp w4, #10
    b.eq bytes_restantesTxt
    //Verificar null terminator
    cmp w4, #0
    b.eq bytes_restantesTxt

    //Almacenar carácter como byte ASCII en column-major --> índice: (index % 4) + (index / 4) * 4
    mov x7, #4
    //columna = index / 4
    udiv x8, x3, x7    
    //fila = index % 4       
    msub x9, x8, x7, x3       
    //offset = columna * 4
    //mul x10, x9, x7
    //se utiliza x8, que representa la columna
    lsl x10, x8, #2  // Multiplicar por 4 usando desplazamiento
    //offset final = columna * 4 + fila
    add x10, x10, x9

    //Almacenar byte ASCII en matriz de estado
    strb w4, [x2, x10]        
    add x3, x3, #1
    b convert_loopTxt

bytes_restantesTxt:
    //Rellenar bytes restantes con 0x00
    cmp x3, #16
    b.ge end_convertDoneTxt

    mov x7, #4
    //columna = index / 4
    udiv x8, x3, x7    
    //fila = index % 4       
    msub x9, x8, x7, x3       
    //offset = columna * 4
    //mul x10, x9, x7
    //se utiliza x8, que representa la columna
    lsl x10, x8, #2  // Multiplicar por 4 usando desplazamiento
    //offset final = columna * 4 + fila
    add x10, x10, x9

    //Padding con ceros
    mov w4, #0
    strb w4, [x2, x10]
    add x3, x3, #1
    b bytes_restantesTxt

end_convertDoneTxt:
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
    //Newline
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
    //offset = columna * 4
    //mul x10, x9, x7
    //se utiliza x8, que representa la columna
    lsl x10, x8, #2  // Multiplicar por 4 usando desplazamiento
    //offset final = columna * 4 + fila
    add x10, x10, x9

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
    stp x19, x20, [sp, #-16]!
    //Reservar espacio en stack (reserva 48 b, alineados a 16)
    sub sp, sp, #48

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

    //BAse de la matriz (cargar una vez)
    ldr x20, [sp, #16]

    //Imprimir matriz en formato debug 4x4
    mov x23, #0          //Contador de filas

print_rows:
    cmp x23, #4
    b.ge end_print

    mov x24, #0          //Contador de columnas

print_columns:
    cmp x24, #4
    b.ge next_row

    //Calcular índice column-major: columna*4 + fila
    //Multiplicar por 4 usando desplazamiento
    lsl x26, x24, #2
    //SUmar fila
    add x25, x26, x23

    //-- Misma funcionalidad que antes --
    //mov x25, #4
    //mul x25, x24, x25
    //add x25, x25, x23

    //Cargar byte de la matriz
    //Puntero a la matriz
    //ldr x0, [sp, #16]
    //Cargar byte      
    //ldrb w1, [x20, x25]  

    ldrb w0, [x20, x25]  // Cargar byte en w0 para imprimir
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
    //ldp x29, x30, [sp], #48
    add sp, sp, #48
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
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

//Funcion SubBytes (Sbox)
.type   SubBytes, %function
.global SubBytes
SubBytes:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    ldr x1, =Sbox         // tabla de 256 bytes 
    mov x2, #16

1:
    ldrb w3, [x0]         // b = state[i]
    ldrb w4, [x1, x3]     // b' = Sbox[b]
    strb w4, [x0]         // state[i] = b'
    add  x0, x0, #1
    subs x2, x2, #1
    b.ne 1b

    ldp x29, x30, [sp], #16
    ret
.size SubBytes, (. - SubBytes)

//Función ShiftRows
.type   ShiftRows, %function
.global ShiftRows
ShiftRows:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    ldr x9, =bufferTemp    // scratch para 4 bytes

    mov x20, #0            // fila = 0..3
0:  // row loop
    cmp x20, #4
    b.ge 3f

    // shift = fila
    mov x21, x20

    // ---- leer fila rotada a temp[c] ----
    mov x22, #0            // c = 0..3
1:  cmp x22, #4
    b.ge 2f
    add x23, x22, x21      // src_col = (c + shift) & 3
    and x23, x23, #3
    lsl x24, x23, #2       // src_col*4
    add x24, x24, x20      // + fila
    ldrb w25, [x0, x24]
    strb w25, [x9, x22]
    add x22, x22, #1
    b   1b

    // ---- escribir temp[c] en fila, col=c ----
2:  mov x22, #0
4:  cmp x22, #4
    b.ge 5f
    ldrb w25, [x9, x22]
    lsl  x24, x22, #2      // c*4
    add  x24, x24, x20     // + fila
    strb w25, [x0, x24]
    add  x22, x22, #1
    b    4b

5:  add x20, x20, #1
    b   0b

3:
    ldp x29, x30, [sp], #16
    ret
.size ShiftRows, (. - ShiftRows)

//--
// --- xtime: multiplica por 2 en GF(2^8) ---
// Entrada:  w0 = byte [0..255]
// Salida:   w0 = (w0 * 2) en Rijndael GF(2^8)
.type   xtime, %function
xtime:
    // Si el bit7 estaba en 1, tras el shift hay que XOR con 0x1B
    and w1, w0, #0x80
    lsl w0, w0, #1
    and w0, w0, #0xFF
    cbz w1, 1f
    mov w2, #0x1B
    eor w0, w0, w2
1:  ret
.size xtime, (. - xtime)


// --- MixColumns(state) --- (x0 = &MatrizEstado)
// Opera cada columna: r = M * c, con
// r0 = 2*s0 ^ 3*s1 ^ 1*s2 ^ 1*s3
// r1 = 1*s0 ^ 2*s1 ^ 3*s2 ^ 1*s3
// r2 = 1*s0 ^ 1*s1 ^ 2*s2 ^ 3*s3
// r3 = 3*s0 ^ 1*s1 ^ 1*s2 ^ 2*s3
.type   MixColumns, %function
.global MixColumns
MixColumns:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!

    mov x20, x0              // base del state (callee-saved)
    mov x22, #0              // columna = 0..3

// loop por columnas
1:
    cmp x22, #4
    b.ge 9f

    // base = col*4
    lsl x23, x22, #2

    // cargar s0..s3 (columna en column-major)
    ldrb w4, [x20, x23]          // s0 (fila0)
    add  x24, x23, #1
    ldrb w5, [x20, x24]          // s1 (fila1)
    add  x24, x23, #2
    ldrb w6, [x20, x24]          // s2 (fila2)
    add  x24, x23, #3
    ldrb w7, [x20, x24]          // s3 (fila3)

    // t0..t3 = 2*si  (xtime)
    mov  w0, w4
    bl   xtime
    mov  w8, w0                  // t0

    mov  w0, w5
    bl   xtime
    mov  w9, w0                  // t1

    mov  w0, w6
    bl   xtime
    mov  w10, w0                 // t2

    mov  w0, w7
    bl   xtime
    mov  w11, w0                 // t3

        // r0 = 2*s0 ^ 3*s1 ^ s2 ^ s3
    mov  w12, w8              // t0
    eor  w12, w12, w9         // ^ t1
    eor  w12, w12, w5         // ^ s1  -> (t1 ^ s1) = 3*s1
    eor  w12, w12, w6         // ^ s2
    eor  w12, w12, w7         // ^ s3

    // r1 = s0 ^ 2*s1 ^ 3*s2 ^ s3
    mov  w13, w4              // s0
    eor  w13, w13, w9         // ^ t1 = 2*s1
    eor  w13, w13, w10        // ^ t2
    eor  w13, w13, w6         // ^ s2   -> (t2 ^ s2) = 3*s2
    eor  w13, w13, w7         // ^ s3

    // r2 = s0 ^ s1 ^ 2*s2 ^ 3*s3
    mov  w14, w4              // s0
    eor  w14, w14, w5         // ^ s1
    eor  w14, w14, w10        // ^ t2 = 2*s2
    eor  w14, w14, w11        // ^ t3
    eor  w14, w14, w7         // ^ s3   -> (t3 ^ s3) = 3*s3

    // r3 = 3*s0 ^ s1 ^ s2 ^ 2*s3
    mov  w15, w8              // t0
    eor  w15, w15, w4         // ^ s0   -> (t0 ^ s0) = 3*s0
    eor  w15, w15, w5         // ^ s1
    eor  w15, w15, w6         // ^ s2
    eor  w15, w15, w11        // ^ t3 = 2*s3


    // escribir r0..r3 en la misma columna
    strb w12, [x20, x23]         // fila0
    add  x24, x23, #1
    strb w13, [x20, x24]         // fila1
    add  x24, x23, #2
    strb w14, [x20, x24]         // fila2
    add  x24, x23, #3
    strb w15, [x20, x24]         // fila3

    add x22, x22, #1
    b   1b

9:
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
.size MixColumns, (. - MixColumns)

//FUncion AddRoundKey (placeholder)
.type   AddRoundKey, %function
.global AddRoundKey
AddRoundKey:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x2, #16
1:
    ldrb w3, [x0]     // *state
    ldrb w4, [x1]     // *key
    eor  w3, w3, w4
    strb w3, [x0]
    add  x0, x0, #1
    add  x1, x1, #1
    subs x2, x2, #1
    b.ne 1b
    ldp x29, x30, [sp], #16
    ret
.size AddRoundKey, (. - AddRoundKey)

//Funcion ROtWord (rota 1 byte a la izquierda)
.type   RotWord, %function
RotWord:
    lsl  w1, w0, #8
    lsr  w2, w0, #24
    orr  w0, w1, w2
    ret
.size RotWord, (. - RotWord)

//SubWOrd (aplica Sbox byte a byte)
//w0=(b0,b1,b2,b3)--> w0=(Sbox[b0],Sbox[b1]<<8,Sbox[b2]<<16,Sbox[b3]<<24)
.type   SubWord, %function
SubWord:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    ldr x3, =Sbox

    //Extraer los bytes y aplicar Sbox
    and w4, w0, #0xFF
    lsr w5, w0, #8
    and w5, w5, #0xFF
    lsr w6, w0, #16
    and w6, w6, #0xFF
    lsr w7, w0, #24

    //Aplicar Sbox (add+ldrb)
    /*mov x8, w4
    add x8, x3, x8
    ldrb w4, [x8]

    mov x8, w5
    add x8, x3, x8
    ldrb w5, [x8]

    mov x8, w6
    add x8, x3, x8
    ldrb w6, [x8]

    mov x8, w7
    add x8, x3, x8
    ldrb w7, [x8]*/
    // Sbox[b0..b3] usando w-index con zero-extend
    // --- Sbox[b0]
    mov  w8, w4           // escribir w8 => x8 queda zero-extendido
    add  x8, x3, x8       // x8 = &Sbox + b0
    ldrb w4, [x8]         // w4 = Sbox[b0]

    // --- Sbox[b1]
    mov  w8, w5
    add  x8, x3, x8
    ldrb w5, [x8]

    // --- Sbox[b2]
    mov  w8, w6
    add  x8, x3, x8
    ldrb w6, [x8]

    // --- Sbox[b3]
    mov  w8, w7
    add  x8, x3, x8
    ldrb w7, [x8]

    //Reensamblar 
    orr w0, wzr, w4         // byte0
    orr w0, w0, w5, lsl #8  // byte1
    orr w0, w0, w6, lsl #16 // byte2
    orr w0, w0, w7, lsl #24 // byte3

    ldp x29, x30, [sp], #16
    ret
.size SubWord, (. - SubWord)

//LLave de expansión (RoundKeys y MatrizKey)
/*.type   KeyExpansion, %function
.global KeyExpansion
KeyExpansion:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    //Puntero RoundKeys in
    mov x19, x0
    //Puntero RoundKeys out
    mov x20, x1

    //COpiar w0-w3 iniciales
    ldr w4, [x19], #4
    ldr w5, [x19], #4
    ldr w6, [x19], #4
    ldr w7, [x19], #4

    str w4, [x20], #4
    str w5, [x20], #4
    str w6, [x20], #4
    str w7, [x20], #4

    //Rcon 
    ldr x21, =Rcon
    mov w22, #0          // Rcon index (0..9)
    mov w23, #1         // round = 1..10

SubClaveRoundR:
    cmp w23, #11
    b.ge EndKeyExpansion

    mov w8, w7          // w3 anterior
    mov  w0, w8
    //RotWord
    bl RotWord
    //SubWord
    bl SubWord
    mov  w8, w0
    //Rcon[r-1] palabra 32 bits
    lsl  x10, x22, #2      // x10 = r * 4
    add  x10, x21, x10     // &Rcon[r]
    ldr  w9, [x10]         // w9 = Rcon[r] (32 bits)
    //ldrb w9, [x21, w22, uxtw #2] 
    ror  w9, w9, #24
    eor w8, w8, w9

    //w0 = w0_prev ^ temp
    eor w4, w4, w8
    str w4, [x20], #4

    //w1 = w1_prev ^ w0
    eor w5, w5, w4
    str w5, [x20], #4

    //w2 = w2_prev ^ w1
    eor w6, w6, w5
    str w6, [x20], #4

    //w3 = w3_prev ^ w2
    eor w7, w7, w6
    str w7, [x20], #4

    //Sig. Rcon y ronda
    add w22, w22, #1
    add w23, w23, #1
    b SubClaveRoundR

EndKeyExpansion:
    ldp x29, x30, [sp], #16
    ret
.size KeyExpansion, (. - KeyExpansion)*/

.type   KeyExpansion, %function
.global KeyExpansion
KeyExpansion:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // &MatrizKey -> x19, &RoundKeys -> x20
    mov x19, x0
    mov x20, x1

    // Copia w0..w3 iniciales
    ldr w4, [x19], #4
    ldr w5, [x19], #4
    ldr w6, [x19], #4
    ldr w7, [x19], #4
    str w4, [x20], #4
    str w5, [x20], #4
    str w6, [x20], #4
    str w7, [x20], #4

    // Rcon como bytes (01 00 00 00, 02 00 00 00, ...)
    ldr x21, =Rcon      // tabla en .rodata
    mov w22, #0         // idx Rcon = 0..9
    mov w23, #1         // ronda   = 1..10

1:  cmp w23, #11
    b.ge 9f

    // temp = SubWord(RotWord(w7))
    mov  w0, w7
    bl   RotWord
    bl   SubWord
    mov  w8, w0

    // RC << 24 (toma SOLO el 1er byte de cada grupo de 4)
    lsl  x10, x22, #2       // offset r*4
    add  x10, x21, x10
    ldrb w9, [x10]          // RC
    lsl  w9, w9, #24        // RC << 24
    eor  w8, w8, w9         // temp ^= RC<<24

    // w4..w7 de la ronda
    eor  w4, w4, w8
    str  w4, [x20], #4
    eor  w5, w5, w4
    str  w5, [x20], #4
    eor  w6, w6, w5
    str  w6, [x20], #4
    eor  w7, w7, w6
    str  w7, [x20], #4

    add  w22, w22, #1
    add  w23, w23, #1
    b    1b

9:  ldp x29, x30, [sp], #16
    ret
.size KeyExpansion, (. - KeyExpansion)

//--


 //Función de encriptación (placeholder)
/*.type   encryptAES, %function
.global encryptAES

encryptAES:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    //Subclaves (176 bytes)
    ldr x0, =MatrizKey
    ldr x1, =RoundKeys
    bl  KeyExpansion

    // Imprimir Subclave de Ronda 1
    ldr x0, =RoundKeys
    add x0, x0, #16
    ldr x1, =debug_round1
    mov x2, lenDebugRound1
    bl  printMatrix

    //Ronda 0: estado ^= clave (AddRoundKey)
    ldr x0, =MatrizEstado
    ldr x1, =RoundKeys
    bl  AddRoundKey

    //Imprimir estado tras AddRoundKey R0
    ldr x0, =MatrizEstado
    ldr x1, =debug_r0
    mov x2, lenDebugR0
    bl printMatrix

    //IMprimir SubBytes (Sbox)
    ldr x0, =MatrizEstado
    bl  SubBytes
    // Debug
    ldr x0, =MatrizEstado
    ldr x1, =debug_sbox
    mov x2, lenDebugSBox
    bl  printMatrix

    //Imprimir ShiftRows
    ldr x0, =MatrizEstado
    bl  ShiftRows
    // Debug
    ldr x0, =MatrizEstado
    ldr x1, =debug_sr
    mov x2, lenDebugSR
    bl  printMatrix

    //Imprimir MixColumns
    ldr x0, =MatrizEstado
    bl  MixColumns
    // Debug
    ldr x0, =MatrizEstado
    ldr x1, =debug_mc
    mov x2, lenDebugMC
    bl  printMatrix

    //AddRoundKey dRonda 1 (RoundKeys + 16)
    ldr x0, =MatrizEstado
    ldr x1, =RoundKeys
    add x1, x1, #16
    bl  AddRoundKey

    // Debug AR1
    ldr x0, =MatrizEstado
    ldr x1, =debug_ar1
    mov x2, lenDebugAR1
    bl  printMatrix

    // Placeholder: copiar matriz de estado a matriz de criptografía
    ldr x0, =MatrizEstado
    ldr x1, =Criptografia
    mov x2, #16
    //bl memcpy

copy:
    cbz x2, done_copy
    ldrb w3, [x0], #1
    strb w3, [x1], #1
    sub x2, x2, #1
    b copy

done_copy:
    ldp x29, x30, [sp], #16
    ret
    .size encryptAES, (. - encryptAES)*/

.type   encryptAES, %function
.global encryptAES
encryptAES:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // Expandir subclaves
    ldr x0, =MatrizKey
    ldr x1, =RoundKeys
    bl  KeyExpansion

    // Ronda 0
    ldr x0, =MatrizEstado
    ldr x1, =RoundKeys
    bl  AddRoundKey

    // Rondas 1..9
    mov w20, #1
1:
    cmp w20, #10
    b.ge 2f

    ldr x0, =MatrizEstado
    bl  SubBytes
    ldr x0, =MatrizEstado
    bl  ShiftRows
    ldr x0, =MatrizEstado
    bl  MixColumns

    // AddRoundKey(state, RoundKeys + 16*round)
    ldr x0, =MatrizEstado
    ldr x1, =RoundKeys
    uxtw x2, w20
    lsl  x2, x2, #4
    add  x1, x1, x2
    bl   AddRoundKey

    add w20, w20, #1
    b   1b

// Ronda 10 (sin MixColumns)
2:
    ldr x0, =MatrizEstado
    bl  SubBytes
    ldr x0, =MatrizEstado
    bl  ShiftRows

    ldr x0, =MatrizEstado
    ldr x1, =RoundKeys
    mov w2, #10
    uxtw x2, w2
    lsl  x2, x2, #4
    add  x1, x1, x2
    bl   AddRoundKey

    // (Opcional) imprime estado final
    // ldr x0, =MatrizEstado
    // ldr x1, =cipher_msg
    // mov x2, lenCipher
    // bl  printMatrix

    // Copia a Criptografia (opcional)
    ldr x0, =MatrizEstado
    ldr x1, =Criptografia
    mov x2, #16
3:  cbz x2, 4f
    ldrb w3, [x0], #1
    strb w3, [x1], #1
    sub x2, x2, #1
    b   3b

4:  ldp x29, x30, [sp], #16
    ret
.size encryptAES, (. - encryptAES)


//Función principal
.type   _start, %function
.global _start
_start:
    //Leer texto de entrada como cadena
    print 1, msg_txt, lenMsgTxt
    bl readTxtInput

    //Debug mostrar matriz de estado
    ldr x0, =MatrizEstado
    ldr x1, =debug_state
    mov x2, lenDebugState
    bl printMatrix

    //Leer clave en hexadecimal
    print 1, msg_key, lenMsgKey
    bl hexKeyConvert

    //Debug mostrar matriz de clave
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