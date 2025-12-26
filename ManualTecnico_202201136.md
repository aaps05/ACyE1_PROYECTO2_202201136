
# Manual Técnico: Implementación de AES-128 en ARM64

## 1. Introducción

El objetivo de este proyecto es implementar el algoritmo de **cifrado AES-128** en **lenguaje ensamblador ARM64**. AES (Advanced Encryption Standard) es un algoritmo de cifrado simétrico ampliamente utilizado para asegurar la confidencialidad de los datos. La versión de 128 bits (AES-128) utiliza una clave de 128 bits y cifra bloques de 128 bits de datos. Este manual detalla la implementación de las operaciones principales del algoritmo AES, explicando cómo se traducen a lenguaje ensamblador.

---

## 2. Descripción General del Algoritmo AES-128

AES-128 es un cifrado de bloques que opera sobre bloques de 128 bits (16 bytes) utilizando una clave de 128 bits. El algoritmo realiza una serie de transformaciones sobre el bloque de datos en varias rondas. En AES-128, se realizan **10 rondas** (9 rondas completas y una final sin MixColumns).

Las operaciones principales de AES incluyen:
1. **AddRoundKey**: Se realiza una operación **XOR** entre el bloque de datos y la subclave de la ronda.
2. **SubBytes**: Sustituye cada byte del bloque de datos por otro utilizando una tabla de sustitución llamada **S-box**.
3. **ShiftRows**: Desplaza las filas de la matriz de estado.
4. **MixColumns**: La mezcla de los bytes de cada columna de la matriz de estado.
5. **KeyExpansion**: Expande la clave original para generar subclaves para cada ronda.

Este manual describe cómo se implementan estas operaciones en ARM64.

---

## 3. Funciones Principales

### 3.1. Función `subBytes`

La función **SubBytes** realiza una sustitución no lineal de cada byte en la matriz de estado utilizando una tabla llamada **S-box**. Esta operación es fundamental para asegurar que el cifrado sea resistente a ataques.

**Código:**
```asm
.type subBytes, %function
.global subBytes
subBytes:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x19, [sp, #16]
    str x20, [sp, #24]
    ldr x19, =matState        // Cargar la dirección de la matriz de estado
    ldr x20, =Sbox            // Cargar la dirección de la S-box
    mov x1, #0                // Inicializar el índice
subbytes_loop:
    cmp x1, #16               // Comparar el índice con 16 (tamaño de matState)
    b.ge subbytes_done        // Si el índice es 16, terminar el bucle
    ldrb w2, [x19, x1]        // Cargar el byte en matState[i]
    uxtw x2, w2               // Convertir el byte a un índice de 32 bits
    ldrb w3, [x20, x2]        // Buscar el valor en la S-box
    strb w3, [x19, x1]        // Sustituir el byte en matState
    add x1, x1, #1            // Incrementar el índice
    b subbytes_loop           // Volver al bucle
subbytes_done:
    ldr x19, [sp, #16]
    ldr x20, [sp, #24]
    ldp x29, x30, [sp], #32
    ret
    .size subBytes, (. - subBytes)
```

**Explicación**: 
- La función **SubBytes** toma cada byte de la matriz de estado (`matState`), lo busca en la **S-box**, y reemplaza el byte original con el valor de la S-box correspondiente. 
- Utiliza un índice (`x1`) para recorrer los 16 bytes del estado y hacer la sustitución. 

---

### 3.2. Función `shiftRows`

La función **ShiftRows** realiza una rotación de las filas de la matriz de estado. La primera fila no se mueve, la segunda se rota una posición a la izquierda, la tercera se rota dos posiciones y la cuarta tres posiciones.

**Código:**
```asm
.type shiftRows, %function
.global shiftRows
shiftRows:
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    str x19, [sp, #16]
    str x20, [sp, #24]
    str x21, [sp, #32]
    str x22, [sp, #40]
    ldr x19, =matState
    ldrb w20, [x19, #4]
    ldrb w21, [x19, #5]
    strb w21, [x19, #4]
    ldrb w21, [x19, #6]
    strb w21, [x19, #5]
    ldrb w21, [x19, #7]
    strb w21, [x19, #6]
    strb w20, [x19, #7]
    // Continúa con las demás filas...
    ldp x29, x30, [sp], #48
    ret
    .size shiftRows, (. - shiftRows)
```

**Explicación**: 
- La función **ShiftRows** rota las filas de la matriz de estado de manera específica. Se mueve byte por byte en cada fila. 
- Se procesan las filas del bloque de datos, modificando su disposición para lograr la rotación deseada.

---

### 3.3. Función `mixColumns`

La función **MixColumns** mezcla las columnas de la matriz de estado. Se utiliza una operación en el campo de Galois para combinar los bytes de cada columna.

**Código:**
```asm
.type mixColumns, %function
.global mixColumns
mixColumns:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    ldr x19, =matState
    // Código para mezclar las columnas usando Galois Field (GF(2^8))
    // Operación sobre cada byte de la columna
    ldp x29, x30, [sp], #80
    ret
    .size mixColumns, (. - mixColumns)
```

**Explicación**: 
- **MixColumns** aplica la multiplicación de Galois a cada columna de la matriz de estado, lo que dispersa los bits en cada columna para lograr una mayor seguridad en el cifrado. 
- Esta operación se realiza sobre cada byte de la columna, utilizando operaciones XOR y multiplicación en el campo Galois.

---

### 3.4. Función `keyExpansion`

La función **KeyExpansion** expande la clave original de 128 bits a un conjunto de subclaves, una para cada ronda.

**Código:**
```asm
.type keyExpansion, %function
.global keyExpansion
keyExpansion:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    ldr x19, =key
    ldr x20, =expandedKeys
    // Copiar la clave inicial
    // Generación de subclaves con rotación y sustitución
    ldp x29, x30, [sp], #64
    ret
    .size keyExpansion, (. - keyExpansion)
```

**Explicación**:
- **KeyExpansion** toma la clave original de 128 bits y genera las subclaves necesarias para las rondas del AES. 
- Utiliza operaciones como **rotByte** y **byteSub** para transformar cada subclave de manera que se utilice una clave distinta en cada ronda del cifrado.

---

## 4. Conclusión

Este manual explica cómo se implementan las funciones principales del algoritmo **AES-128** en **ARM64**. Cada función corresponde a una parte del proceso de cifrado que, combinadas, hacen posible cifrar datos de manera eficiente y segura. 

Este proyecto no solo muestra cómo se traducen operaciones matemáticas de alto nivel a un lenguaje de bajo nivel como ARM64, sino que también resalta la importancia de optimizar el código en términos de velocidad y eficiencia para un rendimiento adecuado en sistemas con recursos limitados.
