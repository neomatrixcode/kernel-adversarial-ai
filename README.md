# kernel-adversarial-ai

Este repositorio ofrece código de ejemplo para generar exploits de kernels vulnerables y aplicar defensas en tiempo real usando IA. Incluye un módulo de kernel en C vulnerable (buffer overflow) y un script en Python que entrena un modelo de aprendizaje automático para generar y ejecutar shellcodes maliciosos. La descripción del proyecto indica: “Código y demos para generar exploits de kernel vulnerables y defensas en tiempo real con IA”​. 

En concreto, el archivo vuln_module.c implementa un dispositivo de caracter con una función de escritura insegura, causando un desbordamiento de búfer intencional (como se indica en el comentario del código)​. 
Por otro lado, el script shellcode_model.py utiliza TensorFlow/Keras para entrenar un modelo de red neuronal que genera código de shell (shellcode) byte a byte, y usa las librerías Qiling (emulador) y Capstone (desensamblador) para ejecutar y validar el shellcode generado. Al ejecutar el script Python, se confirma la ejecución del shellcode mostrando mensajes como “[+] Shellcode ejecutado exitosamente!” junto con la longitud y el código hexadecimal del payload generado. 

El objetivo global es demostrar, con ejemplos prácticos, cómo las técnicas de IA pueden utilizarse tanto para atacar (generación de exploits) como para probar la seguridad de un sistema.


## Requisitos e instalación
Para compilar y ejecutar este proyecto se requieren:
 - Sistema operativo Linux (ya que incluye un módulo de kernel). Debe contar con los headers del kernel instalados para compilar módulos.
- Make y gcc (herramientas de compilación de Linux) para construir el módulo del kernel desde el Makefile.
- Python 3 con las siguientes librerías instaladas: numpy, tensorflow (Keras), qiling y capstone (todas importadas en shellcode_model.py​).  Se recomienda crear un entorno virtual e instalar estas dependencias, por ejemplo con pip install numpy tensorflow qiling capstone.


## Pasos básicos de instalación:
1. Clonar el repositorio:

```bash
git clone https://github.com/neomatrixcode/kernel-adversarial-ai.git
cd kernel-adversarial-ai
```

2. Instalar dependencias de Python: (si aún no están instaladas)
```bash
pip install numpy tensorflow qiling capstone
```

3. Compilar el módulo de kernel vulnerable:
```bash
make
```

Esto compila vuln_module.c usando el Makefile (meta all)​ y genera el archivo vuln_module.ko.

4. (Opcional) Para limpiar la compilación:
```bash
make clean
```

## Uso básico con ejemplos
A continuación se muestran ejemplos de uso de los componentes clave:
* Compilar e insertar el módulo de kernel vulnerable:
```bash
# Compilar (usa el Makefile)
make  

# Insertar el módulo en el kernel (requiere permisos de superusuario)
sudo insmod vuln_module.ko  

# Verificar que el módulo esté cargado
lsmod | grep vuln_module
```

El módulo crea un dispositivo (vuln_dev) que permite escribir datos. Como el código no valida el tamaño de entrada, cualquier escritura mayor a 64 bytes provocará un desbordamiento de búfer​ (solo con fines de demostración).

* Ejecutar el script Python de generación de shellcode:
```bash
python3 shellcode_model.py
```

El script realiza varios pasos automáticamente: genera un dataset sintético de shellcodes de ejemplo, construye y entrena un modelo de red neuronal (usando Keras)​, y luego usa una clase ShellcodeGenerator para producir un nuevo shellcode de longitud fija. 
A continuación emula la ejecución del shellcode con Qiling. En la salida por consola se debe ver un mensaje similar a:
```bash
[+] Shellcode ejecutado exitosamente!
Longitud: 128 bytes
Hex: 90... (código hexadecimal del shellcode generado)
```

Estas líneas (como se observa en el propio código) confirman que el shellcode fue ejecutado sin errores​. 
Al final también se muestra un listado parcial del desensamblado del payload usando Capstone. El shellcode final se guarda en payload.bin.


## Organización del repositorio
El repositorio tiene una estructura sencilla (sin subcarpetas), con los siguientes archivos principales:

* vuln_module.c: Módulo de kernel en C que define un dispositivo vulnerable. Contiene una función de escritura (vuln_write) que copia datos del usuario a un buffer local fijo sin verificar el tamaño, lo que genera un desbordamiento de búfer.
* Makefile: Makefile para compilar el módulo de kernel. Define el objeto vuln_module.o y las metas all (que invoca make -C /lib/modules/... modules para compilar) y clean para limpiar​.
* shellcode_model.py: Script Python que genera un modelo de IA para crear shellcodes. Contiene funciones para preparar datos reales de shellcodes, construir y entrenar una red neuronal (con tf.keras​), y una clase ShellcodeGenerator que genera bytes de shellcode iterativamente usando el modelo entrenado y librerías de emulación/desensamblado (Qiling/Capstone). Ejecutar este archivo produce un shellcode malicioso, lo ejecuta en Qiling y muestra el resultado.

## Contribuciones
Este proyecto es principalmente un ejemplo de demostración; no se han definido pautas específicas de contribución. Si desea colaborar, puede hacerlo a través de Pull Requests o abrir Issues en GitHub. Se recomienda discutir los cambios propuestos mediante issues antes de enviar contribuciones.

## Licencia
Este proyecto se distribuye bajo la Licencia MIT, lo que permite el uso libre del software siempre que se mantenga el aviso de copyright. En palabras de la licencia: “Se concede permiso, sin cargo, a cualquier persona que obtenga una copia de este software y archivos de documentación asociados, para utilizarlo sin restricción, incluyendo los derechos de usar, copiar, modificar, fusionar, publicar, distribuir...”​. Es decir, cualquiera puede usar y modificar este código siempre que se incluya el aviso de licencia original.


