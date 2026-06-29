# Escáner SYN Masivo y Stateless en Rust

Un motor de exploración de red local asíncrono y de alto rendimiento escrito en **Rust** utilizando **Tokio** y sockets crudos (`RAW`). El diseño está optimizado para realizar barridos rápidos en segmentos de red local sin necesidad de almacenar el estado de las conexiones en memoria de espacio de usuario.

## 🚀 Características Principales

* **Arquitectura Stateless:** No almacena tablas de conexiones ni mapas en memoria. Utiliza una fórmula matemática asimétrica basada en operaciones de rotación de bits de puertos, máscaras XOR y una constante criptográfica (`SALT`) para codificar el identificador único del host objetivo dentro del número de secuencia (`SEQ`) del paquete TCP SYN saliente.
* **Safe Rust Nativo:** Eliminación completa de bloques `unsafe` o manipulación cruda de punteros en espacio de usuario. Toda la captura y parsing de buffers se realiza de forma nativa a través de la API segura de `socket2`.
* **Asincronía No Bloqueante:** Concurrencia real implementada mediante `tokio::io::unix::AsyncFd`, permitiendo el procesamiento simultáneo del loop inyector y el sniffer receptor sobre descriptores de archivos asíncronos del sistema operativo.
* **Mitigación de Inanición (Starvation Control):** Uso táctico de `tokio::task::yield_now()` y control estricto de eventos de lectura de búfer (`WouldBlock`) para evitar *spin-locks* y deadlocks asíncronos en entornos de ejecución con alta densidad de tráfico local.

---

## 📐 Diseño Técnico

### Fórmula Stateless (Cálculo de Secuencia)

Para validar si un paquete entrante (`SYN-ACK` o `RST`) pertenece a nuestro escaneo, el sniffer evalúa el campo `ACK` recibido. El servidor remoto incrementa el `SEQ` original en $1$. Al recibirlo, realizamos la verificación matemática de manera inversa e instantánea:

```text
TX: SEQ = (IP_Destino ^ Puerto_Rotado_16) + SALT
RX: Verificar si (ACK_Recibido - 1) == (IP_Origen ^ Puerto_Origen_Rotado_16) + SALT
```
Esto garantiza la ausencia de falsos positivos causados por colisiones lineales sin degradar el rendimiento del procesamiento de la tarjeta de red.

## 📦 Requisitos Previos
Dado que la herramienta inyecta y manipula cabeceras IP y TCP personalizadas desde cero, el kernel del sistema operativo requiere privilegios administrativos para inicializar un socket en modo RAW.

- Rust (Edición 2021 o superior)
- Linux (con soporte para AsyncFd en Tokio)
- Permisos de Superusuario (root o capacidad CAP_NET_RAW)

## 🛠️ Uso e Instalación
Clona este repositorio en tu entorno local:
```bash
git clone https://github.com/hideonn1/lab_seguridad.git
cd lab_seguridad
```
Luego, compila el binario en modo optimización para producción:
```bash
cargo build --release
```
Ejecuta el binario utilizando sudo para proveer acceso a sockets raw:
```bash
sudo ./target/release/lab_seguridad
```
O bien, puedes usar este comando para utilizar el script de manera directa:
```bash
sudo cargo run
```

## 🔒 Descargo de Responsabilidad

Este software ha sido desarrollado con fines estrictamente académicos, de investigación y auditoría de seguridad interna en entornos de laboratorio controlados. El uso de esta herramienta sobre redes de terceros sin autorización explícita es ilegal y bajo la total responsabilidad del operador.
