use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

// =============================================================================
// ESTRUCTURAS DE CABECERA
// =============================================================================

#[derive(Debug)]
struct IpHeader {
    ver_ihl: u8,
    tos: u8,
    longitud_total: u16,
    id: u16,
    flags_fragmento: u16,
    ttl: u8,
    protocolo: u8,
    checksum: u16,
    origen: [u8; 4],
    destino: [u8; 4],
}

#[derive(Debug)]
struct TcpHeader {
    puerto_origen: u16,
    puerto_destino: u16,
    num_secuencia: u32,
    num_ack: u32,
    offset_res_flags: u16,
    ventana: u16,
    checksum: u16,
    puntero_urgente: u16,
}

// =============================================================================
// HELPER: Ipv4Addr → u32 en network byte order
// =============================================================================
#[inline]
fn ipv4_a_u32(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

// =============================================================================
// FÓRMULA STATELESS
// TX: seq = (ip_u32 XOR puerto_rotado) + SALT
// RX: ack_recibido == seq + 1
// =============================================================================
const SALT: u32 = 0xDEAD_C0DE;

#[inline]
fn codificar_seq(ip: Ipv4Addr, puerto: u16) -> u32 {
    let ip_u32 = ipv4_a_u32(ip);
    let puerto_rotado = (puerto as u32).rotate_left(16);
    (ip_u32 ^ puerto_rotado).wrapping_add(SALT)
}

#[inline]
fn verificar_token(ip_src: Ipv4Addr, p_src: u16, ack_recibido: u32) -> bool {
    ack_recibido == codificar_seq(ip_src, p_src).wrapping_add(1)
}

// =============================================================================
// FIX 2: set_ip_hdrincl no existe en socket2 0.5 — activar via setsockopt libc
// =============================================================================
fn activar_ip_hdrincl(socket: &Socket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// =============================================================================
// FIX 3: recv() en socket2 0.5 requiere &mut [MaybeUninit<u8>]
// Este helper convierte el Vec<u8> al tipo correcto y extrae los bytes seguros.
// =============================================================================
fn recv_safe(socket: &Socket, buf: &mut Vec<u8>) -> io::Result<usize> {
    // SAFETY: MaybeUninit<u8> tiene el mismo layout que u8.
    // socket2::recv() inicializa exactamente `n` bytes, que luego leemos.
    let uninit_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
    socket.recv(uninit_buf)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("=== ESCÁNER SYN STATELESS MASIVO: PRODUCCIÓN (FASE 4) ===");

    let ip_origen = Ipv4Addr::new(192, 168, 0, 3);
    let subred_base = "192.168.0";
    let puertos_objetivo: Vec<u16> = vec![80, 8080, 443];
    let p_origen: u16 = 54321;

    let socket_tx = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("❌ Requiere privilegios de Root (sudo cargo run).");
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    // FIX 2: reemplaza socket_tx.set_ip_hdrincl(true) que no existe en socket2 0.5
    activar_ip_hdrincl(&socket_tx)?;
    socket_tx.set_nonblocking(true)?;
    let async_fd_tx = Arc::new(AsyncFd::new(socket_tx)?);

    let socket_rx = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("❌ Requiere privilegios de Root (sudo cargo run).");
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    socket_rx.set_nonblocking(true)?;
    let async_fd_rx = Arc::new(AsyncFd::new(socket_rx)?);

    // =========================================================================
    // 2. SNIFFER RECEPTOR (tarea de fondo)
    // =========================================================================
    let sniffer = tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        let mut abiertos: u32 = 0;
        let mut cerrados: u32 = 0;
        println!("[*] Sniffer activo escuchando respuestas TCP...");

        loop {
            match async_fd_rx.readable().await {
                Err(_) => break,
                Ok(mut guard) => {
                    // Bucle interno para vaciar todo lo que el kernel ya recibió
                    loop {
                        match recv_safe(guard.get_inner(), &mut buffer) {
                            Ok(bytes_leidos) if bytes_leidos >= 40 => {
                                let ihl = (buffer[0] & 0x0F) as usize * 4;
                                let tcp_start = ihl;

                                if bytes_leidos < tcp_start + 20 {
                                    continue;
                                }

                                let ip_src =
                                    Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]);
                                let p_src =
                                    u16::from_be_bytes([buffer[tcp_start], buffer[tcp_start + 1]]);
                                let p_dst_recibido = u16::from_be_bytes([
                                    buffer[tcp_start + 2],
                                    buffer[tcp_start + 3],
                                ]);
                                let ack_recibido = u32::from_be_bytes([
                                    buffer[tcp_start + 8],
                                    buffer[tcp_start + 9],
                                    buffer[tcp_start + 10],
                                    buffer[tcp_start + 11],
                                ]);
                                let flags = buffer[tcp_start + 13];

                                if p_dst_recibido == p_origen
                                    && verificar_token(ip_src, p_src, ack_recibido)
                                {
                                    if flags & 0x12 == 0x12 {
                                        abiertos += 1;
                                        println!("[+] ¡ABIERTO!  -> {}:{}", ip_src, p_src);
                                    } else if flags & 0x04 == 0x04 {
                                        cerrados += 1;
                                        println!("[-] Cerrado    -> {}:{}", ip_src, p_src);
                                    }
                                }
                            }
                            Ok(_) => {} // Paquete inválido/ruido, sigue leyendo el búfer
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                // El búfer del kernel quedó verdaderamente vacío.
                                // AQUÍ es seguro limpiar el estado y esperar al próximo evento de red.
                                guard.clear_ready();
                                break;
                            }
                            Err(_) => return (abiertos, cerrados),
                        }
                    }
                }
            }
        }

        (abiertos, cerrados)
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;

    // =========================================================================
    // 3. INYECTOR GENERATIVO (TX loop)
    // =========================================================================
    println!(
        "[*] Iniciando inyección masiva sobre el segmento {}.1-254...",
        subred_base
    );
    let mut rng = rand::thread_rng();
    let mut paquetes_enviados: u32 = 0;

    for host in 1u8..=254 {
        let ip_dest_str = format!("{}.{}", subred_base, host);
        let ip_destino: Ipv4Addr = ip_dest_str.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("IP inválida '{}': {}", ip_dest_str, e),
            )
        })?;

        if ip_destino == ip_origen {
            continue;
        }

        for &puerto_dest in &puertos_objetivo {
            let seq_stateless = codificar_seq(ip_destino, puerto_dest);
            // FIX 1: `gen` es palabra reservada en Rust >= 1.75 (edición 2024)
            // rng.r#gen() es la forma de escaparla, o usar gen_range / random
            let id_aleatorio: u16 = rng.r#gen();

            // Cabecera TCP
            let tcp = TcpHeader {
                puerto_origen: p_origen,
                puerto_destino: puerto_dest,
                num_secuencia: seq_stateless,
                num_ack: 0,
                offset_res_flags: 0x5002,
                ventana: 1024,
                checksum: 0,
                puntero_urgente: 0,
            };
            let mut tcp_bytes = de_tcp_a_bytes(&tcp);
            let tcp_csum = calcular_tcp_checksum(&ip_origen, &ip_destino, &tcp_bytes);
            tcp_bytes[16] = (tcp_csum >> 8) as u8;
            tcp_bytes[17] = (tcp_csum & 0xFF) as u8;

            // Cabecera IP
            let ip = IpHeader {
                ver_ihl: 0x45,
                tos: 0,
                longitud_total: 40,
                id: id_aleatorio,
                flags_fragmento: 0x4000,
                ttl: 64,
                protocolo: 6,
                checksum: 0,
                origen: ip_origen.octets(),
                destino: ip_destino.octets(),
            };
            let mut ip_bytes = de_ip_a_bytes(&ip);
            let ip_csum = calcular_ip_checksum(&ip_bytes);
            ip_bytes[10] = (ip_csum >> 8) as u8;
            ip_bytes[11] = (ip_csum & 0xFF) as u8;

            let mut paquete = Vec::with_capacity(40);
            paquete.extend_from_slice(&ip_bytes);
            paquete.extend_from_slice(&tcp_bytes);

            let sock_addr = SockAddr::from(std::net::SocketAddr::new(
                std::net::IpAddr::V4(ip_destino),
                puerto_dest,
            ));

            match async_fd_tx.writable().await {
                Ok(mut guard) => {
                    match guard.get_inner().send_to(&paquete, &sock_addr) {
                        Ok(_) => {
                            paquetes_enviados += 1;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            eprintln!(
                                "[!] Error inyectando a {}:{} → {}",
                                ip_destino, puerto_dest, e
                            );
                        }
                    }
                    guard.clear_ready();
                }
                Err(e) => eprintln!("[!] Error esperando socket TX: {}", e),
            }

            tokio::time::sleep(tokio::time::Duration::from_micros(200)).await;

            if paquetes_enviados > 0 && paquetes_enviados.is_multiple_of(20) {
                tokio::task::yield_now().await;
            }
        }
    }

    println!(
        "✔ Inyección completada: {} paquetes SYN enviados. Esperando respuestas residuales...",
        paquetes_enviados
    );

    // =========================================================================
    // 4. VENTANA DE CAPTURA FINAL + RESUMEN
    // =========================================================================
    tokio::select! {
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(3)) => {
            println!("\n[*] Ventana de captura cerrada.");
        }
        result = sniffer => {
            match result {
                Ok((abiertos, cerrados)) => {
                    println!("\n[*] Sniffer terminó. Abiertos: {} | Cerrados: {}", abiertos, cerrados);
                }
                Err(e) => eprintln!("❌ Falla crítica en Sniffer: {:?}", e),
            }
        }
    }

    println!("[*] Escaneo completado. Sockets liberados.");
    Ok(())
}

fn de_ip_a_bytes(ip: &IpHeader) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    bytes.push(ip.ver_ihl);
    bytes.push(ip.tos);
    bytes.extend_from_slice(&ip.longitud_total.to_be_bytes());
    bytes.extend_from_slice(&ip.id.to_be_bytes());
    bytes.extend_from_slice(&ip.flags_fragmento.to_be_bytes());
    bytes.push(ip.ttl);
    bytes.push(ip.protocolo);
    bytes.extend_from_slice(&ip.checksum.to_be_bytes());
    bytes.extend_from_slice(&ip.origen);
    bytes.extend_from_slice(&ip.destino);
    bytes
}

fn de_tcp_a_bytes(tcp: &TcpHeader) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(&tcp.puerto_origen.to_be_bytes());
    bytes.extend_from_slice(&tcp.puerto_destino.to_be_bytes());
    bytes.extend_from_slice(&tcp.num_secuencia.to_be_bytes());
    bytes.extend_from_slice(&tcp.num_ack.to_be_bytes());
    bytes.extend_from_slice(&tcp.offset_res_flags.to_be_bytes());
    bytes.extend_from_slice(&tcp.ventana.to_be_bytes());
    bytes.extend_from_slice(&tcp.checksum.to_be_bytes());
    bytes.extend_from_slice(&tcp.puntero_urgente.to_be_bytes());
    bytes
}

fn calcular_ip_checksum(ip_bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < ip_bytes.len() {
        sum += u32::from(u16::from_be_bytes([ip_bytes[i], ip_bytes[i + 1]]));
        i += 2;
    }
    if i < ip_bytes.len() {
        sum += u32::from(u16::from_be_bytes([ip_bytes[i], 0x00]));
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn calcular_tcp_checksum(origen: &Ipv4Addr, destino: &Ipv4Addr, tcp_bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let oct_orig = origen.octets();
    let oct_dest = destino.octets();

    sum += u32::from(u16::from_be_bytes([oct_orig[0], oct_orig[1]]));
    sum += u32::from(u16::from_be_bytes([oct_orig[2], oct_orig[3]]));
    sum += u32::from(u16::from_be_bytes([oct_dest[0], oct_dest[1]]));
    sum += u32::from(u16::from_be_bytes([oct_dest[2], oct_dest[3]]));
    sum += 0x0006u32;
    sum += tcp_bytes.len() as u32;

    let mut i = 0;
    while i + 1 < tcp_bytes.len() {
        sum += u32::from(u16::from_be_bytes([tcp_bytes[i], tcp_bytes[i + 1]]));
        i += 2;
    }
    if i < tcp_bytes.len() {
        sum += u32::from(u16::from_be_bytes([tcp_bytes[i], 0x00]));
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
