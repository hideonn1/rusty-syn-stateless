use crate::cli::{EscanerArgs, Verbosidad};
use crate::network::*;
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstadoPuerto {
    Abierto,
    Cerrado,
}

fn activar_ip_hdrincl(socket: &Socket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let val: libc::c_int = 1;
    // SAFETY: setsockopt con IP_HDRINCL es una operación segura del kernel;
    // el puntero apunta a un valor válido de tipo c_int con lifetime adecuado.
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

fn recv_safe(socket: &Socket, buf: &mut Vec<u8>) -> io::Result<usize> {
    // SAFETY: La transmutación de &mut [u8] a &mut [MaybeUninit<u8>] es segura
    // porque MaybeUninit<u8> tiene el mismo layout que u8, y los bytes del buffer
    // ya están inicializados (Vec<u8> garantiza inicialización).
    let uninit_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
    socket.recv(uninit_buf)
}

fn crear_socket_raw_tcp() -> io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
}

/// Detecta la IP local de la interfaz con ruta a Internet creando un socket UDP
/// conectado a 8.8.8.8 (no envía datos) y leyendo la dirección local asignada.
fn detectar_ip_local() -> io::Result<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    match socket.local_addr()?.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            "No se pudo detectar una dirección IPv4 local",
        )),
    }
}

fn construir_paquete_syn(
    ip_origen: Ipv4Addr,
    ip_destino: Ipv4Addr,
    p_origen: u16,
    puerto_dest: u16,
    id_ip: u16,
    salt: u32,
) -> Vec<u8> {
    let seq_stateless = codificar_seq(ip_destino, puerto_dest, salt);

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

    let ip = IpHeader {
        ver_ihl: 0x45,
        tos: 0,
        longitud_total: 40,
        id: id_ip,
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

    paquete
}

pub async fn ejecutar_escaner(args: EscanerArgs) -> io::Result<()> {
    let verbosidad = Verbosidad::desde_flags(args.verbose, args.quiet);

    // Validar privilegios de root antes de intentar abrir sockets raw
    // SAFETY: geteuid() es una llamada al sistema sin efectos secundarios.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: se requieren privilegios de root (sudo) para abrir sockets raw.");
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "se requiere root",
        ));
    }

    // Resolver IP de origen: auto-detectar si no se proporcionó
    let ip_origen: Ipv4Addr = match &args.ip_origen {
        Some(ip_str) => ip_str.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("IP de origen inválida '{}': {}", ip_str, e),
            )
        })?,
        None => {
            let ip = detectar_ip_local()?;
            if verbosidad != Verbosidad::Silencioso {
                println!("IP de origen detectada automáticamente: {}", ip);
            }
            ip
        }
    };

    // Salt dinámico y aleatorio por sesión para evadir correlación de firewalls/IDS
    let session_salt: u32 = rand::thread_rng().gen();

    let subred_base = args.subred.clone();
    let puertos_objetivo = args.puertos.clone();
    let p_origen = args.puerto_origen;

    let socket_tx = crear_socket_raw_tcp()?;
    activar_ip_hdrincl(&socket_tx)?;
    socket_tx.set_nonblocking(true)?;
    let async_fd_tx = Arc::new(AsyncFd::new(socket_tx)?);

    let socket_rx = crear_socket_raw_tcp()?;
    socket_rx.set_nonblocking(true)?;
    let async_fd_rx = Arc::new(AsyncFd::new(socket_rx)?);

    // Resultados compartidos: el sniffer escribe aquí, el main los lee al final
    let resultados: Arc<Mutex<Vec<(Ipv4Addr, u16, EstadoPuerto)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let resultados_sniffer = Arc::clone(&resultados);

    let sniffer_handle = tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];

        loop {
            let mut guard = match async_fd_rx.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            match recv_safe(guard.get_inner(), &mut buffer) {
                Ok(bytes_leidos) if bytes_leidos >= 40 => {
                    let ihl = (buffer[0] & 0x0F) as usize * 4;
                    let tcp_start = ihl;

                    if bytes_leidos < tcp_start + 20 {
                        guard.clear_ready();
                        continue;
                    }

                    let ip_src = Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]);
                    let p_src = u16::from_be_bytes([buffer[tcp_start], buffer[tcp_start + 1]]);
                    let p_dst_recibido =
                        u16::from_be_bytes([buffer[tcp_start + 2], buffer[tcp_start + 3]]);
                    let ack_recibido = u32::from_be_bytes([
                        buffer[tcp_start + 8],
                        buffer[tcp_start + 9],
                        buffer[tcp_start + 10],
                        buffer[tcp_start + 11],
                    ]);
                    let flags = buffer[tcp_start + 13];

                    if p_dst_recibido == p_origen
                        && verificar_token(ip_src, p_src, ack_recibido, session_salt)
                    {
                        if flags & 0x12 == 0x12 {
                            if verbosidad != Verbosidad::Silencioso {
                                println!("[+] ¡ABIERTO!  -> {}:{}", ip_src, p_src);
                            }
                            if let Ok(mut res) = resultados_sniffer.lock() {
                                res.push((ip_src, p_src, EstadoPuerto::Abierto));
                            }
                        } else if flags & 0x04 == 0x04 {
                            if let Ok(mut res) = resultados_sniffer.lock() {
                                res.push((ip_src, p_src, EstadoPuerto::Cerrado));
                            }
                        }
                    }
                    guard.clear_ready();
                }
                Ok(_) | Err(_) => guard.clear_ready(),
            }
        }
    });

    let verbosidad_tx = verbosidad;
    let async_fd_tx_loop = Arc::clone(&async_fd_tx);
    let tx_loop = async move {
        let mut rng = rand::thread_rng();
        let mut paquetes_enviados: u32 = 0;
        let mut errores_envio: u32 = 0;

        for host in 1u8..=254 {
            let ip_dest_str = format!("{}.{}", subred_base, host);
            let ip_destino: Ipv4Addr = match ip_dest_str.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            if ip_destino == ip_origen {
                continue;
            }

            for &puerto_dest in &puertos_objetivo {
                let id_aleatorio: u16 = rng.gen();
                let paquete = construir_paquete_syn(
                    ip_origen,
                    ip_destino,
                    p_origen,
                    puerto_dest,
                    id_aleatorio,
                    session_salt,
                );
                let sock_addr = SockAddr::from(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(ip_destino),
                    puerto_dest,
                ));

                if let Ok(mut guard) = async_fd_tx_loop.writable().await {
                    match guard.get_inner().send_to(&paquete, &sock_addr) {
                        Ok(_) => paquetes_enviados += 1,
                        Err(e) => {
                            errores_envio += 1;
                            if verbosidad_tx == Verbosidad::Detallado {
                                eprintln!(
                                    "[!] Error enviando a {}:{}: {}",
                                    ip_destino, puerto_dest, e
                                );
                            }
                        }
                    }
                    guard.clear_ready();
                }
                tokio::time::sleep(tokio::time::Duration::from_micros(50)).await;
            }
        }
        (paquetes_enviados, errores_envio)
    };

    // Select entre TX, timeout global, y Ctrl+C.
    // El sniffer NO está en el select — corre en background y escribe a resultados compartidos.
    tokio::select! {
        (paquetes, errores) = tx_loop => {
            if verbosidad != Verbosidad::Silencioso {
                println!(
                    "Inyección completada: {} paquetes enviados. Esperando respuestas residuales ({}s)...",
                    paquetes, args.ventana_captura_secs
                );
                if errores > 0 {
                    eprintln!("  ⚠ {} paquetes fallaron al enviar.", errores);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(args.ventana_captura_secs)).await;
        }
        _ = tokio::signal::ctrl_c() => {
            if verbosidad != Verbosidad::Silencioso {
                println!("\nInterrupción recibida (Ctrl+C). Mostrando resultados parciales...");
            }
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(args.timeout_secs)) => {
            if verbosidad != Verbosidad::Silencioso {
                println!("Timeout global alcanzado ({}s).", args.timeout_secs);
            }
        }
    }

    // Terminar el sniffer y recoger resultados
    sniffer_handle.abort();
    let _ = sniffer_handle.await;

    // Imprimir resumen final
    if verbosidad != Verbosidad::Silencioso {
        let resultados_finales = resultados.lock().unwrap_or_else(|e| e.into_inner());
        let abiertos: Vec<_> = resultados_finales
            .iter()
            .filter(|(_, _, estado)| *estado == EstadoPuerto::Abierto)
            .collect();
        let cerrados = resultados_finales
            .iter()
            .filter(|(_, _, estado)| *estado == EstadoPuerto::Cerrado)
            .count();

        println!("\n════════════════════════════════════════");
        println!("           RESUMEN DEL ESCANEO");
        println!("════════════════════════════════════════");
        println!("  Puertos abiertos:  {}", abiertos.len());
        println!("  Puertos cerrados:  {}", cerrados);

        if !abiertos.is_empty() {
            println!("\n  Detalle de puertos abiertos:");
            for (ip, puerto, _) in &abiertos {
                println!("    ✔ {}:{}", ip, puerto);
            }
        }
        println!("════════════════════════════════════════\n");
    }

    Ok(())
}
