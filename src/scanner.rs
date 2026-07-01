use crate::cli::{EscanerArgs, Verbosidad};
use crate::network::*;
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::sync::Arc;
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
    let uninit_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
    socket.recv(uninit_buf)
}

fn crear_socket_raw_tcp() -> io::Result<Socket> {
    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
        Ok(s) => Ok(s),
        Err(e) => Err(e),
    }
}

fn construir_paquete_syn(
    ip_origen: Ipv4Addr,
    ip_destino: Ipv4Addr,
    p_origen: u16,
    puerto_dest: u16,
    id_ip: u16,
    salt: u32,
) -> io::Result<Vec<u8>> {
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

    Ok(paquete)
}

pub async fn ejecutar_escaner(args: EscanerArgs) -> io::Result<()> {
    let verbosidad = Verbosidad::desde_flags(args.verbose, args.quiet);
    let ip_origen: Ipv4Addr = args.ip_origen.parse().unwrap();

    // CORRECCIÓN: Salt dinámico y aleatorio para evadir respuestas falsas de Firewalls/IDS
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

    let sniffer = tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        let mut resultados = Vec::new();

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

                    if p_dst_recibido == p_origen {
                        if verificar_token(ip_src, p_src, ack_recibido, session_salt) {
                            if flags & 0x12 == 0x12 {
                                if verbosidad != Verbosidad::Silencioso {
                                    println!("[+] ¡ABIERTO!  -> {}:{}", ip_src, p_src);
                                }
                                resultados.push((ip_src, p_src, EstadoPuerto::Abierto));
                            } else if flags & 0x04 == 0x04 {
                                resultados.push((ip_src, p_src, EstadoPuerto::Cerrado));
                            }
                        }
                    }
                    guard.clear_ready();
                }
                Ok(_) | Err(_) => guard.clear_ready(),
            }
        }
        resultados
    });

    let async_fd_tx_loop = Arc::clone(&async_fd_tx);
    let tx_loop = async move {
        let mut rng = rand::thread_rng();
        let mut paquetes_enviados = 0;

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
                )
                .unwrap();
                let sock_addr = SockAddr::from(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(ip_destino),
                    puerto_dest,
                ));

                if let Ok(mut guard) = async_fd_tx_loop.writable().await {
                    let _ = guard.get_inner().send_to(&paquete, &sock_addr);
                    paquetes_enviados += 1;
                    guard.clear_ready();
                }
                tokio::time::sleep(tokio::time::Duration::from_micros(50)).await;
            }
        }
        paquetes_enviados
    };

    tokio::select! {
        paquetes = tx_loop => {
            if verbosidad != Verbosidad::Silencioso {
                println!("Inyección completada: {} paquetes enviados. Esperando respuestas residuales ({}s)...", paquetes, args.ventana_captura_secs);
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(args.ventana_captura_secs)).await;
        }
        _ = sniffer => {}
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(args.timeout_secs)) => {}
    }
    Ok(())
}
