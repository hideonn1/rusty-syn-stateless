use clap::{Parser, Subcommand};
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

// =============================================================================
// CLI con clap — ahora con subcomandos
// =============================================================================

/// Herramienta de red local: escaneo SYN propio y monitor de conexiones salientes.
#[derive(Parser, Debug)]
#[command(name = "lab_seguridad")]
#[command(about = "Escáner SYN stateless + monitor de conexiones — uso en redes y equipos propios")]
struct Cli {
    #[command(subcommand)]
    modo: Option<Modo>,
}

fn imprimir_banner() {
    println!(
        r#"
 ____             _              ____        _  ____  __
|  _ \ _   _  ___| |_ _   _     / ___| _ __ (_)/ _|/ _| ___ _ __
| |_) | | | |/ __| __| | | |____\___ \| '_ \| | |_| |_ / _ \ '__|
|  _ <| |_| | (__| |_| |_| |____|___) | | | | |  _|  _|  __/ |
|_| \_\\__,_|\___|\__|\__, |    |____/|_| |_|_|_| |_|  \___|_|
                      |___/
"#
    );
    println!("            Escáner SYN + Monitor de conexiones — v0.7\n");
    println!("────────────────────────────────────────────────────────────────");
    println!("⚠  AVISO DE RESPONSABILIDAD");
    println!("────────────────────────────────────────────────────────────────");
    println!("Esta herramienta está pensada para uso EXCLUSIVO sobre redes y");
    println!("equipos de tu propiedad, o sobre los que tengas autorización");
    println!("explícita para realizar pruebas. Escanear o interceptar tráfico");
    println!("de redes o sistemas ajenos sin permiso puede ser ilegal según");
    println!("la legislación de tu país.");
    println!();
    println!("El autor de esta herramienta no se hace responsable del uso que");
    println!("se le dé. Úsala de forma ética y responsable.");
    println!("────────────────────────────────────────────────────────────────\n");
}

/// Imprime el menú de modos disponibles cuando no se pasa ningún subcomando.
fn imprimir_menu() {
    println!("Modos disponibles:\n");
    println!("  escaner   Escáner SYN activo sobre una subred local propia");
    println!("            (inyecta paquetes, requiere privilegios de root)");
    println!();
    println!("  monitor   Monitor pasivo de conexiones TCP salientes de esta");
    println!("            máquina (lee /proc/net/tcp, no requiere root)");
    println!();
    println!("Dentro de este prompt, escribe el comando directamente:");
    println!("  escaner --subred 192.168.0 --puertos 80,443");
    println!("  monitor --solo-publicas --verbose");
    println!();
    println!("Usa --help después de cada modo para ver todas sus opciones:");
    println!("  escaner --help");
    println!("  monitor --help");
    println!();
    println!("NOTA: el modo 'escaner' necesita privilegios de root para");
    println!("abrir raw sockets. Si ves un error de permisos, sal con");
    println!("'exit' y vuelve a arrancar TODO el programa con:");
    println!("  sudo rustysn         (si lo instalaste con cargo install)");
    println!("  sudo cargo run       (si estás desarrollando localmente)");
    println!("No es posible elevar privilegios escribiendo 'sudo' DENTRO");
    println!("de este prompt — sudo debe aplicarse al programa completo");
    println!("desde el inicio, no a un subcomando interno.");
}

#[derive(Subcommand, Debug)]
enum Modo {
    /// Escáner SYN activo sobre una subred local propia
    Escaner(EscanerArgs),
    /// Monitor pasivo de conexiones TCP salientes de esta máquina
    Monitor(MonitorArgs),
}

#[derive(Parser, Debug)]
struct EscanerArgs {
    /// Primeros 3 octetos de la subred a escanear (ej: 192.168.0)
    #[arg(long, default_value = "192.168.0")]
    subred: String,

    /// IP local de origen (tu propia IP en la red)
    #[arg(long, default_value = "192.168.0.3")]
    ip_origen: String,

    /// Puertos a escanear, separados por coma
    #[arg(long, default_value = "80,443,8080", value_delimiter = ',')]
    puertos: Vec<u16>,

    /// Puerto de origen usado para identificar las respuestas propias
    #[arg(long, default_value_t = 54321)]
    puerto_origen: u16,

    /// Timeout global del escaneo completo, en segundos
    #[arg(long, default_value_t = 90)]
    timeout_secs: u64,

    /// Ventana de espera tras terminar el envío, en segundos
    #[arg(long, default_value_t = 3)]
    ventana_captura_secs: u64,

    /// Modo detallado: muestra cada paquete enviado y cada respuesta relevante
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Modo silencioso: solo muestra el resumen final
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
}

#[derive(Parser, Debug)]
struct MonitorArgs {
    /// Intervalo entre refrescos del listado de conexiones, en segundos
    #[arg(long, default_value_t = 2)]
    intervalo_secs: u64,

    /// Duración total del monitoreo, en segundos (0 = correr hasta Ctrl+C)
    #[arg(long, default_value_t = 0)]
    duracion_secs: u64,

    /// Solo mostrar conexiones hacia IPs que no estén en rangos privados
    /// (10.x, 172.16-31.x, 192.168.x, 127.x) — útil para enfocarse en
    /// tráfico hacia internet en vez de tráfico de red local
    #[arg(long)]
    solo_publicas: bool,

    /// Modo detallado: muestra también conexiones en estado distinto a
    /// ESTABLISHED (LISTEN, TIME_WAIT, etc.)
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Modo silencioso: solo muestra nuevas conexiones detectadas, no el
    /// listado completo en cada refresco
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verbosidad {
    Silencioso,
    Normal,
    Detallado,
}

impl Verbosidad {
    fn desde_flags(verbose: bool, quiet: bool) -> Self {
        if verbose {
            Verbosidad::Detallado
        } else if quiet {
            Verbosidad::Silencioso
        } else {
            Verbosidad::Normal
        }
    }
}

// =============================================================================
// MODO MONITOR: lectura pasiva de /proc/net/tcp
//
// A diferencia del escáner, este modo NO usa raw sockets ni envía nada a la
// red. Solo lee la tabla de conexiones TCP que el kernel ya mantiene para
// todos los procesos del sistema, igual que hacen `ss` o `netstat`.
// Esto es estrictamente más seguro y más simple que sniffing con raw socket:
// no captura tráfico ajeno, solo metadatos de conexión (IP:puerto, estado)
// que el kernel expone para cualquier proceso sin privilegios especiales
// (salvo para ver el PID exacto, que sí requiere más acceso).
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Conexion {
    ip_local: Ipv4Addr,
    puerto_local: u16,
    ip_remota: Ipv4Addr,
    puerto_remoto: u16,
    estado: String,
}

/// Convierte el campo hexadecimal little-endian de /proc/net/tcp
/// (formato "0100007F:0050") a una dirección IP y puerto legibles.
///
/// FORMATO REAL: la IP en /proc/net/tcp está en hex, pero con los bytes
/// en orden inverso al de network byte order normal — es el orden de
/// palabra de máquina (little-endian en x86), no el de la red.
fn parsear_direccion_proc(campo: &str) -> Option<(Ipv4Addr, u16)> {
    let partes: Vec<&str> = campo.split(':').collect();
    if partes.len() != 2 {
        return None;
    }

    let ip_hex = partes[0];
    let puerto_hex = partes[1];

    if ip_hex.len() != 8 {
        return None;
    }

    let ip_u32 = u32::from_str_radix(ip_hex, 16).ok()?;
    // Los bytes vienen en orden little-endian de máquina; al voltearlos
    // con to_le_bytes() obtenemos el orden real de los octetos IPv4.
    let octetos = ip_u32.to_le_bytes();
    let ip = Ipv4Addr::new(octetos[0], octetos[1], octetos[2], octetos[3]);

    let puerto = u16::from_str_radix(puerto_hex, 16).ok()?;

    Some((ip, puerto))
}

/// Traduce el código de estado numérico de /proc/net/tcp a texto legible.
/// Referencia: include/net/tcp_states.h del kernel Linux.
fn estado_desde_codigo(codigo: &str) -> String {
    match codigo {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "DESCONOCIDO",
    }
    .to_string()
}

/// Lee y parsea /proc/net/tcp, devolviendo la lista de conexiones actuales.
/// Sin unwrap(): cualquier línea malformada se omite en vez de abortar.
fn leer_conexiones_tcp() -> io::Result<Vec<Conexion>> {
    let contenido = fs::read_to_string("/proc/net/tcp")?;
    let mut conexiones = Vec::new();

    // La primera línea es el encabezado de columnas — se omite.
    for linea in contenido.lines().skip(1) {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        // Columnas mínimas esperadas: sl, local_address, rem_address, st, ...
        if campos.len() < 4 {
            continue;
        }

        let (ip_local, puerto_local) = match parsear_direccion_proc(campos[1]) {
            Some(v) => v,
            None => continue,
        };
        let (ip_remota, puerto_remoto) = match parsear_direccion_proc(campos[2]) {
            Some(v) => v,
            None => continue,
        };
        let estado = estado_desde_codigo(campos[3]);

        conexiones.push(Conexion {
            ip_local,
            puerto_local,
            ip_remota,
            puerto_remoto,
            estado,
        });
    }

    Ok(conexiones)
}

/// Heurística simple para distinguir IPs de rangos privados (RFC 1918) y
/// loopback de IPs públicas de internet.
fn es_ip_privada(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 127                          // loopback 127.0.0.0/8
        || o[0] == 10                    // 10.0.0.0/8
        || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12
        || (o[0] == 192 && o[1] == 168)  // 192.168.0.0/16
        || (o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0) // 0.0.0.0 (LISTEN sin bind)
}

/// Ejecuta el modo monitor: refresca periódicamente la tabla de conexiones
/// y reporta altas/bajas, hasta que se alcance la duración configurada o
/// el usuario interrumpa con Ctrl+C.
async fn ejecutar_monitor(args: MonitorArgs) -> io::Result<()> {
    let verbosidad = Verbosidad::desde_flags(args.verbose, args.quiet);

    if verbosidad != Verbosidad::Silencioso {
        println!("=== MONITOR DE CONEXIONES TCP SALIENTES ===");
        println!(
            "[*] Intervalo: {}s | Solo públicas: {} | Duración: {}",
            args.intervalo_secs,
            args.solo_publicas,
            if args.duracion_secs == 0 {
                "indefinida (Ctrl+C para salir)".to_string()
            } else {
                format!("{}s", args.duracion_secs)
            }
        );
        println!("[*] Fuente de datos: /proc/net/tcp (sin raw sockets, sin captura de paquetes)\n");
    }

    let mut conocidas: std::collections::HashSet<Conexion> = std::collections::HashSet::new();
    let inicio = tokio::time::Instant::now();
    let mut primera_pasada = true;

    loop {
        if args.duracion_secs > 0 {
            let transcurrido = inicio.elapsed().as_secs();
            if transcurrido >= args.duracion_secs {
                if verbosidad != Verbosidad::Silencioso {
                    println!("\n[*] Duración configurada alcanzada. Monitor detenido.");
                }
                break;
            }
        }

        let conexiones = match leer_conexiones_tcp() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[!] Error leyendo /proc/net/tcp: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(args.intervalo_secs)).await;
                continue;
            }
        };

        // Filtrar solo ESTABLISHED salvo en modo verbose (que muestra todo)
        let relevantes: Vec<&Conexion> = conexiones
            .iter()
            .filter(|c| verbosidad == Verbosidad::Detallado || c.estado == "ESTABLISHED")
            .filter(|c| !args.solo_publicas || !es_ip_privada(&c.ip_remota))
            .collect();

        let actuales: std::collections::HashSet<Conexion> =
            relevantes.iter().map(|c| (*c).clone()).collect();

        // Nuevas conexiones desde la última pasada
        for conexion in actuales.difference(&conocidas) {
            if primera_pasada {
                // En la primera pasada no marcamos todo como "nuevo" para
                // no inundar la salida con el estado inicial del sistema;
                // solo lo mostramos como listado base.
                continue;
            }
            println!(
                "[+NUEVA] {}:{} -> {}:{} [{}]",
                conexion.ip_local,
                conexion.puerto_local,
                conexion.ip_remota,
                conexion.puerto_remoto,
                conexion.estado
            );
        }

        // Conexiones que ya no están (se cerraron)
        if verbosidad == Verbosidad::Detallado {
            for conexion in conocidas.difference(&actuales) {
                println!(
                    "[-CERRADA] {}:{} -> {}:{} [{}]",
                    conexion.ip_local,
                    conexion.puerto_local,
                    conexion.ip_remota,
                    conexion.puerto_remoto,
                    conexion.estado
                );
            }
        }

        if primera_pasada && verbosidad != Verbosidad::Silencioso {
            println!("[*] Listado inicial: {} conexiones activas", actuales.len());
            if verbosidad == Verbosidad::Detallado {
                for c in &actuales {
                    println!(
                        "    {}:{} -> {}:{} [{}]",
                        c.ip_local, c.puerto_local, c.ip_remota, c.puerto_remoto, c.estado
                    );
                }
            }
        }

        conocidas = actuales;
        primera_pasada = false;

        tokio::time::sleep(tokio::time::Duration::from_secs(args.intervalo_secs)).await;
    }

    Ok(())
}

// =============================================================================
// MODO ESCÁNER: estructuras de cabecera (idéntico a fases anteriores)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EstadoPuerto {
    Abierto,
    Cerrado,
}

#[inline]
fn ipv4_a_u32(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

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
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("❌ Requiere privilegios de Root.");
            eprintln!("   Sal con 'exit' y vuelve a arrancar TODO el programa así:");
            eprintln!("   sudo rustysn      (binario instalado)");
            eprintln!("   sudo cargo run    (desarrollo local)");
            Err(e)
        }
        Err(e) => Err(e),
    }
}

fn construir_paquete_syn(
    ip_origen: Ipv4Addr,
    ip_destino: Ipv4Addr,
    p_origen: u16,
    puerto_dest: u16,
    id_ip: u16,
) -> io::Result<Vec<u8>> {
    let seq_stateless = codificar_seq(ip_destino, puerto_dest);

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

    if paquete.len() != 40 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Error de serialización: se esperaban 40 bytes, se obtuvieron {}",
                paquete.len()
            ),
        ));
    }

    Ok(paquete)
}

/// Ejecuta el modo escáner SYN (idéntico en lógica a la Fase 6, ahora como
/// función separada para poder convivir con el modo monitor).
async fn ejecutar_escaner(args: EscanerArgs) -> io::Result<()> {
    let verbosidad = Verbosidad::desde_flags(args.verbose, args.quiet);

    let ip_origen: Ipv4Addr = args.ip_origen.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "--ip-origen '{}' no es una IP válida: {}",
                args.ip_origen, e
            ),
        )
    })?;

    if verbosidad != Verbosidad::Silencioso {
        println!("=== ESCÁNER SYN STATELESS MASIVO ===");
        println!(
            "[*] Subred: {}.1-254 | Puertos: {:?} | Origen: {}:{}",
            args.subred, args.puertos, ip_origen, args.puerto_origen
        );
    }

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
        let mut resultados: Vec<(Ipv4Addr, u16, EstadoPuerto)> = Vec::new();

        if verbosidad != Verbosidad::Silencioso {
            println!("[*] Sniffer activo escuchando respuestas TCP...");
        }

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

                    // FIX de diseño: el log [v] RX crudo ahora solo se
                    // muestra si el paquete va dirigido a nuestro puerto
                    // origen — antes mostraba TODO el tráfico TCP de la
                    // máquina (incluyendo conexiones HTTPS ajenas a Google,
                    // Microsoft, etc.), lo cual era ruido irrelevante y
                    // efectivamente un sniffer de tráfico general no deseado.
                    if p_dst_recibido == p_origen {
                        if verbosidad == Verbosidad::Detallado {
                            println!(
                                "[v] RX relevante: {}:{} -> ack={:#010x} flags={:#04x}",
                                ip_src, p_src, ack_recibido, flags
                            );
                        }

                        if verificar_token(ip_src, p_src, ack_recibido) {
                            if flags & 0x12 == 0x12 {
                                if verbosidad != Verbosidad::Silencioso {
                                    println!("[+] ¡ABIERTO!  -> {}:{}", ip_src, p_src);
                                }
                                resultados.push((ip_src, p_src, EstadoPuerto::Abierto));
                            } else if flags & 0x04 == 0x04 {
                                if verbosidad == Verbosidad::Detallado {
                                    println!("[-] Cerrado    -> {}:{}", ip_src, p_src);
                                }
                                resultados.push((ip_src, p_src, EstadoPuerto::Cerrado));
                            }
                        }
                    }
                    guard.clear_ready();
                }
                Ok(_) => {
                    guard.clear_ready();
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                }
                Err(_) => break,
            }
        }

        resultados
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;

    if verbosidad != Verbosidad::Silencioso {
        println!(
            "[*] Iniciando inyección masiva sobre el segmento {}.1-254...",
            subred_base
        );
    }

    let async_fd_tx_loop = Arc::clone(&async_fd_tx);
    let tx_loop = async move {
        let mut rng = rand::thread_rng();
        let mut paquetes_enviados: u32 = 0;
        let mut errores: u32 = 0;

        for host in 1u8..=254 {
            let ip_dest_str = format!("{}.{}", subred_base, host);
            let ip_destino: Ipv4Addr = match ip_dest_str.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    if verbosidad == Verbosidad::Detallado {
                        eprintln!("[!] IP inválida '{}': {} — host omitido", ip_dest_str, e);
                    }
                    errores += 1;
                    continue;
                }
            };

            if ip_destino == ip_origen {
                continue;
            }

            for &puerto_dest in &puertos_objetivo {
                let id_aleatorio: u16 = rng.r#gen();

                let paquete = match construir_paquete_syn(
                    ip_origen,
                    ip_destino,
                    p_origen,
                    puerto_dest,
                    id_aleatorio,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!(
                            "[!] Error construyendo paquete para {}:{} → {}",
                            ip_destino, puerto_dest, e
                        );
                        errores += 1;
                        continue;
                    }
                };

                if verbosidad == Verbosidad::Detallado {
                    println!(
                        "[v] TX -> {}:{} (seq={:#010x})",
                        ip_destino,
                        puerto_dest,
                        codificar_seq(ip_destino, puerto_dest)
                    );
                }

                let sock_addr = SockAddr::from(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(ip_destino),
                    puerto_dest,
                ));

                match async_fd_tx_loop.writable().await {
                    Ok(mut guard) => {
                        match guard.get_inner().send_to(&paquete, &sock_addr) {
                            Ok(_) => paquetes_enviados += 1,
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                            Err(e) => {
                                eprintln!(
                                    "[!] Error inyectando a {}:{} → {}",
                                    ip_destino, puerto_dest, e
                                );
                                errores += 1;
                            }
                        }
                        guard.clear_ready();
                    }
                    Err(e) => {
                        eprintln!("[!] Error esperando socket TX: {}", e);
                        errores += 1;
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_micros(50)).await;

                if paquetes_enviados > 0 && paquetes_enviados.is_multiple_of(10) {
                    tokio::task::yield_now().await;
                }
            }
        }

        (paquetes_enviados, errores)
    };

    let timeout_secs = args.timeout_secs;
    let ventana_secs = args.ventana_captura_secs;

    tokio::select! {
        (paquetes, errores) = tx_loop => {
            if verbosidad != Verbosidad::Silencioso {
                println!(
                    "✔ Inyección completada: {} paquetes enviados, {} errores. Esperando respuestas residuales ({}s)...",
                    paquetes, errores, ventana_secs
                );
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(ventana_secs)).await;
            if verbosidad != Verbosidad::Silencioso {
                println!("\n[*] Ventana de captura cerrada.");
            }
        }
        result = sniffer => {
            match result {
                Ok(resultados) => {
                    let abiertos = resultados.iter().filter(|(_, _, e)| *e == EstadoPuerto::Abierto).count();
                    let cerrados = resultados.iter().filter(|(_, _, e)| *e == EstadoPuerto::Cerrado).count();
                    println!("\n[*] Sniffer terminó antes que el TX. Abiertos: {} | Cerrados: {}", abiertos, cerrados);
                }
                Err(e) => eprintln!("❌ Falla crítica en Sniffer: {:?}", e),
            }
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(timeout_secs)) => {
            eprintln!("\n[!] Timeout global de {}s alcanzado — escaneo cortado por seguridad.", timeout_secs);
        }
    }

    if verbosidad != Verbosidad::Silencioso {
        println!("[*] Escaneo completado. Sockets liberados.");
    }
    Ok(())
}

// =============================================================================
// MAIN: despacha al modo elegido por el usuario
// =============================================================================

/// Parsea una línea de entrada del REPL como si fueran argumentos de CLI,
/// reutilizando la misma estructura `Cli` que clap usa para el modo directo.
/// Esto evita duplicar la lógica de parseo de --flags entre los dos modos
/// de invocación (directo vs interactivo).
fn parsear_linea_repl(linea: &str) -> Result<Option<Modo>, String> {
    let trimmed = linea.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    // shell_words separaría comillas correctamente; para mantenernos sin
    // dependencias nuevas, usamos un split simple por espacios — suficiente
    // para los flags que esta herramienta expone (sin valores con espacios).
    let mut partes: Vec<&str> = trimmed.split_whitespace().collect();
    // clap espera que el primer argumento sea el nombre del binario.
    partes.insert(0, "rustysn");

    match Cli::try_parse_from(partes) {
        Ok(cli) => Ok(cli.modo),
        Err(e) => Err(e.to_string()),
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    imprimir_banner();

    // Si se invocó con argumentos directos (ej: `rustysn escaner --subred ...`),
    // se respeta el modo clásico de un solo comando y se sale sin entrar al REPL.
    // Esto mantiene compatibilidad con scripts/automatización que ya usen
    // la herramienta de forma no interactiva.
    let args_directos: Vec<String> = std::env::args().collect();
    if args_directos.len() > 1 {
        let cli = Cli::parse();
        return match cli.modo {
            Some(Modo::Escaner(args)) => ejecutar_escaner(args).await,
            Some(Modo::Monitor(args)) => ejecutar_monitor(args).await,
            None => {
                imprimir_menu();
                Ok(())
            }
        };
    }

    // Sin argumentos: entrar al modo interactivo (REPL).
    imprimir_menu();

    loop {
        print!("\nrustysn> ");
        use std::io::Write;
        io::stdout().flush()?;

        let mut linea = String::new();
        let bytes_leidos = io::stdin().read_line(&mut linea)?;

        // EOF (Ctrl+D): salir limpiamente, igual que con "exit"
        if bytes_leidos == 0 {
            println!("\n[*] Saliendo de Rusty Sniffer (EOF). ¡Hasta luego!");
            break;
        }

        let comando = linea.trim();

        match comando.to_lowercase().as_str() {
            "" => continue,
            "exit" | "salir" | "quit" | "q" => {
                println!("[*] Saliendo de Rusty Sniffer. ¡Hasta luego!");
                break;
            }
            "help" | "ayuda" | "menu" | "menú" => {
                imprimir_menu();
                continue;
            }
            "clear" | "cls" | "limpiar" => {
                // Secuencia ANSI estándar para limpiar terminal — funciona
                // en la inmensa mayoría de terminales Unix/Linux/macOS.
                print!("\x1B[2J\x1B[1;1H");
                io::stdout().flush()?;
                continue;
            }
            _ => {}
        }

        match parsear_linea_repl(comando) {
            Ok(Some(Modo::Escaner(args))) => {
                if let Err(e) = ejecutar_escaner(args).await {
                    eprintln!("[!] Error en modo escáner: {}", e);
                }
            }
            Ok(Some(Modo::Monitor(args))) => {
                if let Err(e) = ejecutar_monitor(args).await {
                    eprintln!("[!] Error en modo monitor: {}", e);
                }
            }
            Ok(None) => {
                // clap absorbió el comando (ej: alguien escribió "--help"
                // suelto) sin devolver un modo concreto — no hacer nada.
            }
            Err(mensaje) => {
                // clap ya formatea su propio mensaje de error/ayuda con
                // el uso correcto de cada subcomando — se imprime tal cual.
                println!("{}", mensaje);
            }
        }
    }

    Ok(())
}

// =============================================================================
// SERIALIZACIÓN Y CHECKSUMS
// =============================================================================

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
