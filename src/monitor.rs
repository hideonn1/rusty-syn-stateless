use crate::cli::{MonitorArgs, Verbosidad};
use std::io;
use std::net::Ipv4Addr;
use tokio::fs;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Conexion {
    pub ip_local: Ipv4Addr,
    pub puerto_local: u16,
    pub ip_remota: Ipv4Addr,
    pub puerto_remoto: u16,
    pub estado: String,
}

fn parsear_direccion_proc(campo: &str) -> Option<(Ipv4Addr, u16)> {
    let partes: Vec<&str> = campo.split(':').collect();
    if partes.len() != 2 {
        return None;
    }

    let ip_u32 = u32::from_str_radix(partes[0], 16).ok()?;
    let octetos = ip_u32.to_le_bytes();
    let ip = Ipv4Addr::new(octetos[0], octetos[1], octetos[2], octetos[3]);
    let puerto = u16::from_str_radix(partes[1], 16).ok()?;

    Some((ip, puerto))
}

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

// CORRECCIÓN: Ahora es asíncrono y usa tokio::fs para no bloquear el hilo
async fn leer_conexiones_tcp() -> io::Result<Vec<Conexion>> {
    let contenido = fs::read_to_string("/proc/net/tcp").await?;
    let mut conexiones = Vec::new();

    for linea in contenido.lines().skip(1) {
        let campos: Vec<&str> = linea.split_whitespace().collect();
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

fn es_ip_privada(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 127
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0)
}

pub async fn ejecutar_monitor(args: MonitorArgs) -> io::Result<()> {
    let verbosidad = Verbosidad::desde_flags(args.verbose, args.quiet);

    if verbosidad != Verbosidad::Silencioso {
        println!("=== MONITOR DE CONEXIONES TCP SALIENTES ===");
    }

    let mut conocidas: std::collections::HashSet<Conexion> = std::collections::HashSet::new();
    let inicio = tokio::time::Instant::now();
    let mut primera_pasada = true;

    loop {
        if args.duracion_secs > 0 && inicio.elapsed().as_secs() >= args.duracion_secs {
            break;
        }

        let conexiones = match leer_conexiones_tcp().await {
            // CORRECCIÓN: .await
            Ok(c) => c,
            Err(_) => {
                tokio::time::sleep(tokio::time::Duration::from_secs(args.intervalo_secs)).await;
                continue;
            }
        };

        let relevantes: Vec<&Conexion> = conexiones
            .iter()
            .filter(|c| verbosidad == Verbosidad::Detallado || c.estado == "ESTABLISHED")
            .filter(|c| !args.solo_publicas || !es_ip_privada(&c.ip_remota))
            .collect();

        let actuales: std::collections::HashSet<Conexion> =
            relevantes.iter().map(|c| (*c).clone()).collect();

        for conexion in actuales.difference(&conocidas) {
            if !primera_pasada {
                println!(
                    "[+NUEVA] {}:{} -> {}:{} [{}]",
                    conexion.ip_local,
                    conexion.puerto_local,
                    conexion.ip_remota,
                    conexion.puerto_remoto,
                    conexion.estado
                );
            }
        }

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

        conocidas = actuales;
        primera_pasada = false;
        tokio::time::sleep(tokio::time::Duration::from_secs(args.intervalo_secs)).await;
    }
    Ok(())
}
