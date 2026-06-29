use std::env;
use std::net::{Ipv4Addr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

struct ResultadoEscaneo {
    ip: String,
    puerto: u16,
    abierto: bool,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Uso: cargo run -- <IP_O_SEGMENTO/24> <PUERTOS>");
        println!("Ejemplo IP única: cargo run -- 192.168.0.3 22,80");
        println!("Ejemplo Red /24:  cargo run -- 192.168.0.0/24 80,443");
        return;
    }

    let entrada_red = &args[1];
    let puertos_str = &args[2];

    let puertos: Vec<u16> = puertos_str
        .split(',')
        .filter_map(|p| p.trim().parse::<u16>().ok())
        .collect();

    if puertos.is_empty() {
        println!("Error: No se especificaron puertos válidos.");
        return;
    }

    let lista_ips = match parsear_red(entrada_red) {
        Ok(ips) => ips,
        Err(e) => {
            println!("Error al procesar el objetivo: {}", e);
            return;
        }
    };

    println!("Iniciando escaneo en {} hosts...", lista_ips.len());
    println!("Puertos objetivo: {:?}", puertos);
    println!("--------------------------------------------");

    let (tx, rx) = mpsc::channel();
    let mut total_tareas = 0;

    for ip in &lista_ips {
        for &puerto in &puertos {
            let tx_hilo = tx.clone();
            let ip_str = ip.to_string();
            total_tareas += 1;

            thread::spawn(move || {
                let direccion = format!("{}:{}", ip_str, puerto);
                let timeout = Duration::from_millis(200);
                let abierto =
                    TcpStream::connect_timeout(&direccion.parse().unwrap(), timeout).is_ok();

                tx_hilo
                    .send(ResultadoEscaneo {
                        ip: ip_str,
                        puerto,
                        abierto,
                    })
                    .unwrap();
            });
        }
    }

    drop(tx);

    let mut hosts_activos = 0;
    for resultado in rx {
        if resultado.abierto {
            println!(
                "[+] ¡ACTIVO! -> Host: {:<15} | Puerto: {:<5} [ ABIERTO ]",
                resultado.ip, resultado.puerto
            );
            hosts_activos += 1;
        }
    }

    println!("------------------------------------------");
    println!(
        "Escaneo finalizado. Tareas ejecutadas: {}. Hosts con puertos abiertos encontrados {}.",
        total_tareas, hosts_activos
    );
}

fn parsear_red(entrada: &str) -> Result<Vec<Ipv4Addr>, String> {
    if entrada.contains("/24") {
        let ip_base_str = entrada.replace("/24", "");
        let ip_base: Ipv4Addr = ip_base_str
            .parse()
            .map_err(|_| "IP base inválida para el segmento /24")?;

        let octetos = ip_base.octets();
        let ip_u32 = u32::from_be_bytes(octetos);

        let red_base_u32 = ip_u32 & 0xFFFFFF00;

        let mut rango = Vec::new();
        for i in 1..=254 {
            let ip_actual_u32 = red_base_u32 + i;
            rango.push(Ipv4Addr::from(ip_actual_u32.to_be_bytes()));
        }
        Ok(rango)
    } else {
        let ip: Ipv4Addr = entrada.parse().map_err(|_| "Formato de IP inválido")?;
        Ok(vec![ip])
    }
}
