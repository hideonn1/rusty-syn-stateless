use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

struct ResultadoEscaneo {
    puerto: u16,
    abierto: bool,
}

fn main() {
    let ip_objetivo = "127.0.0.1";
    let puertos = vec![21, 22, 53, 80, 443, 27017, 3306, 8080];

    println!("Iniciando escaneo con canales MPSC en: {}", ip_objetivo);
    println!("-----------------------------------------------------");

    let (tx, rx) = mpsc::channel();
    let mut total_hilos = 0;

    for puerto in puertos {
        let tx_hilo = tx.clone();
        let ip = ip_objetivo.to_string();
        total_hilos += 1;

        thread::spawn(move || {
            let direccion = format!("{}:{}", ip, puerto);

            let abierto =
                TcpStream::connect_timeout(&direccion.parse().unwrap(), Duration::from_millis(500))
                    .is_ok();

            tx_hilo.send(ResultadoEscaneo { puerto, abierto }).unwrap();
        });
    }

    drop(tx);

    for resultado in rx {
        let estado = if resultado.abierto {
            "[ ABIERTO ]"
        } else {
            "[ CERRADO ]"
        };
        println!("Puerto {:<5} ... {}", resultado.puerto, estado);
    }

    println!("------------------------------------------------------");
    println!(
        "Escaneo centralizado finalizado con éxito. Se analizaron {} puertos",
        total_hilos
    );
}
