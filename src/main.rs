use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() {
    let ip_objetivo = "127.0.0.1";
    let puertos = vec![21, 22, 53, 80, 443, 27017, 3306, 8080];

    println!("Iniciando escaneo MULTIHILO en: {}", ip_objetivo);
    println!("-----------------------------------------------");

    let mut hilos = vec![];

    for puerto in puertos {
        let ip = ip_objetivo.to_string();

        let handle = thread::spawn(move || {
            let direccion = format!("{}:{}", ip, puerto);

            match TcpStream::connect_timeout(
                &direccion.parse().unwrap(),
                Duration::from_millis(500),
            ) {
                Ok(_) => {
                    println!("Puerto {:<5} ... [ ABIERTO ]", puerto);
                }
                Err(_) => {
                    println!("Puerto {:<5} ... [ CERRADO ]", puerto);
                }
            }
        });

        hilos.push(handle);
    }

    for hilo in hilos {
        hilo.join().unwrap();
    }

    println!("------------------------------------");
    println!("Escaneo multihilo finalizado con éxito.");
}
