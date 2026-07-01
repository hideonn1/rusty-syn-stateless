use clap::Parser;
use std::io::{self, Write};

mod cli;
mod monitor;
mod network;
mod scanner;

use cli::{imprimir_banner, imprimir_menu, Cli, Modo};
use monitor::ejecutar_monitor;
use scanner::ejecutar_escaner;

fn parsear_linea_repl(linea: &str) -> Result<Option<Modo>, String> {
    let trimmed = linea.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let mut partes: Vec<&str> = trimmed.split_whitespace().collect();
    partes.insert(0, "rustysn");

    match Cli::try_parse_from(partes) {
        Ok(cli) => Ok(cli.modo),
        Err(e) => Err(e.to_string()),
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    imprimir_banner();

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

    imprimir_menu();

    loop {
        print!("\nrustysn> ");
        io::stdout().flush()?;

        let mut linea = String::new();
        if io::stdin().read_line(&mut linea)? == 0 {
            break;
        }

        let comando = linea.trim();
        match comando.to_lowercase().as_str() {
            "" => continue,
            "exit" | "salir" | "quit" | "q" => break,
            "help" | "ayuda" | "menu" | "menú" => {
                imprimir_menu();
                continue;
            }
            "clear" | "cls" | "limpiar" => {
                print!("\x1B[2J\x1B[1;1H");
                io::stdout().flush()?;
                continue;
            }
            _ => {}
        }

        match parsear_linea_repl(comando) {
            Ok(Some(Modo::Escaner(args))) => {
                let _ = ejecutar_escaner(args).await;
            }
            Ok(Some(Modo::Monitor(args))) => {
                let _ = ejecutar_monitor(args).await;
            }
            Ok(None) => {}
            Err(mensaje) => println!("{}", mensaje),
        }
    }
    Ok(())
}
