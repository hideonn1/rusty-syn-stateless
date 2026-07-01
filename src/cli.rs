use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "lab_seguridad")]
#[command(about = "Escáner SYN stateless + monitor de conexiones — uso en redes y equipos propios")]
pub struct Cli {
    #[command(subcommand)]
    pub modo: Option<Modo>,
}

pub fn imprimir_banner() {
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
    println!("equipos de tu propiedad. Úsala de forma ética y responsable.");
    println!("────────────────────────────────────────────────────────────────\n");
}

pub fn imprimir_menu() {
    println!("Modos disponibles:\n");
    println!("  escaner   Escáner SYN activo (requiere privilegios de root)");
    println!("  monitor   Monitor pasivo de conexiones TCP salientes (lee /proc/net/tcp)\n");
    println!("Ejemplos:");
    println!("  escaner --subred 192.168.0 --puertos 80,443");
    println!("  monitor --solo-publicas --verbose\n");
}

#[derive(Subcommand, Debug)]
pub enum Modo {
    Escaner(EscanerArgs),
    Monitor(MonitorArgs),
}

#[derive(Parser, Debug)]
pub struct EscanerArgs {
    #[arg(long, default_value = "192.168.0")]
    pub subred: String,
    #[arg(long, default_value = "192.168.0.3")]
    pub ip_origen: String,
    #[arg(long, default_value = "80,443,8080", value_delimiter = ',')]
    pub puertos: Vec<u16>,
    #[arg(long, default_value_t = 54321)]
    pub puerto_origen: u16,
    #[arg(long, default_value_t = 90)]
    pub timeout_secs: u64,
    #[arg(long, default_value_t = 3)]
    pub ventana_captura_secs: u64,
    #[arg(short, long, conflicts_with = "quiet")]
    pub verbose: bool,
    #[arg(short, long, conflicts_with = "verbose")]
    pub quiet: bool,
}

#[derive(Parser, Debug)]
pub struct MonitorArgs {
    #[arg(long, default_value_t = 2)]
    pub intervalo_secs: u64,
    #[arg(long, default_value_t = 0)]
    pub duracion_secs: u64,
    #[arg(long)]
    pub solo_publicas: bool,
    #[arg(short, long, conflicts_with = "quiet")]
    pub verbose: bool,
    #[arg(short, long, conflicts_with = "verbose")]
    pub quiet: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosidad {
    Silencioso,
    Normal,
    Detallado,
}

impl Verbosidad {
    pub fn desde_flags(verbose: bool, quiet: bool) -> Self {
        if verbose {
            Verbosidad::Detallado
        } else if quiet {
            Verbosidad::Silencioso
        } else {
            Verbosidad::Normal
        }
    }
}
