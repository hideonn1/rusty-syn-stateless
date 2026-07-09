use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct IpHeader {
    pub ver_ihl: u8,
    pub tos: u8,
    pub longitud_total: u16,
    pub id: u16,
    pub flags_fragmento: u16,
    pub ttl: u8,
    pub protocolo: u8,
    pub checksum: u16,
    pub origen: [u8; 4],
    pub destino: [u8; 4],
}

#[derive(Debug)]
pub struct TcpHeader {
    pub puerto_origen: u16,
    pub puerto_destino: u16,
    pub num_secuencia: u32,
    pub num_ack: u32,
    pub offset_res_flags: u16,
    pub ventana: u16,
    pub checksum: u16,
    pub puntero_urgente: u16,
}

#[inline]
pub fn ipv4_a_u32(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

#[inline]
pub fn codificar_seq(ip: Ipv4Addr, puerto: u16, salt: u32) -> u32 {
    let mut hasher = DefaultHasher::new();
    salt.hash(&mut hasher);
    ipv4_a_u32(ip).hash(&mut hasher);
    puerto.hash(&mut hasher);
    hasher.finish() as u32
}

#[inline]
pub fn verificar_token(ip_src: Ipv4Addr, p_src: u16, ack_recibido: u32, salt: u32) -> bool {
    ack_recibido == codificar_seq(ip_src, p_src, salt).wrapping_add(1)
}

pub fn de_ip_a_bytes(ip: &IpHeader) -> Vec<u8> {
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

pub fn de_tcp_a_bytes(tcp: &TcpHeader) -> Vec<u8> {
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

pub fn calcular_ip_checksum(ip_bytes: &[u8]) -> u16 {
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

pub fn calcular_tcp_checksum(origen: &Ipv4Addr, destino: &Ipv4Addr, tcp_bytes: &[u8]) -> u16 {
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
