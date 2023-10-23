use etherparse::SlicedPacket;
use std::io::{Error, ErrorKind};
use pcap::Packet;

pub struct PacketData {
    pub protocol: String,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub data: String
}

pub fn process_packet(packet: &Packet)-> Result<PacketData, Error> {
    if packet.data.len() < 20 {
        return Err(Error::new(ErrorKind::Other, "Packet too small"));
    }
    

    match SlicedPacket::from_ethernet(&packet.data) {
        Ok(value) => {
            println!("{:?}", value);
            use etherparse::TransportSlice::{Tcp};
            use etherparse::LinkSlice::{Ethernet2};

            let mut protocol = "Unknown";
            let mut src_port: u16 = 0;
            let mut dest_port: u16 = 0; 

            if let Some(Tcp(value)) = value.transport {
                dest_port = value.destination_port();
            }  

            if dest_port == 21 {
                protocol = "FTP";
            }

            let mut destination_ip: String = String::from("Unknown");
                        let mut source_ip: String = String::from("Unknown");

            if let Some(Ethernet2(value)) = value.link {
                let dst_ip = value.destination();
                destination_ip = format!("{:?}.{:?}.{:?}.{:?}", dst_ip[2], dst_ip[3], dst_ip[4], dst_ip[5]);

                let src_ip = value.source();
                source_ip = format!("{:?}.{:?}.{:?}.{:?}", src_ip[2], src_ip[3], src_ip[4], src_ip[5]);
            }

            let payload_data = String::from_utf8_lossy(value.payload);

            return Ok(PacketData {
                protocol: String::from(protocol),
                source_ip: source_ip,
                source_port: src_port,
                destination_ip: destination_ip,
                destination_port: dest_port,
                data: String::from(payload_data)
            });
            
        }
        Err(err) => {
            return Err(Error::new(ErrorKind::Other, err));
        }
    }
}

#[cfg(test)]
mod tests {
    use pcap::{Packet, PacketHeader};

    use super::*;
    use std::{io::ErrorKind};
    use etherparse::{*, ether_type::IPV4};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_process_packet_too_small() {
        let data = vec![0; 10];  // Less than 20 bytes
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: data.len() as u32,
            len: data.len() as u32,
        };

        // Construct a pcap::Packet using the mock header and data
        let packet = Packet::new(&header, &data);
        let result = process_packet(&packet);
        assert!(matches!(result, Err(e) if e.kind() == ErrorKind::Other && e.to_string().contains("Packet not too small")));
    }

    #[test]
    fn test_process_packet_returns_strict() {
        
        // Construct a pcap::Packet using the mock header and data
        let packet = create_pcap_packet(construct_packet());  // Empty payload
        let result = process_packet(&packet);
        assert!(matches!(result, Ok(value) if value.protocol == "Unknown" && value.source_ip == "Unknown" && value.source_port == 0 && value.destination_ip == "Unknown" && value.destination_port == 0 && value.data == ""));
    }

    fn construct_packet() -> Vec<u8> {
    // Ethernet layer
    let ethernet_header = Ethernet2Header {
        destination: [2, 66, 171, 34, 251, 88],
        source: [2, 66, 172, 17, 0, 2],
        ether_type: IPV4,
    }

    // IPv4 layer
    let ipv4_header = Ipv4Header::new(64, 59233, 16384, 64, etherparse::IpTrafficClass::Tcp, [172, 17, 0, 1], [172, 17, 0, 2]);

    // TCP layer
    let tcp_header_slice = &[
        145, 156, 0, 21, 242, 106, 252, 174, 21, 58, 100, 84, 128, 24, 66, 212, 88, 88, 0, 0, 1, 1, 8, 10, 131, 25, 156, 48, 243, 175, 96, 6
    ];
    let tcp_header = TcpHeader::read(tcp_header_slice).expect("Failed to read TCP header");

    // Payload
    let payload = [85, 83, 69, 82, 32, 97, 102, 102, 105, 120, 13, 10];

    // Construct packet
    let mut packet = Vec::<u8>::with_capacity(ethernet_header.header_len() + ipv4_header.header_len() + tcp_header.header_len() + payload.len());
    PacketBuilder::ethernet2(ethernet_header.source, ethernet_header.destination)
        .ipv4(ipv4_header.source, ipv4_header.destination, 64, etherparse::IpTrafficClass::Tcp)
        .tcp(tcp_header.source_port, tcp_header.destination_port, tcp_header.sequence_number, tcp_header.acknowledgment_number)
        .write(&mut packet, &payload).expect("Failed to write packet");

    packet
    }


    fn create_pcap_packet(data: Vec<u8>) -> Packet<'static> {
        // Get the current time for the timestamp
        let start = SystemTime::now();
        let duration_since_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let ts_sec = duration_since_epoch.as_secs() as i64;
        let ts_usec = duration_since_epoch.subsec_micros() as i64;

        // Create a mock PacketHeader
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: ts_sec,
                tv_usec: ts_usec,
            },
            caplen: data.len() as u32,
            len: data.len() as u32,
        };

        // Unfortunately, pcap::Packet doesn't provide a direct way to construct from raw data and a header
        // So we might need to get creative or work with the underlying byte slices.
        // For the sake of this example, I'll just transmute to satisfy the lifetime requirements
        // This isn't necessarily safe in all contexts. Be very cautious with transmutes.
        let packet: Packet = unsafe {
            std::mem::transmute(pcap::Packet::new(&header, &data))
        };

        packet
    }
}