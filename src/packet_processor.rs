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
            use etherparse::TransportSlice::Tcp;
            use etherparse::LinkSlice::Ethernet2;

            let mut protocol = "Unknown";
            let mut src_port: u16 = 0;
            let mut dest_port: u16 = 0; 

            if let Some(Tcp(value)) = value.transport {
                dest_port = value.destination_port();
                src_port = value.source_port();
            }  

            if dest_port == 21 {
                protocol = "FTP";
            }

            if dest_port == 80 {
                protocol = "HTTP";
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
    use etherparse::PacketBuilder;
    use pcap::{Packet, PacketHeader};

    use super::*;
    use std::{time::{SystemTime, UNIX_EPOCH}, any::Any};

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
        assert!(matches!(result, Err(e) if e.kind() == ErrorKind::Other));
    }

    #[test]
    fn test_process_packet_returns_packet_data() {
        let packet = create_pcap_packet(construct_packet());
        let result = process_packet(&packet);
        if let Some(value) = result.ok() {
            assert!(is_packet_data(&value));
        }
    }

    fn is_packet_data(value: &dyn Any) -> bool {
        value.is::<PacketData>()
    }

    fn construct_packet() -> Vec<u8> {
        // Payload
        let payload = [85, 83, 69, 82, 32, 97, 102, 102, 105, 120, 13, 10]; // USER affix\r\n

        // Construct packet
        let mut packet = Vec::<u8>::with_capacity(payload.len());
        let _ = PacketBuilder::ethernet2([0,0,0,0,0,0], [0,0,0,0,0,0])
        .ipv4([192,168,1,1], [192,168,1,2], 20)  
        .tcp(21, 12, 12345, 4000)
        .write(&mut packet, &payload);

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

        let packet: Packet = unsafe {
            std::mem::transmute(pcap::Packet::new(&header, &data))
        };

        return packet
    }
}