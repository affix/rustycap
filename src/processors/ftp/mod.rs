use std::io::ErrorKind;
use std::io::Error;

use crate::packet_processor::PacketData;

fn extract_user_from_packet(packet: &str) -> Result<String, Error> {
    if packet.contains("USER") {
        return Ok(packet.replace("USER ", "").replace("\r\n", ""));
    } else {
        return Err(Error::new(ErrorKind::Other, "No user found"));
    }
}

fn extract_pass_from_packet(packet: &str) -> Result<String, Error> {
    if packet.contains("PASS") {
        return Ok(packet.replace("PASS ", "").replace("\r\n", ""));
    } else {
        return Err(Error::new(ErrorKind::Other, "No pass found"));
    }
}

pub fn parse_ftp_data(packet: &PacketData){
  if let Ok(user) = extract_user_from_packet(&packet.data) {
      println!("[{}] {}:{} -> Username : {}", packet.protocol, packet.destination_ip, packet.destination_port, user);
  }

  if let Ok(pass) = extract_pass_from_packet(&packet.data) {
      println!("[{}] {}:{} -> Password : {}", packet.protocol, packet.destination_ip, packet.destination_port, pass);
  }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn can_extract_user_from_packet_data() {
        let packet_data = "USER Hello\r\n";
        let user = extract_user_from_packet(packet_data);
        match user {
            Ok(u) => {
                assert_eq!(u, "Hello");
            }
            Err(_) => {}
        }
    }

    #[test]
    fn can_extract_pass_from_packet_data() {
        let packet_data = "PASS world\r\n";
        let user = extract_pass_from_packet(packet_data);
        match user {
            Ok(u) => {
                assert_eq!(u, "world");
            }
            Err(_) => {}
        }
    }
}