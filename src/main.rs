use core::panic;
use std::io::{Error, ErrorKind};
use pcap::{Device};
use pcap::Error as PcapError;

mod packet_processor;


fn find_device_by_name(capture_device: &str) -> Result<Device, Error> {
    match Device::list() {
        Ok(devices) => {
            if let Some(device) = devices.iter().find(|d| d.name == capture_device) {
                return Ok(device.clone());
            }
        }
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, PcapError::from(e)));
        }
    }
    Err(Error::new(ErrorKind::Other, "Device not found"))
}

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

fn main() {
    let capture_device = "docker0";
    println!("Learning pcap in rust! (Ctrl-C to stop)");

    match find_device_by_name(capture_device) {
        Ok(device) => {
            println!("Device found: {}", device.name);
            let filter = "tcp port 21";
            match pcap::Capture::from_device(device).unwrap().immediate_mode(true).open() {
                Ok(mut cap) => {
                    cap.filter(filter, true).unwrap();
                    println!("Capture started on {}...", capture_device);
                    while let Ok(packet) = cap.next_packet() {
                        if let Ok(packet) = packet_processor::process_packet(&packet){
                            if let Ok(user) = extract_user_from_packet(&packet.data) {
                                println!("[{}] {}:{} -> Username : {}", packet.protocol, packet.destination_ip, packet.destination_port, user);
                            }

                            if let Ok(pass) = extract_pass_from_packet(&packet.data) {
                                println!("[{}] {}:{} -> Password : {}", packet.protocol, packet.destination_ip, packet.destination_port, pass);
                            }
                        }
                    }
                }
                Err(err) => {
                    panic!("Error setting filter: {:?}", err);
                }
            }

        }
        Err(err) => {
            panic!("Error: {:?}", err);
        }
    }
}


/*
* UNIT TESTS!
*/
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_device_by_name() {
        let capture_device = "lo0";

        let dev = find_device_by_name(capture_device);
        match dev {
            Ok(device) => {
                assert_eq!(device.name, capture_device)
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_failed_device_name() {
        let capture_device = "ThisDeviceDoesNotExist";

        let d =  find_device_by_name(capture_device);
        assert!(d.is_err());
        match d {
            Ok(_) => {}
            Err(e) => {
                assert_eq!(e.to_string(), "Device not found");
            }
        }
    }

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