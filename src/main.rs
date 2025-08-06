use std::{
    fs::File,
    io::Read,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    os::raw,
};

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<(), ()> {
        self.pos += steps;

        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<(), ()> {
        self.pos = pos;

        Ok(())
    }

    fn read(&mut self) -> Result<u8, String> {
        if self.pos >= self.buf.len() {
            return Err("Buffer overflow".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn write(&mut self, val: u8) -> Result<(), String> {
        if self.pos >= 512 {
            return Err("Buffer overflow".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn get(&mut self, pos: usize) -> Result<u8, String> {
        if pos >= self.buf.len() {
            return Err("Index out of bounds".into());
        }
        Ok(self.buf[pos])
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<(), String> {
        if pos >= self.buf.len() {
            return Err("Index out of bounds".into());
        }
        self.buf[pos] = val;

        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<(), ()> {
        self.write(val).unwrap();

        Ok(())
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], String> {
        if start + len > self.buf.len() {
            return Err("Index out of bounds".into());
        }
        Ok(&self.buf[start..start + len])
    }

    fn read_u16(&mut self) -> Result<u16, ()> {
        let high = self.read().unwrap();
        let low = self.read().unwrap();
        Ok((high as u16) << 8 | (low as u16))
    }

    fn write_u16(&mut self, val: u16) -> Result<(), ()> {
        self.write((val >> 8) as u8).unwrap();
        self.write((val & 0xFF) as u8).unwrap();
        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), String> {
        if pos + 1 > self.buf.len() {
            return Err("Index out of bounds".into());
        }
        self.set(pos, (val >> 8) as u8).unwrap();
        self.set(pos + 1, (val & 0xFF) as u8).unwrap();
        Ok(())
    }

    fn read_u32(&mut self) -> Result<u32, ()> {
        let res = ((self.read().unwrap() as u32) << 24)
            | ((self.read().unwrap() as u32) << 16)
            | ((self.read().unwrap() as u32) << 8)
            | ((self.read().unwrap() as u32) << 0);

        Ok(res)
    }

    fn write_u32(&mut self, val: u32) -> Result<(), ()> {
        self.write(((val >> 24) & 0xFF) as u8).unwrap();
        self.write(((val >> 16) & 0xFF) as u8).unwrap();
        self.write(((val >> 8) & 0xFF) as u8).unwrap();
        self.write(((val >> 0) & 0xFF) as u8).unwrap();

        Ok(())
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<(), String> {
        let mut pos = self.pos();
        let mut jumped = false;

        let mut delim = "";
        let max_jumps = 5;
        let mut jumps_performed = 0;
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) == 0xC0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(pos + 2).unwrap();
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                jumps_performed += 1;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize).unwrap();
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos).unwrap();
        }

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<(), String> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8).unwrap();
            for b in label.as_bytes() {
                self.write_u8(*b).unwrap();
            }
        }

        self.write_u8(0).unwrap();
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_u8(value: u8) -> ResultCode {
        match value {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), ()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_u8(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), ()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_u16(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(v) => v,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_u16(value: u16) -> QueryType {
        match value {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(value),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), ()> {
        buffer.read_qname(&mut self.name).unwrap();
        self.qtype = QueryType::from_u16(buffer.read_u16().unwrap());

        let _class = buffer.read_u16().unwrap(); // Class, TODO
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), ()> {
        buffer.write_qname(&self.name).unwrap();

        let typenum = self.qtype.to_u16();
        buffer.write_u16(typenum).unwrap();
        buffer.write_u16(1).unwrap();

        Ok(())
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: QueryType,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        host: String,
        priority: u16,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, String> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain).unwrap();

        let qtype = QueryType::from_u16(buffer.read_u16().unwrap());
        let _ = buffer.read_u16().unwrap(); // Class, TODO
        let ttl = buffer.read_u32().unwrap();
        let data_len = buffer.read_u16().unwrap();

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32().unwrap();
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );
                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32().unwrap();
                let raw_addr2 = buffer.read_u32().unwrap();
                let raw_addr3 = buffer.read_u32().unwrap();
                let raw_addr4 = buffer.read_u32().unwrap();
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host).unwrap();
                Ok(DnsRecord::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host).unwrap();
                Ok(DnsRecord::CNAME { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read_u16().unwrap();
                let mut host = String::new();
                buffer.read_qname(&mut host).unwrap();

                Ok(DnsRecord::MX {
                    domain,
                    host,
                    priority,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize).unwrap();
                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize, ()> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain).unwrap();
                buffer.write_u16(QueryType::A.to_u16()).unwrap();
                buffer.write_u16(1).unwrap();
                buffer.write_u32(ttl).unwrap();
                buffer.write_u16(4).unwrap();

                let octets = addr.octets();
                buffer.write_u8(octets[0]).unwrap();
                buffer.write_u8(octets[1]).unwrap();
                buffer.write_u8(octets[2]).unwrap();
                buffer.write_u8(octets[3]).unwrap();
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain).unwrap();
                buffer.write_u16(QueryType::NS.to_u16()).unwrap();
                buffer.write_u16(1).unwrap();
                buffer.write_u32(ttl).unwrap();

                let pos = buffer.pos();
                buffer.write_u16(0).unwrap();

                buffer.write_qname(host).unwrap();

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16).unwrap();
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain).unwrap();
                buffer.write_u16(QueryType::CNAME.to_u16()).unwrap();
                buffer.write_u16(1).unwrap();
                buffer.write_u32(ttl).unwrap();

                let pos = buffer.pos();
                buffer.write_u16(0).unwrap();

                buffer.write_qname(host).unwrap();

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16).unwrap();
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain).unwrap();
                buffer.write_u16(QueryType::MX.to_u16()).unwrap();
                buffer.write_u16(1).unwrap();
                buffer.write_u32(ttl).unwrap();

                let pos = buffer.pos();
                buffer.write_u16(0).unwrap();

                buffer.write_u16(priority).unwrap();
                buffer.write_qname(host).unwrap();

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16).unwrap();
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain).unwrap();
                buffer.write_u16(QueryType::AAAA.to_u16()).unwrap();
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket, ()> {
        let mut result = DnsPacket::new();
        result.header.read(buffer).unwrap();

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new(String::new(), QueryType::UNKNOWN(0));
            question.read(buffer).unwrap();
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let record = DnsRecord::read(buffer).unwrap();
            result.answers.push(record);
        }

        for _ in 0..result.header.authoritative_entries {
            let record = DnsRecord::read(buffer).unwrap();
            result.authorities.push(record);
        }

        for _ in 0..result.header.resource_entries {
            let record = DnsRecord::read(buffer).unwrap();
            result.resources.push(record);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), ()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer).unwrap();

        for question in &self.questions {
            question.write(buffer).unwrap();
        }
        for rec in &self.answers {
            rec.write(buffer).unwrap();
        }
        for rec in &self.authorities {
            rec.write(buffer).unwrap();
        }
        for rec in &self.resources {
            rec.write(buffer).unwrap();
        }

        Ok(())
    }
}

fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket, ()> {
    // Forward queries to Google's public DNS
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server).unwrap();

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    DnsPacket::from_buffer(&mut res_buffer)
}

fn handle_query(socket: &UdpSocket) -> Result<(), ()> {
    let mut req_buffer = BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf).unwrap();
    let mut request = DnsPacket::from_buffer(&mut req_buffer).unwrap();

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        if let Ok(result) = lookup(&question.name, question.qtype) {
            packet.questions.push(question);
            packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    }
    else {
        packet.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len).unwrap();

    socket.send_to(data, src).unwrap();

    Ok(())
}


fn main() -> Result<(), String> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();

    loop {
        handle_query(&socket).unwrap();
    }
}
