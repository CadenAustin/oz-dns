use std::{fs::File, io::Read, net::Ipv4Addr, os::raw};

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

    fn get(&mut self, pos: usize) -> Result<u8, String> {
        if pos >= self.buf.len() {
            return Err("Index out of bounds".into());
        }
        Ok(self.buf[pos])
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

    fn read_u32(&mut self) -> Result<u32, ()> {
        let high = self.read_u16().unwrap();
        let low = self.read_u16().unwrap();
        Ok((high as u32) << 16 | (low as u32))
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<(), String> {
        let mut pos = self.pos();
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;
        let mut delim = "";

        loop {
            if jumps_performed >= max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps));
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2).unwrap();
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            } else {
                pos += 1;
                if len == 0 {
                    break;
                }
                outstr.push_str(delim);
                let str_buffer = self.get_range(pos, len as usize).unwrap();
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";
                pos += len as usize
            }
        }

        if !jumped {
            self.seek(pos).unwrap();
        }

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
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryType {
    UNKOWN(u16),
    A,
    
}

impl QueryType {
    pub fn to_u16(&self) -> u16 {
        match *self {
            QueryType::UNKOWN(v) => v,
            QueryType::A => 1,
        }
    }

    pub fn from_u16(value: u16) -> QueryType {
        match value {
            1 => QueryType::A,
            _ => QueryType::UNKOWN(value),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType
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
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKOWN {
        domain: String,
        qtype: QueryType,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }
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
            _ => Ok(DnsRecord::UNKOWN {
                domain,
                qtype,
                data_len,
                ttl,
            }),
        }
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
            let mut question = DnsQuestion::new(String::new(), QueryType::UNKOWN(0));
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
}

fn main() -> Result<(), String> {
    let mut f = File::open("response_packet.txt").expect("Unable to open file");
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf).expect("Unable to read file");

    let packet = DnsPacket::from_buffer(&mut buffer).expect("Failed to parse DNS packet");
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
