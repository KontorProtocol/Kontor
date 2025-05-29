use anyhow::{Result, anyhow};
use bitcoin::{BlockHash, Transaction, Txid, consensus::encode, hashes::Hash};

#[derive(Debug, PartialEq)]
pub enum MonitorMessage {
    Connected,               // 0x0001
    ConnectDelayed,          // 0x0002
    ConnectRetried,          // 0x0004
    Listening,               // 0x0008
    BindFailed,              // 0x0010
    Accepted,                // 0x0020
    AcceptFailed,            // 0x0040
    Closed,                  // 0x0080
    CloseFailed,             // 0x0100
    Disconnected,            // 0x0200
    MonitorStopped,          // 0x0400
    HandshakeFailedNoDetail, // 0x0800
    HandshakeSucceeded,      // 0x1000
    HandshakeFailedProtocol, // 0x2000
    HandshakeFailedAuth,     // 0x4000
    Unknown(u16),            // Catch-all
}

impl MonitorMessage {
    pub fn from_raw(event_type: u16) -> Self {
        match event_type {
            0x0001 => MonitorMessage::Connected,
            0x0002 => MonitorMessage::ConnectDelayed,
            0x0004 => MonitorMessage::ConnectRetried,
            0x0008 => MonitorMessage::Listening,
            0x0010 => MonitorMessage::BindFailed,
            0x0020 => MonitorMessage::Accepted,
            0x0040 => MonitorMessage::AcceptFailed,
            0x0080 => MonitorMessage::Closed,
            0x0100 => MonitorMessage::CloseFailed,
            0x0200 => MonitorMessage::Disconnected,
            0x0400 => MonitorMessage::MonitorStopped,
            0x0800 => MonitorMessage::HandshakeFailedNoDetail,
            0x1000 => MonitorMessage::HandshakeSucceeded,
            0x2000 => MonitorMessage::HandshakeFailedProtocol,
            0x4000 => MonitorMessage::HandshakeFailedAuth,
            other => MonitorMessage::Unknown(other),
        }
    }

    pub fn to_raw(&self) -> u16 {
        match self {
            MonitorMessage::Connected => 0x0001,
            MonitorMessage::ConnectDelayed => 0x0002,
            MonitorMessage::ConnectRetried => 0x0004,
            MonitorMessage::Listening => 0x0008,
            MonitorMessage::BindFailed => 0x0010,
            MonitorMessage::Accepted => 0x0020,
            MonitorMessage::AcceptFailed => 0x0040,
            MonitorMessage::Closed => 0x0080,
            MonitorMessage::CloseFailed => 0x0100,
            MonitorMessage::Disconnected => 0x0200,
            MonitorMessage::MonitorStopped => 0x0400,
            MonitorMessage::HandshakeFailedNoDetail => 0x0800,
            MonitorMessage::HandshakeSucceeded => 0x1000,
            MonitorMessage::HandshakeFailedProtocol => 0x2000,
            MonitorMessage::HandshakeFailedAuth => 0x4000,
            MonitorMessage::Unknown(val) => *val,
        }
    }

    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            MonitorMessage::ConnectRetried
                | MonitorMessage::Closed
                | MonitorMessage::CloseFailed
                | MonitorMessage::Disconnected
                | MonitorMessage::HandshakeFailedNoDetail
                | MonitorMessage::HandshakeFailedProtocol
                | MonitorMessage::HandshakeFailedAuth
        )
    }

    pub fn all_events_mask() -> i32 {
        0xFFFF
    }

    pub fn failure_events_mask() -> i32 {
        0x0004 | 0x0100 | 0x0200 | 0x0800 | 0x2000 | 0x4000
        // CONNECT_RETRIED | CLOSE_FAILED | DISCONNECTED |
        // HANDSHAKE_FAILED_NO_DETAIL | HANDSHAKE_FAILED_PROTOCOL | HANDSHAKE_FAILED_AUTH
    }

    pub fn from_zmq_message(multipart: Vec<Vec<u8>>) -> Result<Self> {
        if multipart.is_empty() || multipart[0].len() < 2 {
            return Err(anyhow!("Received invalid multipart message"));
        }
        let event_type = u16::from_le_bytes(multipart[0][0..2].try_into()?);
        Ok(MonitorMessage::from_raw(event_type))
    }
}

pub const SEQUENCE: &str = "sequence";
pub const RAWTX: &str = "rawtx";

#[derive(Debug)]
pub enum DataMessage {
    // topic: sequence
    BlockConnected(BlockHash),
    BlockDisconnected(BlockHash),
    TransactionAdded {
        txid: Txid,
        mempool_sequence_number: u64,
    },
    TransactionRemoved {
        txid: Txid,
        mempool_sequence_number: u64,
    },

    // topic: rawtx
    RawTransaction(Transaction),
}

impl DataMessage {
    pub fn from_zmq_message(mut multipart: Vec<Vec<u8>>) -> Result<(Option<u32>, Self)> {
        if multipart.len() != 3 {
            return Err(anyhow!("Received invalid multipart message"));
        }
        if multipart[0] == SEQUENCE.as_bytes() {
            let sequence_number = u32::from_le_bytes(multipart[2][..].try_into()?);

            let data = &mut multipart[1];
            let len = data.len();
            if len < 33 {
                return Err(anyhow!("Received message of invalid length"));
            }

            let flag = data[32];
            data[..32].reverse();
            let hash_slice = &data[..32];
            match (flag, len) {
                (b'C', 33) => Ok((
                    Some(sequence_number),
                    DataMessage::BlockConnected(BlockHash::from_slice(hash_slice)?),
                )),
                (b'D', 33) => Ok((
                    Some(sequence_number),
                    DataMessage::BlockDisconnected(BlockHash::from_slice(hash_slice)?),
                )),
                (b'A', 41) => Ok((
                    Some(sequence_number),
                    DataMessage::TransactionAdded {
                        txid: Txid::from_slice(hash_slice)?,
                        mempool_sequence_number: u64::from_le_bytes(data[33..41].try_into()?),
                    },
                )),
                (b'R', 41) => Ok((
                    Some(sequence_number),
                    DataMessage::TransactionRemoved {
                        txid: Txid::from_slice(hash_slice)?,
                        mempool_sequence_number: u64::from_le_bytes(data[33..41].try_into()?),
                    },
                )),
                _ => Err(anyhow!("Received message with unknown flag: {}", flag)),
            }
        } else if multipart[0] == RAWTX.as_bytes() {
            return Ok((
                None,
                DataMessage::RawTransaction(encode::deserialize::<Transaction>(&multipart[1])?),
            ));
        } else {
            return Err(anyhow!(
                "Received multipart message for unknown topic {:?})",
                String::from_utf8(multipart[0].clone()).unwrap()
            ));
        }
    }
}
