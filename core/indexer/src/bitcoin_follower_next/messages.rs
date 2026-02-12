use anyhow::{Result, anyhow};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};

const SEQUENCE: &str = "sequence";

#[derive(Debug)]
pub enum DataMessage {
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
}

impl DataMessage {
    pub fn from_zmq_message(mut multipart: Vec<Vec<u8>>) -> Result<(u32, Self)> {
        if multipart.len() != 3 {
            return Err(anyhow!("Received invalid multipart message"));
        }
        if multipart[0] != SEQUENCE.as_bytes() {
            return Err(anyhow!(
                "Received message for unexpected topic {:?}",
                String::from_utf8(multipart[0].clone()).unwrap_or("Non-UTF8 string".to_string())
            ));
        }

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
                sequence_number,
                DataMessage::BlockConnected(BlockHash::from_slice(hash_slice)?),
            )),
            (b'D', 33) => Ok((
                sequence_number,
                DataMessage::BlockDisconnected(BlockHash::from_slice(hash_slice)?),
            )),
            (b'A', 41) => Ok((
                sequence_number,
                DataMessage::TransactionAdded {
                    txid: Txid::from_slice(hash_slice)?,
                    mempool_sequence_number: u64::from_le_bytes(data[33..41].try_into()?),
                },
            )),
            (b'R', 41) => Ok((
                sequence_number,
                DataMessage::TransactionRemoved {
                    txid: Txid::from_slice(hash_slice)?,
                    mempool_sequence_number: u64::from_le_bytes(data[33..41].try_into()?),
                },
            )),
            _ => Err(anyhow!("Received message with unknown flag: {}", flag)),
        }
    }
}

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
    Unknown(u16),
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

    pub fn from_zmq_message(multipart: Vec<Vec<u8>>) -> Result<Self> {
        if multipart.is_empty() || multipart[0].len() < 2 {
            return Err(anyhow!("Received invalid multipart message"));
        }
        let event_type = u16::from_le_bytes(multipart[0][0..2].try_into()?);
        Ok(MonitorMessage::from_raw(event_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sequence_message(hash: &[u8; 32], flag: u8, extra: &[u8], seq: u32) -> Vec<Vec<u8>> {
        let mut data = Vec::with_capacity(33 + extra.len());
        // ZMQ sends hash in internal byte order (reversed from display)
        let mut hash_bytes = *hash;
        hash_bytes.reverse();
        data.extend_from_slice(&hash_bytes);
        data.push(flag);
        data.extend_from_slice(extra);

        vec![
            SEQUENCE.as_bytes().to_vec(),
            data,
            seq.to_le_bytes().to_vec(),
        ]
    }

    #[test]
    fn parse_transaction_added() {
        let txid_bytes = [0xab; 32];
        let mempool_seq: u64 = 42;
        let msg = make_sequence_message(&txid_bytes, b'A', &mempool_seq.to_le_bytes(), 7);

        let (seq, data) = DataMessage::from_zmq_message(msg).unwrap();
        assert_eq!(seq, 7);
        match data {
            DataMessage::TransactionAdded {
                txid,
                mempool_sequence_number,
            } => {
                assert_eq!(txid, Txid::from_slice(&txid_bytes).unwrap());
                assert_eq!(mempool_sequence_number, 42);
            }
            _ => panic!("Expected TransactionAdded"),
        }
    }

    #[test]
    fn parse_transaction_removed() {
        let txid_bytes = [0xcd; 32];
        let mempool_seq: u64 = 99;
        let msg = make_sequence_message(&txid_bytes, b'R', &mempool_seq.to_le_bytes(), 3);

        let (seq, data) = DataMessage::from_zmq_message(msg).unwrap();
        assert_eq!(seq, 3);
        match data {
            DataMessage::TransactionRemoved {
                txid,
                mempool_sequence_number,
            } => {
                assert_eq!(txid, Txid::from_slice(&txid_bytes).unwrap());
                assert_eq!(mempool_sequence_number, 99);
            }
            _ => panic!("Expected TransactionRemoved"),
        }
    }

    #[test]
    fn parse_block_connected() {
        let hash = [0x11; 32];
        let msg = make_sequence_message(&hash, b'C', &[], 1);
        let (seq, data) = DataMessage::from_zmq_message(msg).unwrap();
        assert_eq!(seq, 1);
        assert!(matches!(data, DataMessage::BlockConnected(_)));
    }

    #[test]
    fn parse_block_disconnected() {
        let hash = [0x22; 32];
        let msg = make_sequence_message(&hash, b'D', &[], 2);
        let (seq, data) = DataMessage::from_zmq_message(msg).unwrap();
        assert_eq!(seq, 2);
        assert!(matches!(data, DataMessage::BlockDisconnected(_)));
    }

    #[test]
    fn unknown_flag_returns_error() {
        let hash = [0x33; 32];
        let msg = make_sequence_message(&hash, b'X', &[], 5);
        assert!(DataMessage::from_zmq_message(msg).is_err());
    }

    #[test]
    fn wrong_topic_returns_error() {
        let msg = vec![b"rawtx".to_vec(), vec![0; 33], 0u32.to_le_bytes().to_vec()];
        assert!(DataMessage::from_zmq_message(msg).is_err());
    }

    #[test]
    fn invalid_multipart_length() {
        let msg = vec![b"sequence".to_vec()];
        assert!(DataMessage::from_zmq_message(msg).is_err());
    }

    #[test]
    fn data_too_short() {
        let msg = vec![
            SEQUENCE.as_bytes().to_vec(),
            vec![0; 10],
            0u32.to_le_bytes().to_vec(),
        ];
        assert!(DataMessage::from_zmq_message(msg).is_err());
    }

    #[test]
    fn monitor_handshake_succeeded() {
        let msg = vec![0x1000u16.to_le_bytes().to_vec(), vec![]];
        let result = MonitorMessage::from_zmq_message(msg).unwrap();
        assert_eq!(result, MonitorMessage::HandshakeSucceeded);
        assert!(!result.is_failure());
    }

    #[test]
    fn monitor_disconnected() {
        let msg = vec![0x0200u16.to_le_bytes().to_vec(), vec![]];
        let result = MonitorMessage::from_zmq_message(msg).unwrap();
        assert_eq!(result, MonitorMessage::Disconnected);
        assert!(result.is_failure());
    }

    #[test]
    fn monitor_invalid_message() {
        let msg: Vec<Vec<u8>> = vec![];
        assert!(MonitorMessage::from_zmq_message(msg).is_err());
    }

    #[test]
    fn monitor_unknown_event() {
        let msg = vec![0xBEEFu16.to_le_bytes().to_vec(), vec![]];
        let result = MonitorMessage::from_zmq_message(msg).unwrap();
        assert_eq!(result, MonitorMessage::Unknown(0xBEEF));
    }
}
