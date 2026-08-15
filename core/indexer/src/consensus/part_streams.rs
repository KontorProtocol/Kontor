use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashSet};

use malachitebft_app_channel::app::streaming::{Sequence, StreamId, StreamMessage};
use malachitebft_app_channel::app::types::PeerId;
use malachitebft_core_types::Round;

use crate::consensus::{Address, Height, ProposalData, ProposalFin, ProposalInit, ProposalPart};

// Reassembles the proposal-part stream a proposer publishes (`Init`, `Data`,
// `Fin`) back into a single `ProposalParts`, so the whole thing can be
// authenticated before any of it is trusted. Ported from Malachite's test-app
// helper (which is generic over its own `ProposalPart`) onto Kontor's types.
//
// The reassembly is what makes the signature check meaningful: the `Fin`
// signature covers `Init` + `Data`, so a peer that forges only the `Data` part
// (the shortcut the old code took) cannot produce a matching `Fin`.

struct MinSeq(StreamMessage<ProposalPart>);

impl PartialEq for MinSeq {
    fn eq(&self, other: &Self) -> bool {
        self.0.sequence == other.0.sequence
    }
}

impl Eq for MinSeq {}

impl Ord for MinSeq {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed: pop smallest sequence first.
        other.0.sequence.cmp(&self.0.sequence)
    }
}

impl PartialOrd for MinSeq {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct MinHeap(BinaryHeap<MinSeq>);

impl MinHeap {
    fn push(&mut self, msg: StreamMessage<ProposalPart>) {
        self.0.push(MinSeq(msg));
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    /// Drain in ascending sequence order — the order the signature was computed
    /// over, which `verify_proposal_parts` relies on.
    fn drain(&mut self) -> Vec<ProposalPart> {
        let mut vec = Vec::with_capacity(self.0.len());
        while let Some(MinSeq(msg)) = self.0.pop() {
            if let Some(data) = msg.content.into_data() {
                vec.push(data);
            }
        }
        vec
    }
}

#[derive(Default)]
struct StreamState {
    buffer: MinHeap,
    init_info: Option<ProposalInit>,
    seen_sequences: HashSet<Sequence>,
    total_messages: usize,
    fin_received: bool,
}

impl StreamState {
    fn is_done(&self) -> bool {
        self.init_info.is_some() && self.fin_received && self.buffer.len() == self.total_messages
    }

    fn insert(&mut self, msg: StreamMessage<ProposalPart>) -> Option<ProposalParts> {
        if msg.is_first() {
            self.init_info = msg.content.as_data().and_then(|p| p.as_init()).cloned();
        }

        if msg.is_fin() {
            self.fin_received = true;
            self.total_messages = msg.sequence as usize + 1;
        }

        self.buffer.push(msg);

        if self.is_done() {
            let init_info = self.init_info.take()?;
            Some(ProposalParts {
                height: init_info.height,
                round: init_info.round,
                proposer: init_info.proposer,
                parts: self.buffer.drain(),
            })
        } else {
            None
        }
    }
}

/// A fully reassembled proposal: the `Init`-derived metadata plus every part in
/// ascending sequence order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalParts {
    pub height: Height,
    pub round: Round,
    pub proposer: Address,
    pub parts: Vec<ProposalPart>,
}

impl ProposalParts {
    pub fn init(&self) -> Option<&ProposalInit> {
        self.parts.iter().find_map(|p| p.as_init())
    }

    pub fn fin(&self) -> Option<&ProposalFin> {
        self.parts.iter().find_map(|p| p.as_fin())
    }

    pub fn data(&self) -> Option<&ProposalData> {
        self.parts.iter().find_map(|p| p.as_data())
    }
}

#[derive(Default)]
pub struct PartStreamsMap {
    streams: BTreeMap<(PeerId, StreamId), StreamState>,
}

impl PartStreamsMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer one received part. Returns the reassembled `ProposalParts` once the
    /// stream is complete (`Init` seen, `Fin` seen, no gaps), otherwise `None`.
    /// A duplicate sequence is dropped rather than double-counted.
    pub fn insert(
        &mut self,
        peer_id: PeerId,
        msg: StreamMessage<ProposalPart>,
    ) -> Option<ProposalParts> {
        let stream_id = msg.stream_id.clone();

        let state = self
            .streams
            .entry((peer_id, stream_id.clone()))
            .or_default();

        if !state.seen_sequences.insert(msg.sequence) {
            return None;
        }

        let result = state.insert(msg);

        if state.is_done() {
            self.streams.remove(&(peer_id, stream_id));
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use malachitebft_app_channel::app::streaming::StreamContent;
    use malachitebft_app_channel::app::types::PeerId;

    use crate::consensus::signing::PrivateKey;
    use crate::consensus::{ProposalData, ProposalFin, ProposalInit};

    fn dummy_signature() -> malachitebft_signing_ed25519::Signature {
        PrivateKey::from([7u8; 32]).sign(&[0u8; 32])
    }

    /// A distinct `PeerId` per seed. Encodes a sha2-256 multihash (code `0x12`,
    /// length `0x20`) over a fixed 32-byte digest — the map only needs the ids to
    /// be distinct and comparable, not to correspond to real keys.
    fn peer(seed: u8) -> PeerId {
        let mut bytes = vec![0x12u8, 0x20];
        bytes.extend_from_slice(&[seed; 32]);
        PeerId::from_bytes(&bytes).expect("valid sha256 multihash peer id")
    }

    /// The four stream messages `stream_proposal` emits: Init (seq 0), Data
    /// (seq 1), Fin part (seq 2), and the Fin marker (seq 3).
    fn messages() -> Vec<StreamMessage<ProposalPart>> {
        let stream_id = StreamId::new(vec![9, 9].into());
        let init = ProposalPart::Init(ProposalInit::new(
            Height::new(4),
            Round::new(1),
            Round::Nil,
            crate::consensus::Address::from_public_key(&PrivateKey::from([1u8; 32]).public_key()),
        ));
        let data = ProposalPart::Data(ProposalData::new_block(
            7,
            bitcoin::BlockHash::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
        ));
        let fin = ProposalPart::Fin(ProposalFin::new(dummy_signature()));
        vec![
            StreamMessage::new(stream_id.clone(), 0, StreamContent::Data(init)),
            StreamMessage::new(stream_id.clone(), 1, StreamContent::Data(data)),
            StreamMessage::new(stream_id.clone(), 2, StreamContent::Data(fin)),
            StreamMessage::new(stream_id, 3, StreamContent::Fin),
        ]
    }

    #[test]
    fn assembles_in_sequence_order_regardless_of_arrival_order() {
        let mut map = PartStreamsMap::new();
        let peer = peer(1);
        let msgs = messages();
        // Feed 2, 0, 3, 1 — only the last completes the stream.
        assert!(map.insert(peer, msgs[2].clone()).is_none());
        assert!(map.insert(peer, msgs[0].clone()).is_none());
        assert!(map.insert(peer, msgs[3].clone()).is_none());
        let parts = map.insert(peer, msgs[1].clone()).expect("stream complete");

        assert_eq!(parts.height, Height::new(4));
        assert_eq!(parts.round, Round::new(1));
        // Parts drained in sequence order: Init, Data, Fin.
        assert!(parts.init().is_some());
        assert!(parts.data().is_some());
        assert!(parts.fin().is_some());
        assert_eq!(parts.parts.len(), 3);
    }

    #[test]
    fn incomplete_stream_yields_nothing() {
        let mut map = PartStreamsMap::new();
        let peer = peer(1);
        let msgs = messages();
        // Everything but the Fin marker.
        assert!(map.insert(peer, msgs[0].clone()).is_none());
        assert!(map.insert(peer, msgs[1].clone()).is_none());
        assert!(map.insert(peer, msgs[2].clone()).is_none());
    }

    #[test]
    fn duplicate_sequence_does_not_complete_a_short_stream() {
        let mut map = PartStreamsMap::new();
        let peer = peer(1);
        let msgs = messages();
        // Init, Data, then Data AGAIN (dup seq 1) and the Fin marker. The dup is
        // dropped, so `total_messages` (4) never matches the 3 buffered — a
        // replayed part cannot forge a complete stream.
        assert!(map.insert(peer, msgs[0].clone()).is_none());
        assert!(map.insert(peer, msgs[1].clone()).is_none());
        assert!(map.insert(peer, msgs[1].clone()).is_none());
        assert!(map.insert(peer, msgs[3].clone()).is_none());
    }

    #[test]
    fn distinct_peers_do_not_share_a_stream() {
        let mut map = PartStreamsMap::new();
        let (a, b) = (peer(1), peer(2));
        let msgs = messages();
        // Same stream id, split across two peers — neither assembles.
        assert!(map.insert(a, msgs[0].clone()).is_none());
        assert!(map.insert(b, msgs[1].clone()).is_none());
        assert!(map.insert(a, msgs[2].clone()).is_none());
        assert!(map.insert(b, msgs[3].clone()).is_none());
    }
}
