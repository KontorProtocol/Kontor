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

/// Cap on concurrently buffered (incomplete) streams. A healthy node buffers a
/// tiny handful — one per proposer per live round, each removed the instant it
/// completes. The cap only bites under a peer flooding never-finished partial
/// streams under fresh stream ids, and when it does it refuses NEW streams rather
/// than evicting in-progress ones — so a flood cannot displace the genuine
/// proposal already being assembled, only fail to add more junk.
const MAX_BUFFERED_STREAMS: usize = 1024;

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
        let key = (peer_id, stream_id);

        // Bound the map: refuse a NEW stream once full, but always accept further
        // parts for a stream already being assembled (so a flood cannot starve an
        // in-progress genuine proposal).
        if self.streams.len() >= MAX_BUFFERED_STREAMS && !self.streams.contains_key(&key) {
            return None;
        }

        let state = self.streams.entry(key.clone()).or_default();

        if !state.seen_sequences.insert(msg.sequence) {
            return None;
        }

        let result = state.insert(msg);

        // Remove on the RESULT, not a re-check of `is_done()`: completing the
        // stream `take`s `init_info` and drains the buffer, so `is_done()` is
        // false again here — re-checking it would leak the spent `StreamState`
        // forever (one per proposer/height/round on a healthy chain).
        if result.is_some() {
            self.streams.remove(&key);
        }

        result
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.streams.len()
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

    #[test]
    fn a_completed_stream_leaves_no_state_behind() {
        let mut map = PartStreamsMap::new();
        let p = peer(1);
        let msgs = messages();
        for m in &msgs[..3] {
            assert!(map.insert(p, m.clone()).is_none());
        }
        assert_eq!(map.len(), 1, "the in-progress stream is buffered");
        assert!(
            map.insert(p, msgs[3].clone()).is_some(),
            "the Fin marker completes the stream"
        );
        assert_eq!(
            map.len(),
            0,
            "a completed stream must be removed, not linger forever"
        );
    }

    /// An `Init`-only message under a distinct stream id — a partial stream that
    /// never completes, the shape a flood would use.
    fn init_only(stream_seed: u32) -> StreamMessage<ProposalPart> {
        let init = ProposalPart::Init(ProposalInit::new(
            Height::new(4),
            Round::new(1),
            Round::Nil,
            crate::consensus::Address::from_public_key(&PrivateKey::from([1u8; 32]).public_key()),
        ));
        StreamMessage::new(
            StreamId::new(stream_seed.to_be_bytes().to_vec().into()),
            0,
            StreamContent::Data(init),
        )
    }

    #[test]
    fn caps_buffered_streams_without_starving_an_in_progress_one() {
        let mut map = PartStreamsMap::new();
        let p = peer(1);

        // Fill the map to the cap with distinct never-completing partial streams.
        for i in 0..super::MAX_BUFFERED_STREAMS as u32 {
            assert!(map.insert(p, init_only(i)).is_none());
        }
        assert_eq!(map.len(), super::MAX_BUFFERED_STREAMS);

        // A brand-new stream is refused while full — memory is bounded.
        assert!(map.insert(p, init_only(u32::MAX)).is_none());
        assert_eq!(
            map.len(),
            super::MAX_BUFFERED_STREAMS,
            "cap must refuse NEW streams once full"
        );

        // An already-buffered stream still accepts more parts: a flood cannot
        // starve a genuine proposal that is already being assembled.
        let data = ProposalPart::Data(ProposalData::new_block(
            7,
            bitcoin::BlockHash::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
        ));
        let more = StreamMessage::new(
            StreamId::new(0u32.to_be_bytes().to_vec().into()),
            1,
            StreamContent::Data(data),
        );
        assert!(map.insert(p, more).is_none());
        assert_eq!(
            map.len(),
            super::MAX_BUFFERED_STREAMS,
            "adding a part to an existing stream must not grow the map"
        );
    }
}
