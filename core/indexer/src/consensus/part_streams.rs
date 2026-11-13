use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashSet, VecDeque};

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
    charged_bytes: usize,
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

// Three bounds keep incomplete, unauthenticated streams finite. A healthy node
// holds a tiny handful of streams, each with four parts, every one removed the
// instant it completes, so these only bite under a flood of never-finished
// partials:
//
// - MAX_PARTS_PER_STREAM caps a SINGLE stream: without it one (peer, stream_id)
//   could buffer unbounded distinct-sequence parts (a `Fin` whose sequence never
//   arrives) and grow without limit. A genuine stream needs four.
// - MAX_BUFFERED_STREAMS caps the whole map. A per-publisher stream quota evicts
//   that publisher's oldest incomplete stream before it can occupy every slot.
// - MAX_REASSEMBLY_PAYLOAD_BYTES caps retained stream IDs, descriptor/body bytes,
//   and a conservative fixed allowance for each part's framing and metadata.
//   Value also retains parsed transactions, and decoding can allocate transient
//   copies. The raw-payload budget does not include those allocations.
//
// Per-publisher eviction does not depend on round transitions: live parts may
// still arrive after StartedRound, while an abandoned partial must not
// permanently consume its publisher's admission quota.
const MAX_PARTS_PER_STREAM: usize = 16;
const MAX_BUFFERED_STREAMS: usize = 4096;
const MAX_REASSEMBLY_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAMS_PER_PEER: usize = 64;
const MAX_PEER_REASSEMBLY_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const PART_FRAMING_ALLOWANCE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReassemblySaturated;

#[derive(Default)]
pub struct PartStreamsMap {
    streams: BTreeMap<(PeerId, StreamId), StreamState>,
    peer_streams: BTreeMap<PeerId, VecDeque<StreamId>>,
    peer_charged_bytes: BTreeMap<PeerId, usize>,
    charged_bytes: usize,
}

impl PartStreamsMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer one received part. Returns the reassembled `ProposalParts` once the
    /// stream is complete (`Init` seen, `Fin` seen, no gaps), otherwise `None`.
    /// Saturation is local backpressure, not a verdict on the proposal.
    pub fn insert(
        &mut self,
        peer_id: PeerId,
        msg: StreamMessage<ProposalPart>,
    ) -> Result<Option<ProposalParts>, ReassemblySaturated> {
        // The handler supplies published_by when present, so relays share the
        // publisher's quota rather than acquiring independent admission slots.
        let key = (peer_id, msg.stream_id.clone());

        if let Some(state) = self.streams.get(&key) {
            if state.seen_sequences.contains(&msg.sequence) {
                return Ok(None);
            }
            if state.seen_sequences.len() >= MAX_PARTS_PER_STREAM {
                return Err(ReassemblySaturated);
            }
        }
        if msg.is_fin() && msg.sequence >= MAX_PARTS_PER_STREAM as u64 {
            return Err(ReassemblySaturated);
        }

        let data_bytes = msg
            .content
            .as_data()
            .and_then(ProposalPart::as_data)
            .map_or(0, ProposalData::size_bytes);
        let part_bytes = msg
            .stream_id
            .to_bytes()
            .len()
            .checked_add(PART_FRAMING_ALLOWANCE_BYTES)
            .and_then(|size| size.checked_add(data_bytes))
            .ok_or(ReassemblySaturated)?;
        if part_bytes > MAX_PEER_REASSEMBLY_PAYLOAD_BYTES {
            return Err(ReassemblySaturated);
        }

        let is_new = !self.streams.contains_key(&key);
        let mut peer_count = self.peer_streams.get(&peer_id).map_or(0, VecDeque::len);
        let mut peer_bytes = self.peer_charged_bytes.get(&peer_id).copied().unwrap_or(0);
        let mut evictions = Vec::new();
        let mut queue = self.peer_streams.get(&peer_id).into_iter().flatten();
        while (is_new && peer_count >= MAX_STREAMS_PER_PEER)
            || peer_bytes
                .checked_add(part_bytes)
                .is_none_or(|total| total > MAX_PEER_REASSEMBLY_PAYLOAD_BYTES)
        {
            let victim = queue
                .find(|stream_id| *stream_id != &key.1)
                .ok_or(ReassemblySaturated)?;
            let victim_key = (peer_id, victim.clone());
            let state = self.streams.get(&victim_key).ok_or(ReassemblySaturated)?;
            peer_bytes -= state.charged_bytes;
            peer_count -= 1;
            evictions.push(victim_key);
        }
        let released_bytes: usize = evictions
            .iter()
            .map(|victim| {
                self.streams
                    .get(victim)
                    .expect("planned victim exists")
                    .charged_bytes
            })
            .sum();
        if self.streams.len() - evictions.len() + usize::from(is_new) > MAX_BUFFERED_STREAMS {
            return Err(ReassemblySaturated);
        }
        let next_bytes = self
            .charged_bytes
            .checked_sub(released_bytes)
            .and_then(|total| total.checked_add(part_bytes))
            .filter(|total| *total <= MAX_REASSEMBLY_PAYLOAD_BYTES)
            .ok_or(ReassemblySaturated)?;

        for victim in evictions {
            self.remove(&victim);
        }
        if is_new {
            self.peer_streams
                .entry(peer_id)
                .or_default()
                .push_back(key.1.clone());
        }

        let state = self.streams.entry(key.clone()).or_default();
        state.seen_sequences.insert(msg.sequence);
        state.charged_bytes += part_bytes;
        self.charged_bytes = next_bytes;
        *self.peer_charged_bytes.entry(peer_id).or_default() += part_bytes;

        let result = state.insert(msg);

        // Remove on the RESULT, not a re-check of `is_done()`: completing the
        // stream `take`s `init_info` and drains the buffer, so `is_done()` is
        // false again here — re-checking it would leak the spent `StreamState`
        // forever (one per proposer/height/round on a healthy chain).
        if result.is_some() {
            self.remove(&key);
        }

        Ok(result)
    }

    fn remove(&mut self, key: &(PeerId, StreamId)) -> bool {
        let Some(state) = self.streams.remove(key) else {
            return false;
        };
        self.charged_bytes -= state.charged_bytes;
        if let Some(bytes) = self.peer_charged_bytes.get_mut(&key.0) {
            *bytes -= state.charged_bytes;
            if *bytes == 0 {
                self.peer_charged_bytes.remove(&key.0);
            }
        }
        if let Some(queue) = self.peer_streams.get_mut(&key.0) {
            queue.retain(|stream_id| stream_id != &key.1);
            if queue.is_empty() {
                self.peer_streams.remove(&key.0);
            }
        }
        true
    }

    /// Use for explicit cancellation only; round changes can race with live parts.
    pub fn discard(&mut self, peer_id: PeerId, stream_id: &StreamId) -> bool {
        self.remove(&(peer_id, stream_id.clone()))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.streams.len()
    }

    #[cfg(test)]
    fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, BlockHash, ScriptBuf, Transaction, TxIn, TxOut};
    use malachitebft_app_channel::app::streaming::StreamContent;
    use malachitebft_app_channel::app::types::PeerId;
    use malachitebft_codec::Codec;
    use std::collections::{BTreeMap, HashSet};

    use crate::consensus::codec::ProtobufCodec;
    use crate::consensus::signing::PrivateKey;
    use crate::consensus::test_fixtures;
    use crate::consensus::{Address, ProposalData, ProposalFin, ProposalInit, Value};
    use crate::protocol::coordinator::certified_input::MAX_BATCH_BYTES;

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

    fn assert_accounting(map: &PartStreamsMap) {
        let mut expected = BTreeMap::<PeerId, (usize, usize)>::new();
        for ((peer_id, _), state) in &map.streams {
            let entry = expected.entry(*peer_id).or_default();
            entry.0 += 1;
            entry.1 += state.charged_bytes;
        }
        assert_eq!(
            map.charged_bytes,
            expected.values().map(|(_, bytes)| bytes).sum::<usize>()
        );
        assert_eq!(map.peer_streams.len(), expected.len());
        assert_eq!(map.peer_charged_bytes.len(), expected.len());
        for (peer_id, (count, bytes)) in expected {
            let queue = &map.peer_streams[&peer_id];
            assert_eq!(queue.len(), count);
            assert_eq!(queue.iter().collect::<HashSet<_>>().len(), count);
            assert_eq!(map.peer_charged_bytes[&peer_id], bytes);
            for stream_id in queue {
                assert!(map.streams.contains_key(&(peer_id, stream_id.clone())));
            }
        }
    }

    /// The four stream messages `stream_proposal` emits: Init (seq 0), Data
    /// (seq 1), Fin part (seq 2), and the Fin marker (seq 3).
    fn messages() -> Vec<StreamMessage<ProposalPart>> {
        let stream_id = StreamId::new(vec![9, 9].into());
        let init = ProposalPart::Init(ProposalInit::new(
            Height::new(4),
            Round::new(1),
            Round::Nil,
            Address::from_public_key(&PrivateKey::from([1u8; 32]).public_key()),
        ));
        let data = ProposalPart::Data(ProposalData::new(test_fixtures::block()));
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
        assert!(map.insert(peer, msgs[2].clone()).unwrap().is_none());
        assert!(map.insert(peer, msgs[0].clone()).unwrap().is_none());
        assert!(map.insert(peer, msgs[3].clone()).unwrap().is_none());
        let parts = map
            .insert(peer, msgs[1].clone())
            .expect("part admitted")
            .expect("stream complete");

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
        assert!(map.insert(peer, msgs[0].clone()).unwrap().is_none());
        assert!(map.insert(peer, msgs[1].clone()).unwrap().is_none());
        assert!(map.insert(peer, msgs[2].clone()).unwrap().is_none());
    }

    #[test]
    fn duplicate_sequence_does_not_complete_a_short_stream() {
        let mut map = PartStreamsMap::new();
        let peer = peer(1);
        let msgs = messages();
        // Init, Data, then Data AGAIN (dup seq 1) and the Fin marker. The dup is
        // dropped, so `total_messages` (4) never matches the 3 buffered — a
        // replayed part cannot forge a complete stream.
        assert!(map.insert(peer, msgs[0].clone()).unwrap().is_none());
        assert!(map.insert(peer, msgs[1].clone()).unwrap().is_none());
        assert!(map.insert(peer, msgs[1].clone()).unwrap().is_none());
        assert!(map.insert(peer, msgs[3].clone()).unwrap().is_none());
    }

    #[test]
    fn distinct_peers_do_not_share_a_stream() {
        let mut map = PartStreamsMap::new();
        let (a, b) = (peer(1), peer(2));
        let msgs = messages();
        // Same stream id, split across two peers — neither assembles.
        assert!(map.insert(a, msgs[0].clone()).unwrap().is_none());
        assert!(map.insert(b, msgs[1].clone()).unwrap().is_none());
        assert!(map.insert(a, msgs[2].clone()).unwrap().is_none());
        assert!(map.insert(b, msgs[3].clone()).unwrap().is_none());
    }

    #[test]
    fn a_completed_stream_leaves_no_state_behind() {
        let mut map = PartStreamsMap::new();
        let p = peer(1);
        let msgs = messages();
        for m in &msgs[..3] {
            assert!(map.insert(p, m.clone()).unwrap().is_none());
        }
        assert_eq!(map.len(), 1, "the in-progress stream is buffered");
        assert!(
            map.insert(p, msgs[3].clone()).unwrap().is_some(),
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
            Address::from_public_key(&PrivateKey::from([1u8; 32]).public_key()),
        ));
        StreamMessage::new(
            StreamId::new(stream_seed.to_be_bytes().to_vec().into()),
            0,
            StreamContent::Data(init),
        )
    }

    /// A part with an arbitrary sequence under stream id `stream_seed`, so a
    /// single stream can be fed many distinct sequences.
    fn part_at(stream_seed: u32, sequence: u64) -> StreamMessage<ProposalPart> {
        let data = ProposalPart::Data(ProposalData::new(test_fixtures::block()));
        StreamMessage::new(
            StreamId::new(stream_seed.to_be_bytes().to_vec().into()),
            sequence,
            StreamContent::Data(data),
        )
    }

    fn transaction_with_size(size: usize, sats: u64) -> Transaction {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: ScriptBuf::from_bytes(vec![0; size - 64]),
            }],
        };
        assert_eq!(tx.total_size(), size);
        tx
    }

    fn maximal_messages(seed: u8) -> Vec<StreamMessage<ProposalPart>> {
        let value = Value::new_batch_raw(
            test_fixtures::context(),
            4,
            BlockHash::all_zeros(),
            vec![
                transaction_with_size(4_000_000, seed as u64),
                transaction_with_size(MAX_BATCH_BYTES - 12 - 4_000_000, seed as u64),
            ],
        )
        .expect("maximum certified batch body is valid");
        assert_eq!(value.input().body().len(), MAX_BATCH_BYTES);
        let mut msgs = messages();
        let stream_id = StreamId::new(vec![seed; 12].into());
        for msg in &mut msgs {
            msg.stream_id = stream_id.clone();
        }
        let data = ProposalData::new(value);
        let signature =
            PrivateKey::from([1u8; 32]).sign(&data.signing_digest(Height::new(4), Round::new(1)));
        msgs[1].content = StreamContent::Data(ProposalPart::Data(data));
        msgs[2].content = StreamContent::Data(ProposalPart::Fin(ProposalFin::new(signature)));
        msgs
    }

    #[test]
    fn one_peer_cannot_fill_all_stream_slots_or_block_a_second_peer() {
        let mut map = PartStreamsMap::new();
        let p = peer(1);

        // Older partials from the same peer are replaced at its quota.
        for i in 0..super::MAX_BUFFERED_STREAMS as u32 {
            assert!(map.insert(p, init_only(i)).unwrap().is_none());
        }
        assert_eq!(map.len(), super::MAX_STREAMS_PER_PEER);
        assert!(map.insert(peer(2), init_only(u32::MAX)).unwrap().is_none());
        assert_eq!(map.len(), super::MAX_STREAMS_PER_PEER + 1);
        assert!(
            map.insert(p, part_at(super::MAX_BUFFERED_STREAMS as u32 - 1, 1))
                .unwrap()
                .is_none()
        );
        assert_accounting(&map);
    }

    #[test]
    fn global_stream_cap_preserves_existing_streams_across_peers() {
        let mut map = PartStreamsMap::new();
        for seed in 1..=64 {
            for stream_id in 0..super::MAX_STREAMS_PER_PEER as u32 {
                assert!(
                    map.insert(peer(seed), init_only(stream_id))
                        .unwrap()
                        .is_none()
                );
            }
        }
        assert_eq!(map.len(), super::MAX_BUFFERED_STREAMS);
        assert_eq!(map.insert(peer(65), init_only(0)), Err(ReassemblySaturated));
        assert!(map.insert(peer(1), part_at(63, 1)).unwrap().is_none());
        assert_eq!(map.len(), super::MAX_BUFFERED_STREAMS);
        assert_accounting(&map);
    }

    #[test]
    fn one_peer_cannot_fill_all_reassembly_bytes_or_block_a_second_peer() {
        let mut map = PartStreamsMap::new();
        let p = peer(1);
        let streams: Vec<_> = (0..3).map(maximal_messages).collect();
        for stream in &streams {
            assert!(map.insert(p, stream[1].clone()).unwrap().is_none());
        }
        assert_eq!(map.len(), 2);
        assert!(
            !map.streams
                .contains_key(&(p, streams[0][1].stream_id.clone()))
        );
        assert!(map.insert(peer(2), init_only(99)).unwrap().is_none());
        assert_eq!(map.len(), 3);
        assert_accounting(&map);
    }

    #[test]
    fn per_stream_part_cap_bounds_a_single_stream() {
        let mut map = PartStreamsMap::new();
        let p = peer(1);

        // One stream, many distinct sequences — the never-completing shape.
        for seq in 0..super::MAX_PARTS_PER_STREAM as u64 {
            assert!(map.insert(p, part_at(42, seq)).unwrap().is_none());
        }
        // The map holds exactly one stream, but it will not grow past the cap.
        assert_eq!(map.len(), 1);
        assert_eq!(map.insert(p, part_at(42, 9999)), Err(ReassemblySaturated));
        // A duplicate of a sequence already seen is still just ignored, not an error.
        assert!(map.insert(p, part_at(42, 0)).unwrap().is_none());
    }

    #[test]
    fn aggregate_payload_bound_preserves_completion_and_rejects_fifth_maximal_stream() {
        let mut map = PartStreamsMap::new();
        let streams: Vec<_> = (0..5).map(maximal_messages).collect();
        let data_bytes = streams[0][1]
            .content
            .as_data()
            .and_then(ProposalPart::as_data)
            .unwrap()
            .size_bytes();
        let charge =
            data_bytes + streams[0][1].stream_id.to_bytes().len() + PART_FRAMING_ALLOWANCE_BYTES;
        for msg in &streams[0] {
            let data_bytes = msg
                .content
                .as_data()
                .and_then(ProposalPart::as_data)
                .map_or(0, ProposalData::size_bytes);
            let allowance = msg.stream_id.to_bytes().len() + PART_FRAMING_ALLOWANCE_BYTES;
            assert!(ProtobufCodec.encode(msg).unwrap().len() <= data_bytes + allowance);
        }
        assert!(charge * 4 <= MAX_REASSEMBLY_PAYLOAD_BYTES);
        assert!(charge * 5 > MAX_REASSEMBLY_PAYLOAD_BYTES);

        for (index, stream) in streams[..4].iter().enumerate() {
            assert!(
                map.insert(peer(index as u8 + 1), stream[1].clone())
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(map.charged_bytes(), charge * 4);
        assert_eq!(map.len(), 4);
        assert_eq!(
            map.insert(peer(5), streams[4][1].clone()),
            Err(ReassemblySaturated)
        );
        assert_eq!(map.charged_bytes(), charge * 4);
        assert_eq!(map.len(), 4, "refused new stream must leave no empty state");
        assert!(
            map.insert(peer(1), streams[0][1].clone())
                .unwrap()
                .is_none()
        );
        assert_eq!(map.charged_bytes(), charge * 4);

        for index in [2, 0] {
            assert!(
                map.insert(peer(1), streams[0][index].clone())
                    .unwrap()
                    .is_none()
            );
        }
        let parts = map
            .insert(peer(1), streams[0][3].clone())
            .unwrap()
            .expect("maximal genuine proposal reassembles");
        assert_eq!(parts.data().unwrap().size_bytes(), data_bytes);
        assert_eq!(map.charged_bytes(), charge * 3);
        assert_eq!(map.len(), 3);
        assert_accounting(&map);
        assert!(
            map.insert(peer(5), streams[4][1].clone())
                .unwrap()
                .is_none()
        );
        assert_eq!(map.charged_bytes(), charge * 4);
        assert_accounting(&map);
    }

    #[test]
    fn global_byte_rejection_does_not_apply_planned_peer_eviction() {
        let mut map = PartStreamsMap::new();
        for seed in 1..=4 {
            assert!(
                map.insert(peer(seed), maximal_messages(seed)[1].clone())
                    .unwrap()
                    .is_none()
            );
        }

        let mut target = maximal_messages(9);
        let target_id = StreamId::new(vec![9; 25_000].into());
        for msg in &mut target {
            msg.stream_id = target_id.clone();
        }
        assert!(map.insert(peer(1), target[0].clone()).unwrap().is_none());
        assert_accounting(&map);

        let before_streams: Vec<_> = map.streams.keys().cloned().collect();
        let before_queues = map.peer_streams.clone();
        let before_peer_bytes = map.peer_charged_bytes.clone();
        let before_bytes = map.charged_bytes();

        // The new part needs its sibling evicted to meet the publisher quota,
        // but that still leaves too many bytes globally. Neither change may land.
        assert_eq!(
            map.insert(peer(1), target[1].clone()),
            Err(ReassemblySaturated)
        );
        assert_eq!(
            map.streams.keys().cloned().collect::<Vec<_>>(),
            before_streams
        );
        assert_eq!(map.peer_streams, before_queues);
        assert_eq!(map.peer_charged_bytes, before_peer_bytes);
        assert_eq!(map.charged_bytes(), before_bytes);
        assert_accounting(&map);
    }

    #[test]
    fn repeated_data_is_charged_once_per_sequence_and_discard_releases_it() {
        let mut map = PartStreamsMap::new();
        let p = peer(1);
        let mut data = maximal_messages(7)[1].clone();
        let stream_id = data.stream_id.clone();
        let data_bytes = data
            .content
            .as_data()
            .and_then(ProposalPart::as_data)
            .unwrap()
            .size_bytes();
        let charge = data_bytes + data.stream_id.to_bytes().len() + PART_FRAMING_ALLOWANCE_BYTES;
        assert!(map.insert(p, data.clone()).unwrap().is_none());
        assert!(map.insert(p, data.clone()).unwrap().is_none());
        assert_eq!(map.charged_bytes(), charge);

        data.sequence = 2;
        assert!(map.insert(p, data.clone()).unwrap().is_none());
        assert_eq!(map.charged_bytes(), charge * 2);
        data.sequence = 3;
        assert_eq!(map.insert(p, data.clone()), Err(ReassemblySaturated));
        assert_eq!(map.charged_bytes(), charge * 2);
        assert!(map.discard(p, &stream_id));
        assert!(!map.discard(p, &stream_id));
        assert_eq!(map.charged_bytes(), 0);
        assert_eq!(map.len(), 0);
        assert!(map.insert(p, data).unwrap().is_none());
        assert_eq!(map.charged_bytes(), charge);
        assert_accounting(&map);
    }

    #[test]
    fn large_stream_ids_cannot_bypass_aggregate_admission() {
        const ID_BYTES: usize = 1024 * 1024;

        let mut map = PartStreamsMap::new();
        for seed in 0..15u8 {
            let mut msg = init_only(seed as u32);
            msg.stream_id = StreamId::new(vec![seed; ID_BYTES].into());
            assert!(map.insert(peer(seed + 1), msg).unwrap().is_none());
        }
        let charge = ID_BYTES + PART_FRAMING_ALLOWANCE_BYTES;
        assert_eq!(map.charged_bytes(), 15 * charge);
        let mut refused = init_only(16);
        refused.stream_id = StreamId::new(vec![16; ID_BYTES].into());
        assert_eq!(
            map.insert(peer(16), refused.clone()),
            Err(ReassemblySaturated)
        );
        assert_eq!(map.len(), 15);
        assert_eq!(map.charged_bytes(), 15 * charge);

        let mut first = init_only(0);
        first.stream_id = StreamId::new(vec![0; ID_BYTES].into());
        assert!(map.discard(peer(1), &first.stream_id));
        assert_eq!(map.charged_bytes(), 14 * charge);
        assert!(map.insert(peer(16), refused).unwrap().is_none());
        assert_eq!(map.charged_bytes(), 15 * charge);
    }

    #[test]
    fn impossible_fin_sequence_is_refused_before_arithmetic_or_retention() {
        let mut map = PartStreamsMap::new();
        let marker: StreamMessage<ProposalPart> =
            StreamMessage::new(StreamId::new(vec![8].into()), u64::MAX, StreamContent::Fin);
        assert_eq!(map.insert(peer(1), marker), Err(ReassemblySaturated));
        assert_eq!(map.len(), 0);
        assert_eq!(map.charged_bytes(), 0);
    }
}
