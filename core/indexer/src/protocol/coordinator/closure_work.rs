use anyhow::{Result, ensure};

use super::application_closure::{CanonicalPosition, WorkItem};
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::identity::domain_digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkOrigin {
    pub(crate) height: u64,
    pub(crate) closure: [u8; 32],
    pub(crate) previous: [u8; 32],
    pub(crate) input: CanonicalPosition,
}

impl WorkOrigin {
    pub(crate) fn encode(self) -> Result<Vec<u8>> {
        ensure!(self.height > 0, "zero work-plan height");
        let mut out = Encoder::default();
        out.fixed(b"KWO1")?;
        out.u64(self.height)?;
        out.fixed(&self.closure)?;
        out.fixed(&self.previous)?;
        self.input.encode(&mut out)?;
        Ok(out.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KWO1",
            "unknown work origin encoding"
        );
        let origin = Self {
            height: input.u64()?,
            closure: input.fixed()?,
            previous: input.fixed()?,
            input: CanonicalPosition::decode(&mut input)?,
        };
        input.finish()?;
        origin.encode()?;
        Ok(origin)
    }

    pub(crate) fn key(self) -> Result<[u8; 32]> {
        Ok(domain_digest(
            b"kontor/closure-work-origin/v1",
            &self.encode()?,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkCursor {
    pub(crate) plan: [u8; 32],
    pub(crate) index: u64,
    pub(crate) count: u64,
    pub(crate) prefix: [u8; 32],
}

impl WorkCursor {
    pub(crate) fn is_empty(self) -> bool {
        self.index == self.count
    }

    pub(super) fn encode(self, out: &mut Encoder) -> Result<()> {
        ensure!(self.index <= self.count, "work cursor exceeds plan");
        out.fixed(&self.plan)?;
        out.u64(self.index)?;
        out.u64(self.count)?;
        out.fixed(&self.prefix)?;
        Ok(())
    }

    pub(super) fn decode(input: &mut Decoder<'_>) -> Result<Self> {
        let cursor = Self {
            plan: input.fixed()?,
            index: input.u64()?,
            count: input.u64()?,
            prefix: input.fixed()?,
        };
        ensure!(cursor.index <= cursor.count, "work cursor exceeds plan");
        Ok(cursor)
    }
}

pub(crate) fn item_bytes(item: WorkItem) -> Result<Vec<u8>> {
    let mut out = Encoder::default();
    item.encode(&mut out)?;
    Ok(out.finish())
}

pub(crate) fn decode_item(bytes: &[u8]) -> Result<WorkItem> {
    let mut input = Decoder::new(bytes);
    let item = WorkItem::decode(&mut input)?;
    input.finish()?;
    Ok(item)
}

pub(crate) fn item_digest(previous: [u8; 32], index: u64, item: WorkItem) -> Result<[u8; 32]> {
    let mut out = Encoder::default();
    out.fixed(&previous)?;
    out.u64(index)?;
    item.encode(&mut out)?;
    Ok(domain_digest(b"kontor/closure-work-item/v1", &out.finish()))
}

pub(crate) fn plan_id(origin: WorkOrigin, count: u64, digest: [u8; 32]) -> Result<[u8; 32]> {
    let mut out = Encoder::default();
    out.bytes(&origin.encode()?)?;
    out.u64(count)?;
    out.fixed(&digest)?;
    Ok(domain_digest(b"kontor/closure-work-plan/v1", &out.finish()))
}
