use stdlib::subtree_end;

use crate::protocol::storage_keys::KeyRange;

pub(super) fn scan_bounds(path: &[u8], lo: Option<Vec<u8>>, hi: Option<Vec<u8>>) -> KeyRange {
    let lo = lo.filter(|bound| !bound.is_empty());
    let hi = hi.filter(|bound| !bound.is_empty());
    let inclusive = lo.is_some();
    let lower = match lo {
        Some(lo) => [path, lo.as_slice()].concat(),
        None => path.to_vec(),
    };
    let upper = Some(match hi {
        Some(hi) => [path, hi.as_slice()].concat(),
        None => subtree_end(path),
    });
    (lower, inclusive, upper)
}
