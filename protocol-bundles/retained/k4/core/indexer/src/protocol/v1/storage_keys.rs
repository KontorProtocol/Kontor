use futures_util::{Stream, stream};
use stdlib::{next_element, subtree_end};

use super::storage_bounds::scan_bounds;
use super::storage_error::ReadError;
use crate::protocol::storage_keys::KeyCallbacks;

pub(crate) fn keys(
    callbacks: KeyCallbacks,
    contract_id: u64,
    path: Vec<u8>,
    lo: Option<Vec<u8>>,
    hi: Option<Vec<u8>>,
    descending: bool,
) -> impl Stream<Item = Result<Vec<u8>, ReadError>> + Send + 'static {
    let range = scan_bounds(&path, lo, hi);
    let owner = callbacks.0(contract_id, range.clone(), descending);
    let prefix_len = path.len();
    stream::try_unfold(
        (owner, None::<Vec<u8>>, range),
        move |(mut owner, mut last, mut range)| {
            let callbacks = callbacks.clone();
            async move {
                let mut skipped = 0;
                loop {
                    let Some((next_owner, full)) = callbacks.1(owner)
                        .await
                        .map_err(ReadError::Infrastructure)?
                    else {
                        return Ok(None);
                    };
                    owner = next_owner;
                    let (element, _) =
                        next_element(&full[prefix_len..]).map_err(ReadError::KeyCodec)?;
                    if last.as_deref() != Some(element) {
                        let child = element.to_vec();
                        last = Some(child.clone());
                        return Ok(Some((child, (owner, last, range))));
                    }
                    skipped += 1;
                    if skipped == 32 {
                        let child_path = &full[..prefix_len + element.len()];
                        if descending {
                            range.2 = Some(child_path.to_vec());
                        } else {
                            range.0 = subtree_end(child_path);
                            range.1 = true;
                        }
                        owner =
                            callbacks.2(owner, range.clone()).map_err(ReadError::Infrastructure)?;
                    }
                }
            }
        },
    )
}
