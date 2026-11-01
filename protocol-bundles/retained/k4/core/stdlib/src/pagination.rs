use alloc::{
    string::String,
    vec::{IntoIter, Vec},
};
use core::{iter::FusedIterator, marker::PhantomData, ops::AsyncFnMut};

/// A generated view request. Construction and iteration setup perform no calls.
pub struct CursorQuery<F, P, T, E> {
    fetch: F,
    split: fn(P) -> (Vec<T>, Option<String>),
    invalid_cursor: fn() -> E,
    after: Option<String>,
}

impl<F, P, T, E> CursorQuery<F, P, T, E>
where
    F: FnMut(Option<&str>, Option<u64>) -> Result<P, E>,
{
    #[doc(hidden)]
    pub fn new(
        fetch: F,
        split: fn(P) -> (Vec<T>, Option<String>),
        invalid_cursor: fn() -> E,
    ) -> Self {
        Self {
            fetch,
            split,
            invalid_cursor,
            after: None,
        }
    }

    pub fn after(mut self, cursor: impl Into<String>) -> Self {
        self.after = Some(cursor.into());
        self
    }

    pub fn set_after(mut self, cursor: Option<&str>) -> Self {
        self.after = cursor.map(String::from);
        self
    }

    /// Executes one call using the contract's default limit.
    pub fn fetch(self) -> Result<P, E> {
        let mut request = self;
        (request.fetch)(request.after.as_deref(), None)
    }

    /// Executes one call with an explicit maximum number of returned entries.
    pub fn fetch_with_limit(mut self, limit: u64) -> Result<P, E> {
        (self.fetch)(self.after.as_deref(), Some(limit))
    }

    /// Consumes this request into an item iterator. `take(n)` bounds yielded
    /// items, not the number or cost of calls; a call may fetch unused items.
    pub fn iter(self) -> CursorIter<F, P, T, E> {
        CursorIter {
            query: self,
            items: Vec::new().into_iter(),
            done: false,
        }
    }
}

pub struct CursorIter<F, P, T, E> {
    query: CursorQuery<F, P, T, E>,
    items: IntoIter<T>,
    done: bool,
}

impl<F, P, T, E> Iterator for CursorIter<F, P, T, E>
where
    F: FnMut(Option<&str>, Option<u64>) -> Result<P, E>,
{
    type Item = Result<T, E>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.items.next() {
                return Some(Ok(item));
            }
            if self.done {
                return None;
            }
            let page = match (self.query.fetch)(self.query.after.as_deref(), None) {
                Ok(page) => page,
                Err(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
            };
            let (items, next) = (self.query.split)(page);
            if next.is_some() && next == self.query.after {
                self.done = true;
                return Some(Err((self.query.invalid_cursor)()));
            }
            self.done = next.is_none();
            self.query.after = next;
            self.items = items.into_iter();
        }
    }
}

impl<F, P, T, E> FusedIterator for CursorIter<F, P, T, E> where
    F: FnMut(Option<&str>, Option<u64>) -> Result<P, E>
{
}

/// Host test bindings borrow the runtime across each asynchronous call.
pub struct AsyncCursorQuery<F, P, E> {
    fetch: F,
    after: Option<String>,
    marker: PhantomData<fn() -> Result<P, E>>,
}

impl<F, P, E> AsyncCursorQuery<F, P, E>
where
    F: AsyncFnMut(Option<String>, Option<u64>) -> Result<P, E>,
{
    #[doc(hidden)]
    pub fn new(fetch: F) -> Self {
        Self {
            fetch,
            after: None,
            marker: PhantomData,
        }
    }

    pub fn after(mut self, cursor: impl Into<String>) -> Self {
        self.after = Some(cursor.into());
        self
    }

    pub fn set_after(mut self, cursor: Option<&str>) -> Self {
        self.after = cursor.map(String::from);
        self
    }

    pub async fn fetch(mut self) -> Result<P, E> {
        (self.fetch)(self.after, None).await
    }

    pub async fn fetch_with_limit(mut self, limit: u64) -> Result<P, E> {
        (self.fetch)(self.after, Some(limit)).await
    }
}

#[cfg(test)]
mod tests {
    use super::CursorQuery;
    use alloc::{string::String, vec, vec::Vec};
    use core::cell::Cell;

    type Page = (Vec<u64>, Option<String>);

    fn query<F>(fetch: F) -> CursorQuery<F, Page, u64, &'static str>
    where
        F: FnMut(Option<&str>, Option<u64>) -> Result<Page, &'static str>,
    {
        CursorQuery::new(fetch, |page| page, || "cursor did not advance")
    }

    #[test]
    fn lazy_take_and_early_end() {
        let calls = Cell::new(0);
        let request = query(|after, limit| {
            calls.set(calls.get() + 1);
            assert_eq!(limit, None);
            match after {
                None => Ok((vec![1, 2], Some(String::from("second")))),
                Some("second") => Ok((vec![3], None)),
                _ => panic!("unexpected cursor"),
            }
        });
        let mut items = request.iter();
        assert_eq!(calls.get(), 0);
        assert_eq!(
            items.by_ref().take(2).collect::<Result<Vec<_>, _>>(),
            Ok(vec![1, 2])
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            items.by_ref().take(50).collect::<Result<Vec<_>, _>>(),
            Ok(vec![3])
        );
        assert_eq!(items.next(), None);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn empty_nonterminal_response_and_resume() {
        let mut cursors = Vec::new();
        let values = query(|after, _| {
            cursors.push(after.map(String::from));
            match after {
                Some("resume") => Ok((vec![], Some(String::from("next")))),
                Some("next") => Ok((vec![7], None)),
                _ => panic!("unexpected cursor"),
            }
        })
        .after("resume")
        .iter()
        .collect::<Result<Vec<_>, _>>();
        assert_eq!(values, Ok(vec![7]));
        assert_eq!(
            cursors,
            vec![Some(String::from("resume")), Some(String::from("next"))]
        );
    }

    #[test]
    fn errors_are_yielded_once_without_retry() {
        let calls = Cell::new(0);
        let mut items = query(|_, _| {
            calls.set(calls.get() + 1);
            Err("contract error")
        })
        .iter();
        assert_eq!(items.next(), Some(Err("contract error")));
        assert_eq!(items.next(), None);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn repeated_cursor_is_an_error_and_fuses() {
        let mut items = query(|_, _| Ok((vec![1], Some(String::from("same")))))
            .after("same")
            .iter();
        assert_eq!(items.next(), Some(Err("cursor did not advance")));
        assert_eq!(items.next(), None);
    }

    #[test]
    fn fetch_preserves_response_and_limit() {
        let result = query(|after, limit| {
            assert_eq!(after, Some("start"));
            assert_eq!(limit, Some(0));
            Ok((vec![], None))
        })
        .after("start")
        .fetch_with_limit(0);
        assert_eq!(result, Ok((vec![], None)));
        assert_eq!(
            query(|_, limit| Ok((vec![limit.unwrap_or(50)], None))).fetch(),
            Ok((vec![50], None))
        );
    }
}
