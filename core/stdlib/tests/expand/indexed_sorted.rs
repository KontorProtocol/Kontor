use stdlib::Indexed;

// A struct-level sorted index (`due`, bucketed by `status`, ordered by
// `deadline_height`) alongside a field-level `#[index]` sugar (`status`). The
// derived lookup trait gets `where_due` → `SortedScan` (with `up_to`/`range`) and
// `where_status` → a plain iterator.
#[derive(Indexed)]
#[index(due, by = status, sort = deadline_height)]
struct Challenge {
    id: String,
    #[index]
    status: u64,
    deadline_height: u64,
    seed: u64,
}
