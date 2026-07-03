use stdlib::Storage;

// Covering indexes (`include = …`). `cheapest` is sorted (by `price`, bucketed by
// `active`) and covers `title`+`seller`, so `.values()`/`.iter()` read those straight
// from the index leaf and `.with_scores()` gives the light `(key, price)` view;
// `by_seller` is a plain covering index (bucketed by `seller`) covering `price`. The
// derive emits a flat value struct per covering index (`ListingCheapestValue` /
// `ListingBySellerValue`) plus the `<index>()` method returning the covering query.
#[derive(Storage)]
#[index(cheapest, by = active, sort = price, include = (title, seller))]
#[index(by_seller, by = seller, include = (price))]
struct Listing {
    active: bool,
    price: u64,
    title: String,
    seller: u64,
}
