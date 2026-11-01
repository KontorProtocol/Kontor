use stdlib::{Wavey, from_wave_expr, to_wave_expr};

#[derive(Debug, PartialEq, Wavey)]
struct Item {
    id: String,
}

type Items = Vec<Item>;

#[derive(Debug, PartialEq, Wavey)]
struct Page {
    items: Items,
    next: Option<String>,
}

#[derive(Debug, PartialEq, Wavey)]
enum Response {
    Page(Page),
    Items(Items),
    Missing,
}

#[derive(Debug, PartialEq, Wavey)]
struct Envelope {
    response: Option<Response>,
}

#[test]
fn lists_and_nested_response_records_round_trip() {
    for response in [
        None,
        Some(Response::Missing),
        Some(Response::Items(vec![])),
        Some(Response::Items(vec![Item { id: "a\0b".into() }])),
        Some(Response::Page(Page {
            items: vec![],
            next: None,
        })),
        Some(Response::Page(Page {
            items: vec![Item { id: "a".into() }, Item { id: "b".into() }],
            next: Some("b".into()),
        })),
    ] {
        let expected = format!("{response:?}");
        let encoded = to_wave_expr(Envelope { response });
        let actual: Envelope = from_wave_expr(&encoded);
        assert_eq!(format!("{:?}", actual.response), expected);
    }
}
