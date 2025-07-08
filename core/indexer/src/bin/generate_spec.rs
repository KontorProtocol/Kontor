use indexer::api::doc::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let spec = ApiDoc::openapi().to_pretty_json().unwrap();
    std::fs::write("openapi.json", spec).unwrap();
    println!("openapi.json spec generated");
}
