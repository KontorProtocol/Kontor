use axum::{Router, routing::get_service};
use std::net::SocketAddr;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    // Define the directory where your built Vite app is located
    let assets_dir = std::env::current_dir().unwrap().join("dist");

    // Create a service that serves files from the dist directory
    let serve_dir = ServeDir::new(assets_dir)
        .fallback(ServeDir::new("dist").append_index_html_on_directories(true));

    // Build our application with the route
    let app = Router::new()
        // Serve all requests with the static files
        .fallback_service(get_service(serve_dir));

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
