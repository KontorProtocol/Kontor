use first_tokio::sync::mpsc::Sender;
use second_tokio::sync::mpsc::channel;

fn accepts_first(_: Sender<()>) {}

fn main() {
    let (second, _) = channel::<()>(1);
    accepts_first(second);
}
