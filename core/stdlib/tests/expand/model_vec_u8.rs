use stdlib::Model;

#[derive(Model)]
struct VecU8 {
    pub bytes: Vec<u8>,
    pub bytes_other: Vec::<u8>,
}
