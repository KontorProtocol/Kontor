pub mod runtime {
  pub trait Storage {
      fn get_int(&self) -> u64;
      fn set_int(&self, value: u64);
  }
}

pub mod storage_utils {
  use super::runtime::Storage;

  pub fn store_and_return_int<S: Storage>(storage: &S, x: u64) -> u64 {
      storage.set_int(x);
      storage.get_int()
  }
}

pub mod memory_storage {
  use super::runtime::Storage;
  
  static mut INT_REF: u64 = 0;

  pub struct MemoryStorage;

  impl MemoryStorage {
      pub fn new() -> Self {
          Self
      }
  }

  impl Storage for MemoryStorage {
      fn get_int(&self) -> u64 {
          unsafe { INT_REF }
      }

      fn set_int(&self, value: u64) {
          unsafe { INT_REF = value }
      }
  }
}
