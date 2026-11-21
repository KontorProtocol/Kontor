use std::fmt::{self, Write};

use crate::api::MetricsError;

const MAX_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(crate) struct BoundedText {
    text: String,
    full: bool,
}

impl Write for BoundedText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if value.len() > MAX_BYTES - self.text.len() {
            self.full = true;
            return Err(fmt::Error);
        }
        self.text.push_str(value);
        Ok(())
    }
}

impl BoundedText {
    pub(crate) fn finish(self, result: fmt::Result) -> Result<String, MetricsError> {
        if self.full {
            Err(MetricsError::OutputLimit)
        } else {
            result
                .map(|()| self.text)
                .map_err(|_| MetricsError::Encoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_never_retains_more_than_the_output_limit() {
        let mut writer = BoundedText::default();
        writer.write_str(&"x".repeat(MAX_BYTES - 1)).unwrap();
        assert!(writer.write_str("é").is_err());
        assert_eq!(writer.text.len(), MAX_BYTES - 1);
        assert_eq!(writer.finish(Ok(())), Err(MetricsError::OutputLimit));
        let mut exact = BoundedText::default();
        exact.write_str(&"x".repeat(MAX_BYTES)).unwrap();
        assert_eq!(exact.finish(Ok(())).unwrap().len(), MAX_BYTES);
        assert_eq!(
            BoundedText::default().finish(Err(fmt::Error)),
            Err(MetricsError::Encoding)
        );
    }
}
