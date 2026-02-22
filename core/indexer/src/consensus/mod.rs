// TODO: Currently uses malachitebft-test types (TestContext, Value, Height, etc.) directly.
// We will need to define our own types when Value needs to carry anchor heights + txids,
// which also means our own protobuf schema, codec, Context impl, and signing provider.

pub mod app;
