use super::OutputType;

pub enum ConnectionType {
    Internal {
        name: String,
        from: String,
        output_index: usize,
        to: String,
        input_index: usize,
    },
    External {
        to: String,
        output_type: OutputType,
    },
}
