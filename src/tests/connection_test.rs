#[cfg(test)]
mod tests {
    use crate::{connections::ProtocolBuilder, errors::ProtocolBuilderError};

    #[test]
    fn test_single_connection() -> Result<(), ProtocolBuilderError> {
        let builder = ProtocolBuilder::new(); 
        //builder.add_transaction();



        Ok(())
    }

}