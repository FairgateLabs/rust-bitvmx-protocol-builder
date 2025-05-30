use crate::errors::ProtocolBuilderError;

pub(crate) fn check_empty_transaction_name(name: &str) -> Result<(), ProtocolBuilderError> {
    if name.trim().is_empty() || name.chars().all(|c| c == '\t') {
        return Err(ProtocolBuilderError::MissingTransactionName);
    }

    Ok(())
}

pub(crate) fn check_empty_connection_name(name: &str) -> Result<(), ProtocolBuilderError> {
    if name.trim().is_empty() || name.chars().all(|c| c == '\t') {
        return Err(ProtocolBuilderError::MissingConnectionName);
    }

    Ok(())
}

pub(crate) fn check_zero_rounds(rounds: u32) -> Result<(), ProtocolBuilderError> {
    if rounds == 0 {
        return Err(ProtocolBuilderError::InvalidZeroRounds);
    }

    Ok(())
}
