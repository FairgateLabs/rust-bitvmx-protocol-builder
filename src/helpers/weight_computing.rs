use bitcoin::{consensus::Encodable, Transaction};
use std::io::Cursor;

pub fn get_transaction_total_size(tx: &Transaction) -> usize {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut Cursor::new(&mut buf)).unwrap();
    buf.len()
}

pub fn get_transaction_non_witness_size(tx: &Transaction) -> usize {
    let mut buf = Vec::new();
    let mut cursor = Cursor::new(&mut buf);

    // Encode only non-witness data: Manually exclude the witness field
    tx.version.consensus_encode(&mut cursor).unwrap();
    tx.input.consensus_encode(&mut cursor).unwrap();
    tx.output.consensus_encode(&mut cursor).unwrap();
    tx.lock_time.consensus_encode(&mut cursor).unwrap();

    buf.len()
}

// Calculate the virtual size of SegWit and Taproot transactions
pub fn get_transaction_vsize(tx: &Transaction) -> usize {
    let total_size = get_transaction_total_size(tx);
    let non_witness_size = get_transaction_non_witness_size(tx);

    let weight = (non_witness_size * 3) + total_size;
    (weight + 3).div_ceil(4)
}

pub fn get_transaction_hex(tx: &Transaction) -> String {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut Cursor::new(&mut buf)).unwrap();
    hex::encode(buf)
}

// Example: Parse a raw SegWit transaction (Replace with your actual transaction)
pub fn example() {
    let raw_tx = "020000000001abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd0000000000ffffffff0100e1f50500000000160014abcdefabcdefabcdefabcdefabcdefabcdef0002483045022100abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef012203abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef01";
    let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(raw_tx).unwrap()).unwrap();

    let vsize = get_transaction_vsize(&tx);
    println!("Transaction virtual size: {} vbytes", vsize);
}
