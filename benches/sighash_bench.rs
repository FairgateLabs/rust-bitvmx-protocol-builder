use std::{hint::black_box, rc::Rc, slice::from_ref};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use bitcoin::{hashes::Hash, Network, ScriptBuf};
use key_manager::{key_manager::KeyManager, key_type::BitcoinKeyType};

use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    scripts::{ProtocolScript, SignMode},
    tests::utils::new_key_manager,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::OutputType,
    },
};

/// Linear chain with Single signatures: ext_utxo -> tx_0 -> ... -> tx_{n-1}
fn build_single_chain(n_txs: usize, km: &Rc<KeyManager>) -> Protocol {
    let key = km.derive_keypair(BitcoinKeyType::P2tr, 0).unwrap();
    let value: u64 = 1_000_000;
    let txid = bitcoin::Txid::all_zeros();
    let script = ProtocolScript::new(ScriptBuf::from(vec![0x01]), &key, SignMode::Single);
    let tr_sighash = SighashType::taproot_all();
    let spend_all = SpendMode::All {
        key_path_sign: SignMode::Single,
    };

    let mut protocol = Protocol::new("bench_single");
    let builder = ProtocolBuilder {};

    let ext_output = OutputType::taproot(value, &key, from_ref(&script)).unwrap();
    builder
        .add_external_connection(
            &mut protocol,
            "ext",
            txid,
            OutputSpec::Auto(ext_output),
            "tx_0",
            InputSpec::Auto(
                tr_sighash.clone(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Single,
                },
            ),
        )
        .unwrap();

    for i in 0..n_txs.saturating_sub(1) {
        builder
            .add_taproot_connection(
                &mut protocol,
                &format!("conn_{i}"),
                &format!("tx_{i}"),
                value,
                &key,
                from_ref(&script),
                &spend_all,
                &format!("tx_{}", i + 1),
                &tr_sighash,
            )
            .unwrap();
    }

    protocol
}

fn bench_compute_sighashes(c: &mut Criterion) {
    let km_single = new_key_manager(Network::Regtest, "bench_single").unwrap();

    let mut group = c.benchmark_group("compute_sighashes");
    group.measurement_time(std::time::Duration::from_secs(10));

    for n_txs in [100, 1000, 10000] {
        let proto_single = build_single_chain(n_txs, &km_single);
        group.bench_with_input(BenchmarkId::new("single_sig", n_txs), &n_txs, |b, _| {
            b.iter(|| {
                let mut p = proto_single.clone();
                p.build(black_box(&km_single), black_box("")).unwrap();
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_compute_sighashes);
criterion_main!(benches);
