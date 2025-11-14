# BitVMX Protocol Builder

BitVMX Protocol Builder is a Rust library for creating Directed Acyclic Graphs (DAGs) of BitVMX pre-signed Bitcoin transactions. Think of a protocol as a map of potential on-chain execution paths, encoded as a graph of dependent Bitcoin transactions where nodes are transactions and edges are spends. The builder takes care of graph construction, signature-hash derivation, signature generation (including MuSig2 and Winternitz), and witness assembly so complex flows stay reproducible, auditable, and ready for broadcast when it is needed.

## ⚠️ Status

This project is under active development. It has not been audited, breaking changes are expected, and it is not production ready.

## Highlights

⚙️ Build protocol DAGs with `Protocol` and the stateless `ProtocolBuilder`, keeping inputs, outputs, and dependencies aligned automatically.
🌳 Mix Taproot key-path, Taproot script-path, P2WPKH, P2WSH, timelock, OP_RETURN, and speedup branches in the same graph without hand-crafting scripts.
🔗 Attach external UTXOs, compute dependency orderings, and create ready-to-broadcast transactions via `transaction_to_send`.
🖊️ Derive Taproot and ECDSA sighashes, generate signatures (including MuSig2 and Winternitz), and build full witnesses in one pass.
📈 Auto-balance outputs with `AUTO_AMOUNT`/`RECOVER_AMOUNT`, run size-aware fee estimates, and visualize the resulting DAG as Graphviz.
🚀 Produce CPFP "speedup" transactions that batch multiple parents into a single change-sweeping child.

## Installation

Add the crate to your workspace either by relative path or directly from git:

```toml
[dependencies]
bitvmx-protocol-builder = { path = "../rust-bitvmx-protocol-builder" }
# or
bitvmx-protocol-builder = { git = "https://github.com/FairgateLabs/rust-bitvmx-protocol-builder", tag = "v0.0.1" }
```

To experiment with the CLI binary:

```bash
cargo run --bin protocol_builder -- --help
```

Set `BITVMX_ENV` to select which JSON configuration under `config/<env>.json` is used for RPC, key manager, and storage settings.

## Library Usage

`Protocol` owns the transaction graph. The `ProtocolBuilder` type is a stateless helper that wires common patterns (Taproot scripts, speedups, timelocks) without requiring you to hand-roll every output or connection. You can mix and match both approaches or work with `Protocol` directly whenever you need full control.

### Use `Protocol` directly

```rust
use protocol_builder::{
    builder::Protocol,
    errors::ProtocolBuilderError,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::OutputType,
    },
};

use bitcoin::PublicKey;

fn build_protocol(spend_key: PublicKey) -> Result<Protocol, ProtocolBuilderError> {
    let mut protocol = Protocol::new("manual-flow");

    protocol.add_transaction("funding")?;
    protocol.add_transaction("spend")?;

    protocol.add_transaction_output(
        "funding",
        &OutputType::segwit_key(50_000, &spend_key)?,
    )?;

    protocol.add_connection(
        "manual_spend",
        "funding",
        OutputSpec::Last, // last output we just added
        "spend",
        InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
        None,
        None,
    )?;

    Ok(protocol)
}
```

Once the graph is ready you can call `build`, `sign`, or `build_and_sign` on the `Protocol` instance:

```rust
use std::rc::Rc;
use key_manager::key_manager::KeyManager;

fn build_with_saved_graph(
    mut protocol: Protocol,
    key_manager: Rc<KeyManager>,
) -> Result<Protocol, ProtocolBuilderError> {
    protocol.build_and_sign(&key_manager, "manual-flow")
}
```

### Wiring inputs and outputs manually or automatically

`Protocol` lets you add inputs and outputs independently and connect them later, or you can let the library allocate them for you when you link transactions.

```rust
use anyhow::Result;
use bitcoin::{hashes::Hash, Sequence};
use protocol_builder::{
    builder::Protocol,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::OutputType,
    },
};

fn connect_existing_slots(spend_key: bitcoin::PublicKey) -> Result<Protocol> {
    let mut protocol = Protocol::new("indexed-wiring");
    protocol.add_transaction("funding")?;
    protocol.add_transaction("spend")?;

    // Add an output and an input up front.
    protocol.add_transaction_output("funding", &OutputType::segwit_key(50_000, &spend_key)?)?;
    protocol.add_transaction_input(
        Hash::all_zeros(),
        0,
        "spend",
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        &SpendMode::Segwit,
        &SighashType::ecdsa_all(),
    )?;

    // Wire the existing slots together using explicit indexes.
    protocol.add_connection(
        "manual_link",
        "funding",
        OutputSpec::Index(0),
        "spend",
        InputSpec::Index(0),
        None,
        None,
    )?;

    Ok(protocol)
}

fn connect_with_auto(spend_key: bitcoin::PublicKey) -> Result<Protocol> {
    let mut protocol = Protocol::new("auto-wiring");
    protocol.add_transaction("funding")?;
    protocol.add_transaction("spend")?;

    // Let the connection create the output and input automatically.
    protocol.add_connection(
        "auto_link",
        "funding",
        OutputSpec::Auto(OutputType::segwit_key(40_000, &spend_key)?),
        "spend",
        InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
        None,
        None,
    )?;

    Ok(protocol)
}
```

### Build and sign a basic flow

```rust
use std::rc::Rc;

use anyhow::Result;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    types::input::{InputArgs, SighashType},
};
use key_manager::key_manager::KeyManager;

fn build_basic_flow(key_manager: Rc<KeyManager>) -> Result<()> {
    let spend_key = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;
    let sighash_all = SighashType::ecdsa_all();

    let mut protocol = Protocol::new("basic-flow");
    let builder = ProtocolBuilder {};

    builder
        .add_p2wpkh_output(&mut protocol, "funding", 75_000, &spend_key)?
        .add_p2wpkh_connection(
            &mut protocol,
            "funding_to_spend",
            "funding",
            75_000,
            &spend_key,
            "spend",
            &sighash_all,
        )?;

    let protocol = protocol.build_and_sign(&key_manager, "basic-flow")?;
    let spend_tx = protocol.transaction_to_send("spend", &[InputArgs::new_segwit_args()])?;
    println!("ready to broadcast {}", spend_tx.compute_txid());

    Ok(())
}
```

`build_and_sign` updates transaction IDs, prepares sighashes, and stores the signatures requested by each connection's `SpendMode`. Call `build` if you only need sighashes or `sign` if the graph is already built.

### Connect an external UTXO

```rust
use std::str::FromStr;

use bitcoin::Txid;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
    },
};

fn connect_external(
    mut protocol: Protocol,
    builder: &ProtocolBuilder,
) -> anyhow::Result<Protocol> {
    let txid = Txid::from_str("ce5ad9ee7979b7e0b8d909870ad9c5ad7b83c1a4e3f3b0a492a3b3730d6f3c5a")?;

    builder.add_external_connection(
        &mut protocol,
        "onchain",                    // name of the upstream transaction
        txid,
        OutputSpec::Index(1),          // output index in the external transaction
        "funding",                     // transaction that will consume the output
        InputSpec::Auto(
            SighashType::ecdsa_all(),
            SpendMode::Segwit,
        ),
    )?;

    Ok(protocol)
}
```

The builder records the `txid`, appends an input to `funding`, and keeps the dependency inside the graph.

### Generate Child-Pays-For-Parent (CPFP) speedup transactions

```rust
use std::rc::Rc;

use anyhow::Result;
use protocol_builder::{
    builder::ProtocolBuilder,
    types::output::{SpeedupData, Utxo},
};
use key_manager::key_manager::KeyManager;

fn speedup_transaction(
    builder: &ProtocolBuilder,
    key_manager: Rc<KeyManager>,
    target: Utxo,
    funding: Utxo,
    change_key: &bitcoin::PublicKey,
) -> Result<bitcoin::Transaction> {
    let cpfp = builder.speedup_transactions(
        &[SpeedupData::new(target)],
        funding,
        change_key,
        1_000, // fee in satoshis
        &key_manager,
    )?;

    Ok(cpfp)
}
```

`speedup_transactions` returns a fully signed CPFP transaction, assembling witnesses for both standard SegWit and Taproot script spends (including optional Winternitz signatures).

### Visualize the transaction graph

```rust
use protocol_builder::{
    builder::Protocol,
    graph::graph::GraphOptions,
};

fn render(protocol: &Protocol) -> anyhow::Result<()> {
    let dot = protocol.visualize(GraphOptions::Default)?;
    std::fs::write("protocol.dot", dot)?;
    // Then: `dot -Tpng protocol.dot -o protocol.png`
    // or copy and paste the content of protocol.dot into https://viz-js.com/
    Ok(())
}
```

`GraphOptions::Default` renders each transaction as a node labeled with indexed inputs/outputs and their satoshi values. Use `GraphOptions::EdgeArrows` to include port-specific arrows that highlight which output feeds each downstream input.

### Auto value outputs and fee estimation

`Protocol::compute_minimum_output_values` backfills outputs marked with `AUTO_AMOUNT` or `RECOVER_AMOUNT`. `AUTO_AMOUNT` placeholders are bumped up just enough for the downstream transaction to pay its own fee estimate (1 sat/vB plus a 5% buffer), while `RECOVER_AMOUNT` placeholders scoop up any leftover value from the parent subtree so no funds are stranded.

```rust
use protocol_builder::{
    builder::Protocol,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::{OutputType, AUTO_AMOUNT, RECOVER_AMOUNT},
    },
};

fn auto_amount_example(spend_key: bitcoin::PublicKey) -> anyhow::Result<Protocol> {
    let mut protocol = Protocol::new("auto-values");

    protocol.add_transaction("parent")?;
    protocol.add_transaction("child")?;

    let parent_auto = OutputType::segwit_key(AUTO_AMOUNT, &spend_key)?;
    protocol.add_transaction_output("parent", &parent_auto)?;

    let child_recover = OutputType::segwit_key(RECOVER_AMOUNT, &spend_key)?;
    protocol.add_transaction_output("child", &child_recover)?;

    protocol.add_connection(
        "auto",
        "parent",
        OutputSpec::Auto(parent_auto.clone()),
        "child",
        InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
        None,
        None,
    )?;

    protocol.compute_minimum_output_values()?;
    Ok(protocol)
}
```

After running the computation every `AUTO_AMOUNT` output is raised to the minimum safe spend so the child can cover fees, and each `RECOVER_AMOUNT` output captures the change that remains in the parent branch.

### A more complex protocol example

```rust
use std::{rc::Rc, str::FromStr};

use anyhow::Result;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::OutputType,
    },
};
use bitcoin::{PublicKey, Txid};
use key_manager::{key_manager::KeyManager, winternitz::WinternitzType};

fn protocol_example(key_manager: Rc<KeyManager>) -> Result<Protocol> {
    let mut protocol = Protocol::new("protocol-demo");
    let builder = ProtocolBuilder {};

    // Keys used along the flow.
    let internal_key: PublicKey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?; // Taproot internal key (x-only)
    let exit_key: PublicKey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 1)?; // Final recipient
    let external_key: PublicKey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 2)?; // Matches the on-chain UTXO
    let participant_key_1: PublicKey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 3)?; // Participant key to create MuSig2 aggregate key
    let participant_key_2: PublicKey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 4)?; // Participant key to create MuSig2 aggregate key
    let participant_key_3: PublicKey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 5)?; // Participant key to create MuSig2 aggregate key

    let aggregated_key = key_manager.new_musig2_session(
        [participant_key_1, participant_key_2, participant_key_3].to_vec(),
        participant_key_1,
    )?;

    // Winternitz key for the one-time authentication branch.
    let winternitz_key = key_manager.derive_winternitz(32, WinternitzType::SHA256, 0)?;

    // Taproot leaves showcasing each sign mode using the helper scripts.
    let skip_leaf = scripts::timelock(
        144,
        &internal_key,
        SignMode::Skip, // CSV-only branch that the builder skips signing
    );

    let single_leaf = scripts::verify_winternitz_signature(
        &internal_key,
        &winternitz_key,
        SignMode::Single, // one-time Winternitz authentication signed by the internal key
    )?;

    let aggregate_leaf = scripts::check_signature(
        &aggregated_key,
        SignMode::Aggregate, // aggregated MuSig2 enforcement branch
    );

    let taproot_leaves = vec![
        skip_leaf.clone(),
        single_leaf.clone(),
        aggregate_leaf.clone(),
    ];
    let taproot_sighash = SighashType::taproot_all();

    // 1. Anchor to an external P2WPKH UTXO already on-chain.
    let external_txid =
        Txid::from_str("9f19b05dc4b58b1e736b9f9fd49f8fb751fab6595e7f6b8b7fda19af2d3404f8")?;
    builder.add_external_connection(
        &mut protocol,
        "external_funding",
        external_txid,
        OutputSpec::Auto(OutputType::segwit_key(120_000, &external_key)?),
        "taproot_key_tx",
        InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
    )?;

    // 2. Build a Taproot output that will be spent via key path only.
    builder.add_taproot_connection(
        &mut protocol,
        "key_path_handoff",
        "taproot_key_tx",
        90_000,
        &internal_key,
        &taproot_leaves,
        &SpendMode::KeyOnly {
            key_path_sign: SignMode::Single,
        },
        "taproot_script_tx",
        &taproot_sighash,
    )?;

    // 3. The next transaction uses the script paths defined above.
    builder.add_taproot_connection(
        &mut protocol,
        "script_fanout",
        "taproot_script_tx",
        60_000,
        &internal_key,
        &taproot_leaves,
        &SpendMode::Scripts {
            leaves: vec![0, 1, 2],
        },
        "segwit_exit_tx",
        &taproot_sighash,
    )?;

    // 4. Attach a standard P2WPKH branch that pays a user and is later spent.
    builder.add_p2wpkh_connection(
        &mut protocol,
        "user_payout",
        "taproot_script_tx",
        25_000,
        &exit_key,
        "p2wpkh_spend_tx",
        &SighashType::ecdsa_all(),
    )?;

    // Final transaction sends aggregated funds to the recipient.
    builder.add_p2wpkh_output(&mut protocol, "segwit_exit_tx", 55_000, &exit_key)?;

    protocol.compute_minimum_output_values()?;
    Ok(protocol.build(&key_manager, "protocol-demo")?)
}
```

This example combines four transaction families: an external P2WPKH anchor, a Taproot key-path handoff, a Taproot script-path fanout, and a closing SegWit branch. The leaves demonstrate every `SignMode` using the helper builders `timelock`, `verify_winternitz_signature`, and `check_signature`, while `SpendMode::KeyOnly`, `SpendMode::Scripts`, and `SpendMode::Segwit` drive the different witness constructions during `build_and_sign`. You can test this code by running the [protocol_example.rs](examples/protocol_example.rs)

## CLI

The `protocol_builder` binary exposes the same operations from the command line. Example:

```bash
cargo run --bin protocol_builder -- \
  --protocol-name demo \
  --graph-storage-path /tmp/protocol.graph \
  build-and-sign
```

Available subcommands include `build`, `build-and-sign`, `add-p2wpkh-output`, `add-speedup-output`, `add-taproot-script-spend-connection`, `add-timelock-connection`, and `connect-with-external-transaction`. Run `--help` on any subcommand for argument details.

## Testing

Use `cargo test` to run the library's integration tests covering connection wiring, witness construction, and weight accounting.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🧩 Part of the BitVMX Ecosystem

This repository is a component of the **BitVMX Ecosystem**, an open platform for disputable computation secured by Bitcoin.
You can find the index of all BitVMX open-source components at [**FairgateLabs/BitVMX**](https://github.com/FairgateLabs/BitVMX).

---
