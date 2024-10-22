# Protocol Builder
Protocol Builder is a Rust library designed to construct and manage Directed Acyclic Graphs (DAGs) of BitVMX pre-signed transactions (protocols). A protocol is an abstraction layer encapsulating all the necessary information about the generated pre-signed transactions. The library provides a suite of tools for creating DAGs of transactions, computing its signature hashes and signatures and generating input witnesses.

## Features

🛠 Create transactions: Automatically create transactions when adding inputs or outputs.
🔗 Connect transactions: Link transactions with specified parameters to form logical transaction flows.
🔄 Multi-round connections: Set up connections across multiple transaction rounds for complex interactions.
🏁 Connect with existing transactions: Integrate Bitcoin blockchain outputs into your transaction flow.
✅ Build the protocol: Complete the DAG structure and update transaction IDs, ensuring data integrity.
🧮 Generate signature hashes: Build transactions with calculated signature hashes for transaction spending.
🔏 Generate signatures: Sign all transactions and their variants.
🧾 Complete witness data: Populate transaction inputs with witness data for validation.
🚀 Assemble complete transactions: Construct fully ready-to-broadcast transactions for the Bitcoin network. 

## Usage

Here’s a basic example of how to use the Protocol Builder to create and connect transactions. More complex usage will follow.

### Creating a Protocol Builder

```rust
let mut builder = ProtocolBuilder::new("protocol_name");
```
### Connecting transactions

In Bitcoin, spending scripts define the spending conditions for an output. The Protocol Builder allows you to connect transactions using these scripts.

To create a Taproot connection between two transactions:

```rust
// Initialize necessary variables
let protocol_value = 1000;
let internal_key = // Internal public key for Taproot
let spending_scripts = vec![/* your scripts here */];

let spending_scripts = vec![/* your scripts here */];
let mut builder = ProtocolBuilder::new("protocol_name");

builder.add_taproot_script_spend_connection("connection_name", "from", protocol_value, internal_key, &spending_scripts, "to", &sighash_type)?;
```

The Protocol Builder provides functions to create different types of connections between transactions. Additionally, it is possible to add inputs and outputs of any type to transactions.

```rust
let mut builder = ProtocolBuilder::new("protocol_name");
builder.add_taproot_script_spend_connection("connection_name", "start", protocol_value, internal_key, &scripts, "timelock", &sighash_type)?
    .add_timelock_connection("timelock", timelock_value, internal_key, &timelock_key, &renew_script, "renew", 0, &sighash_type)?
    .add_speedup_output("start", speedup_value, speedup_key)?;

let protocol = builder.build()?;
```

### Connecting with an existing transaction

You can link an existing Bitcoin blockchain transaction into the DAG:

```rust
let mut builder = ProtocolBuilder::new("protocol_name");
builder.connect_with_external_transaction(previous_tx.compute_txid(), vout, output_spending_type, "start", &sighash_type)?
```

### Connecting transactions for multiple rounds

A round is a simple way to express a repeated connection between two transactions, this generates different transactions with the same parameters for each part (the from and the to) of the connection and also generates the reverse connection to keep the transaction graph connected.

```rust
let spending_scripts_challenge = vec![/* your scripts here */];
let spending_scripts_response = vec![/* your scripts here */];

let mut builder = ProtocolBuilder::new("protocol_name");
builder.connect_rounds("connection_name", 3, "challenge", "response", value, &spending_scripts_challenge, &spending_scripts_response, &sighash_type) 
```

The example generates connections for three rounds of challenge/response with the following names, connected as shown:

```rust
challenge_0 -> response_0 -> challenge_1 -> response_1 -> challenge_2 -> response_2
```

### Building the DAG

Once all transactions are connected, use build() to finalize the DAG. This will generate all necessary transaction IDs and signature hashes. As a result of this process we get a Protocol instance.

```rust
let mut builder = ProtocolBuilder::new("protocol_name");

// ... add connections, inputs and outputs

let protocol = builder.build()?;
```

## Error handling

All methods return Result types, with errors encapsulated in ProtocolBuilderError.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## FAQ
### What is a DAG of transactions?
A Directed Acyclic Graph (DAG) in this context represents a network of connected Bitcoin transactions, where each transaction is a node, and the connections between transactions represent inputs and outputs that link them in a logical flow.

### What is Taproot?
Taproot is a type of Bitcoin script upgrade that improves privacy, scalability, and flexibility in how scripts are executed.

### What are signature hashes?
Signature hashes (sighashes) determine which parts of a Bitcoin transaction are signed. The SighashType enum defines which portions are included in the signature.
