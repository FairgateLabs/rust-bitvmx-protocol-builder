# TemplateBuilder
TemplateBuilder is a Rust library designed to construct and manage Directed Acyclic Graphs (DAGs) of BitVMX pre-signed transactions (templates). A BitVMX template is an abstraction layer for Bitcoin transactions, encapsulating all the necessary information to generate pre-signed transactions tailored to BitVMX protocols. TemplateBuilder offers a suite of tools for creating templates, establishing connections, and finalizing DAGs to compute signature hashes required for signing.

## Features

🛠 Create Templates: Easily generate new templates as foundational elements in your DAG.  
🔗 Connect Templates: Link templates with specified parameters to form logical transaction flows.  
🔄 Multi-Round Connections: Set up connections across multiple transaction rounds to enable complex interactions.  
🏁 Define Endpoints: Mark templates as endpoints to designate final stages within the DAG.  
✅ Finalize the DAG: Complete the DAG structure and update transaction IDs, ensuring data integrity.  
🧮 Generate Spend Signature Hashes: Build templates with calculated signature hashes for transaction spending.  
🧾 Complete Witness Data: Populate transaction inputs with witness data for validation.  
🚀 Assemble Complete Transactions: Construct fully ready-to-broadcast transactions for the Bitcoin network.  

## Usage

### Creating a TemplateBuilder

The TemplateBuilder uses default parameters to build templates, these default values can be overriden in all the the template building methods:

```rust
let defaults = DefaultParams::new(
    protocol_amount,        // The amount of satoshis to be consumed in the protocol output for each template
    speedup_from_key,       // The public key to validate an input trying to spend the speedup output of each 'from' template
    speedup_to_key,         // The public key to validate an input trying to spend the speedup output of each 'to' template
    speedup_amount,         // The amount of satoshis to be consumed in the speedup output for each template
    timelock_from_key,      // The public key to validate an input trying to spend the timelock output of each 'from' template
    timelock_to_key,        // The public key to validate an input trying to spend the timelock output of each 'to' template
    timelock_renew_key,     // The public key to validate an input trying to renew the timelock output of each template
    locked_amount,          // The amount of satoshis to be consumed in the timelock output for each template
    locked_blocks,          // The number of blocks a transaction needs to wait to consume the timelock output of each template
    ecdsa_sighash_type,     // The sighash type used to compute the sighash of a non-taproot input
    taproot_sighash_type,   // The sighash type used to compute the sighash of a taproot input
)?;

let builder = TemplateBuilder::new(defaults)?;
```

### Building templates

When connecting two templates, the `from` template serves as the starting point of the connection, while the `to` template is the endpoint. In the `from` template, the builder generates an output that defines the spending conditions (script_pubkey). Then, in the `to` template the builder creates an input that includes the necessary information to satisfy the output's spending conditions. This input-output relationship ensures that the `to` template can successfully consume the output generated in the `from` template.

Each template includes by default an speedup output, designed to speedup a stalled transaction using the [Child-Pays-For-Parent fee bumping mechanism (CPFP)](https://bitcoinops.org/en/topics/cpfp/).

The script_pubkey of the speedup output uses the `speedup_from_key` by default for a `from` template, and the `speedup_to_key` for a `to` template.

Similarly, when connecting two templates, the builder includes a timelock-controlled output in the `from` template. There are two ways to spend the timelock output:

1. Direct Spend After Timelock Expiry: One of the participants can directly spend the output after a specified number of blocks have passed on the Bitcoin blockchain (defaulting to `locked_blocks` from the default parameters).

2. Timelock Renewal: Both participants can renew the timelock by consuming it through the renew timelock input in the `to` template. This input requires an aggregated signature from both participants, which must be verifiable using the default `timelock_renew_key`. The key can be replaced with another when connecting the templates, if needed.

### Adding a Starting Template

To add a starting template to the DAG:

```rust
builder.add_start("start", previous_txid, previous_vout, amount_to_consume, previous_output_script_pubkey)?;
```

### Connecting Templates

When connecting templates, the spending scripts are the spending conditions in Bitcoin script for the output of the underlying "from" transaction, that can be consumed from a corresponding input in the underlying "to" transaction.

To create a connection between two templates:

```rust
let spending_scripts = vec![/* your scripts here */];
builder.add_connection("from_template", "to_template", &spending_scripts)?;
```

### Connecting Templates for Multiple Rounds

A round is a simple way to express a repeated connection between two templates, this generates different transactions with the same parameters for each part (the from and the to) of the connection and also generates the reverse connection to keep the transaction graph connected. As an example, three rounds of challenge/response will generate templates with the following names, connected as shown here:

challenge_0 -> response_0 -> challenge_1 -> response_1 -> challenge_2 -> response_2

To create connections for a specified number of rounds:

```rust
let spending_scripts_challenge = vec![/* your scripts here */];
let spending_scripts_response = vec![/* your scripts here */];
builder.add_rounds(3, "challenge", "response", &spending_scripts_from, &spending_scripts_to)?;
```

### Marking an Endpoint

Templates that have no outgoing connections in the protocol need to be marked as an ending for the builder to include an output in them. Not marking these templates as endings in the graph will leave them without any outputs to be consumed by future transactions.

To mark a template as an endpoint:

```rust
let spending_conditions = vec![/* your conditions here */];
builder.end("end", end_output_amount, &spending_scripts)?;
```

### Finalizing the DAG

Finalizing the DAG of templates triggers an ordered update of all the transaction IDs in the graph and the transactions' inputs connected to said transactions. It is not possible to trigger a build of the templates in the TemplateBuilder without finalizing the DAG first.

To finalize the DAG and update the transaction IDs and the inputs that reference them:

```rust
builder.finalize()?;
```

### Building Templates

Building the templates will trigger the generation of signature hashes for all the transactions in the DAG, leaving the underlying transactions ready to be signed. The TemplateBuilder does not have signing capabilities; the signing of the transaction needs to be done externally.

To build the templates after finalizing the DAG:

```rust
let templates = builder.build_templates()?;
```

### Finalizing and Building in One Step

To finalize the DAG and build the templates in one step:

```rust
let templates = builder.finalize_and_build()?;
```

## Error Handling

All methods return Result types, with TemplateBuilderError indicating various error conditions such as missing or already existing templates.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
