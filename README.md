# TemplateBuilder

TemplateBuilder is a Rust library for constructing and managing Directed Acyclic Graphs (DAGs) of BitVMX templates. A BitVMX template is a wrapper around Bitcoin transactions that holds all the necessary information to create pre-signed transactions for the BitVMX protocols. The TemplateBuilder provides methods to create templates, connect them, and finalize the DAG to generate all the signature hashes for later signing.

## Features

- Create new templates
- Connect templates with specified parameters
- Create connections for multiple rounds
- Mark templates as endpoints
- Finalize the DAG and update transaction IDs
- Build templates with computed spend signature hashes

## Usage

### Creating a TemplateBuilder

To create a new TemplateBuilder, you need to provide default parameters:

```rust
let defaults = DefaultParams::new(
    protocol_amount, 
    speedup_from_key, 
    speedup_to_key, 
    speedup_amount, 
    timelock_blocks, 
    timelock_from_key, 
    timelock_to_key, 
    locked_amount, 
    sighash_type
)?;

let builder = TemplateBuilder::new(defaults)?;
```

### Adding a Starting Template

To add a starting template to the DAG:

```rust
builder.add_start("template_name")?;
```

### Connecting Templates

When connecting templates, the spending scripts are the spending conditions in Bitcoin script for the ouput of the underlying "from" transaction, that can be consumed from a corresponding input in the underlying "to" transaction.

To create a connection between two templates:

```rust
let spending_scripts = vec![/* your scripts here */];
builder.add_connection("from_template", "to_template", &spending_scripts)?;
```

### Connecting Templates for Multiple Rounds

A round is a simple way to express a repeated connection between two templates, this generates different transactions with the same parameters for each part (the from and the to) of the connection and also generates the reverse connection to keep the transaction graph connected. As an example, a three rounds of challenge / response will generate templates with the following names, connected as shown here:

challenge_0 -> response_0 -> challenge_1 -> response_1 -> challenge_2 -> response_2

To create connections for a specified number of rounds:

```rust
let spending_scripts_from = vec![/* your scripts here */];
let spending_scripts_to = vec![/* your scripts here */];
builder.add_rounds(3, "challenge", "response", &spending_scripts_from, &spending_scripts_to)?;
```

### Marking an Endpoint

Templates that have no outgoing connections need to be marked as an ending for the builder to include an output in them. Not marking this templates as endings in the graph will leave them without any outputs to be consume by future transactions.

To mark a template as an endpoint:

```rust
let spending_conditions = vec![/* your conditions here */];
builder.end("template_name", &spending_conditions)?;
```

### Finalizing the DAG

Finalizing the DAG of templates triggers an ordered update of all the transactions ids in the graph and the transactions inputs connected to said transactions. It is not possible to trigger a build of the templates in the TemplateBuilder without finalyzing the DAG first.

To finalize the DAG and update the transaction IDs and the inputs that references them:

```rust
builder.finalize()?;
```

### Building Templates

Building the templates will trigger the generation of signature hashes for all the transactions in the DAG, leaving the underlying transactions ready to be signed. The TemplateBuilder does not have signing capabilities, the signining of the transaction needs to be done externally.

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
