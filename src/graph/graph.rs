use std::{collections::HashMap, vec};

use bitcoin::{secp256k1::Message, Amount, Transaction, TxOut, Txid};
use petgraph::{
    algo::toposort,
    graph::{EdgeIndex, NodeIndex},
    visit::EdgeRef,
    Graph,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::GraphError,
    types::{
        input::{InputSignatures, InputType, SighashType, Signature, SpendMode},
        output::OutputType,
    },
};

macro_rules! max {
    ($x:expr) => ($x);
    ($x:expr, $($xs:expr),+) => (
        std::cmp::max($x, max!($($xs),+))
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) transaction: Transaction,
    pub(crate) outputs: Vec<OutputType>,
    pub(crate) inputs: Vec<InputType>,
    pub(crate) external: bool,
}

impl Node {
    pub(crate) fn new(name: &str, transaction: Transaction, external: bool) -> Self {
        Node {
            name: name.to_string(),
            transaction,
            outputs: vec![],
            inputs: vec![],
            external,
        }
    }

    pub(crate) fn get_input(&self, input_index: usize) -> Result<&InputType, GraphError> {
        self.inputs
            .get(input_index)
            .ok_or(GraphError::MissingInputInfo(self.name.clone(), input_index))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Connection {
    pub(crate) name: String,
    pub(crate) input_index: u32,
    pub(crate) output_index: u32,
}

impl Connection {
    pub(crate) fn new(name: &str, input_index: usize, output_index: usize) -> Self {
        Connection {
            name: name.to_string(),
            input_index: input_index as u32,
            output_index: output_index as u32,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionGraph {
    graph: Graph<Node, Connection>,
    node_indexes: HashMap<String, petgraph::graph::NodeIndex>,
}

impl Default for TransactionGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum GraphOptions {
    Default,
    EdgeArrows,
}

impl TransactionGraph {
    pub fn new() -> Self {
        let graph = Graph::new();
        let node_indexes = HashMap::new();

        TransactionGraph {
            graph,
            node_indexes,
        }
    }

    pub fn add_transaction(
        &mut self,
        name: &str,
        transaction: Transaction,
        external: bool,
    ) -> Result<(), GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        if self.node_indexes.contains_key(name) {
            return Err(GraphError::TransactionAlreadyExists(name.to_string()));
        }

        let node = Node::new(name, transaction, external);
        let node_index = self.graph.add_node(node.clone());

        self.node_indexes.insert(name.to_string(), node_index);
        Ok(())
    }

    pub fn update_transaction(
        &mut self,
        name: &str,
        transaction: Transaction,
    ) -> Result<(), GraphError> {
        let node = self.get_node_mut(name)?;
        node.transaction = transaction;
        Ok(())
    }

    pub fn add_transaction_input(
        &mut self,
        name: &str,
        transaction: Transaction,
        spend_mode: &SpendMode,
        sighash_type: &SighashType,
    ) -> Result<(), GraphError> {
        let node = self.get_node_mut(name)?;
        node.transaction = transaction;
        node.inputs.push(InputType::new(spend_mode, sighash_type));
        Ok(())
    }

    pub fn add_transaction_output(
        &mut self,
        name: &str,
        transaction: Transaction,
        output_type: OutputType,
    ) -> Result<(), GraphError> {
        let node = self.get_node_mut(name)?;
        node.transaction = transaction;
        node.outputs.push(output_type);
        Ok(())
    }

    pub fn connect(
        &mut self,
        connection_name: &str,
        from: &str,
        output_index: usize,
        to: &str,
        input_index: usize,
    ) -> Result<(), GraphError> {
        let from_node_index = self.get_node_index(from)?;
        let to_node_index = self.get_node_index(to)?;
        let output_type = self.get_output_type(from, output_index)?;

        let connection = Connection::new(connection_name, input_index, output_index);

        self.graph
            .add_edge(from_node_index, to_node_index, connection.clone());

        let to_node = self.get_node_mut(to)?;
        to_node.inputs[input_index].set_output_type(output_type)?;

        Ok(())
    }

    pub fn update_hashed_messages(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        message_hashes: Vec<Option<Message>>,
    ) -> Result<(), GraphError> {
        let node = self.get_node_mut(transaction_name)?;

        node.inputs[input_index as usize].set_hashed_messages(message_hashes);
        Ok(())
    }

    pub fn update_input_signatures(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        signatures: Vec<Option<Signature>>,
    ) -> Result<(), GraphError> {
        let node = self.get_node_mut(transaction_name)?;
        node.inputs[input_index as usize].set_signatures(signatures);

        Ok(())
    }

    pub fn update_input_signature(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        signature: Option<Signature>,
        signature_index: usize,
    ) -> Result<(), GraphError> {
        let node = self.get_node_mut(transaction_name)?;
        node.inputs[input_index as usize].set_signature(signature, signature_index)?;

        Ok(())
    }

    pub fn get_hashed_message(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        message_index: u32,
    ) -> Result<Option<Message>, GraphError> {
        let node = self.get_node_mut(transaction_name)?;

        Ok(node.inputs[input_index as usize].hashed_messages()[message_index as usize])
    }

    pub fn get_transaction_by_name(&self, name: &str) -> Result<&Transaction, GraphError> {
        Ok(&self.get_node(name)?.transaction)
    }

    pub fn get_transaction_by_id(&self, txid: &Txid) -> Result<&Transaction, GraphError> {
        for node in self.graph.node_weights() {
            if node.transaction.compute_txid() == *txid {
                return Ok(&node.transaction);
            }
        }
        Err(GraphError::TransactionNotFound(txid.to_string()))
    }

    pub fn get_transaction_name_by_id(&self, txid: Txid) -> Result<&String, GraphError> {
        for node in self.graph.node_weights() {
            if node.transaction.compute_txid() == txid {
                return Ok(&node.name);
            }
        }
        Err(GraphError::TransactionNotFound(txid.to_string()))
    }

    pub fn next_transactions(&self, name: &str) -> Result<Vec<&Transaction>, GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let dependencies = self.get_dependencies(name)?;
        let next_transactions = dependencies
            .iter()
            .map(|(name, _)| self.get_transaction_by_name(name))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(next_transactions)
    }

    pub fn get_dependencies(&self, name: &str) -> Result<Vec<(String, u32)>, GraphError> {
        let node_index = self.get_node_index(name)?;

        let dependencies = self
            .graph
            .edges(node_index)
            .map(|edge| {
                let node_index = edge.target();
                let node = self.graph.node_weight(node_index).unwrap();
                let connection = edge.weight();
                (node.name.clone(), connection.input_index)
            })
            .collect();

        Ok(dependencies)
    }

    pub fn get_prevouts(&self, name: &str) -> Result<Vec<TxOut>, GraphError> {
        let node_index = self.get_node_index(name)?;
        let transaction = self.get_transaction_by_name(name)?;

        let mut prevouts = vec![None; transaction.input.len()];

        for edge in self.find_incoming_edges(node_index) {
            let from = self.get_from_transaction(edge)?;
            let connection = self.get_connection(edge)?;
            prevouts[connection.input_index as usize] =
                Some(from.output[connection.output_index as usize].clone());
        }

        let result = prevouts
            .iter()
            .map(|txout| {
                txout
                    .clone()
                    .ok_or(GraphError::MissingTransaction(name.to_string()))
            })
            .collect();

        result
    }

    pub fn get_inputs(&self, name: &str) -> Result<Vec<InputType>, GraphError> {
        Ok(self.get_node(name)?.inputs.clone())
    }

    pub fn get_output_for_input(
        &self,
        name: &str,
        input_index: u32,
    ) -> Result<OutputType, GraphError> {
        let node_index = self.get_node_index(name)?;

        for edge in self.find_incoming_edges(node_index) {
            let connection = self.get_connection(edge)?;
            if connection.input_index == input_index {
                let from = self.get_from_node(edge)?;
                return Ok(from.outputs[connection.output_index as usize].clone());
            }
        }

        Err(GraphError::MissingConnection)
    }

    pub fn get_transaction_names(&self) -> Vec<String> {
        self.graph
            .node_weights()
            .map(|node| node.name.clone())
            .collect()
    }

    pub fn get_transaction_ids(&self) -> Vec<Txid> {
        self.graph
            .node_weights()
            .map(|node| node.transaction.compute_txid())
            .collect()
    }

    pub fn get_all_signatures(&self) -> Result<HashMap<String, Vec<InputSignatures>>, GraphError> {
        let mut all_signatures = HashMap::new();

        for (name, inputs) in self.get_transaction_inputs()? {
            let signatures = inputs
                .iter()
                .map(|info| InputSignatures::new(info.signatures().clone()))
                .collect();
            all_signatures.insert(name, signatures);
        }

        Ok(all_signatures)
    }

    pub fn get_input(&self, name: &str, input_index: usize) -> Result<InputType, GraphError> {
        Ok(self.get_node(name)?.get_input(input_index)?.clone())
    }

    pub fn get_output(
        &self,
        name: &str,
        output_index: usize,
    ) -> Result<Option<&OutputType>, GraphError> {
        Ok(self.get_node(name)?.outputs.get(output_index))
    }

    pub fn get_ecdsa_signature(
        &self,
        name: &str,
        input_index: usize,
    ) -> Result<Option<bitcoin::ecdsa::Signature>, GraphError> {
        let node = self.get_node(name)?;

        let input = node.get_input(input_index)?;
        let signature = match input.get_signature(0)? {
            Some(Signature::Ecdsa(signature)) => Some(*signature),
            None => None,
            _ => {
                return Err(GraphError::InvalidSignatureType(
                    name.to_string(),
                    input_index,
                    "Ecdsa".to_string(),
                    "Taproot".to_string(),
                ))
            }
        };

        Ok(signature)
    }

    pub fn get_taproot_script_signature(
        &self,
        name: &str,
        input_index: usize,
        leaf_index: usize,
    ) -> Result<Option<bitcoin::taproot::Signature>, GraphError> {
        let node = self.get_node(name)?;

        let input = node.get_input(input_index)?;
        let signature = match input.get_signature(leaf_index)? {
            Some(Signature::Taproot(signature)) => Some(*signature),
            None => None,
            _ => {
                return Err(GraphError::InvalidSignatureType(
                    name.to_string(),
                    input_index,
                    "Taproot".to_string(),
                    "ECDSA".to_string(),
                ))
            }
        };

        Ok(signature)
    }

    pub fn get_taproot_key_signature(
        &self,
        name: &str,
        input_index: usize,
    ) -> Result<Option<bitcoin::taproot::Signature>, GraphError> {
        let node = self.get_node(name)?;

        let input = node.get_input(input_index)?;
        let signature = match input
            .signatures()
            .last()
            .ok_or(GraphError::MissingSignature)?
        {
            Some(Signature::Taproot(signature)) => Some(*signature),
            None => None,
            _ => {
                return Err(GraphError::InvalidSignatureType(
                    name.to_string(),
                    input_index,
                    "Taproot".to_string(),
                    "ECDSA".to_string(),
                ))
            }
        };

        Ok(signature)
    }

    pub fn contains_transaction(&self, name: &str) -> bool {
        self.node_indexes.contains_key(name)
    }

    pub fn sort(&self) -> Result<Vec<String>, GraphError> {
        let sorted = toposort(&self.graph, None).map_err(|_| GraphError::GraphCycleDetected)?;
        let result = sorted
            .iter()
            .filter(|node_index| {
                let node = self.graph.node_weight(**node_index).unwrap();
                !node.external // Filter out external nodes
            })
            .map(|node_index| {
                let node = self.graph.node_weight(*node_index).unwrap();
                node.name.clone()
            })
            .collect();

        Ok(result)
    }

    pub fn sorted_transactions(&self) -> Result<(Vec<Transaction>, Vec<String>), GraphError> {
        let sorted = toposort(&self.graph, None).map_err(|_| GraphError::GraphCycleDetected)?;
        let result = sorted
            .iter()
            .filter(|node_index| {
                let node = self.graph.node_weight(**node_index).unwrap();
                !node.external // Filter out external nodes
            })
            .map(|node_index| {
                let node = self.graph.node_weight(*node_index).unwrap();
                (node.transaction.clone(), node.name.clone())
            })
            .collect();

        Ok(result)
    }

    /// Computes and sets the minimum required value for each output of each node
    pub fn compute_minimum_output_values(&mut self) -> Result<(), GraphError> {
        let order = toposort(&self.graph, None).map_err(|_| GraphError::GraphCycleDetected)?;
        let mut amounts = HashMap::<String, Amount>::new();
        let mut recover_outputs = HashMap::<String, NodeIndex>::new();

        // Compute output values for all outputs in the graph
        for node in order.iter().rev() {
            // Compute values for all node outputs
            let mut total_amount = 0;

            let (transaction_name, outputs) = {
                let weight = self
                    .graph
                    .node_weight(*node)
                    .ok_or(GraphError::MissingTransaction("".to_string()))?;
                (&weight.name, &weight.outputs)
            };

            for (index, output_type) in outputs.iter().enumerate() {
                let key = format!("{}:{}", transaction_name, index);

                // Save recover outputs to set the full parents value at the end
                if output_type.recover_value() {
                    recover_outputs.insert(key.clone(), *node);
                }

                let amount = amounts.entry(key).or_insert_with(|| {
                    if output_type.auto_value() || output_type.recover_value() {
                        output_type.dust_limit()
                    } else {
                        output_type.get_value()
                    }
                });

                total_amount += amount.to_sat();
            }

            // compute values for outputs of the parent nodes, if any
            let parent_connections = self.find_incoming_edges(*node);

            if !parent_connections.is_empty() {
                let parent_amount = total_amount / parent_connections.len() as u64;

                for connection in parent_connections {
                    let parent = self.get_from_node(connection)?;
                    let output_index = self.get_connection(connection)?.output_index as usize;
                    let output = parent.outputs[output_index].clone();

                    let parent_key = format!("{}:{}", parent.name, output_index);

                    let amount = if output.auto_value() {
                        amounts
                            .get(&parent_key)
                            .map(|v| max!(v.to_sat(), parent_amount, output.dust_limit().to_sat()))
                            .unwrap_or(parent_amount)
                    } else {
                        output.get_value().to_sat()
                    };

                    amounts.insert(parent_key, Amount::from_sat(amount));
                }
            }
        }

        // Update transactions with computed values
        for (key, amount) in amounts {
            let parts: Vec<&str> = key.split(':').collect();
            let transaction_name = parts[0];
            let output_index: usize = parts[1].parse().unwrap();

            // Update OutputType value
            self.update_output_value(transaction_name, output_index, amount)?;
        }

        // Set recover outputs to the sum of their parents values
        for (key, node_index) in recover_outputs {
            let parts: Vec<&str> = key.split(':').collect();
            let recovering_transaction_name = parts[0];
            let recovering_output_index: usize = parts[1].parse().unwrap();
            let recovering_transaction = &self.get_node(recovering_transaction_name)?.transaction;

            // Collect parents outputs amount before mutably borrowing self
            let parent_connections = self.find_incoming_edges(node_index);
            let total_parents_amount =
                parent_connections
                    .iter()
                    .try_fold(0u64, |acc, &connection| {
                        let parent = self.get_from_node(connection)?;
                        let output_index = self.get_connection(connection)?.output_index as usize;
                        Ok(acc + parent.outputs[output_index].get_value().to_sat())
                    })?;

            // Collect the transaction outputs amount, excluding the recovering output
            let total_transaction_amount = recovering_transaction
                .output
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != recovering_output_index)
                .map(|(_, txout)| txout.value.to_sat())
                .sum::<u64>();

            let recover_amount = Amount::from_sat(total_parents_amount - total_transaction_amount);

            // Update OutputType value
            self.update_output_value(
                recovering_transaction_name,
                recovering_output_index,
                recover_amount,
            )?;
        }

        Ok(())
    }

    fn update_output_value(
        &mut self,
        transaction_name: &str,
        output_index: usize,
        value: Amount,
    ) -> Result<(), GraphError> {
        let node = self.get_node_mut(transaction_name)?;
        if output_index >= node.outputs.len() {
            return Err(GraphError::MissingOutput(
                transaction_name.to_string(),
                output_index,
            ));
        }
        node.outputs[output_index].set_value(value);
        node.transaction.output[output_index].value = value;

        Ok(())
    }

    pub fn visualize(&self, options: GraphOptions) -> Result<String, GraphError> {
        let mut result = "digraph {\ngraph [rankdir=LR]\nnode [shape=record]\n".to_owned();

        for node_index in self.graph.node_indices() {
            let from = self.graph.node_weight(node_index).unwrap();

            //Converts the tx in a box to show the inputs and outputs and values
            let inputs = from.transaction.input.len();
            let outputs = from.transaction.output.len();
            let total = inputs.max(outputs);
            let mut inout = String::new();
            for i in 0..total {
                let input_name = if i < inputs {
                    format!("<i{}> in{}", i, i)
                } else {
                    "---".to_string()
                };
                let output_name = if i < outputs {
                    format!(
                        "<o{}> out{} [{}]",
                        i,
                        i,
                        from.transaction.output[i].value.to_sat()
                    )
                } else {
                    "---".to_string()
                };
                inout.push_str(&format!("{{ {} | {} }} ", input_name, output_name));
                if i < total - 1 {
                    inout.push('|');
                }
            }

            result.push_str(&format!(
                "{} [label=\"{{ {} }} | {}  \"] \n",
                from.name, from.name, inout,
            ));

            for edge in self.graph.edges(node_index) {
                let connection = edge.weight();
                let to = self.graph.node_weight(edge.target()).unwrap();
                //Normal view
                //result.push_str(&format!( "{} -> {} [label={}]\n", from.name, to.name, connection.name,));
                //Detailed from:vout-to:in (graph view gets messy)
                //result.push_str(&format!( "{}:o{} -> {}:i{} [label={}]\n", from.name, connection.output_index, to.name, connection.input_index, connection.name,));
                //Detailed from-to:in
                if options == GraphOptions::EdgeArrows {
                    result.push_str(&format!(
                        "{}:o{}:e -> {}:i{}:w [label={}]\n",
                        from.name,
                        connection.output_index,
                        to.name,
                        connection.input_index,
                        connection.name,
                    ));
                } else {
                    result.push_str(&format!(
                        "{} -> {}:i{} [label={}]\n",
                        from.name, to.name, connection.input_index, connection.name,
                    ));
                }
            }
        }

        result.push('}');

        Ok(result)
    }

    fn get_node_mut(&mut self, name: &str) -> Result<&mut Node, GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self
            .graph
            .node_weight_mut(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;
        Ok(node)
    }

    fn get_node(&self, name: &str) -> Result<&Node, GraphError> {
        let node_index = self.get_node_index(name)?;

        let node = self
            .graph
            .node_weight(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;
        Ok(node)
    }

    fn get_node_index(&self, name: &str) -> Result<petgraph::graph::NodeIndex, GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }
        self.node_indexes
            .get(name)
            .cloned()
            .ok_or(GraphError::MissingTransaction(name.to_string()))
    }

    fn get_connection(&self, edge: EdgeIndex) -> Result<&Connection, GraphError> {
        self.graph
            .edge_weight(edge)
            .ok_or(GraphError::MissingConnection)
    }

    fn find_incoming_edges(&self, node_index: NodeIndex) -> Vec<EdgeIndex> {
        self.graph
            .edges_directed(node_index, petgraph::Direction::Incoming)
            .map(|edge| edge.id())
            .collect()
    }

    fn get_from_node(&self, edge: EdgeIndex) -> Result<&Node, GraphError> {
        let (from_index, _) = self
            .graph
            .edge_endpoints(edge)
            .ok_or(GraphError::MissingConnection)?;
        let from = self
            .graph
            .node_weight(from_index)
            .ok_or(GraphError::MissingTransaction("".to_string()))?;
        Ok(from)
    }

    fn get_from_transaction(&self, edge: EdgeIndex) -> Result<&Transaction, GraphError> {
        let from = self.get_from_node(edge)?;
        Ok(&from.transaction)
    }

    fn get_output_type(
        &self,
        transaction_name: &str,
        output_index: usize,
    ) -> Result<OutputType, GraphError> {
        Ok(self.get_node(transaction_name)?.outputs[output_index].clone())
    }

    fn get_transaction_inputs(&self) -> Result<HashMap<String, Vec<InputType>>, GraphError> {
        self.node_indexes
            .keys()
            .map(|name| {
                let node_index = self.get_node_index(name)?;
                let node = self
                    .graph
                    .node_weight(node_index)
                    .ok_or(GraphError::MissingTransaction(name.to_string()))?;

                Ok((name.clone(), node.inputs.clone()))
            })
            .collect()
    }

    // Getters for testing purposes
    pub(crate) fn _get_node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub(crate) fn _get_edge_count(&self) -> usize {
        self.graph.node_count()
    }

    pub(crate) fn _get_node_indexes(&self) -> HashMap<String, petgraph::graph::NodeIndex> {
        self.node_indexes.clone()
    }
}
