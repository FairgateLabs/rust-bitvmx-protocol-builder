use core::fmt;
use std::{collections::HashMap, vec};

use bitcoin::{secp256k1::Message, Transaction, TxOut, Txid};
use petgraph::{
    algo::toposort,
    graph::{EdgeIndex, NodeIndex},
    visit::EdgeRef,
    Graph,
};
use serde::{Deserialize, Serialize};

use crate::errors::GraphError;

use super::{
    input::{InputSignatures, InputSpendingInfo, SighashType, Signature},
    output::OutputSpendingType,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Node {
    name: String,
    transaction: Transaction,
    output_spending_types: Vec<OutputSpendingType>,
    input_spending_infos: Vec<InputSpendingInfo>,
}

impl Node {
    fn new(name: &str, transaction: Transaction) -> Self {
        Node {
            name: name.to_string(),
            transaction,
            output_spending_types: vec![],
            input_spending_infos: vec![],
        }
    }

    fn get_input_spending_info(
        &self,
        input_index: usize,
    ) -> Result<&InputSpendingInfo, GraphError> {
        self.input_spending_infos
            .get(input_index)
            .ok_or(GraphError::MissingInputSpendingInfo(
                self.name.clone(),
                input_index,
            ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Connection {
    name: String,
    input_index: u32,
    output_index: u32,
}

impl Connection {
    fn new(name: String, input_index: u32, output_index: u32) -> Self {
        Connection {
            name,
            input_index,
            output_index,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageId {
    transaction: String,
    input_index: u32,
    script_index: u32,
}

impl MessageId {
    pub fn new(transaction: String, input_index: u32, script_index: u32) -> Self {
        MessageId {
            transaction,
            input_index,
            script_index,
        }
    }

    pub fn new_string_id(transaction: &str, input_index: u32, script_index: u32) -> String {
        format!("tx:{}_ix:{}_sx:{}", transaction, input_index, script_index)
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tx:{}_ix:{}_sx:{}",
            self.transaction, self.input_index, self.script_index
        )
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
    ) -> Result<(), GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        if self.node_indexes.contains_key(name) {
            return Err(GraphError::TransactionAlreadyExists(name.to_string()));
        }

        let node = Node::new(name, transaction);
        let node_index = self.graph.add_node(node.clone());

        self.node_indexes.insert(name.to_string(), node_index);
        Ok(())
    }

    pub fn update_transaction(
        &mut self,
        name: &str,
        transaction: Transaction,
    ) -> Result<(), GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let node_index = self.get_node_index(name)?;
        let node = self
            .graph
            .node_weight_mut(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;

        node.transaction = transaction;
        Ok(())
    }

    pub fn add_transaction_input(
        &mut self,
        name: &str,
        transaction: Transaction,
        sighash_type: &SighashType,
    ) -> Result<(), GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let node_index = self.get_node_index(name)?;
        let node = self
            .graph
            .node_weight_mut(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;

        node.transaction = transaction;
        node.input_spending_infos
            .push(InputSpendingInfo::new(sighash_type));
        Ok(())
    }

    pub fn add_transaction_output(
        &mut self,
        name: &str,
        transaction: Transaction,
        spending_type: OutputSpendingType,
    ) -> Result<(), GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let node_index = self.get_node_index(name)?;
        let node = self
            .graph
            .node_weight_mut(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;

        node.transaction = transaction;
        node.output_spending_types.push(spending_type);
        Ok(())
    }

    pub fn connect(
        &mut self,
        connection_name: &str,
        from: &str,
        output_index: u32,
        to: &str,
        input_index: u32,
    ) -> Result<(), GraphError> {
        if from.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        if to.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let from_node_index = self.get_node_index(from)?;
        let to_node_index = self.get_node_index(to)?;
        let output_spending_type = self.get_output_spending_type(from, output_index)?;

        let connection = Connection::new(connection_name.to_string(), input_index, output_index);

        self.graph
            .add_edge(from_node_index, to_node_index, connection.clone());

        let to_node = self
            .graph
            .node_weight_mut(to_node_index)
            .ok_or(GraphError::MissingTransaction(to.to_string()))?;

        to_node.input_spending_infos[input_index as usize]
            .set_spending_type(output_spending_type)?;

        Ok(())
    }

    pub fn connect_with_external_transaction(
        &mut self,
        output_spending_type: OutputSpendingType,
        to: &str,
    ) -> Result<(), GraphError> {
        if to.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let to_node_index = self.get_node_index(to)?;

        let to_node = self
            .graph
            .node_weight_mut(to_node_index)
            .ok_or(GraphError::MissingTransaction(to.to_string()))?;

        to_node.input_spending_infos[to_node.transaction.input.len() - 1]
            .set_spending_type(output_spending_type)?;

        Ok(())
    }

    pub fn update_hashed_messages(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        message_hashes: Vec<Message>,
    ) -> Result<(), GraphError> {
        if transaction_name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let node_index = self.get_node_index(transaction_name)?;
        let node = self
            .graph
            .node_weight_mut(node_index)
            .ok_or(GraphError::MissingTransaction(transaction_name.to_string()))?;

        node.input_spending_infos[input_index as usize].set_hashed_messages(message_hashes);
        Ok(())
    }

    pub fn update_input_signatures(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        signatures: Vec<Signature>,
    ) -> Result<(), GraphError> {
        if transaction_name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let node_index = self.get_node_index(transaction_name)?;
        let node = self
            .graph
            .node_weight_mut(node_index)
            .ok_or(GraphError::MissingTransaction(transaction_name.to_string()))?;

        node.input_spending_infos[input_index as usize].set_signatures(signatures);

        Ok(())
    }

    pub fn get_hashed_message(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        message_index: u32,
    ) -> Result<Message, GraphError> {
        if transaction_name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let node_index = self.get_node_index(transaction_name)?;
        let node = self
            .graph
            .node_weight_mut(node_index)
            .ok_or(GraphError::MissingTransaction(transaction_name.to_string()))?;

        Ok(node.input_spending_infos[input_index as usize].hashed_messages()[message_index as usize])
    }

    pub fn get_transaction(&self, name: &str) -> Result<&Transaction, GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        self.node_indexes
            .get(name)
            .ok_or(GraphError::MissingTransaction(name.to_string()))
            .map(|node_index| {
                let node = self.graph.node_weight(*node_index).unwrap();
                &node.transaction
            })
    }

    pub fn get_transaction_with_id(&self, txid: Txid) -> Result<&Transaction, GraphError> {
        for node in self.graph.node_weights() {
            if node.transaction.compute_txid() == txid {
                return Ok(&node.transaction);
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
            .map(|(name, _)| self.get_transaction(name))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(next_transactions)
    }

    pub fn get_dependencies(&self, name: &str) -> Result<Vec<(String, u32)>, GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

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
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let node_index = self.get_node_index(name)?;
        let transaction = self.get_transaction(name)?;

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

    pub fn get_transaction_spending_info(
        &self,
        name: &str,
    ) -> Result<Vec<InputSpendingInfo>, GraphError> {
        if name.trim().is_empty() {
            return Err(GraphError::EmptyTransactionName);
        }

        let node_index = self.get_node_index(name)?;
        let node = self
            .graph
            .node_weight(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;

        Ok(node.input_spending_infos.clone())
    }

    pub fn get_transaction_spending_infos(
        &self,
    ) -> Result<HashMap<String, Vec<InputSpendingInfo>>, GraphError> {
        self.node_indexes
            .keys()
            .map(|name| {
                let node_index = self.get_node_index(name)?;
                let node = self
                    .graph
                    .node_weight(node_index)
                    .ok_or(GraphError::MissingTransaction(name.to_string()))?;

                Ok((name.clone(), node.input_spending_infos.clone()))
            })
            .collect()
    }

    pub fn get_all_sighashes(&self) -> Result<Vec<(MessageId, Message)>, GraphError> {
        let mut all_sighashes = Vec::new();

        for (name, input_spending_infos) in self.get_transaction_spending_infos()? {
            for (input_index, spending_info) in input_spending_infos.iter().enumerate() {
                for (script_index, message) in spending_info.hashed_messages().iter().enumerate() {
                    let message_id = MessageId::new(name.clone(), input_index as u32, script_index as u32);
                    all_sighashes.push((message_id, message.clone()));
                }
            }
        }

        Ok(all_sighashes)
    }

    pub fn get_output_for_input(&self, name: &str, input_index: u32) -> Result<OutputSpendingType, GraphError> {
        let node_index = self.get_node_index(name)?;

        for edge in self.find_incoming_edges(node_index) {
            let connection = self.get_connection(edge)?;
            if connection.input_index == input_index {
                let from = self.get_from_node(edge)?;
                return Ok(from.output_spending_types[connection.output_index as usize].clone());
            }
        }

        Err(GraphError::MissingConnection)
    }

    fn get_node_index(&self, name: &str) -> Result<petgraph::graph::NodeIndex, GraphError> {
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

    fn get_output_spending_type(
        &self,
        transaction_name: &str,
        output_index: u32,
    ) -> Result<OutputSpendingType, GraphError> {
        let node_index = self.get_node_index(transaction_name)?;
        let node = self
            .graph
            .node_weight(node_index)
            .ok_or(GraphError::MissingTransaction(transaction_name.to_string()))?;

        Ok(node.output_spending_types[output_index as usize].clone())
    }

    pub fn get_transaction_names(&self) -> Vec<String> {
        self.graph
            .node_weights()
            .map(|node| node.name.clone())
            .collect()
    }

    pub fn get_all_signatures(&self) -> Result<HashMap<String, Vec<InputSignatures>>, GraphError> {
        let mut all_signatures = HashMap::new();

        for (name, input_spending_infos) in self.get_transaction_spending_infos()? {
            let signatures = input_spending_infos
                .iter()
                .map(|info| InputSignatures::new(info.signatures().clone()))
                .collect();
            all_signatures.insert(name, signatures);
        }

        Ok(all_signatures)
    }

    pub fn get_input_ecdsa_signature(
        &self,
        name: &str,
        input_index: usize,
    ) -> Result<bitcoin::ecdsa::Signature, GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self
            .graph
            .node_weight(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;

        let spending_info = node.get_input_spending_info(input_index)?;
        let signature = match spending_info.get_signature(0)? {
            Signature::Ecdsa(signature) => signature,
            _ => {
                return Err(GraphError::InvalidSignatureType(
                    name.to_string(),
                    input_index,
                    "Ecdsa".to_string(),
                    "Taproot".to_string(),
                ))
            }
        };

        Ok(*signature)
    }

    pub fn get_input_taproot_script_spend_signature(
        &self,
        name: &str,
        input_index: usize,
        leaf_index: usize,
    ) -> Result<bitcoin::taproot::Signature, GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self
            .graph
            .node_weight(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;

        let spending_info = node.get_input_spending_info(input_index)?;
        let signature = match spending_info.get_signature(leaf_index)? {
            Signature::Taproot(signature) => signature,
            _ => {
                return Err(GraphError::InvalidSignatureType(
                    name.to_string(),
                    input_index,
                    "Taproot".to_string(),
                    "ECDSA".to_string(),
                ))
            }
        };

        Ok(*signature)
    }

    pub fn get_input_taproot_key_spend_signature(
        &self,
        name: &str,
        input_index: usize,
    ) -> Result<bitcoin::taproot::Signature, GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self
            .graph
            .node_weight(node_index)
            .ok_or(GraphError::MissingTransaction(name.to_string()))?;

        let spending_info = node.get_input_spending_info(input_index)?;
        let signature = match spending_info.signatures().last().ok_or(GraphError::MissingSignature)? {
            Signature::Taproot(signature) => signature,
            _ => {
                return Err(GraphError::InvalidSignatureType(
                    name.to_string(),
                    input_index,
                    "Taproot".to_string(),
                    "ECDSA".to_string(),
                ))
            }
        };

        Ok(*signature)
    }



    pub fn contains_transaction(&self, name: &str) -> bool {
        self.node_indexes.contains_key(name)
    }

    pub fn sort(&self) -> Result<Vec<String>, GraphError> {
        let sorted = toposort(&self.graph, None).map_err(|_| GraphError::GraphCycleDetected)?;
        let result = sorted
            .iter()
            .map(|node_index| {
                let node = self.graph.node_weight(*node_index).unwrap();
                node.name.clone()
            })
            .collect();

        Ok(result)
    }

    pub fn visualize(&self) -> Result<String, GraphError> {
        let mut result = "digraph {\ngraph [rankdir=LR]\nnode [shape=Record]\n".to_owned();

        for node_index in self.graph.node_indices() {
            let from = self.graph.node_weight(node_index).unwrap();

            for edge in self.graph.edges(node_index) {
                let connection = edge.weight();
                let to = self.graph.node_weight(edge.target()).unwrap();
                result.push_str(&format!(
                    "{} -> {} [label={}]\n",
                    from.name, to.name, connection.name
                ));
            }
        }

        result.push('}');

        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use super::Node;
    use bitcoin::hex::test_hex_unwrap as hex;
    use bitcoin::{consensus::Decodable, Transaction};

    const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[test]
    fn create_node() {
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        let node = Node::new("test_tx", tx);

        assert_eq!(node.name, "test_tx");
        assert_eq!(node.output_spending_types.len(), 0);
        assert_eq!(node.input_spending_infos.len(), 0);
    }

    #[test]
    fn create_connection() {
        use super::Connection;

        let connection = Connection::new("test_connection".to_string(), 1, 2);

        assert_eq!(connection.name, "test_connection");
        assert_eq!(connection.input_index, 1);
        assert_eq!(connection.output_index, 2);
    }

    #[test]
    fn create_empty_graph() {
        let graph = super::TransactionGraph::default();

        assert!(graph.node_indexes.is_empty());
        assert_eq!(graph.graph.node_count(), 0);
        assert_eq!(graph.graph.edge_count(), 0);
    }

    #[test]
    fn add_transaction_to_graph() {
        let mut graph = super::TransactionGraph::default();
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        graph.add_transaction("tx1", tx.clone()).unwrap();

        assert!(graph.contains_transaction("tx1"));
        assert_eq!(graph.graph.node_count(), 1);
    }

    #[test]
    fn add_transaction_to_graph_with_empty_name() {
        let mut graph = super::TransactionGraph::default();
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        assert!(graph.add_transaction("", tx.clone()).is_err());
    }

    #[test]
    fn add_duplicated_transaction_to_graph() {
        let mut graph = super::TransactionGraph::default();
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        graph.add_transaction("tx1", tx.clone()).unwrap();
        assert!(graph.add_transaction("tx1", tx.clone()).is_err());

        assert!(graph.contains_transaction("tx1"));
        assert!(!graph.contains_transaction("tx2"));
        assert_eq!(graph.graph.node_count(), 1);
    }

    #[test]
    fn test_graph_sort() {
        let mut graph = super::TransactionGraph::default();
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        graph.add_transaction("tx1", tx.clone()).unwrap();
        graph.add_transaction("tx2", tx).unwrap();

        let sorted = graph.sort().unwrap();
        assert_eq!(sorted.len(), 2);

        // The order is deterministic but either tx1->tx2 or tx2->tx1 is valid
        assert!(
            (sorted[0] == "tx1" && sorted[1] == "tx2")
                || (sorted[0] == "tx2" && sorted[1] == "tx1")
        );
    }

    #[test]
    fn test_missing_input_spending_info() {
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        let node = Node::new("test_tx", tx);

        let result = node.get_input_spending_info(0);
        assert!(result.is_err());

        if let Err(super::GraphError::MissingInputSpendingInfo(name, index)) = result {
            assert_eq!(name, "test_tx");
            assert_eq!(index, 0);
        } else {
            panic!("Expected MissingInputSpendingInfo error");
        }
    }
}
