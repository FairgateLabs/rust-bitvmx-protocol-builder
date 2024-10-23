use std::{collections::HashMap, vec};

use bitcoin::{secp256k1::Message, Transaction, TxOut};
use petgraph::{algo::toposort, graph::{EdgeIndex, NodeIndex}, visit::EdgeRef, Graph};
use serde::{Deserialize, Serialize};

use crate::errors::GraphError;

use super::{input::{InputSignatures, InputSpendingInfo, SighashType, Signature}, output::OutputSpendingType};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionGraph {
    graph: Graph<Node, Connection>,
    node_indexes: HashMap<String, petgraph::graph::NodeIndex>,
}

impl TransactionGraph {
    pub fn new() -> Self{
        let graph = Graph::new();
        let node_indexes = HashMap::new();

        TransactionGraph {
            graph,
            node_indexes,
        }
    }

    pub fn add_transaction(&mut self, name: &str, transaction: Transaction) -> Result<(), GraphError> {
        let node = Node::new(name, transaction);
        let node_index = self.graph.add_node(node.clone());

        self.node_indexes.insert(name.to_string(), node_index);
        Ok(())
    }

    pub fn update_transaction(&mut self, name: &str, transaction: Transaction) -> Result<(), GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            name.to_string())
        )?;

        node.transaction = transaction;
        Ok(())
    }

    pub fn add_transaction_input(&mut self, name: &str, transaction: Transaction, sighash_type: &SighashType) -> Result<(), GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            name.to_string())
        )?;

        node.transaction = transaction;
        node.input_spending_infos.push(InputSpendingInfo::new(sighash_type));
        Ok(())
    }

    pub fn add_transaction_output(&mut self, name: &str, transaction: Transaction, spending_type: OutputSpendingType) -> Result<(), GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            name.to_string())
        )?;

        node.transaction = transaction;        
        node.output_spending_types.push(spending_type);
        Ok(())
    }

    pub fn connect(&mut self, connection_name: &str, from: &str, output_index: u32, to: &str, input_index: u32) -> Result<(), GraphError> {
        let from_node_index = self.get_node_index(from)?;
        let to_node_index = self.get_node_index(to)?;
        let output_spending_type = self.get_output_spending_type(from, output_index)?;

        let connection = Connection::new(
            connection_name.to_string(),
            input_index,
            output_index,
        );
        
        self.graph.add_edge(from_node_index, to_node_index, connection.clone());

        let to_node = self.graph.node_weight_mut(to_node_index).ok_or(GraphError::MissingTransaction(
            to.to_string())
        )?;

        to_node.input_spending_infos[input_index as usize].set_spending_type(output_spending_type)?;

        Ok(())
    }

    pub fn connect_with_external_transaction(&mut self, output_spending_type: OutputSpendingType, to: &str) -> Result<(), GraphError> {
        let to_node_index = self.get_node_index(to)?;

        let to_node = self.graph.node_weight_mut(to_node_index).ok_or(GraphError::MissingTransaction(
            to.to_string())
        )?;

        to_node.input_spending_infos[to_node.transaction.input.len() - 1].set_spending_type(output_spending_type)?;

        Ok(())
    }

    pub fn update_hashed_messages(&mut self, transaction_name: &str, input_index: u32, message_hashes: Vec<Message>) -> Result<(), GraphError> {
        let node_index = self.get_node_index(transaction_name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            transaction_name.to_string())
        )?;

        node.input_spending_infos[input_index as usize].set_hashed_messages(message_hashes);
        Ok(())
    }
        
    pub fn update_input_signatures(&mut self, transaction_name: &str, input_index: u32, signatures: Vec<Signature>) -> Result<(), GraphError> {
        let node_index = self.get_node_index(transaction_name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            transaction_name.to_string())
        )?;

        node.input_spending_infos[input_index as usize].set_signatures(signatures);

        Ok(())
    }

    pub fn get_transaction(&self, name: &str) -> Result<&Transaction, GraphError> {
        self.node_indexes.get(name).ok_or(GraphError::MissingTransaction(name.to_string())).map(
            |node_index| {
                let node = self.graph.node_weight(*node_index).unwrap();
                &node.transaction
            }
        )
    }

    pub fn next_transactions(&self, name: &str) -> Result<Vec<&Transaction>, GraphError> {
        let dependencies = self.get_dependencies(name)?;
        let next_transactions = dependencies.iter()
            .map(|(name, _)| self.get_transaction(name))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(next_transactions)
    }

    pub fn get_dependencies(&self, name: &str) -> Result<Vec<(String, u32)>, GraphError> {
        let node_index = self.get_node_index(name)?;

        let dependencies = self.graph.edges(node_index)
            .map(|edge| {
                let node_index = edge.target();
                let node = self.graph.node_weight(node_index).unwrap();
                let connection = edge.weight();
                (node.name.clone(), connection.input_index)
            }
        ).collect();

        Ok(dependencies)
    }

    pub fn get_prevouts(&self, name: &str) -> Result<Vec<TxOut>, GraphError> {
        let node_index = self.get_node_index(name)?;
        let transaction = self.get_transaction(name)?;

        let mut prevouts = vec![None; transaction.input.len()];

        for edge in self.find_incoming_edges(node_index) {
            let from = self.get_from_transaction(edge)?;
            let connection = self.get_connection(edge)?;
            prevouts[connection.input_index as usize] = Some(from.output[connection.output_index as usize].clone());
        };

        let result = prevouts.iter()
            .map(|txout| txout.clone().ok_or(GraphError::MissingTransaction(name.to_string())))
            .collect();

        result
    }

    pub fn get_transaction_spending_info(&self, name: &str) -> Result<Vec<InputSpendingInfo>, GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self.graph.node_weight(node_index).ok_or(GraphError::MissingTransaction(
            name.to_string())
        )?;

        Ok(node.input_spending_infos.clone())
    }

    pub fn get_transaction_spending_infos(&self) -> Result<HashMap<String, Vec<InputSpendingInfo>>, GraphError> {
        self.node_indexes.keys().map(|name| {
            let node_index = self.get_node_index(name)?;
            let node = self.graph.node_weight(node_index).ok_or(GraphError::MissingTransaction(
                name.to_string())
            )?;
    
            Ok((name.clone(), node.input_spending_infos.clone()))
        }).collect()
    }

    fn get_node_index(&self, name: &str) -> Result<petgraph::graph::NodeIndex, GraphError> {
        self.node_indexes.get(name).cloned().ok_or(GraphError::MissingTransaction(name.to_string()))
    }

    fn get_connection(&self, edge: EdgeIndex) -> Result<&Connection, GraphError> {
        self.graph.edge_weight(edge).ok_or(GraphError::MissingConnection)
    }

    fn find_incoming_edges(&self, node_index: NodeIndex) -> Vec<EdgeIndex> {
        self.graph.edges_directed(node_index, petgraph::Direction::Incoming).map(|edge| edge.id()).collect()
    }

    fn get_from_node(&self, edge: EdgeIndex) -> Result<&Node, GraphError> {
        let (from_index, _) = self.graph.edge_endpoints(edge).ok_or(GraphError::MissingConnection)?;
        let from = self.graph.node_weight(from_index).ok_or(GraphError::MissingTransaction("".to_string()))?;
        Ok(from)
    }
    
    fn get_from_transaction(&self, edge: EdgeIndex) -> Result<&Transaction, GraphError> {
        let from = self.get_from_node(edge)?;
        Ok(&from.transaction)
    }

    fn get_output_spending_type(&self, transaction_name: &str, output_index: u32) -> Result<OutputSpendingType, GraphError> {
        let node_index = self.get_node_index(transaction_name)?;
        let node = self.graph.node_weight(node_index).ok_or(GraphError::MissingTransaction(
            transaction_name.to_string())
        )?;

        Ok(node.output_spending_types[output_index as usize].clone())
    }
    
    pub fn get_transaction_names(&self) -> Vec<String> {
        self.graph.node_weights().map(|node| node.name.clone()).collect()
    }

    pub fn get_all_signatures(&self) -> Result<HashMap<String, Vec<InputSignatures>>, GraphError> {
        let mut all_signatures = HashMap::new();

        for (name, input_spending_infos) in self.get_transaction_spending_infos()? {
            let signatures = input_spending_infos.iter().map(|info| InputSignatures::new(info.signatures().clone())).collect();
            all_signatures.insert(name, signatures);
        }

        Ok(all_signatures)
    }

    pub fn contains_transaction(&self, name: &str) -> bool {
        self.node_indexes.contains_key(name)
    }

    pub fn sort(&self) -> Result<Vec<String>, GraphError> {
        let sorted = toposort(&self.graph, None).map_err(|_| GraphError::GraphCycleDetected)?;
        let result = sorted.iter().map(|node_index| {
            let node = self.graph.node_weight(*node_index).unwrap();
            node.name.clone()
        }).collect();

        Ok(result)
    }
}