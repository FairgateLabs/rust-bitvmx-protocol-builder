use std::{collections::HashMap, path::PathBuf, vec};

use bitcoin::{secp256k1::{Message, Scalar}, taproot::TaprootSpendInfo, Amount, EcdsaSighashType, PublicKey, TapSighashType, Transaction, TxOut};
use petgraph::{algo::toposort, graph::{EdgeIndex, NodeIndex}, visit::EdgeRef, Graph};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use storage_backend::storage::Storage;

use crate::{errors::GraphError, scripts::ScriptWithKeys};

#[derive(Debug, Clone)]
pub struct InputSpendingInfo {
    sighash_type: SighashType,
    hashed_messages: Vec<Message>,
    input_keys: Vec<PublicKey>,
    spending_type: Option<OutputSpendingType>,
}

impl Serialize for InputSpendingInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut messages: Vec<&[u8; 32]> = vec![];
        for message in &self.hashed_messages {
            messages.push(message.as_ref());
        }
        let mut state = serializer.serialize_struct("InputSpendingInfo", 3)?;
        state.serialize_field("sighash_type", &self.sighash_type)?;
        state.serialize_field("hashed_messages", &messages)?;
        state.serialize_field("spending_type", &self.spending_type)?;
        state.end()
    }
    
}

impl<'de> Deserialize<'de> for InputSpendingInfo {
    fn deserialize<D>(deserializer: D) -> Result<InputSpendingInfo, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            SighashType,
            HashedMessages,
            SpendingType,
        }

        struct InputSpendingInfoVisitor;

        impl<'de> serde::de::Visitor<'de> for InputSpendingInfoVisitor {
            type Value = InputSpendingInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct InputSpendingInfo")
            }

            fn visit_map<V>(self, mut map: V) -> Result<InputSpendingInfo, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut sighash_type: Option<SighashType> = None;
                let mut hashed_messages: Option<Vec<[u8; 32]>> = None;
                let mut spending_type: Option<OutputSpendingType> = None;

                while let Some(key_field) = map.next_key()? {
                    match key_field {
                        Field::SighashType => {
                            if sighash_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("sighash_type"));
                            }
                            sighash_type = Some(map.next_value()?);
                        }
                        Field::HashedMessages => {
                            if hashed_messages.is_some() {
                                return Err(serde::de::Error::duplicate_field("hashed_messages"));
                            }
                            hashed_messages = Some(map.next_value()?);
                        }
                        Field::SpendingType => {
                            if spending_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("spending_type"));
                            }
                            spending_type = Some(map.next_value()?);
                        }
                    }
                }
                Ok(InputSpendingInfo {
                    sighash_type: sighash_type.ok_or_else(|| serde::de::Error::missing_field("sighash_type"))?,
                    hashed_messages: {
                        let mut messages = vec![];
                        for message in hashed_messages.ok_or_else(|| serde::de::Error::missing_field("hashed_messages"))? {
                            messages.push(Message::from_digest_slice(&message).map_err(|e| serde::de::Error::custom(e.to_string()))?);
                        }
                        messages
                    },
                    spending_type,
                })
            }
        }

        deserializer.deserialize_struct(
            "InputSpendingInfo",
            &["sighash_type", "hashed_messages", "spending_type"],
            InputSpendingInfoVisitor,
        )
    }
}

impl InputSpendingInfo {
    fn new(sighash_type: &SighashType) -> Self {
        Self { 
            sighash_type: sighash_type.clone(), 
            hashed_messages: vec![],
            input_keys: vec![],
            spending_type: None, 
        }
    }

    fn set_hashed_messages(&mut self, messages: Vec<Message>) {
        self.hashed_messages = messages;
    }

    fn set_input_keys(&mut self, input_keys: Vec<PublicKey>) {
        self.input_keys = input_keys;
    }

    fn set_spending_type(&mut self, spending_type: OutputSpendingType) -> Result<(), GraphError> {
        match self.sighash_type {
            SighashType::Taproot(_) => {
                match spending_type {
                    OutputSpendingType::TaprootTweakedKey { .. } => {},
                    OutputSpendingType::TaprootUntweakedKey { .. } => {},
                    OutputSpendingType::TaprootScript { .. } => {},
                    _ => Err(GraphError::InvalidSpendingTypeForSighashType)?,
                }
            },
            SighashType::Ecdsa(_) => {
                match spending_type {
                    OutputSpendingType::SegwitPublicKey { .. } => {},
                    OutputSpendingType::SegwitScript { .. } => {},
                    _ => Err(GraphError::InvalidSpendingTypeForSighashType)?,
                }
            },
        }

        self.spending_type = Some(spending_type);
        Ok(())
    }

    pub fn sighash_type(&self) -> &SighashType {
        &self.sighash_type
    }

    pub fn hashed_messages(&self) -> &Vec<Message> {
        &self.hashed_messages
    }

    pub fn input_keys(&self) -> &Vec<PublicKey> {
        &self.input_keys
    }

    pub fn spending_type(&self) -> Result<&OutputSpendingType, GraphError> {
        self.spending_type.as_ref().ok_or(GraphError::MissingOutputSpendingTypeForInputSpendingInfo(
            format!("{:?}", self.sighash_type)
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SighashType {
    Taproot(TapSighashType),
    Ecdsa(EcdsaSighashType),
}

#[derive(Debug, Clone)]
pub enum OutputSpendingType {
    TaprootUntweakedKey{
        key: PublicKey,
    },
    TaprootTweakedKey{
        key: PublicKey,
        tweak: Scalar,
    },
    TaprootScript{
        spending_scripts: Vec<ScriptWithKeys>,
        spend_info: TaprootSpendInfo,
        internal_key: PublicKey,
    },
    SegwitPublicKey{
        public_key: PublicKey,
        value: Amount, 
    },
    SegwitScript{
        script: ScriptWithKeys,
        value: Amount, 
    }
}

impl Serialize for OutputSpendingType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            OutputSpendingType::TaprootKey { key } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 1)?;
                state.serialize_field("key", key)?;
                state.end()
            }
            OutputSpendingType::TaprootScript { spending_scripts, spend_info: _, internal_key } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 2)?;
                state.serialize_field("spending_scripts", spending_scripts)?;
                state.serialize_field("internal_key", internal_key)?;
                state.end()
            }
            OutputSpendingType::SegwitPublicKey { public_key, value } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 2)?;
                state.serialize_field("public_key", public_key)?;
                state.serialize_field("value", value)?;
                state.end()
            }
            OutputSpendingType::SegwitScript { script, value } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 2)?;
                state.serialize_field("script", script)?;
                state.serialize_field("value", value)?;
                state.end()
            }
        }
    }
}


impl<'de> Deserialize<'de> for OutputSpendingType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Key,
            SpendingScripts,
            InternalKey,
            PublicKey,
            Script,
            Value,
        }

        struct OutputSpendingTypeVisitor;

        impl<'de> serde::de::Visitor<'de> for OutputSpendingTypeVisitor {
            type Value = OutputSpendingType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct OutputSpendingType")
            }

            fn visit_map<V>(self, mut map: V) -> Result<OutputSpendingType, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut key: Option<Key> = None;
                let mut spending_scripts: Option<Vec<ScriptBuf>> = None;
                let mut internal_key: Option<PublicKey> = None;
                let mut public_key: Option<PublicKey> = None;
                let mut script: Option<ScriptBuf> = None;
                let mut value: Option<Amount> = None;

                while let Some(key_field) = map.next_key()? {
                    match key_field {
                        Field::Key => {
                            if key.is_some() {
                                return Err(serde::de::Error::duplicate_field("key"));
                            }
                            key = Some(map.next_value()?);
                        }
                        Field::SpendingScripts => {
                            if spending_scripts.is_some() {
                                return Err(serde::de::Error::duplicate_field("spending_scripts"));
                            }
                            spending_scripts = Some(map.next_value()?);
                        }
                        Field::InternalKey => {
                            if internal_key.is_some() {
                                return Err(serde::de::Error::duplicate_field("internal_key"));
                            }
                            internal_key = Some(map.next_value()?);
                        }
                        Field::PublicKey => {
                            if public_key.is_some() {
                                return Err(serde::de::Error::duplicate_field("public_key"));
                            }
                            public_key = Some(map.next_value()?);
                        }
                        Field::Script => {
                            if script.is_some() {
                                return Err(serde::de::Error::duplicate_field("script"));
                            }
                            script = Some(map.next_value()?);
                        }
                        Field::Value => {
                            if value.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value = Some(map.next_value()?);
                        }
                    }
                }
                if key.is_some() {
                    let key = key.ok_or_else(|| serde::de::Error::missing_field("key"))?;
                    Ok(OutputSpendingType::TaprootKey { key })
                } else if spending_scripts.is_some() {
                    Ok(OutputSpendingType::TaprootScript {
                        spending_scripts: spending_scripts.clone().ok_or_else(|| serde::de::Error::missing_field("spending_scripts"))?,
                        spend_info: {
                            let secp = Secp256k1::new();
                            let internal_key_ok = internal_key.ok_or_else(|| serde::de::Error::missing_field("taproot_internal_key"))?;
                            let spending_scripts = spending_scripts.clone().ok_or_else(|| serde::de::Error::missing_field("spending_paths"))?;
                            match Protocol::build_taproot_spend_info(&secp,internal_key_ok, &spending_scripts){
                                Ok(taproot_spend_info) => taproot_spend_info,
                                Err(e) => {
                                    eprintln!("Error creating taproot spend info: {:?}", e);
                                    return Err(serde::de::Error::custom("Error creating taproot spend info"))
                                }
                            }
                        },
                        internal_key: internal_key.ok_or_else(|| serde::de::Error::missing_field("internal_key"))?,
                    })
                } else if public_key.is_some() {
                    let public_key = public_key.ok_or_else(|| serde::de::Error::missing_field("public_key"))?;
                    let value = value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                    Ok(OutputSpendingType::SegwitPublicKey { public_key, value })
                } else if script.is_some() {
                    let script = script.ok_or_else(|| serde::de::Error::missing_field("script"))?;
                    let value = value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                    Ok(OutputSpendingType::SegwitScript { script, value })
                } else {
                    Err(serde::de::Error::missing_field("key"))
                }
            }
        }

        deserializer.deserialize_struct(
            "OutputSpendingType",
            &["key", "spending_scripts", "internal_key", "public_key", "script", "value"],
            OutputSpendingTypeVisitor,
        )
    }
}     

impl OutputSpendingType {
    pub fn new_taproot_tweaked_key_spend(public_key: &PublicKey, tweak: &Scalar) -> Self {
        OutputSpendingType::TaprootTweakedKey {
            key: *public_key,
            tweak: *tweak,
        }
    }

    pub fn new_taproot_key_spend(public_key: &PublicKey) -> Self {
        OutputSpendingType::TaprootUntweakedKey {
            key: *public_key,
        }
    }
    
    pub fn new_taproot_script_spend(spending_scripts: &[ScriptWithKeys], spend_info: &TaprootSpendInfo) -> OutputSpendingType {
        OutputSpendingType::TaprootScript {
            spending_scripts: spending_scripts.to_vec(),
            spend_info: spend_info.clone(),
            internal_key: {
                let internal_key = spend_info.internal_key();
                PublicKey::new(internal_key.public_key(spend_info.output_key_parity()))
            },
        }
    }
    
    pub fn new_segwit_key_spend(public_key: &PublicKey, value: Amount) -> OutputSpendingType {
        OutputSpendingType::SegwitPublicKey { 
            public_key: *public_key, 
            value,
        } 
    }
    
    pub fn new_segwit_script_spend(script: &ScriptWithKeys, value: Amount) -> OutputSpendingType {
        OutputSpendingType::SegwitScript { 
            script: script.clone(),
            value,
        } 
    }
}

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

pub struct TransactionGraph {
    graph: Graph<Node, Connection>,
    node_indexes: HashMap<String, petgraph::graph::NodeIndex>,
    storage: Storage,
}


impl TransactionGraph {
    pub fn new(path: PathBuf) -> Result<Self, GraphError> {
        let storage = Storage::new_with_path(&path).map_err(|e| GraphError::StorageError(e))?;

        if storage.is_empty() {
            return Ok(TransactionGraph {
                graph: Graph::new(),
                node_indexes: HashMap::new(),
                storage,
            });
        } else {
            let mut graph = Graph::new();
            let mut node_indexes = HashMap::new();

            for (mut name, data) in storage.partial_compare("node_")? {
                let node: Node = serde_json::from_str(&data)?;
                let node_index = graph.add_node(node.clone());
                let name = name.split_off(10);
                node_indexes.insert(name, node_index);
            }

            for (_, data) in storage.partial_compare("connection_")? {
                let (connection, from_index, to_index): (Connection, usize, usize)  = serde_json::from_str(&data)?;
                let from = NodeIndex::new(from_index);
                let to = NodeIndex::new(to_index);
                graph.add_edge(from, to, connection);
            }

            Ok(TransactionGraph {
                graph,
                node_indexes,
                storage,
            })
        }
    }

    pub fn add_transaction(&mut self, name: &str, transaction: Transaction) -> Result<(), GraphError> {
        let node = Node::new(name, transaction);
        let node_index = self.graph.add_node(node.clone());
        self.storage.write(&format!("node_{:04}_{}", node_index.index() ,name), &serde_json::to_string(&node)?)?;

        self.node_indexes.insert(name.to_string(), node_index);
        Ok(())
    }

    pub fn update_transaction(&mut self, name: &str, transaction: Transaction) -> Result<(), GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            name.to_string())
        )?;

        node.transaction = transaction;

        self.storage.write(&format!("node_{:04}_{}", node_index.index() ,name), &serde_json::to_string(&node)?)?;

        Ok(())
    }

    pub fn add_transaction_input(&mut self, name: &str, transaction: Transaction, sighash_type: &SighashType) -> Result<(), GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            name.to_string())
        )?;

        node.transaction = transaction;
        node.input_spending_infos.push(InputSpendingInfo::new(sighash_type));

        self.storage.write(&format!("node_{:04}_{}", node_index.index() ,name), &serde_json::to_string(&node)?)?;

        Ok(())
    }

    pub fn add_transaction_output(&mut self, name: &str, transaction: Transaction, spending_type: OutputSpendingType) -> Result<(), GraphError> {
        let node_index = self.get_node_index(name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            name.to_string())
        )?;

        node.transaction = transaction;        
        node.output_spending_types.push(spending_type);

        self.storage.write(&format!("node_{:04}_{}", node_index.index() ,name), &serde_json::to_string(&node)?)?;

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
        
        let connection_index = self.graph.add_edge(from_node_index, to_node_index, connection.clone());

        self.storage.write(&format!("connection_{:04}_{}", connection_index.index(), connection_name), &serde_json::to_string(&(connection, from_node_index.index(), to_node_index.index()))?)?;

        let to_node = self.graph.node_weight_mut(to_node_index).ok_or(GraphError::MissingTransaction(
            to.to_string())
        )?;

        to_node.input_spending_infos[input_index as usize].add_spending_type(output_spending_type)?;

        self.storage.write(&format!("node_{:04}_{}", to_node_index.index() ,to), &serde_json::to_string(&to_node)?)?;

        Ok(())
    }

    pub fn connect_with_external_transaction(&mut self, output_spending_type: OutputSpendingType, to: &str) -> Result<(), GraphError> {
        let to_node_index = self.get_node_index(to)?;

        let to_node = self.graph.node_weight_mut(to_node_index).ok_or(GraphError::MissingTransaction(
            to.to_string())
        )?;

        to_node.input_spending_infos[to_node.transaction.input.len() - 1].add_spending_type(output_spending_type)?;

        self.storage.write(&format!("node_{:04}_{}", to_node_index.index() ,to), &serde_json::to_string(&to_node)?)?;

        Ok(())
    }

    pub fn update_input_spending_info(&mut self, transaction_name: &str, input_index: u32, message_hashes: Vec<Message>, keys: Vec<PublicKey>) -> Result<(), GraphError> {
        let node_index = self.get_node_index(transaction_name)?;
        let node = self.graph.node_weight_mut(node_index).ok_or(GraphError::MissingTransaction(
            transaction_name.to_string())
        )?;

        node.input_spending_infos[input_index as usize].set_hashed_messages(message_hashes);
        node.input_spending_infos[input_index as usize].set_input_keys(keys);

        self.storage.write(&format!("node_{:04}_{}", node_index.index(), transaction_name), &serde_json::to_string(node)?)?;

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

    pub fn get_transactions_spending_info(&self) -> Result<HashMap<String, Vec<InputSpendingInfo>>, GraphError> {
        self.node_indexes.keys().map(|name| {
            let node_index = self.get_node_index(name)?;
            let node = self.graph.node_weight(node_index).ok_or(GraphError::MissingTransaction(
                name.to_string())
            )?;
    
            Ok((name.clone(), node.input_spending_infos.clone()))
        }).collect()
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
}
