#[cfg(test)]
mod test {
    use crate::errors::GraphError;
    use crate::graph::graph::{Connection, Node, TransactionGraph};

    use bitcoin::hex::test_hex_unwrap as hex;
    use bitcoin::{consensus::Decodable, Transaction};

    const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[test]
    fn create_node() {
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        let node = Node::new("test_tx", tx, false);

        assert_eq!(node.name, "test_tx");
        assert_eq!(node.outputs.len(), 0);
        assert_eq!(node.inputs.len(), 0);
    }

    #[test]
    fn create_connection() {
        use Connection;

        let connection = Connection::new("test_connection", 1, 2);

        assert_eq!(connection.name, "test_connection");
        assert_eq!(connection.input_index, 1);
        assert_eq!(connection.output_index, 2);
    }

    #[test]
    fn create_empty_graph() {
        let graph = TransactionGraph::default();

        assert!(graph._get_node_indexes().is_empty());
        assert_eq!(graph._get_node_count(), 0);
        assert_eq!(graph._get_edge_count(), 0);
    }

    #[test]
    fn add_transaction_to_graph() {
        let mut graph = TransactionGraph::default();
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        graph.add_transaction("tx1", tx.clone(), false).unwrap();

        assert!(graph.contains_transaction("tx1"));
        assert_eq!(graph._get_node_count(), 1);
    }

    #[test]
    fn add_transaction_to_graph_with_empty_name() {
        let mut graph = TransactionGraph::default();
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        assert!(graph.add_transaction("", tx.clone(), false).is_err());
    }

    #[test]
    fn add_duplicated_transaction_to_graph() {
        let mut graph = TransactionGraph::default();
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        graph.add_transaction("tx1", tx.clone(), false).unwrap();
        assert!(graph.add_transaction("tx1", tx.clone(), false).is_err());

        assert!(graph.contains_transaction("tx1"));
        assert!(!graph.contains_transaction("tx2"));
        assert_eq!(graph._get_node_count(), 1);
    }

    #[test]
    fn test_graph_sort() {
        let mut graph = TransactionGraph::default();
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();

        graph.add_transaction("tx1", tx.clone(), false).unwrap();
        graph.add_transaction("tx2", tx, false).unwrap();

        let sorted = graph.sort().unwrap();
        assert_eq!(sorted.len(), 2);

        // The order is deterministic but either tx1->tx2 or tx2->tx1 is valid
        assert!(
            (sorted[0] == "tx1" && sorted[1] == "tx2")
                || (sorted[0] == "tx2" && sorted[1] == "tx1")
        );
    }

    #[test]
    fn test_missing_input_info() {
        let raw_tx = hex!(SOME_TX);
        let tx: Transaction = Decodable::consensus_decode(&mut raw_tx.as_slice()).unwrap();
        let node = Node::new("test_tx", tx, false);

        let result = node.get_input(0);
        assert!(result.is_err());

        if let Err(GraphError::MissingInputInfo(name, index)) = result {
            assert_eq!(name, "test_tx");
            assert_eq!(index, 0);
        } else {
            panic!("Expected MissingInputInfo error");
        }
    }
}
