use std::collections::{HashMap, HashSet};

use crate::errors::GraphError;

pub struct Graph {
    graph: HashMap<String, HashSet<String>>, 
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

impl Graph {
    pub fn new() -> Self {
        Graph {
            graph: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, name: &str) {
        if !self.graph.contains_key(name) {
            self.graph.insert(name.to_string(), HashSet::new());
        }
    }

    pub fn add_edge(&mut self, from: &str, to: &str) {
        self.graph.get_mut(from).unwrap().insert(to.to_string());
    }

    pub fn topological_sort(&self) -> Result<Vec<String>, GraphError> {
        let mut sorted = Vec::new();
        let mut visited = HashSet::new();
        let mut temp_marked = HashSet::new();
        for name in self.graph.keys() {
            if !visited.contains(name) {
                self.visit(name, &mut visited, &mut temp_marked, &mut sorted)?;
            }
        }
        sorted.reverse();  // Reverse to get the correct topological order
        
        Ok(sorted)
    }

    fn visit(&self, name: &str, visited: &mut HashSet<String>, temp_marked: &mut HashSet<String>, sorted: &mut Vec<String>) -> Result<(), GraphError> {
        if temp_marked.contains(name) {
            return Err(GraphError::GraphCycleDetected)
        }

        if !visited.contains(name) {
            temp_marked.insert(name.to_string());
            if let Some(dependents) = self.graph.get(name) {
                for dependent_txid in dependents {
                    self.visit(dependent_txid, visited, temp_marked, sorted)?;
                }
            }
            temp_marked.remove(name);
            visited.insert(name.to_string());
            sorted.push(name.to_string());
        }

        Ok(())
    }
}

