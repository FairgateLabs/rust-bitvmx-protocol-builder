use std::collections::{hash_map::{Values, ValuesMut}, HashMap, HashSet};

use crate::{errors::GraphError, template::Template};

pub struct Graph {
    graph: HashMap<String, HashSet<String>>, 
    templates: HashMap<String, Template>,
    end_templates: Vec<String>,
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
            templates: HashMap::new(),
            end_templates: Vec::new(),
        }
    }

    pub fn add_template(&mut self, name: &str, template: Template) {
        self.templates.insert(name.to_string(), template);
        if !self.graph.contains_key(name) {
            self.graph.insert(name.to_string(), HashSet::new());
        }
    }

    pub fn get_template(&self, name: &str) -> Option<&Template> {
        self.templates.get(name)
    }

    pub fn get_template_mut(&mut self, name: &str) -> Option<&mut Template> {
        self.templates.get_mut(name)
    }

    pub fn contains_template(&self, name: &str) -> bool {
        self.templates.contains_key(name)
    }

    pub fn templates(&self) -> Values<String, Template> {
        self.templates.values()
    }

    pub fn templates_mut(&mut self) -> ValuesMut<String, Template> {
        self.templates.values_mut()
    }

    pub fn end_template(&mut self, name: &str) {
        self.end_templates.push(name.to_string());
    }

    pub fn is_ended(&self, name: &str) -> bool {
        self.end_templates.contains(&name.to_string())
    }

    pub fn connect(&mut self, from: &str, to: &str) {
        self.graph.get_mut(from).unwrap().insert(to.to_string());
    }

    /// Returns a topological ordering of the graph
    pub fn sort(&self) -> Result<Vec<String>, GraphError> {
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

