use std::collections::{hash_map::{Values, ValuesMut}, HashMap, HashSet};
use storage_backend::storage::Storage;
use crate::errors::GraphError;
use std::path::Path;
use crate::template::Template;

pub struct Graph {
    graph: Storage,
    templates: HashMap<String, Template>,
    end_templates: Vec<String>,
}

impl Graph {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, GraphError> {
        let graph = Storage::new_with_path(&path.as_ref().to_path_buf()).map_err(|e| GraphError::StorageError(e))?;
        Ok(Graph { 
            graph,
            templates: HashMap::new(),
            end_templates: Vec::new(),
      })
    }

    pub fn add_template(&mut self, name: &str, template: Template) -> Result<(), GraphError> {
        self.templates.insert(name.to_string(), template);
        if !self.graph.has_key(name).map_err(|e| GraphError::StorageError(e))?{
            self.graph.write(name, "").map_err(|e| GraphError::StorageError(e))?;
        }
        Ok(())
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

    pub fn connect(&mut self, from: &str, to: &str) -> Result<(), GraphError>{
        let mut dependents = match self.graph.read(from).map_err(|e| GraphError::StorageError(e))? {
            Some(dependents) => dependents,
            None => return Err(GraphError::NodeNotFound),            
        };

        if dependents.contains(to) {
            return Ok(());    
        } else if dependents.is_empty() {
            dependents = to.to_string();
        } else {
            dependents.push_str(&format!(",{}", to));
        }

        self.graph.write(from, &dependents).map_err(|e| GraphError::StorageError(e))?;
        Ok(())
    }

    /// Returns a topological ordering of the graph
    pub fn sort(&self) -> Result<Vec<String>, GraphError> {
        let mut sorted = Vec::new();
        let mut visited = HashSet::new();
        let mut temp_marked = HashSet::new();
        for name in self.graph.keys() {
            if !visited.contains(&name) {
                self.visit(&name, &mut visited, &mut temp_marked, &mut sorted)?;
            }
        }
        sorted.reverse();  // Reverse to get the correct topological order
        
        Ok(sorted)
    }

    fn get_dependents(&self, name: &str) -> Option<Vec<String>> {
        let dependents = match self.graph.read(name).map_err(|e| GraphError::StorageError(e)).unwrap(){
            Some(dependents) => dependents,
            None => return None,
        };

        if dependents.is_empty() {
            return None;
            
        } else {
            return Some(dependents.split(",").map(|s| s.to_string()).collect());
        }
        
    }

    fn visit(&self, name: &str, visited: &mut HashSet<String>, temp_marked: &mut HashSet<String>, sorted: &mut Vec<String>) -> Result<(), GraphError> {
        if temp_marked.contains(name) {
            return Err(GraphError::GraphCycleDetected.into())
        }

        if !visited.contains(name) {
            temp_marked.insert(name.to_string());
            if let Some(dependents) = self.get_dependents(name) {
                for dependent_txid in dependents {
                    self.visit(dependent_txid.as_str(), visited, temp_marked, sorted)?;
                }
            }
            temp_marked.remove(name);
            visited.insert(name.to_string());
            sorted.push(name.to_string());
        }

        Ok(())
    }
}

