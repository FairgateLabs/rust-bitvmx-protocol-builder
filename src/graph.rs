use std::collections::{HashMap, HashSet};
use storage_backend::storage::Storage;
use crate::errors::GraphError;
use std::path::Path;
use crate::template::Template;
use serde_json::from_str;

pub struct Graph {
    storage: Storage,
    end_templates: Vec<String>,
}

impl Graph {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, GraphError> {
        let storage = Storage::new_with_path(&path.as_ref().to_path_buf()).map_err(|e| GraphError::StorageError(e))?;
        Ok(Graph { 
            storage,
            end_templates: Vec::new(),
      })
    }

    pub fn add_template(&mut self, name: &str, template: Template) -> Result<(), GraphError> {
        self.storage.write(&format_template_name(name), &serde_json::to_string(&template)?)?;

        if !self.storage.has_key(&format_name_node(name))?{
            self.storage.write(&format_name_node(name), "")?;
        }
        Ok(())
    }
      
    pub fn get_template(&self, name: &str) -> Result<Option<Template>, GraphError> {
        match self.storage.read(&format_template_name(name)) {
            Ok(value)=>{
                match value {
                    Some(template) => {
                        Ok(Some(from_str(&template)?))
                    },
                    None => Ok(None), 
                }
            },
            Err(_) => Err(GraphError::NodeNotFound),
        }
    }

    pub fn contains_template(&self, name: &str) -> Result<bool, GraphError> {
        match self.storage.has_key(&format_template_name(name)) {
            Ok(value) => Ok(value),
            Err(e) => Err(GraphError::StorageError(e)),
        }
    }

    pub fn templates(&self) -> Result<Vec<(String, Template)>, GraphError> {
        let mut templates = Vec::new();

        let map: HashMap<String, Template> = match self.storage.partial_compare("template_"){
            Ok(values) => {
                let map: HashMap<String, Template> = values.into_iter()
                .map(|(key, value)| {
                    let template: Template = from_str(&value)?;
                    Ok((key, template))
                })
                .collect::<Result<HashMap<_, _>, GraphError>>()?;
            map
        },
            Err(e) => return Err(GraphError::StorageError(e)),
        };

        for (mut key, value) in map {
            key = key.trim_start_matches("template_").to_string();
            templates.push((key, value));
        }

        Ok(templates)
    }

    pub fn end_template(&mut self, name: &str) {
        self.end_templates.push(name.to_string());
    }

    pub fn is_ended(&self, name: &str) -> bool {
        self.end_templates.contains(&name.to_string())
    }

    pub fn connect(&mut self, from: &str, to: &str) -> Result<(), GraphError>{
        let mut dependents = match self.storage.read(&format_name_node(from))? {
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

        self.storage.write(&format_name_node(from), &dependents)?;
        Ok(())
    }

    /// Returns a topological ordering of the graph
    pub fn sort(&self) -> Result<Vec<String>, GraphError> {
        let mut sorted = Vec::new();
        let mut visited = HashSet::new();
        let mut temp_marked = HashSet::new();
        for (name, _) in self.storage.partial_compare("graph_")? {
            let name = name.trim_start_matches("graph_");
            if !visited.contains(name){
                self.visit(&name, &mut visited, &mut temp_marked, &mut sorted)?;
            }
        }
        sorted.reverse();  // Reverse to get the correct topological order
        
        Ok(sorted)
    }

    fn get_dependents(&self, name: &str) -> Result<Option<Vec<String>>, GraphError> {
        let dependents = match self.storage.read(&format_name_node(name))?{
            Some(dependents) => dependents,
            None => return Ok(None),
        };

        if dependents.is_empty() {
            return Ok(None);
            
        } else {
            return Ok(Some(dependents.split(",").map(|s| s.to_string()).collect()));
        }
        
    }

    fn visit(&self, name: &str, visited: &mut HashSet<String>, temp_marked: &mut HashSet<String>, sorted: &mut Vec<String>) -> Result<(), GraphError> {
        if temp_marked.contains(name) {
            return Err(GraphError::GraphCycleDetected)
        }

        if !visited.contains(name) {
            temp_marked.insert(name.to_string());
            if let Some(dependents) = self.get_dependents(name)? {
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

fn format_template_name(name: &str) -> String {
    format!("template_{}", name)
}

fn format_name_node(name: &str) -> String {
    format!("graph_{}", name)
}

