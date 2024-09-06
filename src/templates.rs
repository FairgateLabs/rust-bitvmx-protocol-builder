use std::collections::{hash_map::{Values, ValuesMut}, HashMap};

use crate::template::Template;

pub struct Templates {
    templates: HashMap<String, Template>
}

impl Default for Templates {
    fn default() -> Self {
        Self::new()
    }
}

impl Templates {
    pub fn new() -> Self {
        Templates {
            templates: HashMap::new()
        }
    }

    pub fn add_template(&mut self, name: &str, template: Template) {
        self.templates.insert(name.to_string(), template);
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
}
