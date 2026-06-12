use std::{collections::HashMap, fmt::Debug, hash::Hash};

use indexmap::IndexSet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BidirectionalGraph<T: Eq + Hash + Debug> {
    edges: HashMap<T, IndexSet<T>>,
    reverse_edges: HashMap<T, IndexSet<T>>,
}

impl<T: Eq + Hash + Clone + Debug> BidirectionalGraph<T> {
    pub fn new() -> Self {
        BidirectionalGraph {
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.edges.clear();
        self.reverse_edges.clear();
    }

    pub fn add_edge(&mut self, from: T, to: T) {
        if from == to {
            self.add_node(from);
            return;
        }
        self.edges.entry(from.clone()).or_default().insert(to.clone());
        self.reverse_edges.entry(to).or_default().insert(from);
    }

    pub fn add_node(&mut self, node: T) {
        self.edges.entry(node.clone()).or_default();
        self.reverse_edges.entry(node).or_default();
    }

    pub fn has_node(&self, node: &T) -> bool {
        self.edges.contains_key(node) || self.reverse_edges.contains_key(node)
    }

    pub fn get_dependencies(&self, node: &T) -> Option<&IndexSet<T>> {
        self.edges.get(node)
    }

    pub fn get_dependents(&self, node: &T) -> Option<&IndexSet<T>> {
        self.reverse_edges.get(node)
    }

    pub fn ts_order(&self) -> Vec<Vec<T>> {
        let mut all_nodes: std::collections::HashSet<T> = std::collections::HashSet::new();
        for node in self.edges.keys() {
            all_nodes.insert(node.clone());
        }
        for node in self.reverse_edges.keys() {
            all_nodes.insert(node.clone());
        }

        if all_nodes.is_empty() {
            return Vec::new();
        }

        let total_nodes = all_nodes.len();
        let mut processed_nodes = 0;
        let mut remaining: Vec<T> = all_nodes.into_iter().collect();
        let mut solved: std::collections::HashSet<T> = std::collections::HashSet::new();
        let mut levels = Vec::new();

        while processed_nodes < total_nodes {
            let mut new_remaining = Vec::new();
            let mut level = Vec::new();

            for node in remaining {
                let dependencies = self.edges.get(&node);
                let all_deps_solved = match dependencies {
                    None => true,
                    Some(deps) => deps.iter().all(|dep| solved.contains(dep)),
                };

                if all_deps_solved {
                    level.push(node.clone());
                    processed_nodes += 1;
                } else {
                    new_remaining.push(node);
                }
            }

            for node in level.iter() {
                solved.insert(node.clone());
            }

            remaining = new_remaining;

            if level.is_empty() {
                break;
            }

            levels.push(level);
        }

        levels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_graph() {
        let graph: BidirectionalGraph<i32> = BidirectionalGraph::new();
        let result = graph.ts_order();
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_node() {
        let mut graph = BidirectionalGraph::new();
        graph.add_node(1);
        let result = graph.ts_order();
        assert_eq!(result, vec![vec![1]]);
    }

    #[test]
    fn test_simple_dependency() {
        let mut graph = BidirectionalGraph::new();
        // A depends on B: A -> B
        graph.add_edge(1, 2); // 1 depends on 2
        let result = graph.ts_order();
        assert_eq!(result, vec![vec![2], vec![1]]);
    }

    #[test]
    fn test_multiple_dependencies() {
        let mut graph = BidirectionalGraph::new();
        // A depends on B and C: A -> B, A -> C
        // D depends on B: D -> B
        graph.add_edge(1, 2); // A depends on B
        graph.add_edge(1, 3); // A depends on C
        graph.add_edge(4, 2); // D depends on B

        let result = graph.ts_order();

        // First level should be B(2) and C(3) - no dependencies
        assert_eq!(result.len(), 2);
        let mut first_level = result[0].clone();
        first_level.sort();
        assert_eq!(first_level, vec![2, 3]);

        // Second level should be A(1) and D(4)
        let mut second_level = result[1].clone();
        second_level.sort();
        assert_eq!(second_level, vec![1, 4]);
    }

    #[test]
    fn test_chain_dependency() {
        let mut graph = BidirectionalGraph::new();
        // Chain: A -> B -> C -> D
        graph.add_edge(1, 2); // A depends on B
        graph.add_edge(2, 3); // B depends on C
        graph.add_edge(3, 4); // C depends on D

        let result = graph.ts_order();
        assert_eq!(
            result,
            vec![
                vec![4], // D first
                vec![3], // then C
                vec![2], // then B
                vec![1]  // finally A
            ]
        );
    }

    #[test]
    fn test_no_dependencies() {
        let mut graph = BidirectionalGraph::new();
        graph.add_node(1);
        graph.add_node(2);
        graph.add_node(3);

        let result = graph.ts_order();
        assert_eq!(result.len(), 1);
        let mut first_level = result[0].clone();
        first_level.sort();
        assert_eq!(first_level, vec![1, 2, 3]);
    }

    #[test]
    fn test_cycle_handling() {
        let mut graph = BidirectionalGraph::new();
        // Create a cycle: A -> B -> C -> A
        graph.add_edge(1, 2); // A depends on B
        graph.add_edge(2, 3); // B depends on C
        graph.add_edge(3, 1); // C depends on A (cycle!)

        // Add an independent node
        graph.add_node(4);

        let result = graph.ts_order();

        // Should only process the independent node
        // The cycle should be gracefully ignored
        assert_eq!(result, vec![vec![4]]);
    }

    #[test]
    fn test_partial_cycle() {
        let mut graph = BidirectionalGraph::new();
        // A -> B (no cycle)
        // C -> D -> C (cycle)
        graph.add_edge(1, 2); // A depends on B
        graph.add_edge(3, 4); // C depends on D
        graph.add_edge(4, 3); // D depends on C (cycle!)

        let result = graph.ts_order();

        // Should process A and B, ignore the C-D cycle
        assert_eq!(result, vec![vec![2], vec![1]]);
    }

    #[test]
    fn test_complex_graph() {
        let mut graph = BidirectionalGraph::new();

        // Complex dependency structure:
        // E has no deps (level 0)
        // D depends on E (level 1)
        // B depends on E (level 1)
        // C depends on D, E (level 2)
        // A depends on B, C (level 3)

        graph.add_edge(1, 2); // A depends on B
        graph.add_edge(1, 3); // A depends on C
        graph.add_edge(2, 5); // B depends on E
        graph.add_edge(3, 4); // C depends on D
        graph.add_edge(3, 5); // C depends on E
        graph.add_edge(4, 5); // D depends on E

        let result = graph.ts_order();

        assert_eq!(result.len(), 4);

        // Level 0: E
        assert_eq!(result[0], vec![5]);

        // Level 1: B, D (both depend only on E)
        let mut level1 = result[1].clone();
        level1.sort();
        assert_eq!(level1, vec![2, 4]);

        // Level 2: C (depends on D and E)
        assert_eq!(result[2], vec![3]);

        // Level 3: A (depends on B and C)
        assert_eq!(result[3], vec![1]);
    }

    #[test]
    fn test_self_dependency() {
        let mut graph = BidirectionalGraph::new();
        // A depends on itself - but add_edge(1,1) actually just adds node 1 without
        // self-loop
        graph.add_edge(1, 1);

        let result = graph.ts_order();

        // Self-dependency gets converted to just adding the node (no actual self-loop)
        // So node 1 has no dependencies and can be processed normally
        assert_eq!(result, vec![vec![1]]);
    }

    #[test]
    fn test_mixed_nodes_and_edges() {
        let mut graph = BidirectionalGraph::new();

        // Add some isolated nodes
        graph.add_node(10);
        graph.add_node(20);

        // Add some connected nodes
        graph.add_edge(1, 2); // 1 depends on 2

        let result = graph.ts_order();

        assert_eq!(result.len(), 2);

        // First level should have independent nodes: 2, 10, 20
        let mut level0 = result[0].clone();
        level0.sort();
        assert_eq!(level0, vec![2, 10, 20]);

        // Second level should have dependent node: 1
        assert_eq!(result[1], vec![1]);
    }
}
