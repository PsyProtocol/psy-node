use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TreePosition {
    pub level: u64,
    pub index: u64,
}
impl TreePosition {
    pub fn new(level: u64, index: u64) -> Self {
        Self { level, index }
    }
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }
    pub fn get_left_child(&self) -> TreePosition {
        TreePosition::new(self.level - 1, self.index * 2)
    }
    pub fn get_right_child(&self) -> TreePosition {
        TreePosition::new(self.level - 1, self.index * 2 + 1)
    }
    pub fn get_parent(&self) -> TreePosition {
        TreePosition::new(self.level + 1, self.index >> 1)
    }
    pub fn get_span(&self) -> u64 {
        1 << self.level
    }
    pub fn is_null(&self) -> bool {
        self.level == 0xffffu64
    }
    pub fn new_null() -> Self {
        Self {
            level: 0xffffu64,
            index: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryTreeJob {
    pub position: TreePosition,
    pub left_job: TreePosition,
    pub right_job: TreePosition,
}
pub fn gen_leaves_binary_tree_planner(n: usize) -> Vec<BinaryTreeJob> {
    let mut output = Vec::with_capacity(n);
    for i in 0..n {
        output.push(BinaryTreeJob {
            position: TreePosition::new(0, i as u64),
            left_job: TreePosition::new_null(),
            right_job: TreePosition::new_null(),
        });
    }
    output
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryTreePlanner {
    pub levels: Vec<Vec<BinaryTreeJob>>,
    pub num_leaves: usize,
}
impl BinaryTreePlanner {
    pub fn new(num_leaves: usize) -> Self {
        let mut current = gen_leaves_binary_tree_planner(num_leaves);
        let mut level_index = 1u64;
        let mut levels: Vec<Vec<BinaryTreeJob>> = Vec::new();
        while current.len() > 1 {
            let mut next_level: Vec<BinaryTreeJob> = Vec::new();
            for i in 0..(current.len() / 2) {
                next_level.push(BinaryTreeJob {
                    position: TreePosition::new(level_index, i as u64),
                    left_job: current[i * 2].position,
                    right_job: current[i * 2 + 1].position,
                });
            }
            let mut n_current = next_level.clone();
            levels.push(next_level);

            if current.len() % 2 == 1 {
                n_current.push(current[current.len() - 1]);
            }
            current = n_current;
            level_index += 1;
        }

        Self { levels, num_leaves }
    }
    pub fn get_graphviz(&self) -> String {
        let mut output = String::new();
        output.push_str("digraph G {\n");
        for level in self.levels.iter() {
            for job in level.iter() {
                output.push_str(&format!(
                    "\"{}:{}\" -> \"{}:{}\";\n",
                    job.position.level, job.position.index, job.left_job.level, job.left_job.index
                ));
                output.push_str(&format!(
                    "\"{}:{}\" -> \"{}:{}\";\n",
                    job.position.level,
                    job.position.index,
                    job.right_job.level,
                    job.right_job.index
                ));
            }
        }
        output.push_str("}\n");
        output
    }
}

#[cfg(test)]
mod tests {
    use super::{gen_leaves_binary_tree_planner, BinaryTreePlanner, TreePosition};

    #[test]
    fn tree_position_navigation_and_sentinels() {
        let position = TreePosition::new(3, 5);

        assert!(!position.is_leaf());
        assert_eq!(position.get_span(), 8);
        assert_eq!(position.get_left_child(), TreePosition::new(2, 10));
        assert_eq!(position.get_right_child(), TreePosition::new(2, 11));
        assert_eq!(position.get_parent(), TreePosition::new(4, 2));

        let leaf = TreePosition::new(0, 7);
        assert!(leaf.is_leaf());
        assert_eq!(leaf.get_span(), 1);

        let null = TreePosition::new_null();
        assert!(null.is_null());
        assert!(!position.is_null());
    }

    #[test]
    fn leaf_jobs_have_null_dependencies() {
        let leaves = gen_leaves_binary_tree_planner(3);

        assert_eq!(leaves.len(), 3);
        for (index, job) in leaves.iter().enumerate() {
            assert_eq!(job.position, TreePosition::new(0, index as u64));
            assert!(job.left_job.is_null());
            assert!(job.right_job.is_null());
        }
        assert!(gen_leaves_binary_tree_planner(0).is_empty());
    }

    #[test]
    fn planner_handles_empty_single_even_and_odd_leaf_counts() {
        assert!(BinaryTreePlanner::new(0).levels.is_empty());
        assert!(BinaryTreePlanner::new(1).levels.is_empty());

        let even = BinaryTreePlanner::new(4);
        assert_eq!(even.levels.iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 1]);
        assert_eq!(even.levels[1][0].left_job, TreePosition::new(1, 0));
        assert_eq!(even.levels[1][0].right_job, TreePosition::new(1, 1));

        let odd = BinaryTreePlanner::new(5);
        assert_eq!(odd.levels.iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 1, 1]);
        assert_eq!(odd.levels[1][0].left_job, TreePosition::new(1, 0));
        assert_eq!(odd.levels[1][0].right_job, TreePosition::new(1, 1));
        assert_eq!(odd.levels[2][0].left_job, TreePosition::new(2, 0));
        assert_eq!(odd.levels[2][0].right_job, TreePosition::new(0, 4));
    }

    #[test]
    fn graphviz_and_json_are_stable_and_round_trip() {
        let planner = BinaryTreePlanner::new(3);
        let graphviz = planner.get_graphviz();
        assert_eq!(
            graphviz,
            "digraph G {\n\"1:0\" -> \"0:0\";\n\"1:0\" -> \"0:1\";\n\"2:0\" -> \"1:0\";\n\"2:0\" -> \"0:2\";\n}\n"
        );

        let json = serde_json::to_string(&planner).unwrap();
        let decoded: BinaryTreePlanner = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, planner);
    }
}
