
#[derive(Debug, Clone, PartialEq)]
pub struct FragmentedSplits {
    pub fragments: Vec<(u64, u64, u64)>,
    pub current_fragment_index_start: u64,
    pub current_fragment_index_end: u64,
    pub current_start_counter: u64,
    pub max_contained_fragment: u64,
    pub min_contained_fragment: u64,
    pub is_condensed: bool,
    pub counter: u64,
}

impl FragmentedSplits {
    pub fn new(first_index: u64) -> Self {
        Self {
            fragments: Vec::new(),
            current_fragment_index_start: first_index,
            current_fragment_index_end: first_index + 1,
            current_start_counter: 0,
            max_contained_fragment: first_index,
            min_contained_fragment: first_index,
            is_condensed: true,
            counter: 0,
        }
    }
    pub fn get_max_range(&self) -> (u64, u64, u64) {
        let mut max_start = self.current_fragment_index_start;
        let mut max_end = self.current_fragment_index_end;
        let mut max_start_counter = self.current_start_counter;
        for (start, end, counter) in self.fragments.iter() {
            if *start > max_start {
                max_start = *start;
                max_end = *end;
                max_start_counter = *counter;
            }
        }
        (max_start, max_end, max_start_counter)
    }

    pub fn contains_index(&self, index: u64) -> bool {
        if index < self.current_fragment_index_end && index >= self.current_fragment_index_start {
            true
        } else {
            self.fragments
                .iter()
                .any(|(start, end, _)| index < *end && index >= *start)
        }
    }

    pub fn add_index_get_contained(&mut self, index: u64, force_condense: bool, ensure_accurate_contained: bool) -> bool {
        let result = if self.max_contained_fragment == index || self.min_contained_fragment == index {
            // already contained
            false
        }else if index == self.current_fragment_index_end {
            if index > self.max_contained_fragment {
                self.max_contained_fragment = index;
                self.current_fragment_index_end += 1;
                false
            }else {
                if force_condense && !self.is_condensed && self.fragments.len() > 0 {
                    self.finalize();
                    let contained = self.contains_index(index);
                    self.current_fragment_index_end += 1;
                    contained
                }else if ensure_accurate_contained && !self.is_condensed && self.fragments.len() > 0 {
                    let contained = self.contains_index(index);
                    self.current_fragment_index_end += 1;
                    contained
                }else {
                    self.current_fragment_index_end += 1;
                    false
                }
            }
        } else if !self.contains_index(index) {
            if index < self.min_contained_fragment {
                self.min_contained_fragment = index;
            }
            if index > self.max_contained_fragment {
                self.max_contained_fragment = index;
            }
            // gap detected, store current fragment and start a new one
            let new_fragment = (
                self.current_fragment_index_start,
                self.current_fragment_index_end,
                self.current_start_counter,
            );
            self.fragments.push(new_fragment);
            self.current_fragment_index_start = index;
            self.current_fragment_index_end = index + 1;
            false
        } else {
            // index is already contained, do nothing
            true
        };
        self.counter += 1;
        result
    }

    pub fn add_index(&mut self, index: u64) -> bool {
        self.add_index_get_contained(index, false, true)
    }

    pub fn finalize(&mut self) {
        // 1. Move the current active fragment into the main list
        self.fragments.push((
            self.current_fragment_index_start,
            self.current_fragment_index_end,
            self.current_start_counter,
        ));

        // 2. Sort fragments by start index
        self.fragments.sort_by_key(|&(start, _, _)| start);

        let mut merged: Vec<(u64, u64, u64)> = Vec::with_capacity(self.fragments.len());

        // 3. Merge overlapping or contiguous intervals
        if let Some(first) = self.fragments.first() {
            let (mut curr_start, mut curr_end, _) = *first;

            for &(next_start, next_end, _) in self.fragments.iter().skip(1) {
                // Check for overlap or contiguity.
                // Note: contiguous (curr_end == next_start) should merge.
                // Overlapping (next_start < curr_end) should merge.
                if next_start <= curr_end {
                    curr_end = curr_end.max(next_end);
                } else {
                    merged.push((curr_start, curr_end, 0));
                    curr_start = next_start;
                    curr_end = next_end;
                }
            }
            merged.push((curr_start, curr_end, 0));
        }

        // 4. Update the struct state
        // The last merged fragment becomes the new 'current',
        // everything else stays in 'fragments'.
        if let Some(last) = merged.pop() {
            self.current_fragment_index_start = last.0;
            self.current_fragment_index_end = last.1;
        } else {
            // Should theoretically not happen given the push at step 1,
            // but safe fallback logic:
            self.current_fragment_index_start = 0;
            self.current_fragment_index_end = 0;
        }

        self.is_condensed = true;
    
    }
}
