use std::sync::Arc;
#[auto_impl::auto_impl(&, Arc)]
pub trait GCounterReader {
    fn get_counter_value(&self) -> u64;
}

pub struct ExampleCounter {
    value: u64,
}
impl ExampleCounter {
    pub fn new() -> Self {
        Self { value: 0 }
    }
    pub fn increment(&mut self, amount: u64) {
        self.value += amount;
    }
}
impl GCounterReader for ExampleCounter {
    fn get_counter_value(&self) -> u64 {
        self.value
    }
}

pub struct ExampleOddCounter {
    value: u64,
}
impl ExampleOddCounter {
    pub fn new() -> Self {
        Self { value: 1 }
    }
    pub fn increment(&mut self, amount: u64) {
        self.value += amount * 2;
    }
}
impl GCounterReader for ExampleOddCounter {
    fn get_counter_value(&self) -> u64 {
        self.value
    }
}

pub struct MultiCounter<C1: GCounterReader, C2: GCounterReader> {
    counter1: Arc<C1>,
    counter2: Arc<C2>,
}

fn get_counter_value_times_two<C: GCounterReader>(counter: &C) -> u64 {
    counter.get_counter_value() * 2
}

impl<C1: GCounterReader, C2: GCounterReader> MultiCounter<C1, C2> {
    pub fn new(counter1: Arc<C1>, counter2: Arc<C2>) -> Self {
        Self { counter1, counter2 }
    }

    pub fn total_value(&self) -> u64 {
        self.counter1.get_counter_value() + self.counter2.get_counter_value()
    }
    pub fn total_value_times_two(&self) -> u64 {
        get_counter_value_times_two(&self.counter1) + get_counter_value_times_two(&self.counter2)
    }
}

#[test]
#[ignore = "database slow"]
fn run_test(){
    let mut counter_a = ExampleCounter::new();
    let mut counter_b = ExampleOddCounter::new();
    counter_a.increment(3); // 3
    counter_b.increment(3); // 7
    assert_eq!(counter_a.get_counter_value(), 3);
    assert_eq!(counter_b.get_counter_value(), 7);
    let multi_counter = MultiCounter::new(Arc::new(counter_a), Arc::new(counter_b));
    assert_eq!(multi_counter.total_value(), 10);
    assert_eq!(multi_counter.total_value_times_two(), 20);
}