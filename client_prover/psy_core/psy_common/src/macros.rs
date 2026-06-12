#[macro_export]
macro_rules! hashmap {
    () => {
        ::std::collections::IndexMap::new()
    };
    ($($key:expr => $value:expr),* $(,)?) => {
        {
            let mut map = ::std::collections::IndexMap::new();
            $(map.insert($key, $value);)*
            map
        }
    };
}
