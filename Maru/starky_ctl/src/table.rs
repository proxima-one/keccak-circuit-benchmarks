#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Table {
    KeccakPermutation = 0,
    KeccakSponge = 1,
    KeccakXor = 2,
}

pub const NUM_TABLES: usize = Table::KeccakXor as usize + 1;

impl Table {
    pub fn all() -> [Self; NUM_TABLES] {
        [Self::KeccakPermutation, Self::KeccakSponge, Self::KeccakXor]
    }
}
