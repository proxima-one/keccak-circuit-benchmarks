use std::borrow::{Borrow, BorrowMut};
use std::mem::{size_of, transmute};

use starky_ctl::util::{indices_arr, transmute_no_compile_time_size_checks};

pub const XOR_BLOCK_SIZE: usize = 32;

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct XORColumnsView<T: Copy> {
    pub is_valid: T,
    pub op0: [T; XOR_BLOCK_SIZE],
    pub op1: [T; XOR_BLOCK_SIZE],
    pub res: [T; XOR_BLOCK_SIZE],
}

pub const NUM_XOR_COLUMNS: usize = size_of::<XORColumnsView<u8>>();

impl<T: Copy> From<[T; NUM_XOR_COLUMNS]> for XORColumnsView<T> {
    fn from(value: [T; NUM_XOR_COLUMNS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<XORColumnsView<T>> for [T; NUM_XOR_COLUMNS] {
    fn from(value: XORColumnsView<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<XORColumnsView<T>> for [T; NUM_XOR_COLUMNS] {
    fn borrow(&self) -> &XORColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<XORColumnsView<T>> for [T; NUM_XOR_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut XORColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; NUM_XOR_COLUMNS]> for XORColumnsView<T> {
    fn borrow(&self) -> &[T; NUM_XOR_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; NUM_XOR_COLUMNS]> for XORColumnsView<T> {
    fn borrow_mut(&mut self) -> &mut [T; NUM_XOR_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy + Default> Default for XORColumnsView<T> {
    fn default() -> Self {
        [T::default(); NUM_XOR_COLUMNS].into()
    }
}

const fn make_col_map() -> XORColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_XOR_COLUMNS>();
    let col_view =
        unsafe { transmute::<[usize; NUM_XOR_COLUMNS], XORColumnsView<usize>>(indices_arr) };
    col_view
}

pub const KECCAK_XOR_COL_MAP: XORColumnsView<usize> = make_col_map();
