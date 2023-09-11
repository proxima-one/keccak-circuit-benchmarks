use std::borrow::Borrow;
use hashbrown::HashMap;
use keccak1::cross_table_lookup::cross_table_lookup_data;
use keccak1::cross_table_lookup::ctl_keccak_permutation;
use keccak1::cross_table_lookup::CrossTableLookup;
use keccak1::cross_table_lookup::CtlData;
use keccak1::cross_table_lookup::Table;
use keccak1::cross_table_lookup::TableWithColumns;
use keccak1::cross_table_lookup::NUM_TABLES;
use keccak1::keccak::keccak256;
use keccak_hash::keccak;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::iop::challenger::Challenger;
use plonky2::{plonk::config::PoseidonGoldilocksConfig};
use starky::config::StarkConfig;

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{GenericConfig};
use starky::permutation::get_permutation_challenge_set;
use std::{fs::File, io::{Write}};

fn bench_keccak_136_000() {
    std::fs::create_dir_all("bench").unwrap();
    let file_path = format!("bench/keccak_136_000.csv");
    let mut fs_results = File::create(file_path).unwrap();
    writeln!(
        fs_results,
        "{}", "message_len,"
            .to_owned() +
            "generate_sponge_proof_time," +
            "verify_sponge_proof_time," +
            "generate_permutation_proof_time," +
            "verify_permutation_proof_time," +
            "aggregation_sponge_permutations_proof_time," +
            "verify_aggregation_time," +
            "sponge_proof_size," +
            "permutations_proof_size," +
            "aggregated_proof_size," +
            "build_sponge_circuit," +
            "build_perm_circuit," +
            "aggregation_circuit_build_time"
    )
        .unwrap();

    for i in 1..=1000 {
        let output = keccak_evaluate(i);
        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            output.9,
            output.0,
            output.1,
            output.2,
            output.3,
            output.4,
            output.5,
            output.6,
            output.7,
            output.8,
            output.10,
            output.11,
            output.12
        ).unwrap();
    }
}

fn keccak_evaluate(i: usize) -> (f32, f32, f32, f32, f32, f32, usize, usize, usize, usize, f32, f32, f32) {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let msg_len: usize = 136 * i;

    let input: Vec<u8> = (0..msg_len).map(|_| rand::random()).collect();
    let expected = keccak(&input);
    let result = keccak256::<F, C, D>(&input, expected.as_bytes()).unwrap();
    let (
        _,
        _,
        generate_sponge_proof_time,
        verify_sponge_proof_time,
        generate_permutation_proof_time,
        verify_permutation_proof_time,
        aggregation_sponge_permutations_proof_time,
        verify_aggregation_time,
        sponge_proof_size,
        permutations_proof_size,
        aggregated_proof_size,
        sponge_circuit_time,
        circuit_perm_time,
        aggregation_circuit_build_time
    ) = result;
    (
        generate_sponge_proof_time,
        verify_sponge_proof_time,
        generate_permutation_proof_time,
        verify_permutation_proof_time,
        aggregation_sponge_permutations_proof_time,
        verify_aggregation_time,
        sponge_proof_size,
        permutations_proof_size,
        aggregated_proof_size,
        msg_len,
        sponge_circuit_time,
        circuit_perm_time,
        aggregation_circuit_build_time
    )
}

fn main() {
    bench_keccak_136_000()
}

pub fn get_ctl_data<F, C, const D: usize>(
    config: StarkConfig,
    poly_values: &[Vec<PolynomialValues<F>>; NUM_TABLES],
)
    -> [CtlData<F>; NUM_TABLES]
    where F: RichField + Extendable<D>, C: GenericConfig<D, F=F>
{
    let mut ctl: Vec<CrossTableLookup<F>> = Vec::new();
    ctl.push(ctl_keccak_permutation());

    let num_challenges = config.num_challenges;

    let mut challenger = Challenger::<F, C::Hasher>::new();

    let ctl_challenger = get_permutation_challenge_set(&mut challenger, num_challenges);

    cross_table_lookup_data::<F, D>(poly_values, &ctl, &ctl_challenger)
}

fn check_ctl<F: Field>(
    trace_poly_values: &[Vec<PolynomialValues<F>>],
    ctl: &CrossTableLookup<F>,
    ctl_index: usize,
) {
    let CrossTableLookup { looking_tables, looked_table } = ctl;

    // Maps `m` with `(table, i) in m[row]` iff the `i`-th row of `table` is equal to `row` and
    // the filter is 1. Without default values, the CTL check holds iff `looking_multiset == looked_multiset`.
    let mut looking_multiset = MultiSet::<F>::new();
    let mut looked_multiset = MultiSet::<F>::new();

    for table in looking_tables {
        process_table(trace_poly_values, table, &mut looking_multiset);
    }
    process_table(trace_poly_values, looked_table, &mut looked_multiset);

    let empty = &vec![];
    // Check that every row in the looking tables appears in the looked table the same number of times.
    for (row, looking_locations) in &looking_multiset {
        let looked_locations = looked_multiset.get(row).unwrap_or(empty);
        check_locations(looking_locations, looked_locations, ctl_index, row);
    }
    // Check that every row in the looked tables appears in the looked table the same number of times.
    for (row, looked_locations) in &looked_multiset {
        let looking_locations = looking_multiset.get(row).unwrap_or(empty);
        check_locations(looking_locations, looked_locations, ctl_index, row);
    }
}

type MultiSet<F> = HashMap<Vec<F>, Vec<(Table, usize)>>;

pub fn process_table<F: Field>(
    trace_poly_values: &[Vec<PolynomialValues<F>>],
    table: &TableWithColumns<F>,
    multiset: &mut MultiSet<F>,
) {
    let trace = &trace_poly_values[table.table as usize];
    for i in 0..trace[0].len() {
        let filter = if let Some(column) = &table.filter_column {
            column.eval_table(trace, i)
        } else {
            F::ONE
        };
        if filter.is_one() {
            let row = table.columns
                .iter()
                .map(|c| c.eval_table(trace, i))
                .collect::<Vec<_>>();
            multiset.entry(row).or_default().push((table.table, i));
        } else {
            assert_eq!(filter, F::ZERO, "Non-binary filter?");
        }
    }
}

pub fn check_locations<F: Field>(
    looking_locations: &[(Table, usize)],
    looked_locations: &[(Table, usize)],
    ctl_index: usize,
    row: &[F],
) {
    if looking_locations.len() != looked_locations.len() {
        panic!(
            "CTL #{ctl_index}:\n\
             Row {row:?} is present {l0} times in the looking tables, but {l1} times in the looked table.\n\
             Looking locations (Table, Row index): {looking_locations:?}.\n\
             Looked locations (Table, Row index): {looked_locations:?}.",
            l0 = looking_locations.len(),
            l1 = looked_locations.len()
        );
    }
}
