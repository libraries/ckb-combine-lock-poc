use crate::hash::{blake160, hash};
use crate::{generate_sighash_all, read_tx_template, MockTransaction, ReprMockTransaction};
use ckb_combine_lock_types::combine_lock::{
    ChildScript, ChildScriptArray, ChildScriptConfig, ChildScriptConfigOpt, ChildScriptVec,
    ChildScriptVecVec, CombineLockWitness, Uint16,
};
use ckb_crypto::secp::Privkey;
use ckb_debugger_api::get_script_hash_by_index;
use ckb_script::ScriptGroupType;
use ckb_types::core::{Cycle, ScriptHashType};
use ckb_types::packed::{Byte32, BytesVec, WitnessArgs};
use ckb_types::prelude::Pack;
use ckb_types::H256;
use molecule::prelude::{Builder, Entity};

const G_PRIVKEY_BUF: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

fn debug_printer(_: &Byte32, data: &str) {
    println!("{}", data);
}

fn debug_run(
    repr_tx: ReprMockTransaction,
    script_group_type: ScriptGroupType,
    cell_type: &str,
    cell_index: usize,
) -> Result<Cycle, String> {
    let tx: MockTransaction = repr_tx.into();
    ckb_debugger_api::run(
        &tx,
        &script_group_type,
        &get_script_hash_by_index(&tx, &script_group_type, cell_type, cell_index),
        70000000,
        Some(Box::new(debug_printer)),
    )
}

#[test]
fn test_cl_child_script() {
    let mut repr_tx = read_tx_template("templates/cl-child-script.json").unwrap();

    let child_script_private_key = Privkey::from(H256::from(G_PRIVKEY_BUF));
    let child_script_pubkey = child_script_private_key.pubkey().expect("pubkey");
    let child_script_pubkey_hash = blake160(&child_script_pubkey.serialize());
    let mut auth = vec![0u8; 21];
    auth[0] = 0; // CKB
    auth[1..].copy_from_slice(&child_script_pubkey_hash);

    let chile_script_data = repr_tx.mock_info.cell_deps[1].data.as_bytes();
    let child_script_code_hash = hash(chile_script_data);
    let child_script = ChildScript::new_builder()
        .code_hash(Byte32::from_slice(&child_script_code_hash).unwrap())
        .hash_type(ScriptHashType::Data1.into())
        .args(auth.as_slice().pack())
        .build();
    let child_script_array = ChildScriptArray::new_builder().push(child_script).build();
    let child_script_vec = ChildScriptVec::new_builder().push(0.into()).build();
    let child_script_vec_vec = ChildScriptVecVec::new_builder()
        .push(child_script_vec)
        .build();
    let child_script_config = ChildScriptConfig::new_builder()
        .array(child_script_array)
        .index(child_script_vec_vec)
        .build();

    let mut args = vec![];
    args.extend(hash(child_script_config.as_slice()));
    repr_tx.mock_info.inputs[0].output.lock.args = ckb_jsonrpc_types::JsonBytes::from_vec(args);

    let child_script_config_opt = ChildScriptConfigOpt::new_builder()
        .set(Some(child_script_config))
        .build();

    let inner_witness = BytesVec::new_builder().push(vec![0u8; 65].pack()).build();
    let combine_lock_witness = CombineLockWitness::new_builder()
        .index(Uint16::new_unchecked(0u16.to_le_bytes().to_vec().into()))
        .inner_witness(inner_witness)
        .script_config(child_script_config_opt.clone())
        .build();

    let witness_args = WitnessArgs::new_builder()
        .lock(Some(combine_lock_witness.as_bytes()).pack())
        .build();
    repr_tx.tx.witnesses[0] = ckb_jsonrpc_types::JsonBytes::from(witness_args.as_bytes().pack());

    let message = generate_sighash_all(&repr_tx, 0).unwrap();
    let sig = child_script_private_key
        .sign_recoverable(&H256::from(message))
        .expect("sign")
        .serialize();
    let inner_witness = BytesVec::new_builder().push(sig.pack()).build();
    let combine_lock_witness = CombineLockWitness::new_builder()
        .index(Uint16::new_unchecked(0u16.to_le_bytes().to_vec().into()))
        .inner_witness(inner_witness)
        .script_config(child_script_config_opt)
        .build();

    let witness_args = WitnessArgs::new_builder()
        .lock(Some(combine_lock_witness.as_bytes()).pack())
        .build();
    repr_tx.tx.witnesses[0] = ckb_jsonrpc_types::JsonBytes::from(witness_args.as_bytes().pack());

    let result = debug_run(repr_tx, ScriptGroupType::Lock, "input", 0);
    assert!(result.is_ok(), "{:?}", result);
}
