import json
from pyteal import *
from pyteal.ast.itxn import InnerTxnActionExpr
from pytealutils.strings import prefix, suffix
from pytealutils.strings.string import encode_uvarint


hash_prefix = Bytes("Program")
seed_amt = int(1e6) + int(5e3)


def approval(key_src_map):
    sig_bytes = Bytes("base64", key_src_map["bytecode"])
    key_idx = Int(key_src_map["template_labels"]["TMPL_KEY"]["position"])

    @Subroutine(TealType.bytes)
    def key_address(key: TealType.bytes):
        """key_address returns the address for a logic sig
            where the key template variable `key` is populated
            and the resulting bytecode is hashed

        Args:
            key: The byte string to make this key unique
        """
        return Sha512_256(
            Concat(
                hash_prefix,
                prefix(sig_bytes, key_idx),
                encode_uvarint(Len(key), Bytes("")),
                key,
                suffix(sig_bytes, Len(sig_bytes) - key_idx - Int(1)),
            )
        )

    @Subroutine(TealType.uint64)
    def create_key():
        pay, optin, rekey = Gtxn[0], Gtxn[1], Gtxn[2]
        well_formed_txn = And(
            Global.group_size() == Int(3),
            # Seed transaction for key sig account
            pay.type_enum() == TxnType.Payment,
            pay.sender() == Global.creator_address(),
            pay.amount() == Int(seed_amt),
            # Opt key sig account into
            optin.type_enum() == TxnType.ApplicationCall,
            optin.application_id() == Global.current_application_id(),
            # Rekey key sig to app addr
            rekey.type_enum() == TxnType.Payment,
            rekey.amount() == Int(0),
            rekey.rekey_to() == Global.current_application_address(),
            rekey.close_remainder_to() == Global.zero_address(),
            # Make sure sender/receivers match
            pay.receiver() == optin.sender(),
            rekey.sender() == optin.sender(),
        )

        key = optin.application_args[0]
        return Seq(
            Assert(well_formed_txn),
            key_address(key) == optin.sender(),
        )

    def delete_key():
        rekey_trigger, close_out, close_to = Gtxn[0], Gtxn[1], Gtxn[2]
        well_formed_txn = And(
            Global.group_size() == Int(3),
            # Trigger rekey back to key sig
            rekey_trigger.type_enum() == TxnType.ApplicationCall,
            rekey_trigger.application_id() == Global.current_application_id(),
            rekey_trigger.sender() == Global.creator_address(),
            # Close key sig out of app
            close_out.type_enum() == TxnType.ApplicationCall,
            close_out.application_id() == Global.current_application_id(),
            # send key sig funds to app creator
            close_to.type_enum() == TxnType.Payment,
            close_to.amount() == Int(0),
            close_to.close_remainder_to() == Global.creator_address(),
            close_to.rekey_to() == Global.zero_address(),
            close_out.sender() == close_to.sender(),
            close_to.receiver() == rekey_trigger.sender(),
        )

        key = rekey_trigger.application_args[0]
        return Seq(
            # Check the txn is valid
            Assert(well_formed_txn),
            # Make sure we're rekeying the right key
            Assert(key_address(key) == close_to.sender()),
            # Submit rekey back to original addr
            InnerTxnBuilder.Begin(),
            InnerTxnBuilder.SetFields(
                {
                    TxnField.type_enum: TxnType.Payment,
                    TxnField.amount: Int(0),
                    TxnField.sender: rekey_trigger.accounts[1],
                    TxnField.rekey_to: rekey_trigger.accounts[1],
                }
            ),
            InnerTxnBuilder.Submit(),
            Int(1),
        )

    return Cond(
        [Txn.application_id() == Int(0), Approve()],
        [Txn.on_completion() == OnComplete.DeleteApplication, Approve()],
        [Txn.on_completion() == OnComplete.UpdateApplication, Approve()],
        [Txn.on_completion() == OnComplete.CloseOut, Approve()],
        [Txn.on_completion() == OnComplete.OptIn, Return(create_key())],
        [Txn.on_completion() == OnComplete.NoOp, Return(delete_key())],
    )


def clear():
    return Approve()


def get_approval_src(key_src_map):
    return compileTeal(
        approval(key_src_map), mode=Mode.Application, version=6, assembleConstants=True
    )


def get_clear_src():
    return compileTeal(
        clear(), mode=Mode.Application, version=6, assembleConstants=True
    )


if __name__ == "__main__":
    with open("keysig.json", "r") as f:
        key_src_map = json.loads(f.read())

    print(key_src_map)
    with open("approval.teal", "w") as f:
        f.write(get_approval_src(key_src_map))

    with open("clear.teal", "w") as f:
        f.write(get_clear_src())
