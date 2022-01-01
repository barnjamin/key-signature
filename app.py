import json
from pyteal import *
from pytealutils.strings import prefix, suffix


hash_prefix = Bytes("Program")


with open("keysig.json", "r") as f:
    key_src_map = json.loads(f.read())


def approval():
    sig_bytes = Bytes("base64", key_src_map["source"])
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
                hash_prefix, prefix(sig_bytes, key_idx), key, suffix(sig_bytes, key_idx)
            )
        )

    @Subroutine(TealType.uint64)
    def is_key():
        pay, optin, rekey = Gtxn[0], Gtxn[1], Gtxn[2]
        well_formed_txn = And(
            Global.group_size() == Int(3),
            # Seed transaction for key sig account
            pay.type_enum() == TxnType.Payment,
            pay.sender() == Global.creator_address(),
            pay.amount() == Int(int(1e6) + int(1e3)),
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

    return Cond(
        [Txn.application_id() == Int(0), Approve()],
        [Txn.on_completion() == OnComplete.DeleteApplication, Approve()],
        [Txn.on_completion() == OnComplete.UpdateApplication, Approve()],
        [Txn.on_completion() == OnComplete.CloseOut, Approve()],
        [Txn.on_completion() == OnComplete.OptIn, Return(is_key())],
        [Txn.on_completion() == OnComplete.NoOp, Approve()],
    )


def clear():
    return Approve()


if __name__ == "__main__":
    with open("approval.teal", "w") as f:
        f.write(compileTeal(approval(), mode=Mode.Application, version=5))

    with open("clear.teal", "w") as f:
        f.write(compileTeal(clear(), mode=Mode.Application, version=5))
