import base64
import random
import json

from algosdk.v2client import algod
from algosdk.encoding import msgpack_encode
from algosdk.future.transaction import *

from sandbox import get_accounts

from app import get_approval_src, get_clear_src, seed_amt

token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
url = "http://localhost:4001"

client = algod.AlgodClient(token, url)


class KeySig:
    def __init__(self, name):
        # Read the source map
        with open("{}.json".format(name)) as f:
            self.map = json.loads(f.read())

    def populate(self, value: str) -> LogicSigAccount:
        # Get the template source
        src = list(base64.b64decode(self.map["bytecode"]))
        # Get the position of TMPL_KEY in the assembled bytecode
        pos = self.map["template_labels"]["TMPL_KEY"]["position"]
        # Inject the length prefixed bytestring to the bytecode, account for current 0 value with pos + 1
        src = src[:pos] + [len(value), *list(value.encode())] + src[pos + 1 :]
        # Create a new LogicSigAccount given the populated bytecode
        return LogicSigAccount(bytes(src))


def main(keysig="keysig", app_id=None):
    # Get Account from sandbox
    addr, sk = get_accounts()[0]
    print("Using {}".format(addr))

    # Initialize keysig obj with the mapping we generated
    ksig = KeySig(keysig)

    # Create app if needed
    if app_id is None:
        app_id = create_app(addr, sk, ksig.map)
        print("Created app: {}".format(app_id))

    # No need for this when you're not debugging
    update_app(app_id, addr, sk, ksig.map)
    print("Updated app: {}".format(app_id))

    # Get the app address, we'll need this for rekey txn
    app_addr = logic.get_application_address(app_id)
    print("Application Address {}".format(app_addr))

    # Get some keys

    keys = get_random_keys(2)
    for key in keys:
        lsa = ksig.populate(key)
        sig_addr = lsa.address()
        print("Creating key {} with addres {}".format(key, sig_addr))

        # Create new key
        sp = client.suggested_params()

        seed_txn = PaymentTxn(addr, sp, sig_addr, seed_amt)
        optin_txn = ApplicationOptInTxn(sig_addr, sp, app_id, [key])
        rekey_txn = PaymentTxn(sig_addr, sp, sig_addr, 0, None, None, None, app_addr)

        assign_group_id([seed_txn, optin_txn, rekey_txn])

        signed_seed = seed_txn.sign(sk)
        signed_optin = LogicSigTransaction(optin_txn, lsa)
        signed_rekey = LogicSigTransaction(rekey_txn, lsa)

        send("create", [signed_seed, signed_optin, signed_rekey])

    for key in keys:
        lsa = ksig.populate(key)
        sig_addr = lsa.address()
        print("Deleting key {} with addresss {}".format(key, sig_addr))

        sp = client.suggested_params()

        rekey_txn = ApplicationNoOpTxn(addr, sp, app_id, [key], [sig_addr])
        closeout_txn = ApplicationCloseOutTxn(sig_addr, sp, app_id)
        closeto_txn = PaymentTxn(sig_addr, sp, addr, 0, addr)

        assign_group_id([rekey_txn, closeout_txn, closeto_txn])

        signed_rekey = rekey_txn.sign(sk)
        signed_closeout = LogicSigTransaction(closeout_txn, lsa)
        signed_closeto = LogicSigTransaction(closeto_txn, lsa)

        send("delete", [signed_rekey, signed_closeout, signed_closeto])


def update_app(id, addr, sk, source_map):
    # Read in approval teal source && compile
    app_result = client.compile(get_approval_src(source_map))
    app_bytes = base64.b64decode(app_result["result"])

    # Read in clear teal source && compile
    clear_result = client.compile(get_clear_src())
    clear_bytes = base64.b64decode(clear_result["result"])

    # Get suggested params from network
    sp = client.suggested_params()
    # Create the transaction
    update_txn = ApplicationUpdateTxn(addr, sp, id, app_bytes, clear_bytes)

    # Sign it
    signed_txn = update_txn.sign(sk)

    # Ship it
    txid = client.send_transaction(signed_txn)

    # Wait for the result so we can return the app id
    return wait_for_confirmation(client, txid, 4)


def create_app(addr, sk, source_map):
    # Read in approval teal source && compile
    app_result = client.compile(get_approval_src(source_map))
    app_bytes = base64.b64decode(app_result["result"])

    # Read in clear teal source && compile
    clear_result = client.compile(get_clear_src())
    clear_bytes = base64.b64decode(clear_result["result"])

    # No schema for global
    gschema = StateSchema(0, 0)
    # Max byte storage for local
    lschema = StateSchema(0, 16)

    # Get suggested params from network
    sp = client.suggested_params()
    # Create the transaction
    create_txn = ApplicationCreateTxn(
        addr, sp, 0, app_bytes, clear_bytes, gschema, lschema
    )

    # Sign it
    signed_txn = create_txn.sign(sk)

    # Ship it
    txid = client.send_transaction(signed_txn)

    # Wait for the result so we can return the app id
    result = wait_for_confirmation(client, txid, 4)

    app_id = result["application-index"]

    app_addr = logic.get_application_address(app_id)

    # Fund the app addr
    sp = client.suggested_params()
    pay_txn = PaymentTxn(addr, sp, app_addr, int(1e10))
    txid = client.send_transaction(pay_txn.sign(sk))
    wait_for_confirmation(client, txid, 4)

    return app_id


def send(name, signed_group, debug=False):
    print("Sending Transaction for {}".format(name))

    if debug:
        with open(name + ".msgp", "wb") as f:
            f.write(
                base64.b64decode(msgpack_encode(create_dryrun(client, signed_group)))
            )
        with open(name + ".txns", "wb") as f:
            for tx in signed_group:
                f.write(base64.b64decode(msgpack_encode(tx)))

    txids = [tx.get_txid() for tx in signed_group]
    txid = client.send_transactions(signed_group)
    wait_for_confirmation(client, txid, 4)

    if debug:
        for txid in txids:
            print(wait_for_confirmation(client, txid, 4))


def get_random_keys(num: int):
    import random
    import string
    import time

    random.seed(int(time.time()))
    keys = []
    for _ in range(num):
        # printing lowercase
        letters = string.ascii_lowercase
        keys.append("".join(random.choice(letters) for i in range(10)))

    return keys


if __name__ == "__main__":
    main()
