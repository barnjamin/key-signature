from pyteal import *


def keysig():
    return Seq(Pop(Tmpl.Bytes("TMPL_KEY")), Int(1))


if __name__ == "__main__":
    with open("keysig.tmpl.teal", "w") as f:
        f.write(
            compileTeal(
                keysig(), mode=Mode.Signature, version=6, assembleConstants=True
            )
        )
