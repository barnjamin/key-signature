# Key Signature


## Motivation
Often application developers will want more on chain storage than is provided by global state.  Local state provides up to 16 key/values with a 128 byte limit per k/v. 

In this demo, we use a smart signature in a way that allows us to extend our storage capability by creating a new account given a byte string as a key.  Since the address of the resultant smart sig is predictable we can use it as another level of storage.

## Setup


Project setup starts by installing the [sandbox](https://github.com/algorand/sandbox)

Then:
```sh
git clone git@github.com:barnjamin/key-signature.git
cd key-signature
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run it:
```sh
python main.py
```


## Contents

- app.py: contains approval and clear source PyTeal

- key_sig.py: contains smart sig PyTeal

- main.py: contains python control logic to create the app and a set of key sigs 

- keysig.tmpl.teal: contains the template TEAL

- keysig.json: contains the assembly map details (Created with a [special branch](https://github.com/barnjamin/go-algorand/tree/assembly-map) )

- requirements.txt: contains the specific versions of python packages needed