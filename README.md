# Space-structured_Blockchain

This is a prototype of blockchain (BC) in python 3.6

The system consists of three parts, which are webchain, conchain, and chainbase.

# Description

Different from previous work, this prototype adopts a novel space-structured ledger with several advanced algorihms.

Our motivation is to enabling blockchain in heterogeneous environments, e.g., IoT.

In detail, the roles in P2P network is devided to two parts, which are macroblock miner and microblock miner.

During each epoch, macroblock miners execute leadership selection, while microblock miners just validate transactions.

To find more details, please wait for our update.

# How to use?

Here is a usage example (just for local test, which 1 microblock miner and 2 macroblock miners）

**First**

Use pip to install requirements:
```
pip install -r requirements.txt
```
**Second**

Build lib.so (Pivot Chain selection function, written in C++)
```
g++ main.cpp -fPIC -shared -o lib.so
g++ main.cpp -fPIC -shared -o lib_test.so
g++ main.cpp -fPIC -shared -o lib_test_two.so
```
**Third**

Run backend Chainbase
```
python DAG_macro_chainbase.py
python DAG_macro_chainbsse_test.py
python DAG_micro_chainbase.py
```
**Forth**

Run consensus module Conchain
```
python DAG_macro_conchain.py
python DAG_macro_conchain_test.py
python micro_conchain.py
```
**Fifth**

Run frontend Webchain
```
python webchain.py
python webchain_test.py
python webchin_test_two.py
```
**Sixth**

Run trans-generator
```
python trans_maker.py
python trans_maker_test.py
python trans_maker_test_two.pu
```
Then the test network is build successfully!

If you want to build a public net version, you should:

**First**

Start webchain using Gunicorn:

```
pip install gunicorn
```

```
gunicorn --workers=3 webchain:app -b 0.0.0.0:8000
```

Then, webchain is accessable form port:8000!

**Second**

Build lib.so (Pivot Chain selection function, written in C++)
```
g++ main.cpp -fPIC -shared -o lib.so
```
**Third**

Run backend Chainbase
```
python DAG_macro_chainbase.py
```
**Forth**

Run consensus module Conchain
```
python DAG_macro_conchain.py
```
**Fifth**

Run trans-generator
```
python trans_maker.py
```
Then the public network version is build successfully! :blush:

