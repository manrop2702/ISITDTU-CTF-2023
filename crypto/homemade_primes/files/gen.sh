#!/bin/sh
cp ./secret.py ../release/secret.py
pip install pycryptodome
python ../release/chall.py
rm -rf ../release/secret.py ../release/__pycache__
mv output.txt ../release/output.txt