FROM sagemath/sagemath:latest

WORKDIR /home/challenge

RUN sage -python -m pip install --upgrade pip
RUN sudo apt-get update
RUN sudo apt-get install -y socat

RUN sage -python -m pip install pycryptodome

COPY utils.sage challenge.py secret.py Signature.sage .

ENTRYPOINT ["socat","-v","TCP-LISTEN:9999,reuseaddr,fork","EXEC:sage -python challenge.py,stderr"]