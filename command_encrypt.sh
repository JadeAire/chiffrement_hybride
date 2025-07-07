#!/bin/bash

echo "Ecrivez votre message"
read message
echo $message > message.txt
python3 generate_rsa_key.py
python3 encrypt.py

