import art
import os
import base64
import random
from colorama import Fore, Back, Style
from flask import Flask, render_template, request
from random import choice
from threading import Thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
#print("enter to start sevr")
#input()

svrpublic = serialization.load_pem_public_key(
      bytes(os.environ['pubkey'], 'utf-8'),
      backend=default_backend())

svrprivate = serialization.load_pem_private_key(
      bytes(os.environ['privkey'], 'utf-8'),
      password=None,
      backend=default_backend())
    
app = Flask("")

import vfr
import insm

insm.main(app, svrpublic, svrprivate)
vfr.main(app, svrpublic, svrprivate)

print(Fore.GREEN +Back.RED + art.text2art("server running"))
print(Style.RESET_ALL)