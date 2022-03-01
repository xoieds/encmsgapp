from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import random
import requests
import base64
import math
import time
import os


def accvrf(private_key, public_key, server_address):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    x = requests.post(server_address + "/nec", data={'plk': pem}, verify=False)
    x2 = requests.post(server_address + "/s2vac", data={'uuid': x.text}, verify=False)

    original_message = private_key.decrypt(
        base64.decodebytes(bytes(x2.text, 'utf-8')),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    x3 = requests.post(server_address + "/s2vacs3",
                       data={'uuid': x.text, 'vans': original_message}, verify=False)

    return {"uuid": x.text, "vans": original_message}


def genst(vans, uuid, server_address):
    svrpublic = serialization.load_pem_public_key(
        bytes(requests.post(server_address + "/key",
                            verify=False).text, 'utf-8'),
        backend=default_backend()
    )

    encrypted2 = base64.b64encode(svrpublic.encrypt(
        bytes(str(vans) + str(random.randint(1000001, 9999999)), "utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)))

    sv = requests.post(server_address + "/gns", data={'uuid': uuid, "vans": encrypted2}, verify=False)
    return sv.text


def senmsg(ruuid, uuid, server_address, message, salt, LH):
    open(os.path.join(os.getcwd() + "/" + str(ruuid) + ".cnf"), "a").write(str(message) + "," + str(uuid) + "," + str(hash(str(message) + "," + str(salt))) + "," + str(time.time()) + "\n")

    rcvpub = serialization.load_pem_public_key(
        bytes(requests.post(server_address + "/rtpk", data={'uuid': ruuid}, verify=False).text, 'utf-8'),
        backend=default_backend()
    )

    svrpublic = serialization.load_pem_public_key(
        bytes(requests.post(server_address + "/key", verify=False).text, 'utf-8'),
        backend=default_backend()
    )

    if LH == None:
        ax = base64.b64encode(rcvpub.encrypt(
            bytes(str(message) + "," + str(uuid) + "," + str(hash(str(message) + str(salt))) + "," + str(time.time()), "utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)))
    else:
        ax = base64.b64encode(rcvpub.encrypt(
            bytes(str(message) + "," + str(uuid) + "," + str(hash(message + LH)), "utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)))

    ct = str(ruuid) + "," + str(ax) + "," + str(salt) + ","
    for i in range((100 - (len(ct) - (math.floor(len(ct) / 100) * 100))) - 1):
        ct = ct + "_"

    ctl = [ct[i:i + 100] for i in range(0, len(ct), 100)]

    ctlx = str()
    for i in range(len(ctl)):
        ctlx = ctlx + str(base64.b64encode(svrpublic.encrypt(
            bytes(str(ctl[i]), "utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)))) + "|"

    mgss = requests.post(server_address + "/snm", data={'msgc': ctlx}, verify=False)
    return mgss.text

def rcvd(uuid, server_address, private_key):
    x = requests.post(server_address + "/rcv", data={'uuid': uuid}, verify=False).text
    x = x.split("\n")
    x.pop()
    original_message = []
    for i in range(len(x)):
        try:
            original_message.append(str(private_key.decrypt(
            base64.decodebytes(bytes(x[i][2:-1], "utf-8")),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)))[2:-1])
        except:
            pass

    return original_message
