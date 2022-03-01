from PyQt5.QtWidgets import (QApplication, QComboBox, QGridLayout, QLineEdit, QPushButton, QTextEdit, QWidget)
from qt_material import apply_stylesheet
import apilib
import os
from os.path import exists
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from operator import itemgetter

app = QApplication([])
window = QWidget()
apply_stylesheet(app, theme='dark_amber.xml')
layoutv = QGridLayout(window)
sv = 0
sm = 0

try:
    open(os.path.join(os.getcwd() + "/acdat.inf"), "x")
except:
    pass


def loadk():
    global pubk, privk
    with open("pubkey.pem", "rb") as key_file:
        pubk = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    with open("private_key.pem", "rb") as key_file:
        privk = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )


def genkeyp():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with open('pubkey.pem', 'wb') as f:
        f.write(pem)

    pim = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as f:
        f.write(pim)


def quit():
    exit()


def make_account(serveraddr):
    try:
        x = apilib.accvrf(privk, pubk, serveraddr)
        slt = apilib.genst(x["vans"], x["uuid"], serveraddr)
    except Exception as e:
        print(e)

    with open(os.path.join(os.getcwd() + "/acdat.inf"), "a") as f:
        f.write(str(x["uuid"]) + "," + str(x["vans"]) + "," + str(serveraddr) + "," + str(slt) + "\n")

    for i in reversed(range(layoutv.count())):
        layoutv.itemAt(i).widget().setParent(None)

    maingui(x["uuid"], x["vans"], serveraddr, slt)


def add(serveraddr, l):
    make_account(serveraddr)
    l.addItem(str(serveraddr))


def send(ruuid, uuid, server_address, message, salt, lh):
    try:
        n = apilib.rcvd(uuid, server_address, privk)
    except Exception as e:
        print(e)

    m = []

    for i in range(len(open(os.path.join(os.getcwd() + "/" + str(sm) + ".cnf"), "r").readlines())):
        m.append(open(os.path.join(os.getcwd() + "/" + str(sm) + ".cnf"), "r").readlines()[i].split(","))

    for i in range(len(n)):
        m.append(n[i].split(","))

    a = sorted(m, key=itemgetter(3))
    salt = a[-1:]

    apilib.senmsg(ruuid, uuid, server_address, message, salt, lh)


def refresh(l, uuid, server_address):
    n = apilib.rcvd(uuid, server_address, privk)
    m = []

    for i in range(len(open(os.path.join(os.getcwd() + "/" + str(sm) + ".cnf"), "r").readlines())):
        m.append(open(os.path.join(os.getcwd() + "/" + str(sm) + ".cnf"), "r").readlines()[i].split(","))

    for i in range(len(n)):
        m.append(n[i].split(","))

    a = sorted(m, key=itemgetter(3))

    t = str()
    for i in range(len(a)):
        if str(a[i][1]) == sm or str(a[i][1]) == str(uuid):
            t = t + str(a[i][1]) + ":\n" + str(a[i][0]) + "\n\n"

    l.setText(t)


def onchanged(text):
    sv = text.split(",")[0]


def adc(ct, server_address, l):
    try:
        open(os.path.join(os.getcwd() + "/" + str(ct) + ".cnf"), "x")
    except Exception as e:
        print(e)

    try:
        for i in range(l.count()):
            if ct == l.itemText(i):
                return

        with open(os.path.join(os.getcwd() + "/" + server_address[8:] + ".ct"), "r+") as f:
            f.write(str(ct) + "\n")

        l.addItem(ct)


    except Exception as e:
        print(e)


def smd(text):
    global sm
    sm = text


def remove(ct, l, server_address):
    with open(os.path.join(os.getcwd() + "/" + server_address[8:] + ".ct"), "r+") as f:
        f.truncate(0)
    l.clear()


def maingui(uuid, vans, server_address, slt):
    open(os.path.join(os.getcwd() + "/" + server_address[8:] + ".ct"), "a")

    for i in reversed(range(layoutv.count())):
        layoutv.itemAt(i).widget().setParent(None)

    t = QTextEdit()
    t.setReadOnly(True)
    layoutv.addWidget(t, 0, 1, 6, 1)

    window.setWindowTitle("username: " + str(uuid))

    print(open(os.path.join(os.getcwd() + "/acdat.inf"), "r").readlines())
    if slt is None:
        slt = open(os.path.join(os.getcwd() + "/acdat.inf"), "r").readlines()[sv][3]

    l = QComboBox()
    l.addItem("")
    for i in range(len(open(os.path.join(os.getcwd() + "/" + server_address[8:] + ".ct"), "r+").readlines())):
        l.addItem(str(open(os.path.join(os.getcwd() + "/" + server_address[8:] + ".ct"), "r+").readlines()[i])[:-1])
    l.setFixedSize(200, 30)
    l.activated[str].connect(smd)
    layoutv.addWidget(l, 0, 0)

    mm = QLineEdit()
    layoutv.addWidget(mm, 6, 1)

    ct = QLineEdit()
    ct.setFixedSize(200, 30)
    layoutv.addWidget(ct, 1, 0)

    s = QPushButton('send')
    s.clicked.connect(lambda: send(sm, uuid, server_address, mm.text(), slt, None))
    layoutv.addWidget(s, 6, 0)

    a = QPushButton('add')
    a.clicked.connect(lambda: adc(ct.text(), server_address, l))
    layoutv.addWidget(a, 2, 0)

    r = QPushButton('remove all')
    r.clicked.connect(lambda: remove(sm, l, server_address))
    layoutv.addWidget(r, 3, 0)

    q = QPushButton('quit')
    q.clicked.connect(quit)
    layoutv.addWidget(q, 4, 0)

    r = QPushButton('refresh')
    r.clicked.connect(lambda: refresh(t, uuid, server_address))
    layoutv.addWidget(r, 5, 0)


if exists("pubkey.pem") is True and exists("private_key.pem") is True:
    loadk()
else:
    genkeyp()
    loadk()

t = QLineEdit()
t.setPlaceholderText("enter server address")
layoutv.addWidget(t, 1, 0)

mk = QPushButton('add')
mk.clicked.connect(lambda: add(t.text(), l))
layoutv.addWidget(mk, 1, 1)

l = QComboBox()
for i in range(len(open(os.path.join(os.getcwd() + "/acdat.inf"), "r+").readlines())):
    l.addItem(
        str(i + 1) + ", " + str(open(os.path.join(os.getcwd() + "/acdat.inf"), "r+").readlines()[i]).split(",")[2][:-1])
layoutv.addWidget(l, 0, 0)
l.activated[str].connect(onchanged)

x = QPushButton('start')
layoutv.addWidget(x, 1, 1)
x.setFixedSize(300, 60)
x.clicked.connect(lambda: maingui(open(os.path.join(os.getcwd() + "/acdat.inf")).readlines()[sv].split(",")[0],
                                  open(os.path.join(os.getcwd() + "/acdat.inf")).readlines()[sv].split(",")[1],
                                  open(os.path.join(os.getcwd() + "/acdat.inf")).readlines()[sv].split(",")[2], None))
layoutv.addWidget(x, 2, 0)

window.setLayout(layoutv)
window.show()
app.exec()
