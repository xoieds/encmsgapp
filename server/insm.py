def main(app, svrpublic, svrprivate):
  import os
  import base64
  import random
  from flask import Flask, render_template, request, send_from_directory, send_file
  from random import choice
  from threading import Thread
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.kdf.hkdf import HKDF
  from cryptography.hazmat.primitives.asymmetric import dh
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import padding
  from cryptography.hazmat.primitives.asymmetric import rsa


  @app.route("/gns/", methods=['POST'])
  def gns():
    original_message = svrprivate.decrypt(
      base64.decodebytes(bytes(request.form.get("vans"), "utf-8")),
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None))

    original_message2 = svrprivate.decrypt(
      base64.decodebytes(bytes(open("dta/" + request.form.get("uuid") + "/verstt.dat", "r").read()[2:-1], "utf-8")),
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None))

    if open("dta/" + request.form.get("uuid") + "/verstt.dat", "r").read()[3:-1] in request.form.get("vans") or open("dta/" + request.form.get("uuid") + "/verstt.dat", "r").read()[3:-1] == request.form.get("vans"): return "error try again"

    if str(original_message)[4:-9] == str(original_message2)[2:-1]:
      salt = random.randint(0,999999999999999999999999999999999999999999999999999)
      with open( "dta/" + request.form.get("uuid") + "/salt.dat", 'a+') as f:
        f.truncate(0)
        f.write(str(salt))
        f.close()
      return str(salt)
    else: 
      return "error try again"



  #recipient uuid, (message and sender uuid)recipient public key  , salt
  @app.route("/snm/", methods=['POST'])
  def snm():
    x = str(request.form.get("msgc")).split("|")

    original_message = str()
    for i in range(len(x)-1):
      original_message = original_message +  str(svrprivate.decrypt(
        base64.decodebytes(bytes(x[i][2:-1], "utf-8")),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)))[2:-1]

    print(original_message)
    original_message = original_message.split(",")

    try:
      os.mkdir("dta/" + original_message[0] + "/inboxas")
    except:
      pass

    with open("dta/" + original_message[0] + "/inboxas/msg.msg", 'a+') as f:
      f.write(original_message[1] + "\n" )


    return "c"

  @app.route("/rcv/", methods=['POST'])
  def rcv():
    return send_file(str("dta/" + request.form.get("uuid") + "/inboxas/msg.msg"), as_attachment=True)

