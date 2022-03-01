#defines main function
def main(app, svrpublic, svrprivate):
  #imports libraries, os flask, random, threadding, cryptography and base64
  import os
  import base64
  import random
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

  #makes a path that just returns the servers public key
  @app.route("/key/", methods=["POST"])
  def key():
    return os.environ["pubkey"]

  #function that takes a users public key, creates a file with their public key and user id for that user and returns their user id
  @app.route("/nec/", methods=["POST"])
  def index():
    uuid = random.randint(0,10000000000)

    try:
      os.mkdir("dta/" + str(uuid))
    except OSError:
      return "error try again"

    open("dta/" + str(uuid) + "/pubkey.pem", 'w').write(request.form.get("plk")) 
    
    return str(uuid)

  #generates a shared secret, encrypts it by the users public key and encodes it with base64, and encrypts a copy of it by the servers public key and base64 and saves it to the users file
  @app.route("/s2vac/", methods=["POST"])
  def s2vac():
    vint = random.randint(0,9999999999999999999999999999999999999999999999999999999999999999)
    #secrets.token_bytes([nbytes=None])

    encb6 = base64.b64encode(svrpublic.encrypt(
      bytes(str(vint), "utf-8"),
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None)))

    os.mkdir("dta/" + request.form.get("uuid") + "/inboxas")
    open("dta/" + request.form.get("uuid") + "/inboxas/msg.msg", 'x')

      
    with open( "dta/" + request.form.get("uuid") + "/verstt.dat", "a+") as f:
      f.truncate(0)
      f.write('m')
      f.write(str(encb6))
      f.close()

    with open("dta/" + request.form.get("uuid") + "/pubkey.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
          key_file.read(),
          backend=default_backend())

    encrypted2 = base64.b64encode(public_key.encrypt(
      bytes(str(vint), "utf-8"),
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None)))
      
    return encrypted2
    
  #async function that takes the users user id and the shared secret encrypted by the servers public key
  #if it is what it is supposed to be they are marked as verified in their file
  @app.route("/s2vacs3/", methods=["POST"])
  def s2vacs3():  
    original_message = svrprivate.decrypt(
      base64.decodebytes(bytes(open("dta/" + request.form.get("uuid") + "/verstt.dat", "r").read()[2:-1], "utf-8")),
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None))
    
    if open("dta/" + request.form.get("uuid") + "/verstt.dat", "r").read()[:1] == "m":
      if str(original_message)[2:-1] == request.form.get("vans"):
        f = open("dta/" + request.form.get("uuid") + "/vrfs.dat", "a+")
        f.write("c")
        f.close()
        return "c"
    else:
      pass

    return "error"

  #returns any users public key
  @app.route("/rtpk/", methods=['POST'])
  def rptk():
    return open("dta/" + request.form.get("uuid") + "/pubkey.pem", "r").read()

  #defines a threadding object for the flask application run function
  Thread(target=app.run,args=("0.0.0.0",8080)).start()

  #runs main function only if interpreter is running main thread
  if __name__ == "__main__":
      app.run()