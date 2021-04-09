from flask import Flask, render_template, request, json
from OpenSSL import crypto, SSL
import os
import codecs
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

@app.route("/")
def home():
	return render_template("proba.html")

@app.route("/random")
def random():
	size = 32
	return codecs.encode(os.urandom(size), 'hex').decode();
	
@app.route("/encrypt")
def encrypt():
	size = 40
	return codecs.encode(os.urandom(size), 'hex').decode()

@app.route("/int2byte", methods=['POST'])	
def int2byte():
	return json.dumps(hex(int(request.form['number'])).lstrip("0x"));

@app.route("/certgen", methods=['POST'])
def certgen():
	#emailAddress="emailAddress",
	commonName = "ftn.uns.ac.rs"
	countryName = "RS"
	localityName = "Novi Sad"
	stateOrProvinceName = "Vojvodina"
	organizationName = "Faculty of Technical Sciences"
	organizationUnitName = "Chair of Informatics"
	serialNumber = 0
	validityStartInSeconds = 0
	validityEndInSeconds = 10*365*24*60*60
	KEY_FILE = "private.key"
	CERT_FILE = "selfsigned.crt"
    	#can look at generated file using openssl:
    	#openssl x509 -inform pem -in selfsigned.crt -noout -text
    	# create a key pair
	k = crypto.PKey()
	k.generate_key(crypto.TYPE_RSA, 4096)
    	# create a self-signed cert
	cert = crypto.X509()
	cert.get_subject().C = countryName
	cert.get_subject().ST = stateOrProvinceName
	cert.get_subject().L = localityName
	cert.get_subject().O = organizationName
	cert.get_subject().OU = organizationUnitName
	cert.get_subject().CN = commonName
	#cert.get_subject().emailAddress = emailAddress
	cert.set_serial_number(serialNumber)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(validityEndInSeconds)
	cert.set_issuer(cert.get_subject())
	cert.set_pubkey(k)
	cert.sign(k, 'sha512')
    	#with open(CERT_FILE, "wt") as f:
        #f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    	#with open(KEY_FILE, "wt") as f:
        #f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
	return json.dumps({"cert": codecs.encode(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), 'hex').decode('utf-8'), "key": codecs.encode(crypto.dump_publickey(crypto.FILETYPE_PEM, k), 'hex').decode('utf-8')}); 

@app.route("/sign", methods=['POST'])	
def sign():
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
	signature = private_key.sign(codecs.encode(request.form['data']), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
	return json.dumps({'signature': codecs.encode(signature, 'hex').decode('utf-8')});
	
@app.route("/clientpublickey")
def clientpublickey():
	key = RSA.generate(2048)
	return json.dumps({'clientpublickey': codecs.encode(key.publickey().exportKey("DER"), 'hex').decode('utf-8')});

if __name__=="__main__":
	app.run()
