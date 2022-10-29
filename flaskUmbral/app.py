from flask import Flask, render_template, request
import sys
sys.path.append('/home/dhrumil/pyUmbral/umbral')
# sys.path.append('/home/dhrumil/secret-sharing/secretsharing')
from umbral import config
from umbral.curve import SECP256K1
from umbral import keys, signing, params
from umbral import pre
import json
import base64
#import ipfshttpclient
import random
#from secretsharing import PlaintextToHexSecretSharer

#client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')

config.set_default_curve(SECP256K1)

app = Flask(__name__)
app.secret_key = "Poojan Patel"


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
       if isinstance(obj, set):
          return list(obj)
       return json.JSONEncoder.default(self, obj)

def bytes_to_string(b):
    encoded = base64.b64encode(b)
    return encoded.decode('utf-8')

def string_to_bytes(s):
    sd = s.encode('utf-8')
    return base64.b64decode(sd)

kfrags = list()

@app.route('/alice')
def alice():
    return render_template('alice.html')

@app.route('/gen_keys')
def gen_keys():
    #generate the private and public keys required for encryption of data
    person_privKey =  keys.UmbralPrivateKey.gen_key()
    person_pubKey = person_privKey.get_pubkey()
    #Make a JSON object 
    person_keys = {
        "person_privKey": bytes_to_string(person_privKey.to_bytes()),
        "person_pubKey": bytes_to_string(person_pubKey.to_bytes())
    }
    return render_template('generate.html', person_keys=person_keys)

@app.route('/encrypt',methods=["GET","POST"])
def encrypt():
    if request.method == 'POST':
        # Get the data from the request payload
        print(request.data)
        plaintext = request.form["plaintext"].encode("utf-8")
        pubKey = string_to_bytes(request.form["person_pubKey"])
        pubKey = keys.UmbralPublicKey.from_bytes(pubKey)
    
        #Encrypt the data
        ciphertext, capsule = pre.encrypt(pubKey, plaintext)

        # response Text
        dataToBeStored = {
            "ciphertext": bytes_to_string(ciphertext),
            "capsule": bytes_to_string(capsule.to_bytes())
        }
        with open('data.json', 'w') as outfile:
            json.dump(dataToBeStored, outfile, cls=SetEncoder)
    
    return render_template('encrypt.html')

@app.route('/grant_access',methods=["GET","POST"])
def grant_access():
    if request.method == 'POST':
        # Get the data from the request payload and convert them to bytes
        bobPubKey = string_to_bytes(request.form["bobPubKey"])
        bobPubKey = keys.UmbralPublicKey.from_bytes(bobPubKey)
        alicePrivKey = string_to_bytes(request.form["alicePrivKey"])
        alicePrivKey = keys.UmbralPrivateKey.from_bytes(alicePrivKey)
        alicePubKey = alicePrivKey.get_pubkey()

        #generate the signing key
        alices_signing_key = keys.UmbralPrivateKey.gen_key()
        alices_verifying_key = alices_signing_key.get_pubkey()
        alices_signer = signing.Signer(private_key=alices_signing_key)

        # Generating kfrags
        global kfrags
        kfrags = pre.generate_kfrags(delegating_privkey=alicePrivKey,signer=alices_signer,receiving_pubkey=bobPubKey,threshold=10,N=20)
        
        # Storing the kfrags on the bob's side
        dataToBeStoredBob = {
            "alice_verifying_key": bytes_to_string(alices_verifying_key.to_bytes()),
            "alicePubKey": bytes_to_string(alicePubKey.to_bytes())
        }

        with open('hospital.json', 'w') as outfile:
            json.dump(dataToBeStoredBob, outfile, cls=SetEncoder)
        
    return render_template('grant.html')


@app.route('/decrypt',methods=["GET","POST"])
def decrypt():
    if request.method == 'POST':
        # Get the private key
        bobPrivKey = string_to_bytes(request.form["bobPrivKey"])
        bobPrivKey = keys.UmbralPrivateKey.from_bytes(bobPrivKey)
        bobPubKey = bobPrivKey.get_pubkey()

        # read the capsule from the json dump
        with open('data.json') as json_file:
            data1 = json.load(json_file)
            ciphertext = string_to_bytes(data1['ciphertext'])
            capsule = string_to_bytes(data1['capsule'])
            capsule = pre.Capsule.from_bytes(capsule, params.UmbralParameters(SECP256K1))
        
        # get the kfrags

        with open('hospital.json') as json_file:
            data2 = json.load(json_file)
            # kfrags = data2['kfrags']
            alicePubKey = string_to_bytes(data2["alicePubKey"])
            alicePubKey = keys.UmbralPublicKey.from_bytes(alicePubKey)
            alice_verifying_key = string_to_bytes(data2["alice_verifying_key"])
            alice_verifying_key = keys.UmbralPublicKey.from_bytes(alice_verifying_key)

        global kfrags
        kfrags = random.sample(kfrags,10)

    
        capsule.set_correctness_keys(delegating=alicePubKey,receiving=bobPubKey,verifying=alice_verifying_key)
        cfrags = list()
        for kfrag in kfrags:
            cfrag = pre.reencrypt(kfrag=kfrag, capsule=capsule)
            cfrags.append(cfrag)
    
        capsule.set_correctness_keys(delegating=alicePubKey,receiving=bobPubKey,verifying=alice_verifying_key)

        for cfrag in cfrags:
            capsule.attach_cfrag(cfrag)
        
        #decrypt the data
        plainBobtext = pre.decrypt(ciphertext=ciphertext,capsule=capsule, decrypting_key=bobPrivKey)
        plainBobtext = plainBobtext.decode('utf-8')
        return render_template('decrypt.html', plainBobtext=plainBobtext, data=data1)
    
    with open('data.json') as json_file:
        data1 = json.load(json_file)
    
    return render_template('decrypt.html',data=data1)


@app.route('/split_keys',methods=["GET","POST"])
def split_keys():
    if request.method == 'POST':
        # Get the request data
        dataToSplit = request.form["dataToSplit"]
        howManyCanReContruct = request.form["howManyCanReContruct"]
        howManyPeople = request.form["howManyPeople"]
        shares = PlaintextToHexSecretSharer.split_secret(dataToSplit, howManyCanReContruct, howManyPeople)
        return render_template('split_keys.html', shares=shares)



if __name__ == '__main__':
    app.run(debug=True)