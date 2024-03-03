from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import json
import binascii

''' -----------------------USER_DEFINED FUNCTIONS------------------------ '''
# calculating nonce 
def calc_nonce(block):
    
    # update until satisfy
    while True :
        block_hash = SHA256.new(json.dumps(block,sort_keys=True).encode()).hexdigest()
        
        # check condition
        if int(block_hash,16) < 2**248:
            #print("done with calculate")
            return True
        # update nonce 
        else:
            block['Nonce']+=1

# validate the hash value of block
def validate_block(block_hash):
    
    print("-- Validate Nonce")
    # check
    if int(block_hash,16) < 2**248:
        print("-- Block is valid with nonce.")
        return True
    else:
        print("Block is invalid.")
        return False

''' -----------------------SIGNATURE && OPCHECKSIG------------------------ '''
# create signature
def create_signature(filename,prev_block):
    
    # open private key file
    with open(filename,"rb") as file1:
        private_key = DSA.importKey(file1.read(),'MyPassphrase')
    
    # calculate hash value of prev_block    
    prev_hash = SHA256.new(json.dumps(prev_block,sort_keys=True).encode())
    
    # sign
    signer = DSS.new(private_key,'fips-186-3')
    signature = signer.sign(prev_hash)
    
    # return byte type
    return signature

''' --------------------------------------------------------------------- '''
# Operation : OP_CHECKSIG
def OP_CHECKSIG(filename,prev_block,signature):
    
    # open public key file 
    with open(filename,"rb") as file1:
        public_key = DSA.importKey(file1.read())
    
    # calculate hash of previous block 
    prev_hash = SHA256.new(json.dumps(prev_block,sort_keys=True).encode())
    
    # create verifier
    verifier = DSS.new(public_key,'fips-186-3')
    print("-- Verifier created")

    # verification process 
    try:
        verifier.verify(prev_hash,signature) 
        print("-- Verify Success")
        return True
    except:
        print("Fail")
        return False
''' --------------------------------------------------------------------- '''
    
# generate key pair of Alice
alice_key = DSA.generate(1024)
alice_public_key = alice_key.y 

alice_pub_key = alice_key.publickey()

# Alice public key
with open("public_key_dsa.pem","wb") as file:
    file.write(alice_pub_key.exportKey('PEM'))
    file.close()
# Alice private key
with open("private_key_dsa.pem","wb") as file:
    file.write(alice_key.exportKey('PEM',True,'MyPassphrase'))
    file.close()
    
# generate key pair of Bob
bob_key = DSA.generate(1024)
bob_public_key = bob_key.y

''' ------------------------------------------------------------------- '''

# make a initial block 
# Let Alice have 10 coins 
current_TxID = 0 
genblock = {
            "TxID":current_TxID,
            "Hash":"This is the genesis block",
            "Nonce":0,
            "Output":
                {0:{
                    "Value":10,
                    "ScriptPubkey":{
                        0:alice_public_key,
                        1:"OP_CHECKSIG"}
                }}
            }

# create json file 
fw = open(f"Block{current_TxID}.json","w+")
fw.write(json.dumps(genblock,sort_keys=True,indent=2,separators=(',',':')))
fw.close()

''' ------------------------------------------------------------------- '''

# Until Alice sends all she has to Bob
block = genblock
while True:
    # set previous block
    prev_block = block
    prev_hash = SHA256.new(json.dumps(prev_block,sort_keys=True).encode())
    
    # create signature 
    signature = create_signature("private_key_dsa.pem",prev_block) 
    
    # set current TxID
    current_TxID +=1 
    print(f"\nSTART transaction #{current_TxID}")
    
    # Generate block
    block = {
            "TxId":current_TxID, 
            "Hash":prev_hash.hexdigest(), 
            "Nonce":0, # will be calculated by calc_nonce, later
    }
    
    
    # implementation of stack
    pubkey = prev_block['Output'][0]['ScriptPubkey'][0]
    operation = prev_block['Output'][0]['ScriptPubkey'][1]

    # pop 
    if (operation == "OP_CHECKSIG") and (pubkey == alice_public_key) :
        # OP_CHECKSIG True
        if OP_CHECKSIG("public_key_dsa.pem",prev_block,signature):
            
            block['Input'] = {
                        "Previous Tx":prev_hash.hexdigest(), 
                        "Index":0,  
                        "ScriptSig":binascii.hexlify(signature).decode() # hex_version of signature
                        }
            
            block['Output'] = {
                            0:{
                                "Value":prev_block['Output'][0]['Value']-1, 
                                "ScriptPubkey":{
                                    0:alice_public_key,
                                    1:"OP_CHECKSIG"}
                            },
                            1:{
                                "Value":1, 
                                "ScriptPubkey":bob_public_key
                            }
                        }
        
        # OP_CHECKSIG False
        else:
            print("Failed to OP_CHECKSIG")
            break


    # if setting nonce is well done
    if calc_nonce(block): 
        
        block_hash = SHA256.new(json.dumps(block,sort_keys=True).encode()).hexdigest()
        
        # validate block 
        if validate_block(block_hash):
            
            # if valid ...
            # create json file
            print("Export as json file ...")
            fw = open(f"Block{current_TxID}.json","w+")
            fw.write(json.dumps(block,sort_keys=True,indent=2,separators=(',',':')))
            fw.close()
            print("Created json file!")
        
        else:
            # if invalid ...
            print("block is invalid.")    
            
    # if fail to calculate nonce        
    else:
        print("Failed to calculate nonce.")
    
    print(f"\nEND transaction #{current_TxID}\n\n{current_TxID} transactions occured!!")
    
    # if alice spent all coins, transaction ends
    if block['Output'][0]['Value'] == 0:
        print("Alice spent all coins.")
        break
    
''' --------------------------------------------------------------------- '''

valid_transaction = 0

# Validation process 
for cur_idx in range(1,current_TxID+1):
    
    prev_idx = cur_idx-1
    
    prev_json = f"block{prev_idx}.json"
    current_json = f"block{cur_idx}.json"
    
    # set flag 
    hash_match = False
    sig_match = False
    
    # previous block 
    # - (calculate hash, get scriptPubkey)
    with open(prev_json,"r") as prev:
        data = json.load(prev)
        prev_hash = SHA256.new(json.dumps(data,sort_keys=True).encode())
        scriptPubkey = data['Output']['0']['ScriptPubkey']['0']
    
    # current block 
    # - (get recorded hash of previous block, scriptSig)
    with open(current_json,"r") as cur:
        data = json.load(cur)
        cur_hash = data['Hash']
        scriptSig = binascii.unhexlify(data['Input']['ScriptSig'].encode())
    
    print(f"\n\nSTART VALIDATION OF {prev_idx} block and {cur_idx} block ")
    
    # 1 ) check if hash value is correct 
    if(prev_hash.hexdigest() == cur_hash):
        print("--Hash value matches!")
        hash_match = True
    else:
        print("DOESN'T MATCH!")
    
    # 2 ) check digital signature 
    if(scriptPubkey==alice_public_key):
        with open("public_key_dsa.pem","rb") as file:
            public_key = DSA.importKey(file.read())
        
        verifier = DSS.new(public_key,'fips-186-3')
        print("--Start Verification")
        
        try:
            verifier.verify(prev_hash,scriptSig)
            print("--Verification Success")
            sig_match = True
        except:
            print("verification fail")

    # if validation process done! 
    if(hash_match and sig_match):
        print("Validation well done")
        valid_transaction+=1
    else:
        print("Invalid chain")
        
''' --------------------------------------------------------------------- '''

print(f"\n{valid_transaction}/{current_TxID} is valid!")
