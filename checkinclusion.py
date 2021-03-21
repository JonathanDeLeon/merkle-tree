#!/usr/bin/env python3
# Jonathan De Leon
# CSCI 531 Applied Cryptography
# March, 2021
# This file creates an audit proof to verify a specific data node is included in the Merkle Tree
# It uses the output file from `buildmtree.py`


import sys
import json
import hashlib

def getSibling(hashList, index):
    siblingIndex = 0
    if index % 2 == 0: # even; we are looking at the right child node
        siblingIndex = index - 1
    else: # odd; left child node
        siblingIndex = index + 1
    return hashList[siblingIndex]

def getProof(challenge, hashList):
    index = validateInclusion(challenge, hashList)
    if index < 0: # challenge not in hash list
        return None

    proofPath = []
    # find sibling
    while index > 0:
        sibling = getSibling(hashList, index)
        proofPath.append(sibling)
        index = int((index-1) / 2) # calculate parent index

    proofPath.append(hashList[index]) # add root; root has no sibling
    return proofPath

# Find challenge node in tree using post-order traversal
# Returns -1 if not found
def validateInclusion(challenge, hashList, index=0):
    if len(hashList) <= index: # check if node exists
        return -1
    proof = validateInclusion(challenge, hashList, 2*index + 1)
    if proof >= 0:
        return proof
    proof = validateInclusion(challenge, hashList, 2*(index +1 ))
    if proof >= 0:
        return proof
    return index if hashList[index] == challenge else -1


if __name__=="__main__":
    # Read merkle tree output file
    hashList=[]
    with open('merkle.tree', 'r') as read_file:
        jsonList = json.loads(read_file.read())
        for item in jsonList:
            hashList.append(item)

    # Read argument challenge
    challenge = sys.argv[1]
    challengeHash = hashlib.sha256(challenge.encode('utf-8')).hexdigest()
    print("Challenge argument: " + challenge)
    print("Challenge hash: " + challengeHash, end="\n\n")

    # Get audit proof
    proof = getProof(challengeHash, hashList)
    if (proof is not None and len(proof) > 0):
        print("yes")
        print("Audit Proof: " + str(proof))
    else:
        print("no")
