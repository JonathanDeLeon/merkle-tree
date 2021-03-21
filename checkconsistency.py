#!/usr/bin/env python3
# Jonathan De Leon
# CSCI 531 Applied Cryptography
# March, 2021
# Let's you verify that any two versions of the tree are consistent
# Meaning that the second version includes everything in the earlier version in the same order


import sys
import json
import hashlib
from buildmtree import MerkleTree

def verifyTreeConsistency(newTree, oldRootHash, oldTreeSize):
    newTreeSize = len(newTree.transactions)
    # newTree cannot contain less nodes than the oldTree
    if newTreeSize < oldTreeSize:
        return False

    # compare root hash values if number of transactions are the same
    if newTreeSize == oldTreeSize:
        return newTree.rootHash == oldRootHash

    temp = oldRootHash + newTree.hashList[-2]
    tempHash = hashlib.sha256(temp.encode('utf-8')).hexdigest()
    return tempHash == newTree.rootHash

if __name__=="__main__":
    # Old MerkleTree
    oldTransactions = sys.argv[1].split(',')
    oldMerkleTree = MerkleTree(oldTransactions)

    # New MerkleTree
    newTransactions = sys.argv[2].split(',')
    newMerkleTree = MerkleTree(newTransactions)

    print ("Old Merkle Tree")
    oldMerkleTree.show_tree()
    print ("New Merkle Tree")
    newMerkleTree.show_tree()

    consistent = verifyTreeConsistency(newMerkleTree, oldMerkleTree.rootHash, len(oldMerkleTree.transactions))
    if(consistent == True):
        print("yes ")
        proof = [oldMerkleTree.rootHash, newMerkleTree.hashList[-2], newMerkleTree.rootHash]
        print("Audit Proof: " + str(proof))
    else:
        print("no ")

    # output the merkle trees to a file
    with open('merkle.trees', 'w') as f:
        data = {
            "old": oldMerkleTree.tree,
            "new": newMerkleTree.tree
        }
        f.write(json.dumps(data))
