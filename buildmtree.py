#!/usr/bin/env python3
# Jonathan De Leon
# CSCI 531 Applied Cryptography
# March, 2021

import sys
import json
import hashlib

import math
from io import StringIO

class MerkleTree:

    def __init__(self, transactions):
        self.transactions = transactions
        self.hashList = []
        self.tree = [] # keep track of proper tree representation for printing
        self.height = 0 # TODO: generate this from a method
        self.__generateTree__()

    def __generateTree__(self):
        # hash given list of transactions
        for item in self.transactions:
            self.hashList.append(hashlib.sha256(item.encode('utf-8')).hexdigest())

        if len(self.hashList) > 1:
            self.generateTree(self.hashList)
            self.tree.extend(self.hashList[0:len(self.transactions)])
            if len(self.transactions) % 2 != 0:
                self.tree.append(self.hashList[len(self.transactions)-1])

    # recursively generate parent hashed nodes for the given list
    def generateTree(self, hashList):
        if len(hashList) == 1:
            return hashList[0]

        # duplicate last hash if tree is odd to have a complete tree
        if len(hashList) % 2 != 0:
            hashList.append(hashList[-1])

        self.height += 1

        tempList = []
        # go through pairs and generate hashes
        for i in range(0, len(hashList)-1, 2):
            pair = hashList[i] + hashList[i+1]
            parentHash = hashlib.sha256(pair.encode('utf-8')).hexdigest()
            self.hashList.append(parentHash)
            tempList.append(parentHash)

        rootHash = self.generateTree(tempList)
        self.tree.extend(tempList)
        return

    @property
    def rootHash(self):
        return self.hashList[-1] if len(self.hashList) > 0 else None

    # Source from: https://www.w3resource.com/python-exercises/heap-queue-algorithm/python-heapq-exercise-19.php
    def show_tree(self, total_width=80, fill=' '):
        """Pretty-print a tree.
        total_width depends on your input size"""
        output = StringIO()
        last_row = -1
        for i, n in enumerate(self.tree):
            if i:
                row = int(math.floor(math.log(i+1, 2)))
            else:
                row = 0
            if row != last_row:
                output.write('\n')
            columns = 2**row
            col_width = int(math.floor((total_width * 1.0) / columns))
            output.write(str(n[0:5]).center(col_width, fill))
            last_row = row
        print (output.getvalue())
        print ('-' * total_width)
        return output.getvalue()

    def __repr__(self):
        return self.show_tree()


if __name__ == "__main__":
    print("Welcome to Merkle Tree\n")
    transactions = sys.argv[1].split(',')
    merkleTree = MerkleTree(transactions)
    print("Hashes are printed from top to bottom where the first is the root hash")
    print(merkleTree.tree)
    print('-'*100)
   # print(merkleTree.rootHash)
    merkleTree.show_tree()

    # output the merkle tree to a file
    with open('merkle.tree', 'w') as f:
        f.write(json.dumps(merkleTree.tree))
