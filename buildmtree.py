#!/usr/bin/env python3
# Jonathan De Leon
# CSCI 531 Applied Cryptography
# March, 2021

import sys
import json
import hashlib

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

    # modified function from https://github.com/jdmcpeek/pretty-print-binary-tree
    def prettyPrint(self):
        # get height of tree
        total_layers = self.height

        maxIndex = len(self.tree)
        # start a queue for BFS
        queue = []
        # add root to queue
        nodeIndex = 0
        queue.append(self.tree[nodeIndex]) # self = root
        # index for 'generation' or 'layer' of tree
        gen = 1
        # BFS main
        while queue:
          # copy queue
          # 
          copy = []
          while queue:
            copy.append(queue.pop())
          # 
          # end copy queue 

          first_item_in_layer = True
          edges_string = ""
          extra_spaces_next_node = False

          # modified BFS, layer by layer (gen by gen)
          while copy:

            node = copy.pop()
            node = node[0:5]
            nodeLeftIndex = 2*nodeIndex + 1
            nodeRightIndex = 2*nodeIndex + 2
            nodeLeft = self.tree[nodeLeftIndex] if nodeLeftIndex < maxIndex else None
            nodeRight = self.tree[nodeRightIndex] if nodeRightIndex < maxIndex else None

            # -----------------------------
            # init spacing
            spaces_front = pow(2, total_layers - gen + 1) - 2
            spaces_mid   = pow(2, total_layers - gen + 2) - 2
            dash_count   = pow(2, total_layers - gen) - 2
            if dash_count < 0:
              dash_count = 0
            spaces_mid = spaces_mid - (dash_count*2)
            spaces_front = spaces_front - dash_count
            init_padding = 2
            spaces_front += init_padding
            if first_item_in_layer:
              edges_string += " " * init_padding
            # ----------------------------->

            # -----------------------------
            # construct edges layer
            edge_sym = "/" if nodeLeft is not None else " "
            if first_item_in_layer:
              edges_string += " " * int(pow(2, total_layers - gen) - 1) + edge_sym
            else:
              edges_string += " " * int(pow(2, total_layers - gen + 1) + 1) + edge_sym
            edge_sym = "\\" if nodeRight is not None else " "
            edges_string += " " * int(pow(2, total_layers - gen + 1) - 3) + edge_sym
            # ----------------------------->

            # -----------------------------
            # conditions for dashes
            if nodeLeft is None:
              dash_left = " "
            else:
              dash_left = "_"

            if nodeRight is None:
              dash_right = " "
            else:
              dash_right = "_"
            # ----------------------------->

            # -----------------------------
            # handle condition for extra spaces when node lengths don't match or are even:
            if extra_spaces_next_node:
              extra_spaces = 1
              extra_spaces_next_node = False
            else:
              extra_spaces = 0
            # ----------------------------->
            # -----------------------------
            # account for longer data
            data_length = len(str(node))
            if data_length > 1:
              if data_length % 2 == 1: # odd
                if dash_count > 0:
                  dash_count -= int(((data_length - 1)/2))
                else:
                  spaces_mid -= int((data_length - 1)/2)
                  spaces_front -= int((data_length - 1)/2)
                  if data_length != 1:
                    extra_spaces_next_node = True 
              else: # even
                if dash_count > 0:
                  dash_count -= int(((data_length)/2) - 1)
                  extra_spaces_next_node = True
                  # dash_count += 1
                else:
                  spaces_mid -= (data_length - 1)
                  spaces_front -= (data_length - 1)
            # ----------------------------->
            # -----------------------------
            # print node with/without dashes
            if first_item_in_layer:
              print ((" " * spaces_front) + (dash_left * dash_count) + (node) + (dash_right * dash_count), end=" ")
              first_item_in_layer = False
            else:
              print ((" " * (spaces_mid-extra_spaces)) + (dash_left * dash_count) + (node) + (dash_right * dash_count), end=" ")
            # ----------------------------->

            if nodeLeft is not None: queue.append(nodeLeft)
            if nodeRight is not None: queue.append(nodeRight)
            nodeIndex += 1

          # print the fun squiggly lines
          if queue:
            print("\n" + edges_string)

          # increase layer index
          gen += 1
        return '\n'

    def __repr__(self):
        return self.prettyPrint()


if __name__ == "__main__":
    print("Welcome to Merkle Tree\n")
    transactions = sys.argv[1].split(',')
    merkleTree = MerkleTree(transactions)
    print("Hashes are printed from top to bottom where the first is the root hash")
    print(merkleTree.tree)
    print('-'*100)
   # print(merkleTree.rootHash)
    print(merkleTree.prettyPrint())

    # output the merkle tree to a file
    with open('merkle.tree', 'w') as f:
        f.write(json.dumps(merkleTree.tree))
