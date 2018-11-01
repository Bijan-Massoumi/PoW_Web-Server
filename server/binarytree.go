package server


import (
	"crypto/sha256"
)

type TreeNode struct {
	left *TreeNode
	right *TreeNode
	hash [32]byte
	userName string
	password string
}

type Tree struct {
	Root *TreeNode
}

func (head *Tree) Add(userName string, password string) {
	if head.Root == nil {
		head.Root = createHead(userName, password)
	} else {
		insert(nil, head.Root, newTreeNode(userName, password))
	}
}

func (head *Tree) VerifyAccount(userName string, password string) bool {
	node := find(head.Root, userName)
	return node != nil
}

func (head *Tree) Find(userName string) *TreeNode {
	return find(head.Root,userName)
}



//private methods ---------------

func createHead(userName string, password string)  *TreeNode {
	//calculate hashes here
	returnNode := newTreeNode(userName, password)
	hashBytes := append([]byte(returnNode.userName + "\x00" + returnNode.password + "\x00"), []byte{0,0}...) // go doesnt support terminating \0
	returnNode.hash = sha256.Sum256(hashBytes)
	return returnNode
}

func newTreeNode(userName string, password string) *TreeNode {
	return &TreeNode{left: nil,right: nil, hash: [32]byte{0}, userName:userName, password: password}
}

func find(currentNode *TreeNode, userName string) *TreeNode {
	if currentNode == nil {
		return nil
	} else {
		if currentNode.userName == userName {
			return currentNode
		} else if currentNode.userName < userName {
			return find(currentNode.right, userName)
		} else {
			return find(currentNode.left, userName)
		}
	}
}

func insert(prevNode *TreeNode,currentNode *TreeNode, insertionNode *TreeNode){
	if currentNode == nil {
		if prevNode == nil { //empty tree
			currentNode = insertionNode
		} else { // reached a leaf
			if prevNode.userName < insertionNode.userName {
				prevNode.right = insertionNode
			} else {
				prevNode.left = insertionNode
			}

			currentNode = insertionNode
		}
	} else {
		if currentNode.userName < insertionNode.userName {
			insert(currentNode,currentNode.right,insertionNode)
		} else if currentNode.userName > insertionNode.userName {
			insert(currentNode, currentNode.left, insertionNode)
		}
	}
	//calculate hashes here
	var hashes []byte

	if currentNode.left == nil && currentNode.right == nil {
		hashes = []byte{0,0}
	} else if currentNode.left == nil {
		hashes = append([]byte{0}, currentNode.right.hash[:]...)
	} else if currentNode.right == nil{
		hashes = append(currentNode.left.hash[:], []byte{0}...)
	} else {
		hashes = append(currentNode.left.hash[:],currentNode.right.hash[:]...)
	}

	hashBytes := append([]byte(insertionNode.userName + "\x00" + insertionNode.password + "\x00"), hashes...)
	currentNode.hash = sha256.Sum256(hashBytes)
}