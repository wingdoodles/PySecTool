import hashlib
import itertools

class PasswordCracker:
    def __init__(self):
        self.target_hash = None
        self.wordlist = []
    
    def start_crack(self, target_hash=None, wordlist=None):
        self.target_hash = target_hash
        self.wordlist = wordlist or []
        
        for word in self.wordlist:
            hashed = hashlib.md5(word.encode()).hexdigest()
            if hashed == self.target_hash:
                return word
        return None
